use super::{
    attempt_invalid_tool_call_repair, attempt_patch_build_verify_runtime_patch_miss_repair,
    attempt_refusal_repair, invalid_tool_repair_supported,
    maybe_rewrite_patch_build_verify_post_success_completion,
    maybe_rewrite_patch_build_verify_redundant_refresh_read,
    patch_build_verify_deterministic_allowed_tool_names, patch_build_verify_primary_patch_file,
    repair_tool_names_match, synthesize_patch_build_verify_code_block_edit_repair,
    upconvert_patch_build_verify_runtime_line_edit_repair,
    updated_python_block_candidate_from_raw_output,
    validate_patch_build_verify_deterministic_edit_repair,
    validate_patch_build_verify_runtime_edit_repair,
    validate_patch_build_verify_runtime_goal_constraints, DeterministicEditRepairValidation,
};
use crate::agentic::runtime::keys::get_state_key;
use crate::agentic::runtime::service::lifecycle::persist_worker_assignment;
use crate::agentic::runtime::service::step::action::processing::maybe_rewrite_patch_build_verify_post_command_edit;
use crate::agentic::runtime::service::step::action::record_execution_evidence_with_value;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ToolCallStatus,
    WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{
    ImageEditRequest, ImageGenerationRequest, ImageGenerationResult, InferenceRuntime,
    RerankRequest, RerankResult, SpeechSynthesisRequest, SpeechSynthesisResult,
    TextGenerationRequest, TextGenerationResult, TranscriptionRequest, TranscriptionResult,
    VideoGenerationRequest, VideoGenerationResult, VisionReadRequest, VisionReadResult,
};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    AgentTool, InferenceOptions, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::ContextSlice;
use ioi_types::codec;
use ioi_types::error::VmError;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[derive(Clone)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|error| VmError::HostError(format!("mock PNG encode failed: {}", error)))?;
        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root/>".to_string())
    }

    async fn capture_context(
        &self,
        _intent: &ioi_types::app::ActionRequest,
    ) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![b"<root/>".to_vec()],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

#[derive(Default)]
struct RepairRecordingRuntime {
    outputs: Mutex<Vec<Result<Vec<u8>, VmError>>>,
    text_outputs: Mutex<Vec<Result<Vec<u8>, VmError>>>,
    seen_tools: Mutex<Vec<Vec<String>>>,
    seen_inputs: Mutex<Vec<Vec<u8>>>,
}

#[async_trait]
impl InferenceRuntime for RepairRecordingRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .push(input_context.to_vec());
        self.seen_tools
            .lock()
            .expect("seen_tools mutex poisoned")
            .push(options.tools.iter().map(|tool| tool.name.clone()).collect());
        let mut outputs = self.outputs.lock().expect("outputs mutex poisoned");
        if outputs.is_empty() {
            return Err(VmError::HostError("no repair output queued".to_string()));
        }
        outputs.remove(0)
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        Ok(vec![text.len() as f32, 1.0])
    }

    async fn embed_image(&self, _image_bytes: &[u8]) -> Result<Vec<f32>, VmError> {
        Ok(vec![1.0])
    }

    async fn generate_text(
        &self,
        request: TextGenerationRequest,
    ) -> Result<TextGenerationResult, VmError> {
        let mut outputs = self
            .text_outputs
            .lock()
            .expect("text_outputs mutex poisoned");
        if !outputs.is_empty() {
            let output = outputs.remove(0)?;
            return Ok(TextGenerationResult {
                output,
                model_id: request.model_id,
                streamed: request.stream,
            });
        }
        Ok(TextGenerationResult {
            output: request.input_context,
            model_id: request.model_id,
            streamed: request.stream,
        })
    }

    async fn rerank(&self, _request: RerankRequest) -> Result<RerankResult, VmError> {
        Err(VmError::HostError("rerank not supported".to_string()))
    }

    async fn transcribe_audio(
        &self,
        _request: TranscriptionRequest,
    ) -> Result<TranscriptionResult, VmError> {
        Err(VmError::HostError("transcribe not supported".to_string()))
    }

    async fn synthesize_speech(
        &self,
        _request: SpeechSynthesisRequest,
    ) -> Result<SpeechSynthesisResult, VmError> {
        Err(VmError::HostError("speech not supported".to_string()))
    }

    async fn vision_read(&self, _request: VisionReadRequest) -> Result<VisionReadResult, VmError> {
        Err(VmError::HostError("vision not supported".to_string()))
    }

    async fn generate_image(
        &self,
        _request: ImageGenerationRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Err(VmError::HostError(
            "image generation not supported".to_string(),
        ))
    }

    async fn edit_image(
        &self,
        _request: ImageEditRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Err(VmError::HostError("image edit not supported".to_string()))
    }

    async fn generate_video(
        &self,
        _request: VideoGenerationRequest,
    ) -> Result<VideoGenerationResult, VmError> {
        Err(VmError::HostError(
            "video generation not supported".to_string(),
        ))
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_worker_state(session_id: [u8; 32]) -> AgentState {
    AgentState {
        session_id,
        goal: "Implement the parity fix.".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 4,
        last_action_type: None,
        parent_session_id: Some([9u8; 32]),
        child_session_ids: Vec::new(),
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 1,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
        pending_search_completion: None,
        planner_state: None,
    }
}

fn patch_assignment() -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:test".to_string(),
        budget: 24,
        goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string(),
        success_criteria: "Patch the bug and verify it.".to_string(),
        max_retries: 0,
        retries_used: 0,
        assigned_session_id: Some([0x77; 32]),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "filesystem__read_file".to_string(),
            "filesystem__write_file".to_string(),
            "filesystem__edit_line".to_string(),
            "filesystem__search".to_string(),
            "filesystem__list_directory".to_string(),
            "filesystem__stat".to_string(),
            "filesystem__patch".to_string(),
            "sys__exec_session".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Patch the bug and verify it.".to_string(),
            expected_output: "Patched and verified.".to_string(),
            merge_mode: WorkerMergeMode::AppendAsEvidence,
            verification_hint: None,
        },
    }
}

fn patch_assignment_with_allowed_tools(allowed_tools: Vec<&str>) -> WorkerAssignment {
    let mut assignment = patch_assignment();
    assignment.allowed_tools = allowed_tools.into_iter().map(str::to_string).collect();
    assignment
}

fn patch_assignment_with_path_parity_goal() -> WorkerAssignment {
    let mut assignment = patch_assignment();
    assignment.goal = concat!(
        "Port the path-normalization parity fix into the repo root. Patch only `path_utils.py`, ",
        "keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it ",
        "converts backslashes to forward slashes, collapses duplicate separators, and preserves ",
        "a leading `./` or `/`, then rerun `python3 -m unittest tests.test_path_utils -v` after the edit.\n\n",
        "[PARENT PLAYBOOK CONTEXT]\n",
        "- likely_files: path_utils.py; tests/test_path_utils.py\n",
        "- targeted_checks: python3 -m unittest tests.test_path_utils -v"
    )
    .to_string();
    assignment
}

fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "test".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.92,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn record_targeted_check_failure(worker_state: &mut AgentState) {
    worker_state
        .command_history
        .push_back(crate::agentic::runtime::types::CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 0,
        });
}

mod code_write_repairs;
mod refusal;
mod runtime_patch_repairs;
mod runtime_validation;
mod support_and_targeted_exec;
