use super::router::AttentionMode;
use super::{
    assemble_prompt_sections, browser_prompt_visual_grounding_required, browser_rule_relevant,
    browser_surface_requires_visual_grounding, build_browser_operating_rules,
    build_compact_browser_action_prompt_assembly, build_compact_browser_action_system_instructions,
    build_operating_rules, build_recent_command_history_context, build_standard_prompt_assembly,
    build_strategy_instruction, build_tool_routing_contract, command_workspace_action_phase_tools,
    compact_browser_action_prompt_eligible, compact_browser_action_prompt_tools,
    encode_browser_prompt_screenshot, filter_cognition_tools, filter_cognition_tools_with_recovery,
    format_prompt_assembly_report, has_meaningful_visual_context,
    inference_error_system_fail_reason, mailbox_connector_instruction,
    preflight_missing_capability, render_active_worker_instruction,
    render_selected_parent_playbook_instruction, render_workspace_scope_instruction,
    reply_safe_browser_semantics_enabled, top_edge_jump_name, top_edge_jump_tool_call,
    top_edge_jump_tool_call_with_grounded_selector, workspace_reference_context,
    CognitionToolRecovery, PromptSection,
};
use crate::agentic::runtime::service::visual_loop::perception::PerceptionContext;
use crate::agentic::runtime::types::{
    AgentState, CommandExecution, ExecutionTier, PendingSearchCompletion, PendingSearchReadSummary,
    WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_types::app::agentic::{
    CapabilityId, ChatMessage, InstructionContract, InstructionSideEffectMode,
    IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition, ResolvedIntentState,
};
use std::collections::VecDeque;
use std::io::Cursor;

fn tool(name: &str) -> LlmToolDefinition {
    LlmToolDefinition {
        name: name.to_string(),
        description: "".to_string(),
        parameters: "{}".to_string(),
    }
}

fn tool_with_schema(name: &str, description: &str, parameters: &str) -> LlmToolDefinition {
    LlmToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters: parameters.to_string(),
    }
}

fn resolved_intent(intent_id: &str, scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: intent_id.to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "test".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "test".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn chat_message(role: &str, content: &str, timestamp: u64) -> ChatMessage {
    ChatMessage {
        role: role.to_string(),
        content: content.to_string(),
        timestamp,
        trace_hash: None,
    }
}

fn encode_png_base64(width: u32, height: u32) -> String {
    let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(width, height);
    for pixel in img.pixels_mut() {
        *pixel = Rgba([255, 0, 0, 255]);
    }
    let mut bytes = Vec::new();
    img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
        .expect("encode png");
    BASE64.encode(bytes)
}

fn perception_context() -> PerceptionContext {
    PerceptionContext {
        tier: ExecutionTier::DomHeadless,
        screenshot_base64: None,
        visual_phash: [0u8; 32],
        active_window_title: "Chromium".to_string(),
        project_index: "|root: ./ioi-data".to_string(),
        agents_md_content: "do browser things".to_string(),
        memory_pointers: "- [ID:0] remember this".to_string(),
        available_tools: vec![],
        tool_desc: String::new(),
        worker_assignment: None,
        visual_verification_note: None,
        last_failure_reason: None,
        consecutive_failures: 0,
    }
}

fn automation_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "automation.monitor".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("automation.monitor.install")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
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

include!("tests_parts/root/prompt_assembly.rs");
include!("tests_parts/root/browser_prompting.rs");
include!("tests_parts/root/reply_routing.rs");
include!("tests_parts/root/final_reply_evidence.rs");
include!("tests_parts/root/context_rules.rs");
include!("tests_parts/root/command_inference_misc.rs");
