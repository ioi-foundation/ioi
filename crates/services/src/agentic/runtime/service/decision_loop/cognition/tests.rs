use super::router::AttentionMode;
use super::{
    assemble_prompt_sections, browser_prompt_visual_grounding_required, browser_rule_relevant,
    browser_surface_requires_visual_grounding, build_browser_operating_rules,
    build_compact_browser_action_prompt_assembly, build_compact_browser_action_system_instructions,
    build_operating_rules, build_recent_command_history_context, build_standard_prompt_assembly,
    build_strategy_instruction, build_tool_routing_contract,
    compact_browser_action_prompt_eligible, compact_browser_action_prompt_tools,
    encode_browser_prompt_screenshot, filter_cognition_tools, format_prompt_assembly_report,
    has_meaningful_visual_context, inference_error_system_fail_reason,
    mailbox_connector_instruction, preflight_missing_capability, render_active_worker_instruction,
    render_selected_parent_playbook_instruction, render_workspace_scope_instruction,
    reply_safe_browser_semantics_enabled, top_edge_jump_name, top_edge_jump_tool_call,
    top_edge_jump_tool_call_with_grounded_selector, workspace_reference_context, PromptSection,
};
use crate::agentic::runtime::service::visual_loop::perception::PerceptionContext;
use crate::agentic::runtime::types::{
    CommandExecution, ExecutionTier, WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_types::app::agentic::{
    CapabilityId, ChatMessage, IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition,
    ResolvedIntentState,
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

#[test]
fn prompt_assembly_enforces_section_budgets_and_reports_truncation() {
    let assembly = assemble_prompt_sections(vec![
        PromptSection::new("alpha", "abcdef").with_budget(4),
        PromptSection::new("beta", "second section"),
        PromptSection::new("empty", "   ").with_budget(10),
    ]);

    assert!(assembly.system_instructions.contains("a..."));
    assert!(assembly.system_instructions.contains("second section"));
    assert!(!assembly.system_instructions.contains("empty"));
    assert_eq!(
        assembly.report.total_chars,
        assembly.system_instructions.chars().count()
    );
    assert_eq!(assembly.report.sections.len(), 3);
    assert!(assembly.report.sections[0].truncated);
    assert!(!assembly.report.sections[1].truncated);
    assert!(!assembly.report.sections[2].included);

    let report = format_prompt_assembly_report(&assembly.report);
    assert!(report.contains("alpha:included=true"));
    assert!(report.contains("truncated=true"));
    assert!(report.contains("empty:included=false"));
}

#[test]
fn standard_prompt_assembly_omits_empty_sections_and_keeps_specialized_sections() {
    let assembly = build_standard_prompt_assembly(
        "Kernel guidance.",
        "Chromium",
        "Finish checkout",
        "browser.checkout (scope=Browser band=High score=0.99)",
        "CORE MEMORY:\n- Current Goal: Finish checkout",
        "",
        "",
        "Strategy goes here.",
        "TOOL ROUTING CONTRACT:\n- prefer specific tools",
        "",
        "",
        "COMMAND EXECUTION CONTRACT:\n- Use terminal evidence.",
        "browser__inspect",
        "CURRENT BROWSER OBSERVATION:\n<button id=\"checkout\" />",
        "",
        "",
        "RECENT SESSION EVENTS:\nclicked checkout",
        "",
        "WORKSPACE CONTEXT:\nrepo=ioi",
        "OPERATING RULES:\n- verify success",
        Some("MAILBOX CONNECTOR RULE:\n- stay mailbox-local"),
        Some("SELECTED EXECUTION ROUTE:\n- Parent playbook: `evidence_audited_patch`"),
        Some("ACTIVE WORKER CONTRACT:\n- Finish with a bounded brief"),
        "WORKSPACE OPS CONTRACT:\n- prefer filesystem tools",
        "",
    );

    assert!(assembly
        .system_instructions
        .contains("=== LAYER 1: KERNEL POLICY ==="));
    assert!(assembly
        .system_instructions
        .contains("CURRENT BROWSER OBSERVATION"));
    assert!(assembly
        .system_instructions
        .contains("RECENT SESSION EVENTS"));
    assert!(assembly
        .system_instructions
        .contains("MAILBOX CONNECTOR RULE"));
    assert!(assembly
        .system_instructions
        .contains("SELECTED EXECUTION ROUTE"));
    assert!(assembly
        .system_instructions
        .contains("ACTIVE WORKER CONTRACT"));
    assert!(assembly
        .system_instructions
        .contains("WORKSPACE OPS CONTRACT"));
    assert!(assembly
        .system_instructions
        .contains("TOOL ROUTING CONTRACT"));
    assert!(!assembly.system_instructions.contains("automation.monitor"));

    let included_sections: Vec<_> = assembly
        .report
        .sections
        .iter()
        .filter(|section| section.included)
        .map(|section| section.name)
        .collect();
    assert!(included_sections.contains(&"mailbox_instruction"));
    assert!(included_sections.contains(&"selected_parent_playbook_instruction"));
    assert!(included_sections.contains(&"active_worker_instruction"));
    assert!(included_sections.contains(&"workspace_scope_contract"));
    assert!(included_sections.contains(&"tool_routing_contract"));
    assert!(!included_sections.contains(&"automation_monitor_contract"));
}

#[test]
fn selected_parent_playbook_instruction_surfaces_root_route_kickoff() {
    let rendered = render_selected_parent_playbook_instruction(Some(&ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: ioi_types::app::agentic::IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
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
        instruction_contract: Some(ioi_types::app::agentic::InstructionContract {
            operation: "delegate".to_string(),
            side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::Update,
            slot_bindings: vec![
                ioi_types::app::agentic::InstructionSlotBinding {
                    slot: "playbook_id".to_string(),
                    binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                    value: Some("evidence_audited_patch".to_string()),
                    origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
                    protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
                },
                ioi_types::app::agentic::InstructionSlotBinding {
                    slot: "template_id".to_string(),
                    binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                    value: Some("context_worker".to_string()),
                    origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
                    protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
                },
                ioi_types::app::agentic::InstructionSlotBinding {
                    slot: "workflow_id".to_string(),
                    binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                    value: Some("repo_context_brief".to_string()),
                    origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
                    protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
                },
            ],
            negative_constraints: vec![],
            success_criteria: vec![],
        }),
        constrained: false,
    }))
    .expect("selected route guidance should render");

    assert!(rendered.contains("Root-session kickoff must be `agent__delegate`"));
    assert!(rendered.contains("evidence_audited_patch"));
    assert!(rendered.contains("planner_authority=kernel"));
    assert!(rendered.contains("verifier_role=test_verifier"));
    assert!(rendered.contains("context_worker"));
    assert!(rendered.contains("repo_context_brief"));
}

#[test]
fn active_worker_instruction_surfaces_repo_context_completion_contract() {
    let rendered = render_active_worker_instruction(
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 48,
            goal: "Inspect repo context".to_string(),
            success_criteria: "Return a bounded brief.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("context_worker".to_string()),
            workflow_id: Some("repo_context_brief".to_string()),
            role: Some("Context Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__search".to_string(),
                "file__info".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded repo brief.".to_string(),
                expected_output: "Repo context brief.".to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: None,
            },
        }),
        "/tmp/repo",
    )
    .expect("worker instruction should render");

    assert!(rendered.contains("ACTIVE WORKER CONTRACT"));
    assert!(rendered.contains("evidence_audited_patch"));
    assert!(rendered.contains("repo_context_brief"));
    assert!(rendered.contains("Current working directory: `/tmp/repo`"));
    assert!(rendered.contains("Delegated goal: `Inspect repo context`"));
    assert!(rendered.contains("do not repeat the same root `file__info`"));
    assert!(rendered.contains("`likely_files`"));
}

#[test]
fn active_worker_instruction_surfaces_coder_repo_root_contract() {
    let rendered = render_active_worker_instruction(
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 96,
            goal: "Patch the workspace".to_string(),
            success_criteria: "Land the patch.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }),
        "/tmp/repo-root",
    )
    .expect("coder worker instruction should render");

    assert!(rendered.contains("patch_build_verify"));
    assert!(rendered.contains("Current working directory: `/tmp/repo-root`"));
    assert!(rendered.contains("Delegated goal: `Patch the workspace`"));
    assert!(rendered.contains("Do not spend more than one probe confirming the repo root"));
    assert!(rendered.contains("focused verification command"));
    assert!(rendered.contains("your next action must be `file__edit`"));
}

#[test]
fn active_worker_instruction_surfaces_patch_context_hints() {
    let rendered = render_active_worker_instruction(
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 96,
            goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v\n- open_questions: Widen only if the focused verification command fails.".to_string(),
            success_criteria: "Land the patch.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__search".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }),
        "/tmp/repo-root",
    )
    .expect("coder worker instruction should render");

    assert!(rendered.contains("Likely patch files from parent context"));
    assert!(rendered.contains("path_utils.py, tests/test_path_utils.py"));
    assert!(rendered.contains("Focused verification command from parent context"));
    assert!(rendered.contains("python3 -m unittest tests.test_path_utils -v"));
    assert!(rendered.contains("do not reread the identical file"));
    assert!(rendered.contains("file__write"));
    assert!(!rendered.contains("file__replace_line"));
    assert!(rendered.contains("If `file__search` fails or returns nothing useful"));
}

#[test]
fn workspace_ops_contract_distinguishes_root_planner_from_active_worker() {
    let root_contract = render_workspace_scope_instruction(
        Some("evidence_audited_patch"),
        true,
        true,
        true,
        true,
        None,
    );
    let worker_contract = render_workspace_scope_instruction(
        Some("evidence_audited_patch"),
        true,
        true,
        true,
        true,
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 96,
            goal: "Patch the workspace".to_string(),
            success_criteria: "Land the patch.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }),
    );

    assert!(root_contract.contains("Start the selected parent playbook with `agent__delegate`"));
    assert!(worker_contract.contains("do not restart the parent playbook from this worker"));
    assert!(worker_contract.contains("repeated repo-root `file__info` / `file__list` probes"));
}

#[test]
fn compact_browser_prompt_assembly_reports_named_sections() {
    let assembly = build_compact_browser_action_prompt_assembly(
        "Kernel guidance.",
        "Chromium",
        "Keep following the moving target.",
        "browser.hover (scope=Browser band=High score=0.91)",
        "CORE MEMORY:\n- Workflow Stage: Follow target",
        "URGENT UPDATE: keep the cursor on the shape.",
        "",
        "Choose a grounded next tool call.",
        "TOOL ROUTING CONTRACT:\n- prefer grounded browser tools",
        "",
        "browser__move_pointer",
        "CURRENT BROWSER OBSERVATION:\n<canvas id=\"surface\" />",
        "",
        "",
        "OPERATING RULES:\n- use grounded browser state",
    );

    assert!(assembly
        .system_instructions
        .contains("Follow policy. Output exactly one grounded browser tool call"));
    assert!(assembly
        .system_instructions
        .contains("TOOL ROUTING CONTRACT"));
    assert!(assembly
        .report
        .sections
        .iter()
        .any(|section| section.name == "state"));
    assert!(assembly
        .report
        .sections
        .iter()
        .any(|section| section.name == "available_tools" && section.included));
    assert!(assembly
        .report
        .sections
        .iter()
        .any(|section| section.name == "tool_routing_contract" && section.included));
}

#[test]
fn tool_routing_contract_prefers_specific_workspace_tools_over_shell() {
    let contract = build_tool_routing_contract(false, IntentScopeProfile::WorkspaceOps);
    assert!(contract.contains("Prefer the most specific typed workspace tool"));
    assert!(contract.contains("`file__search` only when the path is still unknown"));
    assert!(contract.contains("`file__info` for timestamps and metadata"));
    assert!(contract.contains("generic shell commands"));
}

#[test]
fn tool_routing_contract_prefers_browser_semantic_tools_for_browser_steps() {
    let contract = build_tool_routing_contract(true, IntentScopeProfile::UiInteraction);
    assert!(contract.contains("grounded browser tool"));
    assert!(contract.contains("`browser__inspect`"));
    assert!(contract.contains("`browser__select_option`"));
    assert!(contract.contains("`screen__click_at`"));
    assert!(contract.contains("`web__search` / `web__read`"));
}

#[test]
fn command_execution_does_not_require_clipboard() {
    let tools = vec![tool("shell__run")];
    assert!(preflight_missing_capability(
        None,
        IntentScopeProfile::CommandExecution,
        false,
        &tools
    )
    .is_none());
}

#[test]
fn tiny_screenshot_is_not_meaningful_visual_context() {
    let screenshot = encode_png_base64(1, 1);
    assert!(!has_meaningful_visual_context(Some(&screenshot)));
}

#[test]
fn larger_screenshot_is_meaningful_visual_context() {
    let screenshot = encode_png_base64(32, 32);
    assert!(has_meaningful_visual_context(Some(&screenshot)));
}

#[test]
fn browser_surface_requires_visual_grounding_for_svg_geometry_snapshot() {
    let snapshot = r#"<svg id="svg-grid" tag_name="svg"><generic shape_kind="circle" geometry_role="vertex" /></svg>"#;
    assert!(browser_surface_requires_visual_grounding(
        Some(snapshot),
        "RECENT BROWSER OBSERVATION:"
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_plain_browser_forms() {
    let snapshot = r#"<root><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_canvas_wrapper_when_dom_targets_exist() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation =
        "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit selector=[id=\"submit\"] dom_clickable=true\ngrp_click_canvas tag=generic name=click canvas";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_packed_canvas_wrapper_when_dom_targets_exist()
{
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: btn_submit tag=button name=Submit selector=[id=\"submit\"] dom_clickable=true | grp_click_canvas tag=generic name=click canvas | root_dom_fallback_tree tag=root name=DOM fallback tree </root>";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_requires_canvas_when_only_wrapper_is_grounded() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\ngrp_click_canvas tag=generic name=click canvas";
    assert!(browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_skips_grounded_shape_targets() {
    let snapshot = r#"<root><svg id="area_svg" tag_name="svg"><generic id="grp_5" name="5" shape_kind="rectangle" center="63,154" /></svg></root>"#;
    let observation =
        "RECENT BROWSER OBSERVATION:\ngrp_5 tag=generic name=5 shape_kind=rectangle center=63,154";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_canvas_wrapper_when_shape_target_is_grounded()
{
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><svg id="area_svg" tag_name="svg"><generic id="grp_circ" name="large circle" shape_kind="circle" center="84,141" /></svg></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: grp_circ tag=generic name=large circle centered at 84,141 radius 22 dom_id=circ selector=[id=\"circ\"] shape_kind=circle center=84,141 radius=22 | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id=\"click-canvas\"] | root_dom_fallback_tree tag=root name=DOM fallback tree </root>";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_drops_dom_form_screenshot() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation =
        "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit selector=[id=\"submit\"] dom_clickable=true\ngrp_click_canvas tag=generic name=click canvas";
    assert!(!browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_keeps_canvas_screenshot() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas></root>"#;
    assert!(browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        "RECENT BROWSER OBSERVATION:\ngrp_click_canvas tag=generic name=click canvas"
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_drops_canvas_screenshot_when_shape_target_is_grounded()
{
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><svg id="area_svg" tag_name="svg"><generic id="grp_circ" name="large circle" shape_kind="circle" center="84,141" /></svg></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: grp_circ tag=generic name=large circle centered at 84,141 radius 22 dom_id=circ selector=[id=\"circ\"] shape_kind=circle center=84,141 radius=22 | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id=\"click-canvas\"] | root_dom_fallback_tree tag=root name=DOM fallback tree </root>";
    assert!(!browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_drops_canvas_screenshot_when_start_gate_is_first_priority_target(
) {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><generic id="grp_start" name="START" dom_id="sync-task-cover" dom_clickable="true"></generic></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: grp_start tag=generic name=START dom_id=sync-task-cover selector=[id=\"sync-task-cover\"] dom_clickable=true | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id=\"click-canvas\"] </root>";
    assert!(!browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        observation
    ));
}

#[test]
fn encoded_browser_prompt_screenshot_stays_meaningful() {
    let screenshot = encode_png_base64(160, 120);
    let raw_bytes = BASE64.decode(screenshot).expect("decode png");
    let encoded = encode_browser_prompt_screenshot(&raw_bytes).expect("encode prompt jpeg");
    assert!(has_meaningful_visual_context(Some(&encoded)));
}

#[test]
fn encoded_browser_prompt_screenshot_does_not_upscale_small_inputs() {
    let screenshot = encode_png_base64(160, 120);
    let raw_bytes = BASE64.decode(screenshot).expect("decode png");
    let encoded = encode_browser_prompt_screenshot(&raw_bytes).expect("encode prompt jpeg");
    let encoded_bytes = BASE64.decode(encoded).expect("decode jpeg");
    let image = image::load_from_memory(&encoded_bytes).expect("load jpeg");
    assert_eq!((image.width(), image.height()), (160, 120));
}

#[test]
fn browser_prompt_uses_trimmed_browser_tool_surface() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("screen"),
            tool("screen__click"),
            tool("agent__complete"),
            tool("agent__escalate"),
        ],
        None,
        true,
        "",
        "",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__inspect",
            "browser__click",
            "agent__complete",
            "agent__escalate",
        ]
    );
}

#[test]
fn browser_prompt_compacts_structured_tool_schema_metadata() {
    let filtered = filter_cognition_tools(
        &[tool_with_schema(
            "browser__hover",
            "Move the pointer onto a grounded browser target.",
            r#"{
                "type":"object",
                "description":"Hover arguments",
                "properties":{
                    "id":{
                        "type":"string",
                        "description":"Semantic target id",
                        "examples":["grp_circ"]
                    },
                    "duration_ms":{
                        "type":"integer",
                        "title":"Duration",
                        "description":"How long to track the hover target."
                    }
                },
                "required":["id"]
            }"#,
        )],
        None,
        true,
        "",
        "",
        "",
    );
    let tool = filtered.first().expect("browser tool should remain");

    assert_eq!(
        tool.description,
        "Move the pointer onto a grounded browser target."
    );
    assert!(
        tool.parameters.contains("\"description\""),
        "{}",
        tool.parameters
    );
    assert!(
        !tool.parameters.contains("\"title\""),
        "{}",
        tool.parameters
    );
    assert!(
        !tool.parameters.contains("\"examples\""),
        "{}",
        tool.parameters
    );
    assert!(tool.parameters.contains("\"required\":[\"id\"]"));
    assert!(tool.parameters.contains("\"duration_ms\""));
}

#[test]
fn browser_prompt_hides_synthetic_click_when_shape_targets_are_semantically_grounded() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        "RECENT BROWSER OBSERVATION:\ngrp_1 tag=generic name=1 shape_kind=digit center=125,96",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["browser__inspect", "browser__click", "agent__complete"]
    );
}

#[test]
fn browser_prompt_keeps_synthetic_click_when_only_canvas_wrapper_is_grounded() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        "RECENT BROWSER OBSERVATION:\ngrp_click_canvas tag=generic name=click canvas",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__inspect",
            "browser__click",
            "browser__click_at",
            "agent__complete"
        ]
    );
}

#[test]
fn browser_prompt_keeps_synthetic_click_for_grounded_geometry_targets() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        concat!(
            "RECENT BROWSER OBSERVATION:\n",
            "grp_vertex tag=generic name=small blue circle at 31,108 radius 4 ",
            "shape_kind=circle geometry_role=vertex connected_line_angles=-24|23deg ",
            "angle_mid=0deg center=31,108"
        ),
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__inspect",
            "browser__click",
            "browser__click_at",
            "agent__complete"
        ]
    );
}

#[test]
fn browser_operating_rules_do_not_inject_geometry_degree_heuristics() {
    let rules = build_browser_operating_rules(
        "",
        concat!(
            "RECENT BROWSER OBSERVATION:\n",
            "grp_vertex tag=generic name=vertex shape_kind=circle geometry_role=vertex connected_line_angles=-24|23deg angle_mid=-1deg angle_span=47deg | ",
            "grp_blue_circle tag=generic name=endpoint shape_kind=circle geometry_role=endpoint target_angle_mid=-1deg angle_mid_offset=6deg angle_mid_delta=6deg | ",
            "grp_line tag=generic name=line shape_kind=line line_angle=5deg"
        ),
        "",
        "",
    );

    assert!(
        !rules.contains("Geometry degree fields are directly comparable"),
        "{rules}"
    );
}

#[test]
fn browser_prompt_hides_synthetic_click_while_start_gate_is_pending() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        concat!(
            "RECENT BROWSER OBSERVATION:\n",
            "btn_submit tag=button name=Submit selector=#subbtn"
        ),
        "RECENT PENDING BROWSER STATE:\nA visible start gate `grp_start` is still covering the task surface.\n",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["browser__inspect", "browser__click", "agent__complete"]
    );
}

#[test]
fn browser_prompt_reduces_tool_surface_for_sustained_hover_goals() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__navigate"),
            tool("browser__hover"),
            tool("browser__move_pointer"),
            tool("browser__wait"),
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click"),
            tool("browser__press_key"),
            tool("agent__complete"),
            tool("agent__escalate"),
        ],
        None,
        true,
        "Keep your mouse inside the circle as it moves around.",
        "",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__hover",
            "browser__move_pointer",
            "browser__wait",
            "browser__inspect",
            "browser__click",
            "agent__complete",
            "agent__escalate",
        ]
    );
}

#[test]
fn compact_browser_action_prompt_is_eligible_for_grounded_hover_state() {
    assert!(compact_browser_action_prompt_eligible(
        true,
        false,
        "Keep your mouse inside the circle as it moves around.",
        "RECENT BROWSER OBSERVATION:\ngrp_circ tag=generic name=large circle shape_kind=circle center=95,135",
        "",
        "",
    ));
}

#[test]
fn pure_conversation_reply_uses_reply_safe_tool_surface() {
    let filtered = filter_cognition_tools(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("agent__pause"),
            tool("agent__escalate"),
            tool("shell__run"),
            tool("memory__search"),
        ],
        Some(&ResolvedIntentState {
            intent_id: "conversation.reply".to_string(),
            scope: IntentScopeProfile::Conversation,
            band: ioi_types::app::agentic::IntentConfidenceBand::High,
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
        }),
        false,
        "",
        "",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "chat__reply",
            "agent__complete",
            "agent__pause",
            "agent__escalate"
        ]
    );
}

#[test]
fn pure_conversation_reply_disables_browser_semantics_even_in_browser_window() {
    let resolved = ResolvedIntentState {
        intent_id: "conversation.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: ioi_types::app::agentic::IntentConfidenceBand::High,
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
    };

    assert!(!reply_safe_browser_semantics_enabled(
        true,
        &[tool("browser__inspect"), tool("chat__reply")],
        Some(&resolved),
    ));
    assert!(reply_safe_browser_semantics_enabled(
        true,
        &[tool("browser__inspect"), tool("chat__reply")],
        None,
    ));
}

#[test]
fn compact_browser_action_prompt_requires_clean_grounded_browser_state() {
    assert!(!compact_browser_action_prompt_eligible(
        true,
        false,
        "Keep your mouse inside the circle as it moves around.",
        "",
        "",
        "",
    ));
    assert!(!compact_browser_action_prompt_eligible(
        true,
        false,
        "Keep your mouse inside the circle as it moves around.",
        "RECENT BROWSER OBSERVATION:\ngrp_circ tag=generic name=large circle shape_kind=circle center=95,135",
        "RECENT PENDING BROWSER STATE:\n`browser__hover` exact action",
        "",
    ));
    assert!(!compact_browser_action_prompt_eligible(
        true,
        true,
        "Keep your mouse inside the circle as it moves around.",
        "RECENT BROWSER OBSERVATION:\ngrp_circ tag=generic name=large circle shape_kind=circle center=95,135",
        "",
        "",
    ));
}

#[test]
fn compact_browser_action_system_instructions_omit_workspace_scaffolding() {
    let prompt = build_compact_browser_action_system_instructions(
        "IMPORTANT: Use grounded evidence.",
        "Chromium",
        "Keep your mouse inside the circle as it moves around.",
        "computer_use_suite.browser (scope=UiInteraction band=High score=0.990)",
        "CORE MEMORY:\n- Workflow Stage: Follow target",
        "",
        "",
        "MODE: BROWSER ACTION.",
        "TOOL ROUTING CONTRACT:\n- prefer grounded browser tools",
        "",
        "- browser__hover\n- browser__inspect\n- agent__escalate",
        "RECENT BROWSER OBSERVATION:\ngrp_circ tag=generic name=large circle shape_kind=circle center=95,135",
        "",
        "",
        "OPERATING RULES:\n1. Output EXACTLY ONE valid JSON tool call.",
    );
    assert!(prompt.contains("RECENT BROWSER OBSERVATION:"));
    assert!(prompt.contains("[AVAILABLE TOOLS]"));
    assert!(prompt.contains("browser__hover"));
    assert!(prompt.contains("TOOL ROUTING CONTRACT"));
    assert!(!prompt.contains("LAYER 3"));
    assert!(!prompt.contains("WORKSPACE CONTEXT"));
    assert!(!prompt.contains("RECENT SESSION EVENTS"));
}

#[test]
fn compact_browser_action_prompt_tools_preserve_locator_descriptions() {
    let compacted = compact_browser_action_prompt_tools(&[tool_with_schema(
        "browser__hover",
        "Move the browser pointer onto a target without clicking. Useful for hover-driven menus.",
        r#"{
            "type":"object",
            "properties":{
                "id":{"type":"string","description":"Semantic ID from browser__inspect."},
                "duration_ms":{"type":"integer","description":"Tracking window."}
            }
        }"#,
    )]);

    assert_eq!(compacted.len(), 1);
    assert_eq!(
        compacted[0].description,
        "Move the browser pointer onto a target without clicking. Useful for hover-driven menus."
    );

    let schema: serde_json::Value =
        serde_json::from_str(&compacted[0].parameters).expect("compact schema");
    assert_eq!(
        schema["properties"]["id"]["description"],
        "Semantic ID from browser__inspect."
    );
    assert!(schema["properties"]["duration_ms"]
        .get("description")
        .is_none());
}

#[test]
fn browser_prompt_strategy_calls_out_missing_visual_context() {
    let instruction = build_strategy_instruction(
        crate::agentic::runtime::types::ExecutionTier::VisualForeground,
        IntentScopeProfile::UiInteraction,
        true,
        true,
        false,
    );
    assert!(instruction.contains("No trustworthy visual screenshot"));
    assert!(instruction.contains("browser semantic tools"));
    assert!(instruction.contains("ordered `ids`"));
}

#[test]
fn workspace_reference_context_omits_passive_docs_for_browser_semantic_steps() {
    let context = workspace_reference_context(true, &perception_context());
    assert!(context.contains("WORKSPACE CONTEXT (Omitted)"));
    assert!(context.contains("browser-semantic action steps"));
    assert!(!context.contains("[PROJECT INDEX]"));
    assert!(!context.contains("[AGENTS.MD CONTENT]"));
    assert!(!context.contains("[MEMORY HINTS]"));
}

#[test]
fn workspace_reference_context_keeps_passive_docs_for_non_browser_steps() {
    let context = workspace_reference_context(false, &perception_context());
    assert!(context.contains("WORKSPACE CONTEXT (Untrusted Reference)"));
    assert!(context.contains("[PROJECT INDEX]"));
    assert!(context.contains("[AGENTS.MD CONTENT]"));
    assert!(context.contains("[MEMORY HINTS]"));
    assert!(context.contains("|root: ./ioi-data"));
}

#[test]
fn browser_operating_rules_drop_unrelated_command_and_launch_rules() {
    let rules = build_operating_rules(
        true,
        "Keep your mouse inside the circle as it moves around.",
        "RECENT BROWSER OBSERVATION:\ngrp_circ tag=generic name=large circle shape_kind=circle center=95,135",
        "",
        "",
    );
    assert!(rules.chars().count() < 2000, "{rules}");
    assert!(rules.contains("grounded browser state"), "{rules}");
    assert!(rules.contains("browser__hover"), "{rules}");
    assert!(rules.contains("duration_ms"), "{rules}");
    assert!(rules.contains("30000"), "{rules}");
    assert!(rules.contains("short probe hover"), "{rules}");
    assert!(rules.contains("browser__move_pointer"), "{rules}");
    assert!(rules.contains("browser__inspect"), "{rules}");
    assert!(rules.contains("target is missing"), "{rules}");
    assert!(!rules.contains("submit already turned over the page"));
    assert!(!rules.contains("Do not interact with the newly visible page"));
    assert!(!rules.contains("Only use `browser__click` ids"));
    assert!(!rules.contains("modifier chord"));
    assert!(!rules.contains("PageUp"));
    assert!(!rules.contains(top_edge_jump_name()));
    assert!(!rules.contains(top_edge_jump_tool_call()));
    assert!(!rules.contains("can_scroll_up=false"));
    assert!(!rules.contains("do not start with page-level `Home` or `End` on `body`"));
    assert!(!rules.contains("do not repeat it blindly"));
    assert!(!rules.contains("COMMAND PROBE RULE"));
    assert!(!rules.contains("APP LAUNCH RULE"));
}

#[test]
fn browser_rule_relevant_matches_words_not_unrelated_substrings() {
    assert!(browser_rule_relevant(
        "Reply to the visible post row.",
        &["reply", "row"]
    ));
    assert!(!browser_rule_relevant(
        "Time left: 9 / 10sec",
        &["item", "mark"]
    ));
}

#[test]
fn browser_operating_rules_restore_scroll_guidance_when_scroll_cues_are_present() {
    let rules = build_operating_rules(
        true,
        "Scroll the textarea to the top and submit.",
        "RECENT BROWSER OBSERVATION:\ninp_lorem tag=textbox can_scroll_up=true scroll_top=257",
        "RECENT PENDING BROWSER STATE:\nVisible scroll target `inp_lorem tag=textbox dom_id=text-area` is already on the page.",
        "",
    );
    assert!(rules.contains("modifier chord"), "{rules}");
    assert!(rules.contains("PageUp"), "{rules}");
    assert!(rules.contains(top_edge_jump_name()), "{rules}");
    assert!(
        rules.contains(top_edge_jump_tool_call_with_grounded_selector()),
        "{rules}"
    );
    assert!(rules.contains("reuse that same `selector`"), "{rules}");
}

#[test]
fn browser_operating_rules_require_fully_grounded_continue_with() {
    let rules = build_operating_rules(
        true,
        "Click start and then submit the visible form.",
        "RECENT BROWSER OBSERVATION:\nbtn_start tag=button name=START\nbtn_submit tag=button name=Submit",
        "RECENT PENDING BROWSER STATE:\nA visible start gate `btn_start` is still covering the task surface. Use `browser__click` on `btn_start` now to begin the page, then continue with the working controls.\n",
        "",
    );
    assert!(
        rules.contains(
            "Use `continue_with` only when the follow-up tool name and every required argument are already fully grounded"
        ),
        "{rules}"
    );
    assert!(
        rules.contains(
            "RECENT BROWSER OBSERVATION, RECENT PENDING BROWSER STATE, or RECENT SUCCESS SIGNAL"
        ),
        "{rules}"
    );
    assert!(
        rules.contains(
            "If the follow-up action is only implied by the page instruction, take the first action alone and re-evaluate."
        ),
        "{rules}"
    );
}

#[test]
fn browser_operating_rules_allow_single_grounded_follow_up_after_exact_coordinate_call() {
    let rules = build_operating_rules(
        true,
        "Complete the visible browser task.",
        "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit selector=[id=\"subbtn\"]",
        "RECENT PENDING BROWSER STATE:\nGeometry click drift detected. Use `{\"name\":\"browser__click_at\",\"arguments\":{\"x\":78.6,\"y\":89}}` now. If the corrected click lands and grounded follow-up control `btn_submit` is still the next required control, you may emit `{\"name\":\"browser__click_at\",\"arguments\":{\"x\":78.6,\"y\":89,\"continue_with\":{\"name\":\"browser__click\",\"arguments\":{\"id\":\"btn_submit\"}}}}` to avoid another inference turn.\n",
        "",
    );
    assert!(
        rules.contains("single grounded follow-up control"),
        "{rules}"
    );
    assert!(
        rules.contains("coordinate click's observable browser reaction"),
        "{rules}"
    );
}

#[test]
fn browser_operating_rules_prefer_browser_type_selector_for_grounded_fields() {
    let rules = build_operating_rules(
        true,
        "Enter the username into the visible field and submit.",
        "RECENT BROWSER OBSERVATION:\ninp_username tag=input name=Username selector=#username\nbtn_submit tag=button name=Submit selector=#subbtn",
        "",
        "",
    );
    assert!(
        rules.contains(
            "prefer one `browser__type` with `selector` over a separate focus click plus typing"
        ),
        "{rules}"
    );
    assert!(
        rules.contains("you may use `browser__click` with `continue_with` `browser__type`"),
        "{rules}"
    );
}

#[test]
fn browser_operating_rules_preserve_grounded_synthetic_click_precedence() {
    let rules = build_operating_rules(
        true,
        "Create a line on the visible SVG and then submit.",
        "RECENT BROWSER OBSERVATION:\ngrp_blue_circle tag=generic shape_kind=circle center=63,96\nbtn_submit tag=button name=Submit",
        "RECENT PENDING BROWSER STATE:\nGrounded geometry target `grp_blue_circle` is already visible. Use `browser__click_at` with `id` on `grp_blue_circle` now.\n",
        "RECENT SUCCESS SIGNAL:\nRecent synthetic click changed grounded geometry at `grp_vertex`.",
    );
    assert!(rules.contains("coordinate-style target"), "{rules}");
    assert!(
        rules.contains("follow that tool instead of converting it to `browser__click`"),
        "{rules}"
    );
    assert!(rules.contains("`browser__click_at`"), "{rules}");
}

#[test]
fn browser_only_goals_do_not_append_mailbox_connector_rule() {
    let goal = "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Find the email by Lonna and click the trash icon to delete it.";
    assert!(mailbox_connector_instruction(goal, &[]).is_none());
}

#[test]
fn command_execution_does_not_require_clipboard_when_exec_session_available() {
    let tools = vec![tool("shell__start")];
    assert!(preflight_missing_capability(
        None,
        IntentScopeProfile::CommandExecution,
        false,
        &tools
    )
    .is_none());
}

#[test]
fn command_execution_accepts_software_install_tooling() {
    let tools = vec![tool("software_install__execute_plan")];
    assert!(preflight_missing_capability(
        None,
        IntentScopeProfile::CommandExecution,
        false,
        &tools
    )
    .is_none());
}

#[test]
fn command_execution_requires_sys_exec_when_missing() {
    let tools = vec![tool("chat__reply")];
    let missing =
        preflight_missing_capability(None, IntentScopeProfile::CommandExecution, false, &tools)
            .expect("missing capability");
    assert_eq!(missing.0, "shell__run");
}

#[test]
fn automation_monitor_requires_automation_tool_not_sys_exec() {
    let tools = vec![tool("chat__reply")];
    let missing = preflight_missing_capability(
        Some(&automation_resolved_intent()),
        IntentScopeProfile::CommandExecution,
        false,
        &tools,
    )
    .expect("missing capability");
    assert_eq!(missing.0, "monitor__create");
}

#[test]
fn command_history_context_shows_latest_five_entries_reverse_chronological() {
    let mut history = VecDeque::new();
    for step in 0..6 {
        history.push_back(CommandExecution {
            command: format!("command-{step}"),
            exit_code: 0,
            stdout: format!("stdout-{step}"),
            stderr: String::new(),
            timestamp_ms: step,
            step_index: step as u32,
        });
    }

    let context = build_recent_command_history_context(&history);
    assert!(context.contains("1. [Step 5] command-5"));
    assert!(context.contains("5. [Step 1] command-1"));
    assert!(!context.contains("command-0"));
}

#[test]
fn command_history_context_is_empty_without_history() {
    let context = build_recent_command_history_context(&VecDeque::new());
    assert!(context.is_empty());
}

#[test]
fn command_history_context_uses_latest_five_and_excludes_older_entries() {
    let mut history = VecDeque::new();
    for step in 0..8 {
        history.push_back(CommandExecution {
            command: format!("command-{step}"),
            exit_code: 0,
            stdout: "no secrets here".to_string(),
            stderr: String::new(),
            timestamp_ms: step,
            step_index: step as u32,
        });
    }

    let context = build_recent_command_history_context(&history);
    assert!(context.contains("1. [Step 7] command-7"));
    assert!(context.contains("5. [Step 3] command-3"));
    assert!(!context.contains("command-2"));
}

#[test]
fn command_history_context_renders_sanitized_entries() {
    let mut history = VecDeque::new();
    history.push_back(CommandExecution {
        command: "command-1".to_string(),
        exit_code: 1,
        stdout: "<REDACTED>".to_string(),
        stderr: "<REDACTED>".to_string(),
        timestamp_ms: 1,
        step_index: 1,
    });
    history.push_back(CommandExecution {
        command: "command-2".to_string(),
        exit_code: 0,
        stdout: "healthy".to_string(),
        stderr: String::new(),
        timestamp_ms: 2,
        step_index: 2,
    });

    let context = build_recent_command_history_context(&history);
    assert!(context.contains("command-1"));
    assert!(context.contains("command-2"));
    assert!(context.contains("<REDACTED>"));
}

#[test]
fn inference_error_reason_marks_quota_failures_as_user_intervention() {
    let reason = inference_error_system_fail_reason(
        "Provider Error 429 Too Many Requests: { \"error\": { \"code\": \"insufficient_quota\" } }",
    );
    assert!(reason.contains("ERROR_CLASS=UserInterventionNeeded"));
    assert!(reason.contains("insufficient_quota"));
}

#[test]
fn inference_error_reason_marks_auth_failures_as_user_intervention() {
    let reason =
        inference_error_system_fail_reason("Provider Error 401 Unauthorized: invalid_api_key");
    assert!(reason.contains("ERROR_CLASS=UserInterventionNeeded"));
    assert!(reason.contains("authentication failed"));
}

#[test]
fn inference_error_reason_includes_compact_detail_for_unknown_failures() {
    let reason = inference_error_system_fail_reason(
        "upstream runtime panic: envelope decode failed in cognition bridge",
    );
    assert!(reason.contains("ERROR_CLASS=UserInterventionNeeded"));
    assert!(reason.contains("detail=upstream runtime panic"));
}

#[test]
fn browser_observation_context_prefers_current_snapshot_over_stale_history() {
    let history = vec![chat_message(
        "tool",
        r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_one" name="ONE" dom_id="subbtn" selector="[id=&quot;subbtn&quot;]" rect="105,79,40,40" /><button id="btn_two" name="TWO" dom_id="subbtn2" selector="[id=&quot;subbtn2&quot;]" rect="56,117,40,40" /></root>"#,
        1,
    )];
    let current_snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_start\" name=\"START\" dom_id=\"sync-task-cover\" selector=\"[id=&quot;sync-task-cover&quot;]\" rect=\"0,0,160,210\" />",
        "<button id=\"btn_one\" name=\"ONE\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"105,79,40,40\" />",
        "<button id=\"btn_two\" name=\"TWO\" dom_id=\"subbtn2\" selector=\"[id=&quot;subbtn2&quot;]\" rect=\"56,117,40,40\" />",
        "</root>",
    );

    let context =
        super::resolve_browser_observation_context(&history, Some(current_snapshot), true);

    assert!(context.contains("grp_start"), "{context}");
    assert!(!context.contains("btn_one"), "{context}");
    assert!(!context.contains("btn_two"), "{context}");
}

#[test]
fn format_tool_desc_appends_worker_template_catalog_when_delegate_is_available() {
    let formatted = super::format_tool_desc(
        &[LlmToolDefinition {
            name: "agent__delegate".to_string(),
            description: "Spawn a bounded child worker.".to_string(),
            parameters: "{}".to_string(),
        }],
        false,
        "Port the LocalAI parity fix in the Rust crate, research the current behavior, patch the workspace, and verify the postcondition.",
        Some(&automation_resolved_intent()),
    );

    assert!(formatted.contains("[WORKER TEMPLATES]"));
    assert!(formatted.contains("[PARENT PLAYBOOKS]"));
    assert!(formatted.contains("`researcher`"));
    assert!(formatted.contains("`verifier`"));
    assert!(formatted.contains("`coder`"));
    assert!(formatted.contains("Playbook `live_research_brief`"));
}
