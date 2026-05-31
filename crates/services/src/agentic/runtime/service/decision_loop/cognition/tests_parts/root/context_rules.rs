#[test]
fn final_reply_evidence_context_keeps_markdown_stage_outline_for_progress_questions() {
    let history = vec![chat_message(
        "tool",
        concat!(
            "Tool Output (file__read):\n",
            "# Example Guide\n",
            "Intro with progress words only.\n",
            "### Stage 3: Currentness And Retrieval Gate\n",
            "Stage body.\n",
            "### Stage 4: Repo-Aware Read/Search\n",
            "Stage body.\n",
        ),
        1,
    )];

    let context = super::final_reply_evidence_context(
        &history,
        "What does progress look like per .internal/plans/example-guide.md?",
        "fallback",
    );

    assert!(context.contains("Markdown heading outline"), "{context}");
    assert!(context.contains("Stage 3"), "{context}");
    assert!(context.contains("Stage 4"), "{context}");
}

#[test]
fn workspace_recent_context_preserves_long_plan_stage_outline() {
    let long_intro = "Intro line about progress.\n".repeat(180);
    let history = vec![chat_message(
        "tool",
        &format!(
            "Tool Output (file__read):\n{}### Stage 3: Currentness And Retrieval Gate\nStage body.\n### Stage 4: Repo-Aware Read/Search\nStage body.\n",
            long_intro
        ),
        1,
    )];

    let context = super::contextual_recent_session_events_context(
        &history,
        false,
        IntentScopeProfile::WorkspaceOps,
        "What does progress look like per .internal/plans/example-guide.md?",
    );

    assert!(
        context.starts_with("Relevant workspace evidence"),
        "{context}"
    );
    assert!(context.contains("Markdown heading outline"), "{context}");
    assert!(context.contains("Stage 3"), "{context}");
    assert!(context.contains("Stage 4"), "{context}");
}

#[test]
fn recent_events_budget_preserves_late_plan_outline_for_final_reply() {
    let history = vec![chat_message(
        "tool",
        concat!(
            "Tool Output (file__read):\n",
            "Markdown heading outline:\n",
            "# Product Reliability Guide\n",
            "## Stage 0: Campaign Seed And Baseline\n",
            "## Stage 1: Product Reliability Defect Inventory\n",
            "## Stage 10: User-Like Repository Fixture Suite\n",
            "## Stage 11: Evidence, Tracing, And Cleanup\n",
            "## Stage 12: Integrated Soak\n",
            "## Final Deliverables\n\n",
            "# Product Reliability Guide intro ",
            "body body body body body body body body body body body body body body body body body body body body"
        ),
        1,
    )];

    let context = super::contextual_recent_session_events_context(
        &history,
        false,
        IntentScopeProfile::WorkspaceOps,
        "Read the guide, focus on the Stage 11 and Stage 12 sections near the end, and summarize what remains.",
    );
    let section = format!("RECENT SESSION EVENTS:\n{} \n", context);
    let (rendered, truncated) =
        super::truncate_prompt_section(&section, super::PROMPT_SECTION_RECENT_EVENTS_MAX_CHARS);

    assert!(!truncated, "{rendered}");
    assert!(
        rendered.contains("## Stage 11: Evidence, Tracing, And Cleanup"),
        "{rendered}"
    );
    assert!(
        rendered.contains("## Stage 12: Integrated Soak"),
        "{rendered}"
    );
    assert!(
        rendered.contains("cleanup") || rendered.contains("Cleanup"),
        "{rendered}"
    );
    assert!(
        rendered.contains("soak") || rendered.contains("Soak"),
        "{rendered}"
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

