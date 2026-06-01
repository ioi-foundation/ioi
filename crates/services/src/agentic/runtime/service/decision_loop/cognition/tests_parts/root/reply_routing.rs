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
fn unresolved_non_browser_prompt_uses_compact_general_tool_surface() {
    let filtered = filter_cognition_tools(
        &[
            tool("chat__reply"),
            tool("web__search"),
            tool("web__read"),
            tool("memory__search"),
            tool("shell__run"),
            tool("connector__google__gmail_send_email"),
            tool("media__generate_video"),
            tool("model_registry__install"),
        ],
        None,
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
            "web__search",
            "web__read",
            "memory__search",
            "shell__run"
        ]
    );
}

#[test]
fn compact_general_tool_surface_strips_schema_prompt_metadata() {
    let filtered = filter_cognition_tools(
        &[tool_with_schema(
            "web__search",
            "Search public web sources with query planning and result ranking that has a long prompt-facing explanation.",
            r#"{
                "type":"object",
                "title":"Search arguments",
                "description":"Long schema description",
                "properties":{
                    "query":{
                        "type":"string",
                        "description":"The search query",
                        "examples":["AKT Filecoin"]
                    }
                },
                "required":["query"]
            }"#,
        )],
        None,
        false,
        "",
        "",
        "",
    );
    let schema: serde_json::Value =
        serde_json::from_str(&filtered[0].parameters).expect("compact schema");
    assert!(schema.get("title").is_none());
    assert!(schema.get("description").is_none());
    assert!(schema.pointer("/properties/query/description").is_none());
}

#[test]
fn web_research_prompt_excludes_heavy_diagnostic_tool_surface() {
    let resolved = resolved_intent("web.research", IntentScopeProfile::WebResearch);
    let filtered = filter_cognition_tools(
        &[
            tool("chat__reply"),
            tool("web__search"),
            tool("web__read"),
            tool("memory__read"),
            tool("agent__delegate"),
            tool("shell__run"),
            tool("connector__google__gmail_read_emails"),
        ],
        Some(&resolved),
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
            "web__search",
            "web__read",
            "memory__read",
            "agent__delegate"
        ]
    );
}

#[test]
fn workspace_ops_prompt_excludes_connector_catalogue_from_local_cognition() {
    let resolved = resolved_intent("workspace.context", IntentScopeProfile::WorkspaceOps);
    let filtered = filter_cognition_tools(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("file__read"),
            tool("file__search"),
            tool("file__info"),
            tool("shell__run"),
            tool("connector__google__gmail_read_emails"),
            tool("browser__click"),
            tool("media__generate_video"),
        ],
        Some(&resolved),
        false,
        "Where are local/native model providers registered in this repo?",
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
            "file__read",
            "file__search",
            "file__info",
            "shell__run"
        ]
    );
}

#[test]
fn workspace_ops_no_effect_file_recovery_keeps_workspace_tools_available() {
    let resolved = resolved_intent("workspace.context", IntentScopeProfile::WorkspaceOps);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("file__read"),
            tool("file__search"),
            tool("shell__run"),
        ],
        Some(&resolved),
        false,
        "Where are local/native model providers registered in this repo?",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: false,
            web_context_ready_for_reply: false,
        },
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
            "file__read",
            "file__search",
            "shell__run"
        ]
    );
}

#[test]
fn command_workspace_prompt_uses_compact_edit_and_shell_surface() {
    let mut resolved = resolved_intent("workspace.edit_and_test", IntentScopeProfile::CommandExecution);
    resolved.required_capabilities = vec![
        CapabilityId::from("filesystem.read"),
        CapabilityId::from("filesystem.write"),
        CapabilityId::from("command.exec"),
    ];
    let filtered = filter_cognition_tools(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("file__read"),
            tool("file__edit"),
            tool("file__multi_edit"),
            tool("workspace_change__rollback"),
            tool("shell__run"),
            tool("shell__status"),
            tool("connector__google__gmail_read_emails"),
            tool("browser__click"),
            tool("media__generate_video"),
        ],
        Some(&resolved),
        false,
        "Fix src/format.mjs, run node --test tests/*.test.mjs, and summarize the result.",
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
            "file__read",
            "file__edit",
            "file__multi_edit",
            "workspace_change__rollback",
            "shell__run",
            "shell__status",
        ]
    );
}

#[test]
fn command_workspace_goal_compacts_tool_surface_without_workspace_capabilities() {
    let resolved = resolved_intent("command.exec", IntentScopeProfile::CommandExecution);
    let filtered = filter_cognition_tools(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("agent__pause"),
            tool("file__read"),
            tool("file__edit"),
            tool("file__multi_edit"),
            tool("workspace_change__rollback"),
            tool("shell__run"),
            tool("shell__status"),
            tool("connector__google__gmail_read_emails"),
            tool("browser__click"),
            tool("media__generate_video"),
            tool("model_registry__install"),
        ],
        Some(&resolved),
        false,
        "Fix src/format.mjs so the formatter test passes, then run node --test tests/*.test.mjs.",
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
            "file__read",
            "file__edit",
            "file__multi_edit",
            "workspace_change__rollback",
            "shell__run",
            "shell__status",
        ]
    );
}

#[test]
fn command_workspace_failed_edit_phase_forces_refresh_read() {
    let mut resolved =
        resolved_intent("workspace.edit_and_test", IntentScopeProfile::CommandExecution);
    resolved.required_capabilities = vec![
        CapabilityId::from("filesystem.read"),
        CapabilityId::from("filesystem.write"),
        CapabilityId::from("command.exec"),
    ];
    let mut agent_state = AgentState {
        session_id: [0u8; 32],
        goal:
            "Fix src/format.mjs so the formatter test passes, then run node --test tests/*.test.mjs."
                .to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: crate::agentic::runtime::types::AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: Some("file__edit".to_string()),
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec!["attempt::NoEffectAfterAction::first".to_string()],
        mode: crate::agentic::runtime::types::AgentMode::Agent,
        current_tier: crate::agentic::runtime::types::ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(resolved),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    };
    crate::agentic::runtime::service::tool_execution::record_execution_evidence(
        &mut agent_state.tool_execution_log,
        "file_context",
    );

    let filtered = command_workspace_action_phase_tools(
        &agent_state,
        &[
            tool("chat__reply"),
            tool("file__read"),
            tool("file__edit"),
            tool("shell__run"),
        ],
    )
    .expect("command workspace phase should apply");
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["file__read"]);
}

#[test]
fn command_workspace_rollback_phase_exposes_status_and_rollback_then_verification_read() {
    let mut resolved =
        resolved_intent("workspace.rollback", IntentScopeProfile::CommandExecution);
    resolved.required_capabilities = vec![
        CapabilityId::from("filesystem.read"),
        CapabilityId::from("filesystem.write"),
    ];
    let mut agent_state = AgentState {
        session_id: [0u8; 32],
        goal: "Roll back the formatter edit using the workspace change lifecycle handle, then read src/format.mjs.".to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: crate::agentic::runtime::types::AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: crate::agentic::runtime::types::AgentMode::Agent,
        current_tier: crate::agentic::runtime::types::ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(resolved),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    };
    let tools = [
        tool("chat__reply"),
        tool("file__read"),
        tool("workspace_change__status"),
        tool("workspace_change__rollback"),
        tool("shell__run"),
    ];

    let filtered =
        command_workspace_action_phase_tools(&agent_state, &tools).expect("rollback phase should apply");
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["workspace_change__status", "workspace_change__rollback"]
    );

    crate::agentic::runtime::service::tool_execution::record_execution_evidence(
        &mut agent_state.tool_execution_log,
        "workspace_change_rolled_back",
    );
    agent_state.last_action_type = Some("workspace_change__rollback".to_string());
    let filtered = command_workspace_action_phase_tools(&agent_state, &tools)
        .expect("post-rollback verification phase should apply");
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["file__read"]);

    agent_state.last_action_type = Some("file__read".to_string());
    let filtered = command_workspace_action_phase_tools(&agent_state, &tools)
        .expect("verified rollback phase should apply");
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["chat__reply"]);
}

#[test]
fn workspace_ops_no_effect_fingerprint_recovery_keeps_workspace_tools_available() {
    let resolved = resolved_intent("workspace.context", IntentScopeProfile::WorkspaceOps);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("file__read"),
            tool("file__search"),
        ],
        Some(&resolved),
        false,
        "What does progress look like per .internal/plans/example.md?",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: false,
            web_context_ready_for_reply: false,
        },
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["chat__reply", "agent__complete", "file__read", "file__search"]
    );
}

#[test]
fn web_research_no_effect_recovery_keeps_retrieval_tools_available() {
    let resolved = resolved_intent("web.research", IntentScopeProfile::WebResearch);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("web__search"),
            tool("web__read"),
            tool("memory__search"),
        ],
        Some(&resolved),
        false,
        "Find current sources for today's top local AI model runtime issue.",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: false,
            web_context_ready_for_reply: false,
        },
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
            "web__search",
            "web__read",
            "memory__search"
        ]
    );
}

#[test]
fn workspace_ops_ready_context_forces_reply_only_surface() {
    let resolved = resolved_intent("workspace.context", IntentScopeProfile::WorkspaceOps);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("file__read"),
            tool("file__search"),
            tool("shell__run"),
        ],
        Some(&resolved),
        false,
        "Where are local/native model providers registered in this repo?",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: true,
            web_context_ready_for_reply: false,
        },
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["chat__reply"]);
}

#[test]
fn web_research_ready_context_forces_reply_only_surface() {
    let resolved = resolved_intent("web.research", IntentScopeProfile::WebResearch);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("web__search"),
            tool("web__read"),
            tool("memory__search"),
        ],
        Some(&resolved),
        false,
        "Which is a better investment right now, Akash or Filecoin?",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: false,
            web_context_ready_for_reply: true,
        },
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["chat__reply"]);
}

#[test]
fn ready_web_context_forces_reply_only_surface_even_before_scope_resolution() {
    let resolved = resolved_intent("unknown", IntentScopeProfile::Unknown);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("web__search"),
            tool("web__read"),
            tool("file__read"),
        ],
        Some(&resolved),
        false,
        "Which is a better investment right now, Akash or Filecoin?",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: false,
            web_context_ready_for_reply: true,
        },
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["chat__reply"]);
}

#[test]
fn ready_web_context_forces_reply_only_surface_even_for_conversation_scope() {
    let resolved = resolved_intent("conversation.reply", IntentScopeProfile::Conversation);
    let filtered = filter_cognition_tools_with_recovery(
        &[
            tool("chat__reply"),
            tool("agent__complete"),
            tool("web__search"),
            tool("web__read"),
            tool("file__read"),
        ],
        Some(&resolved),
        false,
        "Which is a better investment right now, Akash or Filecoin?",
        "",
        "",
        CognitionToolRecovery {
            workspace_context_ready_for_reply: false,
            web_context_ready_for_reply: true,
        },
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["chat__reply"]);
}
