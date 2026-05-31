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
fn workspace_ops_no_effect_file_recovery_forces_reply_only_surface() {
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
            consecutive_failures: 1,
            last_failure_reason: Some(
                "ERROR_CLASS=NoEffectAfterAction incident_skip_root_tool=file__search",
            ),
            workspace_context_ready_for_reply: false,
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
fn workspace_ops_no_effect_fingerprint_recovery_forces_reply_only_surface() {
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
            consecutive_failures: 1,
            last_failure_reason: Some("NoEffectAfterAction (fingerprint: attempt::abc123)"),
            workspace_context_ready_for_reply: false,
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
fn web_research_no_effect_recovery_forces_reply_only_surface() {
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
            consecutive_failures: 1,
            last_failure_reason: Some(
                "ERROR_CLASS=NoEffectAfterAction Skipped immediate replay of 'web__search'.",
            ),
            workspace_context_ready_for_reply: false,
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
            consecutive_failures: 0,
            last_failure_reason: None,
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
            consecutive_failures: 0,
            last_failure_reason: None,
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
            consecutive_failures: 0,
            last_failure_reason: None,
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
            consecutive_failures: 0,
            last_failure_reason: None,
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

