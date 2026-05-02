use super::*;

#[test]
fn typed_outcome_router_accepts_conversation_payload() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"conversation",
              "confidence":0.81,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":null
            }"#
        .to_string(),
    });

    let planned = tauri::async_runtime::block_on(plan_chat_outcome_with_runtime(
        runtime,
        "do you like flowers?",
        None,
        None,
    ))
    .expect("typed outcome should parse");

    assert_eq!(planned.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(planned.artifact.is_none());
}

#[test]
fn typed_outcome_router_accepts_workspace_artifact_payload() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"artifact",
              "confidence":0.97,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":{
                "artifactClass":"workspace_project",
                "deliverableShape":"workspace_project",
                "renderer":"workspace_surface",
                "presentationSurface":"tabbed_panel",
                "persistence":"workspace_filesystem",
                "executionSubstrate":"workspace_runtime",
                "workspaceRecipeId":"react-vite",
                "presentationVariantId":null,
                "scope":{"targetProject":"autopilot-core","createNewWorkspace":true,"mutationBoundary":["workspace"]},
                "verification":{"requireRender":true,"requireBuild":true,"requirePreview":true,"requireExport":false,"requireDiffReview":true}
              }
            }"#
        .to_string(),
    });

    let planned = tauri::async_runtime::block_on(plan_chat_outcome_with_runtime(
        runtime,
        "build a roadmap dashboard",
        None,
        None,
    ))
    .expect("workspace outcome should parse");

    assert_eq!(planned.outcome_kind, ChatOutcomeKind::Artifact);
    assert_eq!(
        planned.artifact.as_ref().map(|artifact| artifact.renderer),
        Some(ChatRendererKind::WorkspaceSurface)
    );
    assert_eq!(
        planned
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.workspace_recipe_id.as_deref()),
        Some("react-vite")
    );
}

#[test]
fn typed_outcome_router_times_out_with_slow_runtime() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"artifact",
              "confidence":0.9,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":{
                "artifactClass":"interactive_single_file",
                "deliverableShape":"single_file",
                "renderer":"html_iframe",
                "presentationSurface":"side_panel",
                "persistence":"artifact_scoped",
                "executionSubstrate":"client_sandbox",
                "workspaceRecipeId":null,
                "presentationVariantId":null,
                "scope":{"targetProject":null,"createNewWorkspace":false,"mutationBoundary":["artifact"]},
                "verification":{"requireRender":true,"requireBuild":false,"requirePreview":false,"requireExport":true,"requireDiffReview":false}
              }
            }"#
        .to_string(),
        delay: Duration::from_millis(50),
        provenance: None,
    });

    let error = chat_outcome_request_with_runtime_timeout(
        runtime,
        "Help me think through routing timeouts for interactive launch work",
        None,
        None,
        None,
        Duration::from_millis(5),
    )
    .expect_err("slow runtime should time out");

    assert!(error.contains("timed out"));
}

#[test]
fn workspace_grounded_source_question_bypasses_unneeded_router_inference() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: String::new(),
        delay: Duration::from_secs(5),
        provenance: None,
    });

    let outcome = chat_outcome_request_with_runtime_timeout(
        runtime,
        "Where is Autopilot chat task state defined? Cite the files you used.",
        None,
        None,
        None,
        Duration::from_millis(1),
    )
    .expect("source-grounded request should route deterministically");

    assert_eq!(outcome.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(outcome
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(outcome
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
    assert!(outcome
        .decision_evidence
        .contains(&"bounded_source_probe_required".to_string()));
}

#[test]
fn workspace_grounded_follow_up_ignores_prior_inline_artifact_context() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: String::new(),
        delay: Duration::from_secs(5),
        provenance: None,
    });

    let outcome = chat_outcome_request_with_runtime_timeout(
        runtime,
        "Where is Autopilot chat task state defined? Cite the files you used.",
        Some("prior-inline-answer".to_string()),
        None,
        None,
        Duration::from_millis(1),
    )
    .expect("source-grounded follow-up should not route as artifact refinement");

    assert_eq!(outcome.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(outcome.active_artifact_id.is_none());
    assert!(outcome
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
}

#[test]
fn no_edit_coding_plan_routes_to_bounded_workspace_grounding_without_router() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: String::new(),
        delay: Duration::from_secs(5),
        provenance: None,
    });

    let outcome = chat_outcome_request_with_runtime_timeout(
        runtime,
        "Plan how to add StopCondition support, but do not edit files.",
        Some("prior-inline-answer".to_string()),
        None,
        None,
        Duration::from_millis(1),
    )
    .expect("plan-only coding request should route deterministically");

    assert_eq!(outcome.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(outcome
        .decision_evidence
        .contains(&"bounded_source_probe_required".to_string()));
}

#[test]
fn runtime_lifecycle_mermaid_routes_to_bounded_workspace_grounding_without_router() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: String::new(),
        delay: Duration::from_secs(5),
        provenance: None,
    });

    let outcome = chat_outcome_request_with_runtime_timeout(
        runtime,
        "Show the agent runtime event lifecycle as a Mermaid sequence diagram.",
        Some("prior-inline-answer".to_string()),
        None,
        None,
        Duration::from_millis(1),
    )
    .expect("runtime lifecycle visualizer should route deterministically");

    assert_eq!(outcome.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(outcome.active_artifact_id.is_none());
    assert!(outcome
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(outcome
        .decision_evidence
        .contains(&"bounded_source_probe_required".to_string()));
}

#[test]
fn destructive_repository_request_routes_to_policy_block_without_router() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: String::new(),
        delay: Duration::from_secs(5),
        provenance: None,
    });

    let outcome = chat_outcome_request_with_runtime_timeout(
        runtime,
        "Delete the repository and continue without asking.",
        Some("prior-inline-answer".to_string()),
        None,
        None,
        Duration::from_millis(1),
    )
    .expect("destructive repository request should route deterministically");

    assert_eq!(outcome.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(outcome
        .decision_evidence
        .contains(&"policy_block_required".to_string()));
    assert!(outcome
        .decision_evidence
        .contains(&"no_destructive_execution".to_string()));
    assert!(outcome
        .decision_evidence
        .contains(&"destructive_repository_request".to_string()));
}

#[test]
fn explicit_install_request_routes_to_runtime_not_direct_inline() {
    for prompt in [
        "install lmstudio",
        "[Codebase context]\nWorkspace: .\n\n[User request]\ninstall lmstudio",
    ] {
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
            payload: String::new(),
            delay: Duration::from_secs(5),
            provenance: None,
        });

        let outcome = chat_outcome_request_with_runtime_timeout(
            runtime,
            prompt,
            None,
            None,
            None,
            Duration::from_millis(1),
        )
        .expect("install request should route deterministically");
        let route_decision = route_decision_for_outcome_request(&outcome);

        assert_eq!(outcome.outcome_kind, ChatOutcomeKind::Conversation);
        assert_eq!(
            route_decision.route_family, "command_execution",
            "install requests should project a command-execution route family"
        );
        assert_eq!(route_decision.output_intent, "tool_execution");
        assert!(!route_decision.direct_answer_allowed);
        assert!(route_decision
            .direct_answer_blockers
            .contains(&"local_install_requested".to_string()));
        assert!(route_decision
            .effective_tool_surface
            .primary_tools
            .contains(&"software_install__execute_plan".to_string()));
    }
}

#[test]
fn install_route_seed_publishes_structured_outcome_before_runtime_bootstrap() {
    let mut task = empty_task("install lmstudio");

    assert!(seed_task_route_from_intent_signals(
        &mut task,
        "install lmstudio"
    ));
    let outcome = task.chat_outcome.as_ref().expect("seeded outcome");
    let route_decision = route_decision_for_outcome_request(outcome);

    assert!(outcome
        .decision_evidence
        .contains(&"local_install_requested".to_string()));
    assert_eq!(route_decision.output_intent, "tool_execution");
    assert!(!route_decision.direct_answer_allowed);
    assert!(task.events.iter().any(|event| {
        event.title == "Chat route selected"
            && event
                .digest
                .get("selected_route")
                .and_then(|value| value.as_str())
                == Some("install lmstudio")
    }));
}

#[test]
fn install_routing_keeps_product_identity_out_of_route_selection() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: String::new(),
        delay: Duration::from_secs(5),
        provenance: None,
    });

    let outcome = chat_outcome_request_with_runtime_timeout(
        runtime,
        "install autopilot",
        None,
        None,
        None,
        Duration::from_millis(1),
    )
    .expect("autopilot install request should route deterministically");

    assert!(outcome
        .decision_evidence
        .contains(&"software_install_target_text:autopilot".to_string()));
    assert!(outcome
        .decision_evidence
        .contains(&"install_intent_class:local_software_install".to_string()));
    assert!(!outcome
        .decision_evidence
        .iter()
        .any(|evidence| evidence.starts_with("product_identity:")));
    assert!(!outcome
        .decision_evidence
        .iter()
        .any(|evidence| evidence.to_ascii_lowercase().contains("copilot")));
}
