use super::*;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ChatLaneFamily, ChatNormalizedRequest, ChatRetainedWidgetState, ChatSourceFamily,
    ChatWidgetStateBinding,
};
use ioi_types::error::VmError;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[test]
fn parses_planning_payload_with_wrapped_text() {
    let parsed = parse_chat_outcome_planning_payload(
        "router output\n{\"outcomeKind\":\"conversation\",\"confidence\":0.6,\"needsClarification\":false,\"clarificationQuestions\":[],\"artifact\":null}",
    )
    .expect("planning payload");
    assert_eq!(
        parsed.outcome_kind,
        ioi_types::app::ChatOutcomeKind::Conversation
    );
}

#[test]
fn parses_planning_payload_with_missing_scope_and_verification_defaults() {
    let parsed = parse_chat_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "artifactClass": "document",
                "deliverableShape": "single_file",
                "renderer": "markdown",
                "presentationSurface": "side_panel",
                "persistence": "artifact_scoped",
                "executionSubstrate": "none",
                "workspaceRecipeId": null,
                "presentationVariantId": null
            }
        }"#,
    )
    .expect("planning payload should recover missing scope and verification");

    let artifact = parsed.artifact.expect("artifact payload");
    assert_eq!(artifact.renderer, ChatRendererKind::Markdown);
    assert_eq!(artifact.scope.target_project, None);
    assert!(!artifact.scope.create_new_workspace);
    assert!(artifact.scope.mutation_boundary.is_empty());
    assert!(!artifact.verification.require_render);
    assert!(!artifact.verification.require_build);
    assert!(!artifact.verification.require_preview);
    assert!(!artifact.verification.require_export);
    assert!(!artifact.verification.require_diff_review);
}

#[test]
fn parses_planning_payload_with_null_scope_and_verification_defaults() {
    let parsed = parse_chat_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "artifactClass": "document",
                "deliverableShape": "single_file",
                "renderer": "html_iframe",
                "presentationSurface": "side_panel",
                "persistence": "artifact_scoped",
                "executionSubstrate": "client_sandbox",
                "workspaceRecipeId": null,
                "presentationVariantId": null,
                "scope": null,
                "verification": null
            }
        }"#,
    )
    .expect("planning payload should recover null scope and verification");

    let artifact = parsed.artifact.expect("artifact payload");
    assert_eq!(artifact.renderer, ChatRendererKind::HtmlIframe);
    assert_eq!(artifact.scope.target_project, None);
    assert!(!artifact.scope.create_new_workspace);
    assert!(artifact.scope.mutation_boundary.is_empty());
    assert!(!artifact.verification.require_render);
    assert!(!artifact.verification.require_build);
    assert!(!artifact.verification.require_preview);
    assert!(!artifact.verification.require_export);
    assert!(!artifact.verification.require_diff_review);
}

#[test]
fn places_anchor_phrase_parses_bare_follow_up_prefixes() {
    let context = ChatIntentContext::new("Near Williamsburg, Brooklyn.");
    assert_eq!(
        context.places_anchor_phrase().as_deref(),
        Some("williamsburg, brooklyn")
    );
}

#[test]
fn places_anchor_phrase_preserves_multi_segment_locations() {
    let context =
        ChatIntentContext::new("Find coffee shops near Williamsburg, Brooklyn and show the map.");
    assert_eq!(
        context.places_anchor_phrase().as_deref(),
        Some("williamsburg, brooklyn")
    );
}

#[test]
fn using_repo_docs_request_requires_workspace_grounding() {
    let context =
        ChatIntentContext::new("Using repo docs, summarize the chat UX contract and cite sources.");

    assert!(context.source_citation_grounding_required());
    assert!(context.workspace_grounding_required());
}

#[test]
fn harness_validation_request_requires_workspace_grounding() {
    let context = ChatIntentContext::new(
        "Validate this answer path through the harness and explain the result.",
    );

    assert!(context.agent_validation_grounding_required());
    assert!(context.workspace_grounding_required());
}

#[test]
fn parses_planning_payload_with_renderer_derived_defaults() {
    let parsed = parse_chat_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "renderer": "markdown"
            }
        }"#,
    )
    .expect("planning payload should derive renderer-shaped defaults");

    let artifact = parsed.artifact.expect("artifact payload");
    assert_eq!(artifact.artifact_class, ChatArtifactClass::Document);
    assert_eq!(
        artifact.deliverable_shape,
        ChatArtifactDeliverableShape::SingleFile
    );
    assert_eq!(artifact.renderer, ChatRendererKind::Markdown);
    assert_eq!(
        artifact.presentation_surface,
        ChatPresentationSurface::SidePanel
    );
    assert_eq!(
        artifact.persistence,
        ChatArtifactPersistenceMode::SharedArtifactScoped
    );
    assert_eq!(artifact.execution_substrate, ChatExecutionSubstrate::None);
    assert_eq!(artifact.scope.target_project, None);
    assert!(!artifact.scope.create_new_workspace);
    assert!(artifact.scope.mutation_boundary.is_empty());
    assert!(!artifact.verification.require_render);
    assert!(!artifact.verification.require_build);
    assert!(!artifact.verification.require_preview);
    assert!(!artifact.verification.require_export);
    assert!(!artifact.verification.require_diff_review);
}

#[test]
fn parses_html_iframe_payload_with_document_defaults() {
    let parsed = parse_chat_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "renderer": "html_iframe"
            }
        }"#,
    )
    .expect("planning payload should derive document defaults for html_iframe");

    let artifact = parsed.artifact.expect("artifact payload");
    assert_eq!(artifact.renderer, ChatRendererKind::HtmlIframe);
    assert_eq!(artifact.artifact_class, ChatArtifactClass::Document);
    assert_eq!(
        artifact.deliverable_shape,
        ChatArtifactDeliverableShape::SingleFile
    );
    assert_eq!(
        artifact.execution_substrate,
        ChatExecutionSubstrate::ClientSandbox
    );
}

#[test]
fn parses_planning_payload_preserves_execution_strategy() {
    let parsed = parse_chat_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "executionStrategy": "single-pass",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "renderer": "markdown"
            }
        }"#,
    )
    .expect("planning payload should preserve execution strategy");

    assert_eq!(parsed.execution_strategy, ChatExecutionStrategy::SinglePass);
}

#[test]
fn request_grounded_html_document_brief_keeps_interactions_optional() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };

    let brief = derive_request_grounded_chat_artifact_brief(
        "Quantum computers",
        "Create an HTML file that explains quantum computers",
        &request,
        None,
    );

    assert!(brief.required_interactions.is_empty());
    assert!(brief
        .query_profile
        .as_ref()
        .expect("query profile")
        .interaction_goals
        .is_empty());
}

#[test]
fn request_grounded_artifact_brief_uses_user_request_inside_context_envelope() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };
    let contextual_intent = "[Codebase context]\nWorkspace: .\n\n[User request]\nCreate an interactive HTML artifact that explains quantum computers";

    let brief = derive_request_grounded_chat_artifact_brief(
        "[Codebase context]",
        contextual_intent,
        &request,
        None,
    );

    assert_eq!(brief.subject_domain, "quantum computers");
    assert!(brief.job_to_be_done.contains("quantum computers"));
    assert!(!brief.subject_domain.contains("Codebase context"));
    assert!(!brief.job_to_be_done.contains("Workspace:"));
}

#[test]
fn request_grounded_interactive_html_brief_does_not_invent_inspection_or_sequence_goals() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };

    let brief = derive_request_grounded_chat_artifact_brief(
        "Mortgage payment calculator",
        "show me an interactive mortgage payment calculator I can adjust",
        &request,
        None,
    );
    let profile = brief.query_profile.as_ref().expect("query profile");

    assert_eq!(brief.required_interaction_goal_count(), 1);
    assert!(profile.has_interaction_kind(ChatArtifactInteractionGoalKind::StateAdjust));
    assert!(!profile.has_interaction_kind(ChatArtifactInteractionGoalKind::StateSwitch));
    assert!(!profile.has_interaction_kind(ChatArtifactInteractionGoalKind::DetailInspect));
    assert!(!profile.has_interaction_kind(ChatArtifactInteractionGoalKind::SequenceBrowse));
    assert!(brief
        .required_interaction_summaries()
        .iter()
        .any(|interaction| interaction.contains("on-page result")));
}

#[test]
fn outcome_router_prompt_spells_out_html_vs_jsx_contracts() {
    let prompt = build_chat_outcome_router_prompt(
        "Create an interactive HTML artifact that explains a product rollout with charts",
        None,
        None,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");
    assert!(prompt_text.contains("executionStrategy"));
    assert!(prompt_text.contains("decisionEvidence"));
    assert!(prompt_text.contains("direct_author = direct first-pass authoring"));
    assert!(
        prompt_text.contains("Prefer direct_author for a fresh coherent single-file document ask")
    );
    assert!(prompt_text.contains("html_iframe = a single self-contained .html document"));
    assert!(prompt_text.contains("jsx_sandbox = a single .jsx source module with a default export"));
    assert!(prompt_text.contains(
        "html_iframe uses single_file deliverableShape and client_sandbox executionSubstrate, and may be artifactClass=document"
    ));
    assert!(prompt_text.contains(
        "Non-workspace artifact renderers should not request build or preview verification."
    ));
    assert!(prompt_text.contains(
        "Treat explicit medium-plus-deliverable requests as sufficiently specified artifact work."
    ));
    assert!(prompt_text
        .contains("Create an interactive HTML artifact for an AI tools editorial launch page"));
    assert!(prompt_text.contains("Do not use lexical fallbacks or benchmark phrase maps."));
}

#[test]
fn outcome_router_prompt_compacts_for_local_runtime() {
    let full_prompt = build_chat_outcome_router_prompt(
        "Create a markdown artifact that documents a release checklist",
        None,
        None,
    );
    let compact_prompt = build_chat_outcome_router_prompt_for_runtime(
        "Create a markdown artifact that documents a release checklist",
        None,
        None,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
    );
    let full_prompt_text = serde_json::to_string(&full_prompt).expect("full prompt text");
    let compact_prompt_text = decode_chat_test_prompt(
        &serde_json::to_vec(&compact_prompt).expect("compact prompt bytes"),
    );

    assert!(compact_prompt_text.len() < full_prompt_text.len());
    assert!(compact_prompt_text.len() * 2 < full_prompt_text.len());
    assert!(compact_prompt_text.contains("executionStrategy"));
    assert!(compact_prompt_text.contains("Return exactly one JSON object"));
    assert!(compact_prompt_text.contains("Renderer meanings:"));
    assert!(compact_prompt_text
        .contains("html_iframe may be artifactClass=document for plain authored HTML documents"));
    assert!(compact_prompt_text.contains("Defaults are derived from renderer when omitted"));
    assert!(compact_prompt_text.contains(
        "Explicit medium-plus-deliverable requests are sufficiently specified artifact work."
    ));
    assert!(compact_prompt_text.contains("Do not use lexical fallbacks or benchmark phrase maps."));
    assert!(!compact_prompt_text
        .contains("Create an interactive HTML artifact for an AI tools editorial launch page"));
}

#[test]
fn local_outcome_router_prompt_uses_summarized_active_artifact_context() {
    let prompt = build_chat_outcome_router_prompt_for_runtime(
        "Make it feel more enterprise",
        Some("artifact-1"),
        Some(&ChatArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-2".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Interactive rollout artifact".to_string(),
            renderer: ChatRendererKind::HtmlIframe,
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>".repeat(20),
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
        ChatRuntimeProvenanceKind::RealLocalRuntime,
    );
    let prompt_text = decode_chat_test_prompt(&serde_json::to_vec(&prompt).expect("prompt bytes"));

    assert!(prompt_text.len() < 2600);
    assert!(prompt_text.contains("Active artifact context summary JSON"));
    assert!(prompt_text.contains("follow-up turn for the active artifact"));
    assert!(prompt_text.contains("\"bodyChars\""));
    assert!(prompt_text.contains("\"lineCount\""));
    assert!(!prompt_text.contains("Renderer meanings:"));
    assert!(!prompt_text.contains("bodyPreview"));
}

#[tokio::test(flavor = "current_thread")]
async fn local_outcome_router_uses_text_json_contract() {
    #[derive(Debug, Clone)]
    struct LocalOutcomeRouterRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
        max_tokens: Arc<Mutex<Vec<u32>>>,
    }

    #[async_trait]
    impl InferenceRuntime for LocalOutcomeRouterRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            self.prompts
                .lock()
                .expect("prompt log")
                .push(decode_chat_test_prompt(input_context));
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            self.max_tokens
                .lock()
                .expect("max tokens log")
                .push(options.max_tokens);
            Ok(serde_json::json!({
                "outcomeKind": "artifact",
                "executionStrategy": "direct_author",
                "confidence": 0.97,
                "needsClarification": false,
                "clarificationQuestions": [],
                "artifact": {
                    "renderer": "html_iframe"
                }
            })
            .to_string()
            .into_bytes())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "local router".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let max_tokens = Arc::new(Mutex::new(Vec::<u32>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(LocalOutcomeRouterRuntime {
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
        max_tokens: max_tokens.clone(),
    });

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Create an interactive HTML canvas artifact that explains quantum computers",
        None,
        None,
    )
    .await
    .expect("local routing should succeed");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Artifact);
    assert_eq!(
        planning.execution_strategy,
        ChatExecutionStrategy::DirectAuthor
    );
    assert_eq!(
        planning.artifact.expect("artifact").renderer,
        ChatRendererKind::HtmlIframe
    );
    assert!(json_modes
        .lock()
        .expect("json mode log")
        .iter()
        .all(|json_mode| !json_mode));
    assert!(max_tokens
        .lock()
        .expect("max tokens log")
        .iter()
        .all(|max_tokens| *max_tokens <= 224));
    let prompt_log = prompts.lock().expect("prompt log");
    assert_eq!(prompt_log.len(), 1);
    assert!(prompt_log[0].contains("typed outcome router for local runtimes"));
    assert!(prompt_log[0].contains("Renderer meanings:"));
    assert!(prompt_log[0].contains("decisionEvidence"));
    assert!(prompt_log[0].contains("JSON only."));
}

#[tokio::test(flavor = "current_thread")]
async fn local_outcome_router_repairs_non_json_router_output_once() {
    #[derive(Debug, Clone)]
    struct SequentialOutcomeRouterRuntime {
        responses: Arc<Mutex<VecDeque<String>>>,
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
    }

    #[async_trait]
    impl InferenceRuntime for SequentialOutcomeRouterRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            self.prompts
                .lock()
                .expect("prompt log")
                .push(decode_chat_test_prompt(input_context));
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            let response = self
                .responses
                .lock()
                .expect("responses")
                .pop_front()
                .expect("scripted response");
            Ok(response.into_bytes())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "local router".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let responses = Arc::new(Mutex::new(VecDeque::from([
        "I would answer this directly in chat.".to_string(),
        serde_json::json!({
            "outcomeKind": "conversation",
            "executionStrategy": "single_pass",
            "confidence": 0.71,
            "needsClarification": false,
            "clarificationQuestions": [],
            "decisionEvidence": ["json_parse_repair"],
            "artifact": null
        })
        .to_string(),
    ])));
    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SequentialOutcomeRouterRuntime {
        responses,
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
    });

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Plan how to add StopCondition support, but do not edit files.",
        None,
        None,
    )
    .await
    .expect("local router should repair malformed JSON output");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert_eq!(
        planning.execution_strategy,
        ChatExecutionStrategy::SinglePass
    );
    assert!(planning
        .decision_evidence
        .iter()
        .any(|entry| entry == "json_parse_repair"));
    assert_eq!(
        *json_modes.lock().expect("json mode log"),
        vec![false, true]
    );
    let prompt_log = prompts.lock().expect("prompt log");
    assert_eq!(prompt_log.len(), 2);
    assert!(prompt_log[1].contains("repair Chat typed outcome-router output"));
}

#[tokio::test(flavor = "current_thread")]
async fn weather_route_derives_lane_request_normalized_request_and_source_decision() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.41,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": [],
        "artifact": null
    }));

    let planning =
        plan_chat_outcome_with_runtime(runtime, "What is the weather in Boston today?", None, None)
            .await
            .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::ToolWidget);
    let lane_request = planning.lane_request.expect("lane frame");
    assert_eq!(lane_request.primary_lane, ChatLaneFamily::Research);
    assert_eq!(lane_request.tool_widget_family.as_deref(), Some("weather"));
    let normalized_request = planning.normalized_request.expect("request frame");
    match normalized_request {
        ChatNormalizedRequest::Weather(frame) => {
            assert_eq!(frame.inferred_locations, vec!["boston".to_string()]);
            assert_eq!(frame.temporal_scope.as_deref(), Some("today"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
    let source_decision = planning.source_decision.expect("source decision");
    assert_eq!(
        source_decision.selected_source,
        ChatSourceFamily::SpecializedTool
    );
    assert!(source_decision
        .candidate_sources
        .contains(&ChatSourceFamily::WebSearch));
    assert!(planning.orchestration_state.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn weather_advice_route_uses_weather_widget_without_weather_keyword() {
    for prompt in [
        "Should I wear a jacket today in New York City?",
        "[Codebase context] Workspace: . [User request] Should I wear a jacket today in New York City?",
    ] {
        let runtime = scripted_outcome_router_runtime(serde_json::json!({
            "outcomeKind": "conversation",
            "executionStrategy": "single_pass",
            "confidence": 0.41,
            "needsClarification": false,
            "clarificationQuestions": [],
            "decisionEvidence": [],
            "artifact": null
        }));

        let planning = plan_chat_outcome_with_runtime(runtime, prompt, None, None)
            .await
            .expect("planning");

        assert_eq!(planning.outcome_kind, ChatOutcomeKind::ToolWidget);
        assert!(planning
            .decision_evidence
            .iter()
            .any(|hint| hint == "tool_widget:weather"));
        match planning.normalized_request.as_ref().expect("request frame") {
            ChatNormalizedRequest::Weather(frame) => {
                assert_eq!(frame.inferred_locations, vec!["new york city".to_string()]);
                assert!(frame.clarification_required_slots.is_empty());
            }
            other => panic!("expected weather frame, got {other:?}"),
        }
        let source_decision = planning.source_decision.expect("source decision");
        assert_eq!(
            source_decision.selected_source,
            ChatSourceFamily::SpecializedTool
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn complete_specialized_source_overrides_model_live_data_clarification() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "tool_widget",
        "executionStrategy": "direct_author",
        "confidence": 0.0,
        "needsClarification": true,
        "clarificationQuestions": [
            "I do not have live access to sports scores. Please provide the game result."
        ],
        "decisionEvidence": ["tool_widget:sports"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Did the Lakers win their most recent completed game, and who led them in scoring?",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::ToolWidget);
    assert!(!planning.needs_clarification);
    assert!(planning.clarification_questions.is_empty());
    match planning.normalized_request.as_ref().expect("request frame") {
        ChatNormalizedRequest::Sports(frame) => {
            assert_eq!(frame.league.as_deref(), Some("nba"));
            assert_eq!(frame.team_or_target.as_deref(), Some("Los Angeles Lakers"));
            assert!(frame.clarification_required_slots.is_empty());
        }
        other => panic!("expected sports frame, got {other:?}"),
    }
    assert_eq!(
        planning
            .source_decision
            .as_ref()
            .map(|selection| selection.selected_source),
        Some(ChatSourceFamily::SpecializedTool)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn interactive_adjustable_calculator_overrides_user_input_gate() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "tool_widget",
        "executionStrategy": "plan_execute",
        "confidence": 0.72,
        "needsClarification": true,
        "clarificationQuestions": [
            "What options or decision shape should Chat present?"
        ],
        "decisionEvidence": ["tool_widget:user_input", "no_persistent_artifact_requested"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Show me an interactive mortgage payment calculator I can adjust.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Artifact);
    assert!(!planning.needs_clarification);
    assert!(planning.clarification_questions.is_empty());
    assert_eq!(
        planning.artifact.as_ref().map(|artifact| artifact.renderer),
        Some(ChatRendererKind::HtmlIframe)
    );
    assert_eq!(
        planning
            .artifact
            .as_ref()
            .map(|artifact| artifact.artifact_class),
        Some(ChatArtifactClass::InteractiveSingleFile)
    );
    assert_eq!(
        planning
            .artifact
            .as_ref()
            .map(|artifact| artifact.verification.require_render),
        Some(true)
    );
    assert!(!planning
        .decision_evidence
        .iter()
        .any(|hint| hint == "tool_widget:user_input"));
    assert!(planning
        .decision_evidence
        .iter()
        .any(|hint| hint == "interactive_single_file_artifact"));
}

#[tokio::test(flavor = "current_thread")]
async fn active_interactive_artifact_follow_up_preserves_typed_contract() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "artifact",
        "executionStrategy": "direct_author",
        "confidence": 0.82,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": [],
        "artifact": {
            "renderer": "html_iframe",
            "scope": { "mutationBoundary": ["loan_amount"] },
            "verification": { "requireExport": false }
        }
    }));
    let active_artifact = ChatArtifactRefinementContext {
        artifact_id: Some("artifact-1".to_string()),
        revision_id: Some("revision-1".to_string()),
        title: "Mortgage calculator".to_string(),
        summary: "Interactive mortgage calculator with adjustable loan inputs.".to_string(),
        renderer: ChatRendererKind::HtmlIframe,
        files: Vec::new(),
        selected_targets: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        blueprint: None,
        artifact_ir: Some(ChatArtifactIR {
            version: 1,
            renderer: ChatRendererKind::HtmlIframe,
            scaffold_family: "calculator".to_string(),
            semantic_structure: Vec::new(),
            interaction_graph: vec![ChatArtifactIRInteractionEdge {
                id: "adjust-loan".to_string(),
                family: "state_adjust".to_string(),
                control_node_ids: vec!["loan-amount".to_string()],
                target_node_ids: vec!["payment".to_string()],
                default_state: "loan amount defaults are editable".to_string(),
            }],
            evidence_surfaces: Vec::new(),
            design_tokens: Vec::new(),
            motion_plan: Vec::new(),
            accessibility_obligations: Vec::new(),
            responsive_layout_rules: Vec::new(),
            component_bindings: Vec::new(),
            static_audit_expectations: Vec::new(),
            render_eval_checklist: Vec::new(),
        }),
        selected_skills: Vec::new(),
    };

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Update the default loan amount to $550,000.",
        Some("artifact-1"),
        Some(&active_artifact),
    )
    .await
    .expect("planning");

    let artifact = planning.artifact.as_ref().expect("artifact request");
    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Artifact);
    assert_eq!(artifact.renderer, ChatRendererKind::HtmlIframe);
    assert_eq!(
        artifact.artifact_class,
        ChatArtifactClass::InteractiveSingleFile
    );
    assert_eq!(
        artifact.execution_substrate,
        ChatExecutionSubstrate::ClientSandbox
    );
    assert!(artifact.verification.require_render);
    assert_eq!(artifact.scope.mutation_boundary, vec!["loan_amount"]);
    assert!(planning
        .decision_evidence
        .iter()
        .any(|hint| hint == "interactive_single_file_artifact"));
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_table_artifact_overrides_conversation_router_output() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.52,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Create a concise comparison table artifact for Local GPU vs Remote Model routing.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Artifact);
    assert_eq!(
        planning.execution_strategy,
        ChatExecutionStrategy::DirectAuthor
    );
    let artifact = planning.artifact.expect("artifact request");
    assert_eq!(artifact.renderer, ChatRendererKind::Markdown);
    assert!(planning
        .decision_evidence
        .contains(&"persistent_artifact_requested".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_inline_answer_request_removes_workspace_clarification() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "plan_execute",
        "confidence": 0.49,
        "needsClarification": true,
        "clarificationQuestions": ["What specific type of artifact do you expect to generate?"],
        "decisionEvidence": [
            "workspace_grounding_required",
            "coding_workspace_context",
            "shared_answer_surface"
        ],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Do not create an artifact: describe what an artifact generation pipeline should validate before showing a preview.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(!planning.needs_clarification);
    assert!(planning.clarification_questions.is_empty());
    assert!(!planning
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(!planning
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"no_persistent_artifact_requested".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn low_risk_conversation_answers_with_uncertainty_instead_of_overasking() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.52,
        "needsClarification": true,
        "clarificationQuestions": [
            "Is this a fresh workspace or an existing project with context?"
        ],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Explain what this workspace is for in two concise paragraphs.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(!planning.needs_clarification);
    assert!(planning.clarification_questions.is_empty());
    assert!(planning
        .decision_evidence
        .contains(&"answer_with_stated_uncertainty".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"shared_answer_surface".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn source_citation_question_requires_workspace_grounding_even_without_repo_phrase() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.76,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Where is Autopilot chat task state defined? Cite the files you used.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(planning
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn explain_this_workspace_requires_grounding_without_clarification() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.58,
        "needsClarification": true,
        "clarificationQuestions": ["Is this a fresh workspace or an existing project with context?"],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Explain what this workspace is for in two concise paragraphs.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(!planning.needs_clarification);
    assert!(planning
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn no_edit_coding_plan_requires_workspace_grounding() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.61,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Plan how to add StopCondition support, but do not edit files.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(planning
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_lifecycle_mermaid_request_requires_workspace_grounding() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "artifact",
        "executionStrategy": "direct_author",
        "confidence": 0.72,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["persistent_artifact_requested"],
        "artifact": {
            "renderer": "mermaid"
        }
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Show the agent runtime event lifecycle as a Mermaid sequence diagram.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(planning.artifact.is_none());
    assert!(planning
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"shared_answer_surface".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn harness_probe_requests_require_workspace_grounding() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.66,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Find the cheapest way to verify whether desktop chat sources render.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(planning
        .decision_evidence
        .contains(&"workspace_grounding_required".to_string()));
    assert!(planning
        .decision_evidence
        .contains(&"coding_workspace_context".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn example_request_does_not_materialize_artifact_without_artifact_signal() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "artifact",
        "executionStrategy": "direct_author",
        "confidence": 0.73,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["persistent_artifact_requested"],
        "artifact": {
            "renderer": "markdown"
        }
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Show a compact example of a useful thoughts drawer entry for a web-search answer, without actually browsing.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(planning.artifact.is_none());
    assert!(planning
        .decision_evidence
        .contains(&"no_persistent_artifact_requested".to_string()));
}

#[tokio::test(flavor = "current_thread")]
async fn messy_task_list_with_coffee_does_not_escalate_to_places_widget() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "tool_widget",
        "executionStrategy": "plan_execute",
        "confidence": 0.86,
        "needsClarification": true,
        "clarificationQuestions": ["Which neighborhood, city, or anchor location should Chat search around?"],
        "decisionEvidence": ["tool_widget:places", "narrow_surface_preferred"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Turn this messy note into a concise task list: call Sam, renew domain, fix onboarding copy, ship the model selector bug, buy coffee.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::Conversation);
    assert!(!planning.needs_clarification);
    assert!(planning
        .decision_evidence
        .contains(&"shared_answer_surface".to_string()));
    assert!(!planning
        .decision_evidence
        .iter()
        .any(|hint| hint.starts_with("tool_widget:")));
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_places_lookup_still_routes_to_places_widget() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.58,
        "needsClarification": false,
        "clarificationQuestions": [],
        "decisionEvidence": ["shared_answer_surface"],
        "artifact": null
    }));

    let planning = plan_chat_outcome_with_runtime(
        runtime,
        "Find coffee shops near downtown Boston.",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::ToolWidget);
    assert!(planning
        .decision_evidence
        .contains(&"tool_widget:places".to_string()));
}

#[test]
fn communication_draft_without_recipient_context_does_not_gate() {
    let projection = derive_chat_topology_projection(
        "Write a short email declining a meeting while keeping the relationship warm.",
        None,
        None,
        ChatOutcomeKind::Conversation,
        ChatExecutionStrategy::SinglePass,
        None,
        0.82,
        false,
        &[],
        &["shared_answer_surface".to_string()],
        None,
    );

    let normalized_request = projection.normalized_request.expect("request frame");
    match normalized_request {
        ChatNormalizedRequest::MessageCompose(frame) => {
            assert_eq!(frame.channel.as_deref(), Some("email"));
            assert_eq!(frame.purpose.as_deref(), Some("draft"));
            assert!(frame.recipient_context.is_none());
            assert!(frame.missing_slots.is_empty());
            assert!(frame.clarification_required_slots.is_empty());
        }
        other => panic!("expected message compose frame, got {other:?}"),
    }
}

#[test]
fn communication_projection_infers_message_compose_lane_and_missing_slots() {
    let projection = derive_chat_topology_projection(
        "Draft an email to the finance team about delaying the launch by one week",
        None,
        None,
        ChatOutcomeKind::Conversation,
        ChatExecutionStrategy::PlanExecute,
        None,
        0.88,
        false,
        &[],
        &["shared_answer_surface".to_string()],
        None,
    );

    let lane_request = projection.lane_request.expect("lane frame");
    assert_eq!(lane_request.primary_lane, ChatLaneFamily::Communication);
    let normalized_request = projection.normalized_request.expect("request frame");
    match normalized_request {
        ChatNormalizedRequest::MessageCompose(frame) => {
            assert_eq!(frame.channel.as_deref(), Some("email"));
            assert_eq!(frame.purpose.as_deref(), Some("draft"));
            assert_eq!(frame.recipient_context.as_deref(), Some("The Finance Team"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected message compose frame, got {other:?}"),
    }
    assert_eq!(
        projection
            .source_decision
            .expect("source decision")
            .selected_source,
        ChatSourceFamily::DirectAnswer
    );
}

#[test]
fn retained_widget_state_backfills_weather_scope_and_domain_policy_bundle() {
    let widget_state = ChatRetainedWidgetState {
        widget_family: Some("weather".to_string()),
        bindings: vec![ChatWidgetStateBinding {
            key: "weather.location".to_string(),
            value: "Boston".to_string(),
            source: "widget_click".to_string(),
        }],
        last_updated_at: None,
    };
    let projection = derive_chat_topology_projection(
        "What about tomorrow?",
        None,
        Some(&widget_state),
        ChatOutcomeKind::ToolWidget,
        ChatExecutionStrategy::PlanExecute,
        None,
        0.86,
        false,
        &[],
        &["tool_widget:weather".to_string()],
        None,
    );

    let normalized_request = projection
        .normalized_request
        .as_ref()
        .expect("request frame");
    match normalized_request {
        ChatNormalizedRequest::Weather(frame) => {
            assert_eq!(frame.assumed_location.as_deref(), Some("Boston"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }

    let policy_bundle = derive_chat_domain_policy_bundle(
        projection.lane_request.as_ref(),
        projection.normalized_request.as_ref(),
        projection.source_decision.as_ref(),
        ChatOutcomeKind::ToolWidget,
        &["tool_widget:weather".to_string()],
        false,
        Some(&widget_state),
    );
    assert_eq!(
        policy_bundle
            .retained_widget_state
            .as_ref()
            .and_then(|state| state.widget_family.as_deref()),
        Some("weather")
    );
    assert_eq!(
        policy_bundle
            .clarification_policy
            .as_ref()
            .map(|policy| policy.mode),
        Some(ioi_types::app::ChatClarificationMode::AssumeFromRetainedState)
    );
}

#[test]
fn retained_weather_widget_state_inherits_follow_up_without_tool_hint() {
    let widget_state = ChatRetainedWidgetState {
        widget_family: Some("weather".to_string()),
        bindings: vec![
            ChatWidgetStateBinding {
                key: "weather.location".to_string(),
                value: "New York City".to_string(),
                source: "normalized_request".to_string(),
            },
            ChatWidgetStateBinding {
                key: "weather.temporal_scope".to_string(),
                value: "today".to_string(),
                source: "normalized_request".to_string(),
            },
        ],
        last_updated_at: None,
    };
    let projection = derive_chat_topology_projection(
        "What about tomorrow?",
        Some("weather-widget-artifact"),
        Some(&widget_state),
        ChatOutcomeKind::Conversation,
        ChatExecutionStrategy::SinglePass,
        None,
        0.9,
        false,
        &[],
        &["shared_answer_surface".to_string()],
        None,
    );

    let normalized_request = projection
        .normalized_request
        .as_ref()
        .expect("normalized request");
    match normalized_request {
        ChatNormalizedRequest::Weather(frame) => {
            assert_eq!(frame.assumed_location.as_deref(), Some("New York City"));
            assert_eq!(frame.temporal_scope.as_deref(), Some("tomorrow"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
    assert_eq!(
        projection
            .lane_request
            .as_ref()
            .expect("lane request")
            .primary_lane,
        ChatLaneFamily::Research
    );
    assert_eq!(
        projection
            .source_decision
            .as_ref()
            .expect("source decision")
            .selected_source,
        ChatSourceFamily::SpecializedTool
    );
}

#[test]
fn weather_missing_scope_uses_domain_specific_degradation_reason() {
    let projection = derive_chat_topology_projection(
        "What's the weather tomorrow?",
        None,
        None,
        ChatOutcomeKind::ToolWidget,
        ChatExecutionStrategy::PlanExecute,
        None,
        0.88,
        true,
        &["Which city should Chat check?".to_string()],
        &["tool_widget:weather".to_string()],
        None,
    );

    assert_eq!(
        projection
            .source_decision
            .as_ref()
            .and_then(|selection| selection.degradation_reason.as_deref()),
        Some("weather execution is blocked until location scope is clarified or safely inherited")
    );
}

#[test]
fn complete_specialized_lanes_select_specialized_source_not_generic_web() {
    let scenarios = [
        (
            "Did the Lakers win their most recent completed game?",
            "tool_widget:sports",
            "sports",
        ),
        (
            "Find coffee shops near downtown Boston.",
            "tool_widget:places",
            "places",
        ),
        (
            "Recipe for chickpea curry for 4.",
            "tool_widget:recipe",
            "recipe",
        ),
    ];

    for (prompt, hint, expected_frame) in scenarios {
        let projection = derive_chat_topology_projection(
            prompt,
            None,
            None,
            ChatOutcomeKind::ToolWidget,
            ChatExecutionStrategy::PlanExecute,
            None,
            0.9,
            false,
            &[],
            &[hint.to_string()],
            None,
        );
        let normalized_request = projection
            .normalized_request
            .as_ref()
            .expect("request frame");
        let (actual_frame, missing_slots) = match normalized_request {
            ChatNormalizedRequest::Sports(frame) => ("sports", &frame.missing_slots),
            ChatNormalizedRequest::Places(frame) => ("places", &frame.missing_slots),
            ChatNormalizedRequest::Recipe(frame) => ("recipe", &frame.missing_slots),
            other => panic!("unexpected request frame for {prompt}: {other:?}"),
        };
        assert_eq!(actual_frame, expected_frame);
        assert!(missing_slots.is_empty());

        let source_decision = projection
            .source_decision
            .as_ref()
            .expect("source decision");
        assert_eq!(
            source_decision.selected_source,
            ChatSourceFamily::SpecializedTool
        );
        assert!(source_decision
            .candidate_sources
            .contains(&ChatSourceFamily::WebSearch));
        assert!(source_decision.degradation_reason.is_none());
    }
}

#[test]
fn message_compose_domain_policy_bundle_is_explicit_and_medium_risk() {
    let projection = derive_chat_topology_projection(
        "Draft an email to my manager about delaying the launch by one day.",
        None,
        None,
        ChatOutcomeKind::Conversation,
        ChatExecutionStrategy::SinglePass,
        None,
        0.93,
        false,
        &[],
        &[
            "email_draft".to_string(),
            "shared_answer_surface".to_string(),
        ],
        None,
    );

    let bundle = derive_chat_domain_policy_bundle(
        projection.lane_request.as_ref(),
        projection.normalized_request.as_ref(),
        projection.source_decision.as_ref(),
        ChatOutcomeKind::Conversation,
        &[
            "email_draft".to_string(),
            "shared_answer_surface".to_string(),
        ],
        false,
        None,
    );

    assert_eq!(
        bundle
            .presentation_policy
            .as_ref()
            .map(|policy| policy.primary_surface.as_str()),
        Some("communication_surface")
    );
    assert_eq!(
        bundle.fallback_policy.as_ref().map(|policy| policy.mode),
        Some(ioi_types::app::ChatFallbackMode::AllowRankedFallbacks)
    );
    assert_eq!(
        bundle
            .risk_profile
            .as_ref()
            .map(|profile| profile.sensitivity),
        Some(ioi_types::app::ChatRiskSensitivity::Medium)
    );
    assert_eq!(
        bundle
            .verification_contract
            .as_ref()
            .map(|contract| contract.strategy.as_str()),
        Some("message_shape_and_audience")
    );
}

#[test]
fn weather_scope_extraction_separates_location_from_temporal_suffix() {
    let projection = derive_chat_topology_projection(
        "What's the weather in Boston this weekend?",
        None,
        None,
        ChatOutcomeKind::ToolWidget,
        ChatExecutionStrategy::PlanExecute,
        None,
        0.9,
        false,
        &[],
        &["tool_widget:weather".to_string()],
        None,
    );

    let normalized_request = projection
        .normalized_request
        .as_ref()
        .expect("request frame");
    match normalized_request {
        ChatNormalizedRequest::Weather(frame) => {
            assert_eq!(frame.inferred_locations, vec!["boston".to_string()]);
            assert_eq!(frame.temporal_scope.as_deref(), Some("this_weekend"));
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
}

#[test]
fn weather_current_area_requests_resolve_runtime_locality_without_placeholder_slots() {
    with_runtime_locality_scope_hint_override(Some("Brooklyn, NY"), || {
        let projection = derive_chat_topology_projection(
            "What's the weather near me tomorrow?",
            None,
            None,
            ChatOutcomeKind::ToolWidget,
            ChatExecutionStrategy::PlanExecute,
            None,
            0.9,
            false,
            &[],
            &["tool_widget:weather".to_string()],
            None,
        );

        let normalized_request = projection
            .normalized_request
            .as_ref()
            .expect("request frame");
        match normalized_request {
            ChatNormalizedRequest::Weather(frame) => {
                assert_eq!(frame.assumed_location.as_deref(), Some("Brooklyn, NY"));
                assert!(frame.missing_slots.is_empty());
            }
            other => panic!("expected weather frame, got {other:?}"),
        }
    });
}

#[test]
fn places_current_area_requests_resolve_runtime_locality_without_near_me_placeholder() {
    with_runtime_locality_scope_hint_override(Some("Williamsburg, Brooklyn"), || {
        let projection = derive_chat_topology_projection(
            "Find coffee shops near me.",
            None,
            None,
            ChatOutcomeKind::ToolWidget,
            ChatExecutionStrategy::PlanExecute,
            None,
            0.92,
            false,
            &[],
            &["tool_widget:places".to_string()],
            None,
        );

        let normalized_request = projection
            .normalized_request
            .as_ref()
            .expect("request frame");
        match normalized_request {
            ChatNormalizedRequest::Places(frame) => {
                assert_eq!(
                    frame.location_scope.as_deref(),
                    Some("Williamsburg, Brooklyn")
                );
                assert_eq!(
                    frame.search_anchor.as_deref(),
                    Some("Williamsburg, Brooklyn")
                );
                assert!(frame.missing_slots.is_empty());
            }
            other => panic!("expected places frame, got {other:?}"),
        }
    });
}

#[test]
fn places_anchor_extraction_drops_presentation_suffixes() {
    let projection = derive_chat_topology_projection(
        "Find three good coffee shops near downtown Portland, show them on a map, and tell me which one opens earliest.",
        None,
        None,
        ChatOutcomeKind::ToolWidget,
        ChatExecutionStrategy::PlanExecute,
        None,
        0.92,
        false,
        &[],
        &["tool_widget:places".to_string()],
        None,
    );

    let normalized_request = projection
        .normalized_request
        .as_ref()
        .expect("request frame");
    match normalized_request {
        ChatNormalizedRequest::Places(frame) => {
            assert_eq!(frame.search_anchor.as_deref(), Some("downtown portland"));
            assert_eq!(frame.location_scope.as_deref(), Some("downtown portland"));
            assert_eq!(frame.category.as_deref(), Some("coffee shops"));
        }
        other => panic!("expected places frame, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn local_html_brief_planner_uses_text_json_contract() {
    #[derive(Debug, Clone)]
    struct LocalBriefPlannerRuntime {
        json_modes: Arc<Mutex<Vec<bool>>>,
    }

    #[async_trait]
    impl InferenceRuntime for LocalBriefPlannerRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            Ok(serde_json::to_string(&sample_html_brief())
                .expect("sample html brief")
                .into_bytes())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "local brief planner".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(LocalBriefPlannerRuntime {
        json_modes: json_modes.clone(),
    });
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );

    let brief = plan_chat_artifact_brief_with_runtime(
        runtime,
        "Quantum explainer",
        "Create an interactive HTML canvas artifact that explains quantum computers",
        &request,
        None,
    )
    .await
    .expect("brief planning should succeed");

    assert_eq!(brief.subject_domain, sample_html_brief().subject_domain);
    assert!(json_modes
        .lock()
        .expect("json mode log")
        .iter()
        .all(|json_mode| !json_mode));
}

#[derive(Debug, Clone)]
struct ScriptedOutcomeRouterRuntime {
    response: String,
}

#[async_trait]
impl InferenceRuntime for ScriptedOutcomeRouterRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(self.response.clone().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
        ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "scripted router".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }
    }
}

fn scripted_outcome_router_runtime(payload: serde_json::Value) -> Arc<dyn InferenceRuntime> {
    Arc::new(ScriptedOutcomeRouterRuntime {
        response: payload.to_string(),
    })
}

#[test]
fn outcome_router_prompt_surfaces_active_artifact_context_for_follow_ups() {
    let prompt = build_chat_outcome_router_prompt(
        "Make it feel more enterprise",
        Some("artifact-1"),
        Some(&ChatArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-2".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Interactive rollout artifact".to_string(),
            renderer: ChatRendererKind::HtmlIframe,
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>".to_string(),
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
    );
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_chat_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("Active artifact context JSON"));
    assert!(prompt_text.contains("\"renderer\":\"html_iframe\""));
    assert!(prompt_text.contains("patch or branch the current artifact by default"));
    assert!(prompt_text.contains("continue the active artifact"));
}
