use super::*;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ChatLaneFamily, ChatNormalizedRequestFrame, ChatRetainedWidgetState, ChatSourceFamily,
    ChatWidgetStateBinding,
};
use ioi_types::error::VmError;
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
fn outcome_router_prompt_spells_out_html_vs_jsx_contracts() {
    let prompt = build_chat_outcome_router_prompt(
        "Create an interactive HTML artifact that explains a product rollout with charts",
        None,
        None,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");
    assert!(prompt_text.contains("executionStrategy"));
    assert!(prompt_text.contains("routingHints"));
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
    assert!(prompt_log[0].contains("routingHints"));
    assert!(prompt_log[0].contains("JSON only."));
}

#[tokio::test(flavor = "current_thread")]
async fn weather_route_derives_lane_frame_request_frame_and_source_selection() {
    let runtime = scripted_outcome_router_runtime(serde_json::json!({
        "outcomeKind": "conversation",
        "executionStrategy": "single_pass",
        "confidence": 0.41,
        "needsClarification": false,
        "clarificationQuestions": [],
        "routingHints": [],
        "artifact": null
    }));

    let planning =
        plan_chat_outcome_with_runtime(runtime, "What is the weather in Boston today?", None, None)
            .await
            .expect("planning");

    assert_eq!(planning.outcome_kind, ChatOutcomeKind::ToolWidget);
    let lane_frame = planning.lane_frame.expect("lane frame");
    assert_eq!(lane_frame.primary_lane, ChatLaneFamily::Research);
    assert_eq!(lane_frame.tool_widget_family.as_deref(), Some("weather"));
    let request_frame = planning.request_frame.expect("request frame");
    match request_frame {
        ChatNormalizedRequestFrame::Weather(frame) => {
            assert_eq!(frame.inferred_locations, vec!["boston".to_string()]);
            assert_eq!(frame.temporal_scope.as_deref(), Some("today"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
    let source_selection = planning.source_selection.expect("source selection");
    assert_eq!(
        source_selection.selected_source,
        ChatSourceFamily::SpecializedTool
    );
    assert!(source_selection
        .candidate_sources
        .contains(&ChatSourceFamily::WebSearch));
    assert!(planning.orchestration_state.is_some());
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

    let lane_frame = projection.lane_frame.expect("lane frame");
    assert_eq!(lane_frame.primary_lane, ChatLaneFamily::Communication);
    let request_frame = projection.request_frame.expect("request frame");
    match request_frame {
        ChatNormalizedRequestFrame::MessageCompose(frame) => {
            assert_eq!(frame.channel.as_deref(), Some("email"));
            assert_eq!(frame.purpose.as_deref(), Some("draft"));
            assert_eq!(frame.recipient_context.as_deref(), Some("The Finance Team"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected message compose frame, got {other:?}"),
    }
    assert_eq!(
        projection
            .source_selection
            .expect("source selection")
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

    let request_frame = projection.request_frame.as_ref().expect("request frame");
    match request_frame {
        ChatNormalizedRequestFrame::Weather(frame) => {
            assert_eq!(frame.assumed_location.as_deref(), Some("Boston"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }

    let policy_bundle = derive_chat_domain_policy_bundle(
        projection.lane_frame.as_ref(),
        projection.request_frame.as_ref(),
        projection.source_selection.as_ref(),
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
fn weather_missing_scope_uses_domain_specific_fallback_reason() {
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
            .source_selection
            .as_ref()
            .and_then(|selection| selection.fallback_reason.as_deref()),
        Some("weather execution is blocked until location scope is clarified or safely inherited")
    );
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
        projection.lane_frame.as_ref(),
        projection.request_frame.as_ref(),
        projection.source_selection.as_ref(),
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

    let request_frame = projection.request_frame.as_ref().expect("request frame");
    match request_frame {
        ChatNormalizedRequestFrame::Weather(frame) => {
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

        let request_frame = projection.request_frame.as_ref().expect("request frame");
        match request_frame {
            ChatNormalizedRequestFrame::Weather(frame) => {
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

        let request_frame = projection.request_frame.as_ref().expect("request frame");
        match request_frame {
            ChatNormalizedRequestFrame::Places(frame) => {
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

    let request_frame = projection.request_frame.as_ref().expect("request frame");
    match request_frame {
        ChatNormalizedRequestFrame::Places(frame) => {
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
