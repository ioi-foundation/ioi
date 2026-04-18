use super::*;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioLaneFamily, StudioNormalizedRequestFrame, StudioRetainedWidgetState, StudioSourceFamily,
    StudioWidgetStateBinding,
};
use ioi_types::error::VmError;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[test]
fn parses_planning_payload_with_wrapped_text() {
    let parsed = parse_studio_outcome_planning_payload(
        "router output\n{\"outcomeKind\":\"conversation\",\"confidence\":0.6,\"needsClarification\":false,\"clarificationQuestions\":[],\"artifact\":null}",
    )
    .expect("planning payload");
    assert_eq!(
        parsed.outcome_kind,
        ioi_types::app::StudioOutcomeKind::Conversation
    );
}

#[test]
fn parses_planning_payload_with_missing_scope_and_verification_defaults() {
    let parsed = parse_studio_outcome_planning_payload(
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
    assert_eq!(artifact.renderer, StudioRendererKind::Markdown);
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
    let context = StudioIntentContext::new("Near Williamsburg, Brooklyn.");
    assert_eq!(
        context.places_anchor_phrase().as_deref(),
        Some("williamsburg, brooklyn")
    );
}

#[test]
fn places_anchor_phrase_preserves_multi_segment_locations() {
    let context =
        StudioIntentContext::new("Find coffee shops near Williamsburg, Brooklyn and show the map.");
    assert_eq!(
        context.places_anchor_phrase().as_deref(),
        Some("williamsburg, brooklyn")
    );
}

#[test]
fn parses_planning_payload_with_renderer_derived_defaults() {
    let parsed = parse_studio_outcome_planning_payload(
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
    assert_eq!(artifact.artifact_class, StudioArtifactClass::Document);
    assert_eq!(
        artifact.deliverable_shape,
        StudioArtifactDeliverableShape::SingleFile
    );
    assert_eq!(artifact.renderer, StudioRendererKind::Markdown);
    assert_eq!(
        artifact.presentation_surface,
        StudioPresentationSurface::SidePanel
    );
    assert_eq!(
        artifact.persistence,
        StudioArtifactPersistenceMode::SharedArtifactScoped
    );
    assert_eq!(artifact.execution_substrate, StudioExecutionSubstrate::None);
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
fn parses_planning_payload_preserves_execution_strategy() {
    let parsed = parse_studio_outcome_planning_payload(
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

    assert_eq!(
        parsed.execution_strategy,
        StudioExecutionStrategy::SinglePass
    );
}

#[test]
fn outcome_router_prompt_spells_out_html_vs_jsx_contracts() {
    let prompt = build_studio_outcome_router_prompt(
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
    let full_prompt = build_studio_outcome_router_prompt(
        "Create a markdown artifact that documents a release checklist",
        None,
        None,
    );
    let compact_prompt = build_studio_outcome_router_prompt_for_runtime(
        "Create a markdown artifact that documents a release checklist",
        None,
        None,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    let full_prompt_text = serde_json::to_string(&full_prompt).expect("full prompt text");
    let compact_prompt_text = decode_studio_test_prompt(
        &serde_json::to_vec(&compact_prompt).expect("compact prompt bytes"),
    );

    assert!(compact_prompt_text.len() < full_prompt_text.len());
    assert!(compact_prompt_text.len() * 2 < full_prompt_text.len());
    assert!(compact_prompt_text.contains("executionStrategy"));
    assert!(compact_prompt_text.contains("Return exactly one JSON object"));
    assert!(compact_prompt_text.contains("Renderer meanings:"));
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
    let prompt = build_studio_outcome_router_prompt_for_runtime(
        "Make it feel more enterprise",
        Some("artifact-1"),
        Some(&StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-2".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Interactive rollout artifact".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>".repeat(20),
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    let prompt_text =
        decode_studio_test_prompt(&serde_json::to_vec(&prompt).expect("prompt bytes"));

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
                .push(decode_studio_test_prompt(input_context));
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
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

    let planning = plan_studio_outcome_with_runtime(
        runtime,
        "Create an interactive HTML canvas artifact that explains quantum computers",
        None,
        None,
    )
    .await
    .expect("local routing should succeed");

    assert_eq!(planning.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planning.execution_strategy,
        StudioExecutionStrategy::DirectAuthor
    );
    assert_eq!(
        planning.artifact.expect("artifact").renderer,
        StudioRendererKind::HtmlIframe
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

    let planning = plan_studio_outcome_with_runtime(
        runtime,
        "What is the weather in Boston today?",
        None,
        None,
    )
    .await
    .expect("planning");

    assert_eq!(planning.outcome_kind, StudioOutcomeKind::ToolWidget);
    let lane_frame = planning.lane_frame.expect("lane frame");
    assert_eq!(lane_frame.primary_lane, StudioLaneFamily::Research);
    assert_eq!(lane_frame.tool_widget_family.as_deref(), Some("weather"));
    let request_frame = planning.request_frame.expect("request frame");
    match request_frame {
        StudioNormalizedRequestFrame::Weather(frame) => {
            assert_eq!(frame.inferred_locations, vec!["boston".to_string()]);
            assert_eq!(frame.temporal_scope.as_deref(), Some("today"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
    let source_selection = planning.source_selection.expect("source selection");
    assert_eq!(
        source_selection.selected_source,
        StudioSourceFamily::SpecializedTool
    );
    assert!(source_selection
        .candidate_sources
        .contains(&StudioSourceFamily::WebSearch));
    assert!(planning.orchestration_state.is_some());
}

#[test]
fn communication_projection_infers_message_compose_lane_and_missing_slots() {
    let projection = derive_studio_topology_projection(
        "Draft an email to the finance team about delaying the launch by one week",
        None,
        None,
        StudioOutcomeKind::Conversation,
        StudioExecutionStrategy::PlanExecute,
        None,
        0.88,
        false,
        &[],
        &["shared_answer_surface".to_string()],
        None,
    );

    let lane_frame = projection.lane_frame.expect("lane frame");
    assert_eq!(lane_frame.primary_lane, StudioLaneFamily::Communication);
    let request_frame = projection.request_frame.expect("request frame");
    match request_frame {
        StudioNormalizedRequestFrame::MessageCompose(frame) => {
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
        StudioSourceFamily::DirectAnswer
    );
}

#[test]
fn retained_widget_state_backfills_weather_scope_and_domain_policy_bundle() {
    let widget_state = StudioRetainedWidgetState {
        widget_family: Some("weather".to_string()),
        bindings: vec![StudioWidgetStateBinding {
            key: "weather.location".to_string(),
            value: "Boston".to_string(),
            source: "widget_click".to_string(),
        }],
        last_updated_at: None,
    };
    let projection = derive_studio_topology_projection(
        "What about tomorrow?",
        None,
        Some(&widget_state),
        StudioOutcomeKind::ToolWidget,
        StudioExecutionStrategy::PlanExecute,
        None,
        0.86,
        false,
        &[],
        &["tool_widget:weather".to_string()],
        None,
    );

    let request_frame = projection.request_frame.as_ref().expect("request frame");
    match request_frame {
        StudioNormalizedRequestFrame::Weather(frame) => {
            assert_eq!(frame.assumed_location.as_deref(), Some("Boston"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }

    let policy_bundle = derive_studio_domain_policy_bundle(
        projection.lane_frame.as_ref(),
        projection.request_frame.as_ref(),
        projection.source_selection.as_ref(),
        StudioOutcomeKind::ToolWidget,
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
        Some(ioi_types::app::StudioClarificationMode::AssumeFromRetainedState)
    );
}

#[test]
fn weather_missing_scope_uses_domain_specific_fallback_reason() {
    let projection = derive_studio_topology_projection(
        "What's the weather tomorrow?",
        None,
        None,
        StudioOutcomeKind::ToolWidget,
        StudioExecutionStrategy::PlanExecute,
        None,
        0.88,
        true,
        &["Which city should Studio check?".to_string()],
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
    let projection = derive_studio_topology_projection(
        "Draft an email to my manager about delaying the launch by one day.",
        None,
        None,
        StudioOutcomeKind::Conversation,
        StudioExecutionStrategy::SinglePass,
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

    let bundle = derive_studio_domain_policy_bundle(
        projection.lane_frame.as_ref(),
        projection.request_frame.as_ref(),
        projection.source_selection.as_ref(),
        StudioOutcomeKind::Conversation,
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
        Some(ioi_types::app::StudioFallbackMode::AllowRankedFallbacks)
    );
    assert_eq!(
        bundle
            .risk_profile
            .as_ref()
            .map(|profile| profile.sensitivity),
        Some(ioi_types::app::StudioRiskSensitivity::Medium)
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
    let projection = derive_studio_topology_projection(
        "What's the weather in Boston this weekend?",
        None,
        None,
        StudioOutcomeKind::ToolWidget,
        StudioExecutionStrategy::PlanExecute,
        None,
        0.9,
        false,
        &[],
        &["tool_widget:weather".to_string()],
        None,
    );

    let request_frame = projection.request_frame.as_ref().expect("request frame");
    match request_frame {
        StudioNormalizedRequestFrame::Weather(frame) => {
            assert_eq!(frame.inferred_locations, vec!["boston".to_string()]);
            assert_eq!(frame.temporal_scope.as_deref(), Some("this_weekend"));
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
}

#[test]
fn weather_current_area_requests_resolve_runtime_locality_without_placeholder_slots() {
    with_studio_runtime_locality_scope_hint_override(Some("Brooklyn, NY"), || {
        let projection = derive_studio_topology_projection(
            "What's the weather near me tomorrow?",
            None,
            None,
            StudioOutcomeKind::ToolWidget,
            StudioExecutionStrategy::PlanExecute,
            None,
            0.9,
            false,
            &[],
            &["tool_widget:weather".to_string()],
            None,
        );

        let request_frame = projection.request_frame.as_ref().expect("request frame");
        match request_frame {
            StudioNormalizedRequestFrame::Weather(frame) => {
                assert_eq!(frame.assumed_location.as_deref(), Some("Brooklyn, NY"));
                assert!(frame.missing_slots.is_empty());
            }
            other => panic!("expected weather frame, got {other:?}"),
        }
    });
}

#[test]
fn places_current_area_requests_resolve_runtime_locality_without_near_me_placeholder() {
    with_studio_runtime_locality_scope_hint_override(Some("Williamsburg, Brooklyn"), || {
        let projection = derive_studio_topology_projection(
            "Find coffee shops near me.",
            None,
            None,
            StudioOutcomeKind::ToolWidget,
            StudioExecutionStrategy::PlanExecute,
            None,
            0.92,
            false,
            &[],
            &["tool_widget:places".to_string()],
            None,
        );

        let request_frame = projection.request_frame.as_ref().expect("request frame");
        match request_frame {
            StudioNormalizedRequestFrame::Places(frame) => {
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
    let projection = derive_studio_topology_projection(
        "Find three good coffee shops near downtown Portland, show them on a map, and tell me which one opens earliest.",
        None,
        None,
        StudioOutcomeKind::ToolWidget,
        StudioExecutionStrategy::PlanExecute,
        None,
        0.92,
        false,
        &[],
        &["tool_widget:places".to_string()],
        None,
    );

    let request_frame = projection.request_frame.as_ref().expect("request frame");
    match request_frame {
        StudioNormalizedRequestFrame::Places(frame) => {
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );

    let brief = plan_studio_artifact_brief_with_runtime(
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

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
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
    let prompt = build_studio_outcome_router_prompt(
        "Make it feel more enterprise",
        Some("artifact-1"),
        Some(&StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-2".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Interactive rollout artifact".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
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
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("Active artifact context JSON"));
    assert!(prompt_text.contains("\"renderer\":\"html_iframe\""));
    assert!(prompt_text.contains("patch or branch the current artifact by default"));
    assert!(prompt_text.contains("continue the active artifact"));
}
