use super::*;

#[test]
fn typed_outcome_router_accepts_conversation_payload() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"conversation",
              "confidence":0.81,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":null
            }"#
        .to_string(),
    });

    let planned = tauri::async_runtime::block_on(plan_studio_outcome_with_runtime(
        runtime,
        "do you like flowers?",
        None,
        None,
    ))
    .expect("typed outcome should parse");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Conversation);
    assert!(planned.artifact.is_none());
}

#[test]
fn typed_outcome_router_accepts_workspace_artifact_payload() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
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

    let planned = tauri::async_runtime::block_on(plan_studio_outcome_with_runtime(
        runtime,
        "build a roadmap dashboard",
        None,
        None,
    ))
    .expect("workspace outcome should parse");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planned.artifact.as_ref().map(|artifact| artifact.renderer),
        Some(StudioRendererKind::WorkspaceSurface)
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
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
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

    let error = studio_outcome_request_with_runtime_timeout(
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
fn explicit_single_document_html_requests_bypass_router_timeout() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"conversation",
              "confidence":0.1,
              "needsClarification":true,
              "clarificationQuestions":["unexpected fallback"],
              "artifact":null
            }"#
        .to_string(),
        delay: Duration::from_millis(50),
        provenance: None,
    });

    let planned = studio_outcome_request_with_runtime_timeout(
        runtime,
        "Create an interactive HTML artifact that explains quantum computers.",
        None,
        None,
        None,
        Duration::from_millis(5),
    )
    .expect("explicit single-document requests should short-circuit routing");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planned.execution_strategy,
        StudioExecutionStrategy::DirectAuthor
    );
    assert!(!planned.needs_clarification);
    let artifact = planned.artifact.expect("artifact request");
    assert_eq!(artifact.renderer, StudioRendererKind::HtmlIframe);
    assert_eq!(
        artifact.deliverable_shape,
        StudioArtifactDeliverableShape::SingleFile
    );
}

#[test]
fn explicit_workspace_requests_bypass_router_timeout() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"conversation",
              "confidence":0.1,
              "needsClarification":true,
              "clarificationQuestions":["unexpected fallback"],
              "artifact":null
            }"#
        .to_string(),
        delay: Duration::from_millis(50),
        provenance: None,
    });

    let planned = studio_outcome_request_with_runtime_timeout(
        runtime,
        "Build a React + Vite workspace project for a task tracker with separate components, filters, and local state",
        None,
        None,
        None,
        Duration::from_millis(5),
    )
    .expect("explicit workspace requests should short-circuit routing");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planned.execution_strategy,
        StudioExecutionStrategy::AdaptiveWorkGraph
    );
    assert!(!planned.needs_clarification);
    let artifact = planned.artifact.expect("artifact request");
    assert_eq!(artifact.renderer, StudioRendererKind::WorkspaceSurface);
    assert_eq!(
        artifact.deliverable_shape,
        StudioArtifactDeliverableShape::WorkspaceProject
    );
    assert_eq!(artifact.workspace_recipe_id.as_deref(), Some("react-vite"));
}
