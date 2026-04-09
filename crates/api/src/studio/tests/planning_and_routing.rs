use super::*;

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
    let compact_prompt_text = serde_json::to_string(&compact_prompt).expect("compact prompt text");

    assert!(compact_prompt_text.len() < full_prompt_text.len());
    assert!(compact_prompt_text.contains("executionStrategy"));
    assert!(
        compact_prompt_text.contains("single_pass = one bounded draft with no candidate search.")
    );
    assert!(compact_prompt_text.contains("direct_author = direct first-pass authoring"));
    assert!(compact_prompt_text.contains("Derived automatically from renderer when omitted"));
    assert!(compact_prompt_text
        .contains("Build, preview, and diff review are only valid for workspace_surface."));
    assert!(compact_prompt_text.contains(
        "Explicit medium-plus-deliverable requests are sufficiently specified artifact work."
    ));
    assert!(compact_prompt_text.contains("Do not use lexical fallbacks or benchmark phrase maps."));
    assert!(!compact_prompt_text
        .contains("Create an interactive HTML artifact for an AI tools editorial launch page"));
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
