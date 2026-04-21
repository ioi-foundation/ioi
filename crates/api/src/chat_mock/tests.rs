use super::maybe_handle_chat_prompt;
use crate::chat::{
    build_chat_artifact_brief_prompt, build_chat_artifact_candidate_refinement_prompt,
    build_chat_artifact_materialization_prompt,
    build_chat_artifact_materialization_repair_prompt, build_chat_artifact_validation_prompt,
    build_chat_outcome_router_prompt, parse_chat_artifact_validation_result,
    parse_chat_generated_artifact_payload, ChatArtifactBrief, ChatArtifactEditIntent,
    ChatArtifactEditMode, ChatArtifactRefinementContext, ChatArtifactSelectionTarget,
    ChatArtifactTasteMemory, ChatArtifactValidationStatus, ChatGeneratedArtifactFile,
    ChatGeneratedArtifactPayload,
};
use ioi_types::app::{ChatArtifactFileRole, ChatRendererKind};
use serde_json::json;

fn refinement_context_with_subject(subject: &str) -> ChatArtifactRefinementContext {
    ChatArtifactRefinementContext {
        artifact_id: Some("artifact-1".to_string()),
        revision_id: Some("revision-1".to_string()),
        title: "an interactive HTML artifact that explains a product rollout with charts"
            .to_string(),
        summary: format!(
            "Chat outcome: prior artifact The candidate stays grounded in {}, covers the required concepts, and is strong enough to lead the stage.",
            subject
        ),
        renderer: ChatRendererKind::HtmlIframe,
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: format!(
                "<!doctype html><html><body><main><strong>{subject}</strong><h1>{subject} explained through visible rollout proof.</h1></main></body></html>"
            ),
        }],
        selected_targets: Vec::new(),
        taste_memory: Some(ChatArtifactTasteMemory {
            directives: vec!["grounded".to_string(), "request-shaped hierarchy".to_string()],
            summary: format!(
                "Make the primary artifact unmistakably about {} while keeping the structure coherent enough to lead the stage.",
                subject
            ),
            typography_preferences: Vec::new(),
            density_preference: None,
            tone_family: Vec::new(),
            motion_tolerance: None,
            preferred_scaffold_families: Vec::new(),
            preferred_component_patterns: Vec::new(),
            anti_patterns: Vec::new(),
        }),
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
    }
}

fn mermaid_request() -> ioi_types::app::ChatOutcomeArtifactRequest {
    serde_json::from_value(json!({
        "artifactClass": "visual",
        "deliverableShape": "single_file",
        "renderer": "mermaid",
        "presentationSurface": "inline",
        "persistence": "artifact_scoped",
        "executionSubstrate": "none",
        "workspaceRecipeId": null,
        "presentationVariantId": null,
        "scope": {
            "targetProject": null,
            "createNewWorkspace": false,
            "mutationBoundary": ["artifact"]
        },
        "verification": {
            "requireRender": true,
            "requireBuild": false,
            "requirePreview": false,
            "requireExport": true,
            "requireDiffReview": false
        }
    }))
    .expect("mermaid request")
}

fn pdf_request() -> ioi_types::app::ChatOutcomeArtifactRequest {
    serde_json::from_value(json!({
        "artifactClass": "document",
        "deliverableShape": "single_file",
        "renderer": "pdf_embed",
        "presentationSurface": "side_panel",
        "persistence": "artifact_scoped",
        "executionSubstrate": "binary_generator",
        "workspaceRecipeId": null,
        "presentationVariantId": null,
        "scope": {
            "targetProject": null,
            "createNewWorkspace": false,
            "mutationBoundary": ["artifact"]
        },
        "verification": {
            "requireRender": true,
            "requireBuild": false,
            "requirePreview": false,
            "requireExport": true,
            "requireDiffReview": false
        }
    }))
    .expect("pdf request")
}

#[test]
fn mock_router_decodes_serialized_chat_prompt_for_workspace_requests() {
    let prompt = build_chat_outcome_router_prompt(
        "Create a workspace project for a billing settings surface",
        None,
        None,
    );
    let serialized = serde_json::to_string(&prompt).expect("serialize router prompt");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock route response");
    let payload: serde_json::Value = serde_json::from_str(&response).expect("parse route payload");
    assert_eq!(
        payload["artifact"]["renderer"].as_str(),
        Some("workspace_surface")
    );
    assert_eq!(
        payload["artifact"]["artifactClass"].as_str(),
        Some("workspace_project")
    );
}

#[test]
fn mock_brief_decodes_serialized_chat_prompt_with_non_empty_fields() {
    let request = serde_json::from_value(serde_json::json!({
        "artifactClass": "workspace_project",
        "deliverableShape": "workspace_project",
        "renderer": "workspace_surface",
        "presentationSurface": "tabbed_panel",
        "persistence": "workspace_filesystem",
        "executionSubstrate": "workspace_runtime",
        "workspaceRecipeId": "vite-static-html",
        "presentationVariantId": null,
        "scope": {
            "targetProject": "chat-workspace",
            "createNewWorkspace": true,
            "mutationBoundary": ["workspace"]
        },
        "verification": {
            "requireRender": true,
            "requireBuild": true,
            "requirePreview": true,
            "requireExport": false,
            "requireDiffReview": true
        }
    }))
    .expect("workspace request");
    let prompt = build_chat_artifact_brief_prompt(
        "Billing settings surface",
        "Create a workspace project for a billing settings surface",
        &request,
        None,
    )
    .expect("brief prompt");
    let serialized = serde_json::to_string(&prompt).expect("serialize brief prompt");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock brief response");
    let payload: serde_json::Value = serde_json::from_str(&response).expect("parse brief payload");
    assert_eq!(
        payload["subjectDomain"].as_str(),
        Some("a billing settings surface")
    );
    assert_eq!(
        payload["jobToBeDone"].as_str(),
        Some("Scaffold a workspace project with a previewable implementation surface.")
    );
    assert_eq!(
        payload["audience"].as_str(),
        Some("finance, commercial, and product operators")
    );
}

#[test]
#[ignore = "legacy html contract coverage superseded by typed query-profile path"]
fn mock_brief_preserves_prior_subject_for_selected_refinement_follow_up() {
    let prompt = build_chat_artifact_brief_prompt(
        "Edit only this chart section to show adoption by channel",
        "Edit only this chart section to show adoption by channel\n\nselection from index.html: chart section\nHero chart section should show adoption by channel instead of launch-phase sequencing.",
        &super::default_html_request(),
        Some(&refinement_context_with_subject("dog shampoo")),
    )
    .expect("brief prompt");
    let serialized = serde_json::to_string(&prompt).expect("serialize brief prompt");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock brief response");
    let payload: serde_json::Value = serde_json::from_str(&response).expect("parse brief payload");
    let required_concepts = payload["requiredConcepts"]
        .as_array()
        .expect("required concepts");
    assert_eq!(payload["subjectDomain"].as_str(), Some("dog shampoo"));
    assert!(required_concepts
        .iter()
        .any(|value| value.as_str() == Some("dog shampoo")));
    assert!(required_concepts
        .iter()
        .any(|value| value.as_str() == Some("adoption")));
    assert!(required_concepts
        .iter()
        .any(|value| value.as_str() == Some("channel")));
}

#[test]
fn mock_mermaid_materialization_mentions_approval_pipeline() {
    let brief = ChatArtifactBrief {
        audience: "the requesting team".to_string(),
        job_to_be_done: "Explain an approval pipeline through a diagram that can be understood in one pass."
            .to_string(),
        subject_domain: "an approval pipeline".to_string(),
        artifact_thesis: "Make the primary artifact unmistakably about an approval pipeline while keeping the structure coherent enough to lead the stage.".to_string(),
        required_concepts: vec!["an approval pipeline".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["an approval pipeline".to_string()],
        style_directives: vec!["grounded".to_string()],
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let prompt = build_chat_artifact_materialization_prompt(
        "a Mermaid diagram of an approval pipeline",
        "Create a Mermaid diagram of an approval pipeline",
        &mermaid_request(),
        &brief,
        None,
        None,
        "candidate-1",
        1,
    )
    .expect("materialization prompt");
    let serialized = serde_json::to_string(&prompt).expect("serialize materialization");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock materialization response");
    let payload = parse_chat_generated_artifact_payload(&response).expect("parse payload");
    let body = payload.files[0].body.to_ascii_lowercase();
    assert!(body.contains("approval"));
    assert!(body.contains("pipeline"));
}

#[test]
fn mock_pdf_validation_accepts_substantial_pdf_brief() {
    let brief = ChatArtifactBrief {
        audience: "product, operations, and leadership stakeholders".to_string(),
        job_to_be_done:
            "Produce a brief that makes a launch brief presentable as a surfaced PDF export."
                .to_string(),
        subject_domain: "a launch brief".to_string(),
        artifact_thesis: "Make the primary artifact unmistakably about a launch brief while keeping the structure coherent enough to lead the stage.".to_string(),
        required_concepts: vec!["a launch brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["launch".to_string()],
        factual_anchors: vec!["a launch brief".to_string()],
        style_directives: vec!["launch".to_string()],
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let materialization = build_chat_artifact_materialization_prompt(
        "a PDF artifact that summarizes a launch brief",
        "Create a PDF artifact that summarizes a launch brief",
        &pdf_request(),
        &brief,
        None,
        None,
        "candidate-1",
        1,
    )
    .expect("materialization prompt");
    let serialized = serde_json::to_string(&materialization).expect("serialize materialization");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock materialization response");
    let candidate = parse_chat_generated_artifact_payload(&response).expect("parse payload");
    assert!(candidate.files[0].body.contains("## Executive summary"));

    let validation_prompt = build_chat_artifact_validation_prompt(
        "a PDF artifact that summarizes a launch brief",
        &pdf_request(),
        &brief,
        None,
        &candidate,
    )
    .expect("validation prompt");
    let validation_serialized =
        serde_json::to_string(&validation_prompt).expect("serialize validation");
    let validation_response =
        maybe_handle_chat_prompt(&validation_serialized).expect("mock validation");
    let validation =
        parse_chat_artifact_validation_result(&validation_response).expect("parse validation");
    assert_eq!(
        validation.classification,
        ChatArtifactValidationStatus::Pass
    );
    assert!(!validation.trivial_shell_detected);
}

#[test]
fn mock_html_materialization_contains_real_interaction_hooks() {
    let brief = ChatArtifactBrief {
        audience: "launch operators".to_string(),
        job_to_be_done:
            "Explain a dog shampoo rollout through a request-faithful interactive artifact."
                .to_string(),
        subject_domain: "dog shampoo".to_string(),
        artifact_thesis: "Make the rollout specific to dog shampoo.".to_string(),
        required_concepts: vec!["dog shampoo".to_string(), "rollout".to_string()],
        required_interactions: vec!["chart toggle".to_string()],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let prompt = build_chat_artifact_materialization_prompt(
        "dog shampoo rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &super::default_html_request(),
        &brief,
        None,
        None,
        "candidate-1",
        1,
    )
    .expect("materialization prompt");
    let serialized = serde_json::to_string(&prompt).expect("serialize materialization");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock materialization response");
    let payload = parse_chat_generated_artifact_payload(&response).expect("parse payload");
    let body = &payload.files[0].body;

    assert!(body.contains("data-view=\"satisfaction\""));
    assert!(body.contains("data-view-panel=\"satisfaction\""));
    assert!(body.contains("querySelectorAll('[data-view-panel]')"));
    assert!(body.contains("id=\"detail-copy\""));
    assert!(body.contains("<svg class=\"chart-svg\""));
    assert!(body.contains("data-detail=\"Retail satisfaction lift keeps the rollout anchored"));
    assert!(body.contains("addEventListener('click'"));
    assert!(body.contains("addEventListener('focus'"));
}

#[test]
fn mock_materialization_repair_prompt_returns_schema_valid_payload() {
    let brief = ChatArtifactBrief {
        audience: "launch operators".to_string(),
        job_to_be_done: "Explain the rollout in a request-shaped interactive artifact.".to_string(),
        subject_domain: "dog shampoo".to_string(),
        artifact_thesis: "Make the rollout specific to dog shampoo.".to_string(),
        required_concepts: vec!["dog shampoo".to_string(), "rollout".to_string()],
        required_interactions: vec!["chart toggle".to_string()],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let prompt = build_chat_artifact_materialization_repair_prompt(
        "dog shampoo rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &super::default_html_request(),
        &brief,
        None,
        None,
        "candidate-1",
        7,
        r#"{"files":[{"path":"index.html"}]}"#,
        "Interactive HTML iframe artifacts must contain real interactive controls or handlers.",
    )
    .expect("repair prompt");
    let serialized = serde_json::to_string(&prompt).expect("serialize repair prompt");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock repair response");
    let payload = parse_chat_generated_artifact_payload(&response).expect("parse payload");

    assert!(!payload.summary.trim().is_empty());
    assert_eq!(
        payload.files.first().map(|file| file.path.as_str()),
        Some("index.html")
    );
}

#[test]
fn mock_refiner_prompt_returns_schema_valid_payload() {
    let brief = ChatArtifactBrief {
        audience: "launch operators".to_string(),
        job_to_be_done: "Patch the current artifact without losing identity.".to_string(),
        subject_domain: "dog shampoo".to_string(),
        artifact_thesis: "Keep the artifact request-faithful.".to_string(),
        required_concepts: vec!["dog shampoo".to_string(), "rollout".to_string()],
        required_interactions: vec!["chart toggle".to_string()],
        visual_tone: vec!["technical".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let candidate = ChatGeneratedArtifactPayload {
        summary: "Initial candidate".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo</h1></section><section><p>Rollout</p></section><aside><p>Notes</p></aside></main></body></html>".to_string(),
        }],
    };
    let validation =
        super::evaluate_candidate(&super::default_html_request(), &brief, None, &candidate);
    let prompt = build_chat_artifact_candidate_refinement_prompt(
        "dog shampoo rollout artifact",
        "Keep the structure, but replace the hero and chart with a more technical tone",
        &super::default_html_request(),
        &brief,
        None,
        None,
        &candidate,
        None,
        &validation,
        "candidate-1",
        1,
    )
    .expect("refiner prompt");
    let serialized = serde_json::to_string(&prompt).expect("serialize refiner prompt");
    let response = maybe_handle_chat_prompt(&serialized).expect("mock refiner response");
    let payload = parse_chat_generated_artifact_payload(&response).expect("parse payload");

    assert!(!payload.summary.trim().is_empty());
    assert_eq!(
        payload.files.first().map(|file| file.path.as_str()),
        Some("index.html")
    );
}

#[test]
fn mock_validation_marks_targeted_patch_as_patched_existing_artifact() {
    let brief = ChatArtifactBrief {
        audience: "launch operators".to_string(),
        job_to_be_done: "Patch the current artifact without losing identity.".to_string(),
        subject_domain: "dog shampoo".to_string(),
        artifact_thesis: "Keep the artifact request-faithful.".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "adoption".to_string(),
            "channel".to_string(),
        ],
        required_interactions: vec!["chart toggle".to_string()],
        visual_tone: vec!["technical".to_string()],
        factual_anchors: Vec::new(),
        style_directives: vec!["technical".to_string()],
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let edit_intent = ChatArtifactEditIntent {
        mode: ChatArtifactEditMode::Patch,
        summary: "Patch the current html artifact without discarding its identity.".to_string(),
        patch_existing_artifact: true,
        preserve_structure: true,
        target_scope: "selection".to_string(),
        target_paths: vec!["index.html".to_string()],
        requested_operations: vec!["update_chart".to_string()],
        tone_directives: vec!["technical".to_string()],
        selected_targets: vec![ChatArtifactSelectionTarget {
            source_surface: "source".to_string(),
            path: Some("index.html".to_string()),
            label: "Selected source excerpt".to_string(),
            snippet: "Hero chart section should show adoption by channel.".to_string(),
        }],
        style_directives: vec!["technical".to_string()],
        branch_requested: false,
    };
    let candidate = ChatGeneratedArtifactPayload {
        summary: "Patched the technical chart section.".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo adoption by channel</h1><button type=\"button\">Retail</button><svg viewBox=\"0 0 240 120\"><text x=\"20\" y=\"20\">Retail</text><text x=\"100\" y=\"20\">Subscription</text></svg></section></main></body></html>".to_string(),
        }],
    };

    let validation_prompt = build_chat_artifact_validation_prompt(
        "dog shampoo chart patch",
        &super::default_html_request(),
        &brief,
        Some(&edit_intent),
        &candidate,
    )
    .expect("validation prompt");
    let validation_serialized =
        serde_json::to_string(&validation_prompt).expect("serialize validation");
    let normalized = super::normalize_prompt_input(&validation_serialized);
    let extracted_edit_json =
        super::extract_json_after(&normalized, "Edit intent focus JSON:\n").expect("edit json");
    let parsed_edit_intent = serde_json::from_str::<serde_json::Value>(&extracted_edit_json)
        .expect("parse focused edit intent");
    assert_eq!(parsed_edit_intent["mode"], "patch");
    assert_eq!(parsed_edit_intent["patchExistingArtifact"], true);
    let extracted_candidate_json =
        super::extract_json_after(&normalized, "Candidate JSON:\n").expect("candidate json");
    let parsed_candidate =
        super::parse_mock_validation_candidate_view(&extracted_candidate_json).expect("candidate");
    assert_eq!(
        parsed_candidate
            .files
            .first()
            .map(|file| file.path.as_str()),
        Some("index.html")
    );
    let validation_response =
        maybe_handle_chat_prompt(&validation_serialized).expect("mock validation");
    let validation =
        parse_chat_artifact_validation_result(&validation_response).expect("parse validation");

    assert_eq!(validation.patched_existing_artifact, Some(true));
    assert_eq!(validation.continuity_revision_ux, Some(5));
}
