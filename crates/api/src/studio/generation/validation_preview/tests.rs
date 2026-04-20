use super::*;
use ioi_types::app::{
    StudioArtifactDeliverableShape, StudioArtifactPersistenceMode, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest,
};

fn sample_request(renderer: StudioRendererKind) -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: match renderer {
            StudioRendererKind::HtmlIframe
            | StudioRendererKind::JsxSandbox
            | StudioRendererKind::Svg
            | StudioRendererKind::Mermaid => StudioExecutionSubstrate::ClientSandbox,
            StudioRendererKind::PdfEmbed => StudioExecutionSubstrate::BinaryGenerator,
            StudioRendererKind::WorkspaceSurface => StudioExecutionSubstrate::WorkspaceRuntime,
            _ => StudioExecutionSubstrate::None,
        },
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: renderer == StudioRendererKind::WorkspaceSurface,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: renderer == StudioRendererKind::WorkspaceSurface,
            require_preview: renderer == StudioRendererKind::WorkspaceSurface,
            require_export: true,
            require_diff_review: false,
        },
    }
}

fn sample_payload(body: String, mime: &str, path: &str) -> StudioGeneratedArtifactPayload {
    StudioGeneratedArtifactPayload {
        summary: "sample preview payload".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: path.to_string(),
            mime: mime.to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body,
        }],
    }
}

#[test]
fn non_swarm_canonical_preview_preserves_full_primary_file_body() {
    let request = sample_request(StudioRendererKind::HtmlIframe);
    let long_body = format!(
        "<!doctype html><html><body>{}<!-- preview tail marker --></body></html>",
        "a".repeat(5000)
    );
    let payload = sample_payload(long_body.clone(), "text/html", "index.html");

    let preview = non_swarm_canonical_preview(&request, &payload, "draft_ready", false)
        .expect("non-swarm canonical preview");

    assert_eq!(preview.kind, ExecutionLivePreviewKind::ChangePreview);
    assert_eq!(preview.content, long_body);
    assert!(preview.content.contains("preview tail marker"));
}

#[test]
fn swarm_canonical_preview_preserves_full_primary_file_body() {
    let long_body = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\">{}<!-- preview tail marker --></svg>",
        "<g><text>quantum</text></g>".repeat(350)
    );
    let payload = sample_payload(long_body.clone(), "image/svg+xml", "index.svg");

    let preview = studio_swarm_canonical_preview(
        &payload,
        Some("repair-pass-1".to_string()),
        Some(StudioArtifactWorkerRole::Repair),
        "repairing",
        false,
    )
    .expect("swarm canonical preview");

    assert_eq!(preview.kind, ExecutionLivePreviewKind::ChangePreview);
    assert_eq!(preview.content, long_body);
    assert!(preview.content.contains("preview tail marker"));
}
