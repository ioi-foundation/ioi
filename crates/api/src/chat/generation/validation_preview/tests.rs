use super::*;
use ioi_types::app::{
    ChatArtifactDeliverableShape, ChatArtifactPersistenceMode, ChatOutcomeArtifactScope,
    ChatOutcomeArtifactVerificationRequest,
};

fn sample_request(renderer: ChatRendererKind) -> ChatOutcomeArtifactRequest {
    ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: match renderer {
            ChatRendererKind::HtmlIframe
            | ChatRendererKind::JsxSandbox
            | ChatRendererKind::Svg
            | ChatRendererKind::Mermaid => ChatExecutionSubstrate::ClientSandbox,
            ChatRendererKind::PdfEmbed => ChatExecutionSubstrate::BinaryGenerator,
            ChatRendererKind::WorkspaceSurface => ChatExecutionSubstrate::WorkspaceRuntime,
            _ => ChatExecutionSubstrate::None,
        },
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: renderer == ChatRendererKind::WorkspaceSurface,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: renderer == ChatRendererKind::WorkspaceSurface,
            require_preview: renderer == ChatRendererKind::WorkspaceSurface,
            require_export: true,
            require_diff_review: false,
        },
    }
}

fn sample_payload(body: String, mime: &str, path: &str) -> ChatGeneratedArtifactPayload {
    ChatGeneratedArtifactPayload {
        summary: "sample preview payload".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: path.to_string(),
            mime: mime.to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body,
        }],
    }
}

#[test]
fn single_pass_canonical_preview_preserves_full_primary_file_body() {
    let request = sample_request(ChatRendererKind::HtmlIframe);
    let long_body = format!(
        "<!doctype html><html><body>{}<!-- preview tail marker --></body></html>",
        "a".repeat(5000)
    );
    let payload = sample_payload(long_body.clone(), "text/html", "index.html");

    let preview = single_pass_canonical_preview(&request, &payload, "draft_ready", false)
        .expect("non-work_graph canonical preview");

    assert_eq!(preview.kind, ExecutionLivePreviewKind::ChangePreview);
    assert_eq!(preview.content, long_body);
    assert!(preview.content.contains("preview tail marker"));
}

#[test]
fn work_graph_canonical_preview_preserves_full_primary_file_body() {
    let long_body = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\">{}<!-- preview tail marker --></svg>",
        "<g><text>quantum</text></g>".repeat(350)
    );
    let payload = sample_payload(long_body.clone(), "image/svg+xml", "index.svg");

    let preview = chat_work_graph_canonical_preview(
        &payload,
        Some("repair-pass-1".to_string()),
        Some(ChatArtifactWorkerRole::Repair),
        "repairing",
        false,
    )
    .expect("work_graph canonical preview");

    assert_eq!(preview.kind, ExecutionLivePreviewKind::ChangePreview);
    assert_eq!(preview.content, long_body);
    assert!(preview.content.contains("preview tail marker"));
}
