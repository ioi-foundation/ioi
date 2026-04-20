use crate::studio::*;

pub(super) fn studio_planning_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

pub(super) fn truncate_planning_preview(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "<empty>".to_string();
    }
    let mut preview = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

pub(super) fn compact_local_html_brief_prompt(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
}

pub(super) fn brief_planner_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_brief_prompt(renderer, runtime_kind) {
        return 320;
    }

    448
}

pub(super) fn brief_repair_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_brief_prompt(renderer, runtime_kind) {
        return 320;
    }

    448
}

pub(super) fn brief_field_repair_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_brief_prompt(renderer, runtime_kind) {
        return 256;
    }

    320
}

#[derive(Clone, Copy)]
pub(super) struct StudioOutcomeArtifactRendererDefaults {
    pub artifact_class: &'static str,
    pub deliverable_shape: &'static str,
    pub presentation_surface: &'static str,
    pub persistence: &'static str,
    pub execution_substrate: &'static str,
}

pub(super) fn outcome_artifact_renderer_defaults(
    renderer: &str,
) -> Option<StudioOutcomeArtifactRendererDefaults> {
    match renderer {
        "markdown" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "document",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "none",
        }),
        "html_iframe" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "document",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "client_sandbox",
        }),
        "jsx_sandbox" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "interactive_single_file",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "client_sandbox",
        }),
        "svg" | "mermaid" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "visual",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "client_sandbox",
        }),
        "pdf_embed" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "document",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "binary_generator",
        }),
        "download_card" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "downloadable_file",
            deliverable_shape: "file_set",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "none",
        }),
        "workspace_surface" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "workspace_project",
            deliverable_shape: "workspace_project",
            presentation_surface: "tabbed_panel",
            persistence: "workspace_filesystem",
            execution_substrate: "workspace_runtime",
        }),
        "bundle_manifest" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "compound_bundle",
            deliverable_shape: "file_set",
            presentation_surface: "side_panel",
            persistence: "artifact_scoped",
            execution_substrate: "none",
        }),
        _ => None,
    }
}
