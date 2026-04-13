use super::*;

pub(super) fn compact_local_html_materialization_request_focus(
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    json!({
        "artifactClass": request.artifact_class,
        "renderer": request.renderer,
        "presentationSurface": request.presentation_surface,
        "executionSubstrate": request.execution_substrate,
        "presentationVariantId": request.presentation_variant_id,
        "verification": {
            "requireRender": request.verification.require_render,
            "requireExport": request.verification.require_export,
        },
    })
}

pub(super) fn compact_local_html_materialization_brief_focus(
    brief: &StudioArtifactBrief,
) -> serde_json::Value {
    let required_interactions = brief.required_interaction_summaries();
    json!({
        "audience": truncate_materialization_focus_text(&brief.audience, 80),
        "jobToBeDone": truncate_materialization_focus_text(&brief.job_to_be_done, 120),
        "subjectDomain": truncate_materialization_focus_text(&brief.subject_domain, 120),
        "artifactThesis": truncate_materialization_focus_text(&brief.artifact_thesis, 160),
        "requiredConcepts": brief
            .required_concepts
            .iter()
            .take(4)
            .map(|concept| truncate_materialization_focus_text(concept, 80))
            .collect::<Vec<_>>(),
        "requiredInteractions": required_interactions
            .iter()
            .take(3)
            .map(|interaction| truncate_materialization_focus_text(interaction, 100))
            .collect::<Vec<_>>(),
        "visualTone": brief
            .visual_tone
            .iter()
            .take(3)
            .map(|tone| truncate_materialization_focus_text(tone, 48))
            .collect::<Vec<_>>(),
        "factualAnchors": brief
            .factual_anchors
            .iter()
            .take(3)
            .map(|anchor| truncate_materialization_focus_text(anchor, 120))
            .collect::<Vec<_>>(),
        "styleDirectives": brief
            .style_directives
            .iter()
            .take(3)
            .map(|directive| truncate_materialization_focus_text(directive, 120))
            .collect::<Vec<_>>(),
        "referenceHints": brief
            .reference_hints
            .iter()
            .take(2)
            .map(|hint| truncate_materialization_focus_text(hint, 120))
            .collect::<Vec<_>>(),
    })
}

pub(super) fn compact_local_html_materialization_request_text(
    request: &StudioOutcomeArtifactRequest,
) -> String {
    [
        "renderer: html_iframe".to_string(),
        format!(
            "surface: {}",
            match request.presentation_surface {
                StudioPresentationSurface::Inline => "inline",
                StudioPresentationSurface::SidePanel => "side_panel",
                StudioPresentationSurface::Overlay => "overlay",
                StudioPresentationSurface::TabbedPanel => "tabbed_panel",
            }
        ),
        format!(
            "execution: {}",
            match request.execution_substrate {
                StudioExecutionSubstrate::None => "none",
                StudioExecutionSubstrate::ClientSandbox => "client_sandbox",
                StudioExecutionSubstrate::WorkspaceRuntime => "workspace_runtime",
                StudioExecutionSubstrate::BinaryGenerator => "binary_generator",
            }
        ),
        format!(
            "render verification: {}",
            request.verification.require_render
        ),
        format!("export required: {}", request.verification.require_export),
    ]
    .join("\n")
}

pub(super) fn compact_local_html_materialization_brief_text(brief: &StudioArtifactBrief) -> String {
    let required_interactions = brief.required_interaction_summaries();
    let concepts = brief
        .required_concepts
        .iter()
        .take(3)
        .map(|concept| truncate_materialization_focus_text(concept, 48))
        .collect::<Vec<_>>()
        .join(" | ");
    let interactions = required_interactions
        .iter()
        .take(2)
        .map(|interaction| truncate_materialization_focus_text(interaction, 64))
        .collect::<Vec<_>>()
        .join(" | ");
    let anchors = brief
        .factual_anchors
        .iter()
        .take(2)
        .map(|anchor| truncate_materialization_focus_text(anchor, 72))
        .collect::<Vec<_>>()
        .join(" | ");
    let tones = brief
        .visual_tone
        .iter()
        .take(2)
        .map(|tone| truncate_materialization_focus_text(tone, 32))
        .collect::<Vec<_>>()
        .join(" | ");
    let reference_hint = brief
        .reference_hints
        .iter()
        .find(|hint| !hint.trim().is_empty())
        .map(|hint| truncate_materialization_focus_text(hint, 72))
        .unwrap_or_else(|| "none".to_string());

    [
        format!(
            "audience: {}",
            truncate_materialization_focus_text(&brief.audience, 56)
        ),
        format!(
            "job: {}",
            truncate_materialization_focus_text(&brief.job_to_be_done, 96)
        ),
        format!(
            "domain: {}",
            truncate_materialization_focus_text(&brief.subject_domain, 72)
        ),
        format!(
            "thesis: {}",
            truncate_materialization_focus_text(&brief.artifact_thesis, 104)
        ),
        format!(
            "concepts: {}",
            if concepts.is_empty() {
                "none".to_string()
            } else {
                concepts
            }
        ),
        format!(
            "interactions: {}",
            if interactions.is_empty() {
                "none".to_string()
            } else {
                interactions
            }
        ),
        format!(
            "anchors: {}",
            if anchors.is_empty() {
                "none".to_string()
            } else {
                anchors
            }
        ),
        format!(
            "tone: {}",
            if tones.is_empty() {
                "none".to_string()
            } else {
                tones
            }
        ),
        format!("reference hint: {reference_hint}"),
    ]
    .join("\n")
}

pub(super) fn compact_local_html_interaction_contract_text(brief: &StudioArtifactBrief) -> String {
    let contract = super::studio_artifact_interaction_contract(brief);
    [
        format!(
            "view switching required: {}",
            contract["viewSwitchingRequired"].as_bool().unwrap_or(false)
        ),
        format!(
            "rollover detail required: {}",
            contract["rolloverDetailRequired"]
                .as_bool()
                .unwrap_or(false)
        ),
        format!(
            "sequence browsing required: {}",
            contract["sequenceBrowsingRequired"]
                .as_bool()
                .unwrap_or(false)
        ),
    ]
    .join("\n")
}

pub(super) fn direct_authoring_enabled(
    execution_strategy: StudioExecutionStrategy,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> bool {
    execution_strategy == StudioExecutionStrategy::DirectAuthor
        && direct_author_uses_raw_document(request)
        && refinement.is_none()
}

pub(super) fn direct_author_uses_raw_document(request: &StudioOutcomeArtifactRequest) -> bool {
    matches!(
        request.renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::HtmlIframe
            | StudioRendererKind::Svg
            | StudioRendererKind::Mermaid
            | StudioRendererKind::PdfEmbed
    )
}

pub(super) fn direct_author_stop_sequences(request: &StudioOutcomeArtifactRequest) -> Vec<String> {
    match request.renderer {
        StudioRendererKind::HtmlIframe => vec!["</html>".to_string()],
        StudioRendererKind::Svg => vec!["</svg>".to_string()],
        _ => Vec::new(),
    }
}

pub(super) fn direct_author_completion_boundary(
    request: &StudioOutcomeArtifactRequest,
) -> Option<&'static str> {
    match request.renderer {
        StudioRendererKind::HtmlIframe => Some("</html>"),
        StudioRendererKind::Svg => Some("</svg>"),
        _ => None,
    }
}

pub(super) fn direct_author_document_is_incomplete(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
    error_message: &str,
) -> bool {
    let Some(boundary) = direct_author_completion_boundary(request) else {
        return false;
    };

    if !raw
        .to_ascii_lowercase()
        .contains(&boundary.to_ascii_lowercase())
    {
        return true;
    }

    error_message.contains("fully closed </body></html> document")
        || error_message.contains("must contain a closing </svg>")
}

pub(super) fn direct_author_continuation_pass_limit(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::Svg => {
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                2
            } else {
                1
            }
        }
        _ => 0,
    }
}

pub(super) fn merge_direct_author_document(existing: &str, next: &str) -> String {
    let existing_trimmed = existing.trim_end();
    let next_trimmed = next.trim();
    if next_trimmed.is_empty() {
        return existing_trimmed.to_string();
    }

    if next_trimmed.starts_with("<!doctype html")
        || next_trimmed.starts_with("<html")
        || next_trimmed.starts_with("<svg")
    {
        return next_trimmed.to_string();
    }

    let existing_chars = existing_trimmed.chars().collect::<Vec<_>>();
    let next_chars = next_trimmed.chars().collect::<Vec<_>>();
    let max_overlap = existing_chars.len().min(next_chars.len()).min(512);
    let mut overlap = 0usize;
    for candidate in (1..=max_overlap).rev() {
        if existing_chars[existing_chars.len() - candidate..] == next_chars[..candidate] {
            overlap = candidate;
            break;
        }
    }

    let suffix = next_chars[overlap..].iter().collect::<String>();
    format!("{existing_trimmed}{suffix}")
}

pub(super) fn compact_local_direct_author_prompt(
    runtime_kind: StudioRuntimeProvenanceKind,
    returns_raw_document: bool,
) -> bool {
    runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime && returns_raw_document
}

pub(super) fn direct_author_search_budget(
    request: &StudioOutcomeArtifactRequest,
    production_kind: StudioRuntimeProvenanceKind,
) -> StudioAdaptiveSearchBudget {
    let max_semantic_refinement_passes = if renderer_supports_semantic_refinement(request.renderer)
    {
        1
    } else {
        0
    };
    StudioAdaptiveSearchBudget {
        initial_candidate_count: 1,
        max_candidate_count: 1,
        shortlist_limit: 1,
        max_semantic_refinement_passes,
        plateau_limit: usize::from(max_semantic_refinement_passes > 0),
        min_score_delta: if max_semantic_refinement_passes > 0 {
            1
        } else {
            i32::MAX
        },
        target_judge_score_for_early_stop: match request.renderer {
            StudioRendererKind::HtmlIframe => 356,
            StudioRendererKind::JsxSandbox => 348,
            StudioRendererKind::Svg => 340,
            StudioRendererKind::Markdown => 312,
            StudioRendererKind::Mermaid => 308,
            StudioRendererKind::PdfEmbed => 314,
            StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => 306,
            StudioRendererKind::WorkspaceSurface => 300,
        },
        expansion_score_margin: 0,
        signals: if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
            vec![StudioAdaptiveSearchSignal::LocalGenerationConstraint]
        } else {
            Vec::new()
        },
    }
}

pub(super) fn studio_direct_author_renderer_guidance(
    request: &StudioOutcomeArtifactRequest,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> String {
    match request.renderer {
        StudioRendererKind::Markdown => {
            "- Treat the raw user request as the dominant instruction.\n- Return only the finished markdown document body with request-specific headings, sections, and supporting detail.\n- Do not wrap the document in JSON or markdown fences.\n- Avoid generic platform framing, dashboards, or boilerplate artifact language."
                .to_string()
        }
        StudioRendererKind::HtmlIframe => {
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                return "- Treat the raw user request as the dominant instruction.\n- Author one concise self-contained index.html with inline CSS and inline JavaScript only.\n- Use standard HTML with <main> and at least three meaningful sections.\n- Keep first-paint content visible before scripts run, and include one real inline interaction that changes visible evidence or explanatory copy.\n- Keep the document request-specific, minimal, and fully closed with </html>."
                    .to_string();
            }
            let composition_recipe = match candidate_seed % 3 {
                0 => "editorial explainer with one strong evidence seam",
                1 => "guided comparison with visible state changes",
                _ => "annotated interactive narrative with focused data views",
            };
            let compact_runtime_note =
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    "- Keep the structure concise enough to reach a complete closing </main></body></html> in one pass.\n"
                } else {
                    ""
                };
            format!(
                "- Treat the raw user request as the dominant instruction. Do not translate it into a generic dashboard, control plane, or platform shell.\n- Compose a single self-contained index.html with inline CSS and inline JavaScript only.\n- Use standard HTML, open the body with <main>, and make the first paint complete before any script runs.\n- Follow this composition recipe for variety: {composition_recipe}.\n- If the request implies interaction, make the controls update visible evidence, comparison state, or explanatory copy on the page.\n- Prefer authored diagrams, comparisons, annotations, sceneboards, or guided explanation over app chrome.\n- Keep headings, labels, captions, and evidence specific to the request instead of generic artifact language.\n- Do not use placeholder copy, TODO markers, dead buttons, empty shells, or external libraries.\n{compact_runtime_note}- The artifact should feel authored for this exact request, not interchangeable with nearby prompts."
            )
        }
        StudioRendererKind::Svg => {
            "- Treat the raw user request as the dominant instruction.\n- Return only one complete standalone <svg> document with visible labels and enough marks to stand as the primary artifact.\n- Include <title> and <desc> when they help ground the request.\n- Do not wrap the SVG in JSON, prose, or markdown fences."
                .to_string()
        }
        StudioRendererKind::Mermaid => {
            "- Treat the raw user request as the dominant instruction.\n- Return only Mermaid source for one request-specific diagram.\n- Do not wrap the diagram in markdown fences or JSON.\n- Keep labels, nodes, and edges concrete to the request instead of generic platform language."
                .to_string()
        }
        StudioRendererKind::PdfEmbed => {
            "- Treat the raw user request as the dominant instruction.\n- Return only the authored document text that should be compiled into the PDF artifact.\n- Use clear sections and enough detail for a complete document, but do not emit LaTeX, JSON, or markdown fences.\n- Keep the document request-specific instead of generic artifact boilerplate."
                .to_string()
        }
        _ => "- Treat the raw user request as the dominant instruction and author the requested artifact directly."
            .to_string(),
    }
}
