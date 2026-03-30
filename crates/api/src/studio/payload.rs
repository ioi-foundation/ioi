use super::html::*;
use super::*;

pub fn parse_studio_generated_artifact_payload(
    raw: &str,
) -> Result<StudioGeneratedArtifactPayload, String> {
    parse_studio_generated_artifact_payload_json(raw)
        .or_else(|_| {
            let extracted = extract_first_json_object(raw).ok_or_else(|| {
                "Studio artifact materialization output missing JSON payload".to_string()
            })?;
            parse_studio_generated_artifact_payload_json(&extracted)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            format!(
                "Failed to parse Studio artifact materialization payload: {}",
                error
            )
        })
}

fn parse_studio_generated_artifact_payload_json(
    raw: &str,
) -> Result<StudioGeneratedArtifactPayload, serde_json::Error> {
    let value = serde_json::from_str::<serde_json::Value>(raw)?;
    serde_json::from_value::<StudioGeneratedArtifactPayload>(value)
}

pub fn validate_generated_artifact_payload(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) -> Result<(), String> {
    if payload.summary.trim().is_empty() {
        return Err("Studio artifact materialization summary must not be empty.".to_string());
    }
    if payload.files.is_empty() {
        return Err("Studio artifact materialization must contain at least one file.".to_string());
    }
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return Err(
            "workspace_surface artifacts must be materialized through the workspace renderer path."
                .to_string(),
        );
    }

    let mut paths = HashSet::new();
    for file in &payload.files {
        if file.path.trim().is_empty() {
            return Err("Generated artifact file path must not be empty.".to_string());
        }
        if !paths.insert(file.path.clone()) {
            return Err(format!(
                "Generated artifact file path '{}' is duplicated.",
                file.path
            ));
        }
        if file.body.trim().is_empty() {
            return Err(format!(
                "Generated artifact file '{}' must not have an empty body.",
                file.path
            ));
        }
    }

    let primary_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
            )
        })
        .ok_or_else(|| {
            "Generated artifact payload must include a primary or export file.".to_string()
        })?;

    match request.renderer {
        StudioRendererKind::Markdown => {
            validate_exact_primary_file(primary_file, ".md", "text/markdown", true)?;
        }
        StudioRendererKind::HtmlIframe => {
            validate_exact_primary_file(primary_file, ".html", "text/html", true)?;
            let lower = primary_file.body.to_ascii_lowercase();
            if !(lower.contains("<html") || lower.contains("<!doctype html")) {
                return Err("HTML iframe artifacts must contain an HTML document.".to_string());
            }
            if !lower.contains("<main") {
                return Err("HTML iframe artifacts must contain a <main> region.".to_string());
            }
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                return Err(
                    "HTML iframe artifacts must contain at least three sectioning elements with first-paint content."
                        .to_string(),
                );
            }
            if lower.contains("alert(") {
                return Err(
                    "HTML iframe artifacts must not use alert() as the surfaced interaction."
                        .to_string(),
                );
            }
            if html_uses_external_runtime_dependency(&lower) {
                return Err(
                    "HTML iframe artifacts must not depend on external libraries or undefined globals."
                        .to_string(),
                );
            }
            if html_contains_placeholder_markers(&lower) {
                return Err(
                    "HTML iframe artifacts must not contain placeholder-grade copy, comments, or TODO markers in the surfaced artifact."
                        .to_string(),
                );
            }
            if html_contains_placeholder_svg_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint."
                        .to_string(),
                );
            }
            if html_contains_unlabeled_chart_svg_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint."
                        .to_string(),
                );
            }
            if html_contains_empty_chart_container_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint."
                        .to_string(),
                );
            }
            if html_contains_empty_detail_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include shared detail or comparison regions must populate them on first paint."
                        .to_string(),
                );
            }
            if html_references_missing_dom_ids(&lower) {
                return Err(
                    "HTML iframe artifacts must not target missing DOM ids from their surfaced controls or scripts."
                        .to_string(),
                );
            }
            if html_interactions_are_navigation_only(&lower) {
                return Err(
                    "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log."
                        .to_string(),
                );
            }
            if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && !contains_html_interaction_hooks(&lower)
            {
                return Err(
                    "Interactive HTML iframe artifacts must contain real interactive controls or handlers."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::JsxSandbox => {
            if !(primary_file.path.ends_with(".jsx") || primary_file.path.ends_with(".tsx")) {
                return Err("JSX sandbox artifacts must end with .jsx or .tsx.".to_string());
            }
            if !primary_file.renderable {
                return Err("JSX sandbox artifacts must be renderable.".to_string());
            }
            if !(primary_file.body.contains("export default")
                || primary_file.body.contains("return ("))
            {
                return Err(
                    "JSX sandbox artifacts must contain a default export or renderable component."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::Svg => {
            validate_exact_primary_file(primary_file, ".svg", "image/svg+xml", true)?;
            if !primary_file.body.contains("<svg") {
                return Err("SVG artifacts must contain an <svg element.".to_string());
            }
        }
        StudioRendererKind::Mermaid => {
            if !primary_file.path.ends_with(".mermaid") && !primary_file.path.ends_with(".mmd") {
                return Err("Mermaid artifacts must end with .mermaid or .mmd.".to_string());
            }
            if !primary_file.renderable {
                return Err("Mermaid artifacts must be renderable.".to_string());
            }
        }
        StudioRendererKind::PdfEmbed => {
            validate_exact_primary_file(primary_file, ".pdf", "application/pdf", true)?;
            if let Some(failure) = pdf_source_contract_failure(&primary_file.body) {
                return Err(failure.to_string());
            }
        }
        StudioRendererKind::DownloadCard => {
            if payload.files.iter().any(|file| file.renderable) {
                return Err(
                    "Download-card artifacts must not mark files as renderable.".to_string()
                );
            }
        }
        StudioRendererKind::BundleManifest => {
            if !primary_file.path.ends_with(".json") {
                return Err(
                    "Bundle-manifest artifacts must include a primary .json file.".to_string(),
                );
            }
            if serde_json::from_str::<serde_json::Value>(&primary_file.body).is_err() {
                return Err("Bundle-manifest primary file must contain valid JSON.".to_string());
            }
            if !matches!(
                request.artifact_class,
                StudioArtifactClass::CompoundBundle | StudioArtifactClass::ReportBundle
            ) {
                return Err(
                    "bundle_manifest renderer requires compound_bundle or report_bundle."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::WorkspaceSurface => {}
    }

    Ok(())
}

pub(crate) fn parse_and_validate_generated_artifact_payload(
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let mut generated = parse_studio_generated_artifact_payload(raw)?;
    normalize_generated_artifact_file_paths(&mut generated, request);
    normalize_generated_artifact_payload(&mut generated, request);
    if let Err(error) = validate_generated_artifact_payload(&generated, request) {
        if studio_artifact_soft_validation_error(&error) {
            generated.notes.push(format!("soft validation: {error}"));
        } else {
            return Err(error);
        }
    }
    Ok(generated)
}

pub(crate) fn validate_generated_artifact_payload_against_brief(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> Result<(), String> {
    validate_generated_artifact_payload_against_brief_with_edit_intent(
        payload, request, brief, None,
    )
}

pub(crate) fn validate_generated_artifact_payload_against_brief_with_edit_intent(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> Result<(), String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return Ok(());
    }

    let Some(primary_file) = payload.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    }) else {
        return Ok(());
    };
    let lower = primary_file.body.to_ascii_lowercase();
    let detail_regions = count_populated_html_detail_regions(&lower);
    let chart_regions = count_populated_html_chart_regions(&lower);
    let evidence_regions = count_populated_html_evidence_regions(&lower);
    let selection_scoped_patch = edit_intent.is_some_and(|intent| {
        intent.patch_existing_artifact && !intent.selected_targets.is_empty()
    });
    let has_chart_surface = chart_regions > 0
        || count_html_svg_regions(&lower) > 0
        || html_contains_empty_chart_container_regions(&lower);

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && !brief.required_interactions.is_empty()
        && detail_regions == 0
    {
        return Err(
            "HTML iframe briefs with required interactions must include a populated shared detail or comparison region on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && html_has_static_view_mapping_markers(&lower)
        && !html_contains_view_switching_control_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must wire controls to change panel visibility or selection state on click."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && !html_contains_explicit_view_mapping(&lower)
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must map at least two controls to pre-rendered view panels with explicit static selectors."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && count_empty_html_mapped_view_panels(&lower) > 0
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must keep every mapped evidence panel pre-rendered with first-paint content."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && !html_has_visible_populated_mapped_view_panel(&lower)
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must keep one populated mapped evidence panel visible on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && count_html_rollover_detail_marks(&lower) < 3
    {
        return Err(
            "HTML iframe briefs that call for rollover detail must surface at least three visible data-detail marks or cards on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && !html_contains_rollover_detail_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for rollover detail must wire hover or focus handlers on visible marks to update shared detail on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && has_chart_surface
        && brief.required_interactions.len() >= 2
        && evidence_regions < 2
        && !selection_scoped_patch
    {
        return Err(
            "HTML iframe briefs with charted evidence must surface at least two populated evidence views on first paint."
                .to_string(),
        );
    }

    Ok(())
}

fn studio_artifact_soft_validation_error(error: &str) -> bool {
    [
        "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint.",
        "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint.",
        "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint.",
        "HTML iframe artifacts must contain at least three sectioning elements with first-paint content.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

pub(crate) fn normalize_generated_artifact_payload(
    payload: &mut StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    primary_html.body = strip_html_comments(&primary_html.body);
    primary_html.body = normalize_html_semantic_structure(&primary_html.body);
    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile {
        primary_html.body = normalize_html_interactions(&primary_html.body);
    }
}

fn normalize_generated_artifact_file_paths(
    payload: &mut StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) {
    for file in &mut payload.files {
        file.mime = normalize_generated_artifact_file_mime(&file.mime);
        file.path =
            normalize_generated_artifact_file_path(&file.path, request.renderer, &file.mime);
    }
}

fn normalize_generated_artifact_file_mime(mime: &str) -> String {
    let trimmed = mime.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }

    let canonical = trimmed
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or(trimmed)
        .to_ascii_lowercase();

    match canonical.as_str() {
        "text/html" => "text/html".to_string(),
        "text/markdown" => "text/markdown".to_string(),
        "image/svg+xml" => "image/svg+xml".to_string(),
        "application/pdf" => "application/pdf".to_string(),
        _ => canonical,
    }
}

fn normalize_generated_artifact_file_path(
    path: &str,
    renderer: StudioRendererKind,
    mime: &str,
) -> String {
    let normalized = path.replace('\\', "/");
    let segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
        .collect::<Vec<_>>();
    let candidate = if segments.is_empty() {
        default_generated_artifact_file_path(renderer, mime)
    } else {
        segments.join("/")
    };
    if candidate.trim().is_empty() {
        default_generated_artifact_file_path(renderer, mime)
    } else {
        candidate
    }
}

fn default_generated_artifact_file_path(renderer: StudioRendererKind, mime: &str) -> String {
    match renderer {
        StudioRendererKind::Markdown => "artifact.md".to_string(),
        StudioRendererKind::HtmlIframe => "index.html".to_string(),
        StudioRendererKind::JsxSandbox => "artifact.jsx".to_string(),
        StudioRendererKind::Svg => "artifact.svg".to_string(),
        StudioRendererKind::Mermaid => "diagram.mermaid".to_string(),
        StudioRendererKind::PdfEmbed => "artifact.pdf".to_string(),
        StudioRendererKind::BundleManifest => "bundle-manifest.json".to_string(),
        StudioRendererKind::DownloadCard => {
            if mime.eq_ignore_ascii_case("application/pdf") {
                "download.pdf".to_string()
            } else {
                "download.bin".to_string()
            }
        }
        StudioRendererKind::WorkspaceSurface => "artifact".to_string(),
    }
}

pub(crate) fn enrich_generated_artifact_payload(
    payload: &mut StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) {
    match request.renderer {
        StudioRendererKind::Svg => {
            let Some(primary_svg) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
                ) && (file.mime == "image/svg+xml" || file.path.ends_with(".svg"))
            }) else {
                return;
            };

            primary_svg.body = ensure_svg_accessibility_metadata(&primary_svg.body, brief);
        }
        StudioRendererKind::HtmlIframe => {
            let Some(primary_html) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
                ) && (file.mime == "text/html" || file.path.ends_with(".html"))
            }) else {
                return;
            };

            primary_html.body =
                ensure_minimum_brief_rollover_detail_marks(&primary_html.body, brief);
            primary_html.body = ensure_html_rollover_detail_contract(&primary_html.body);
        }
        _ => {}
    }
}

fn renderer_primary_view_contract_failure(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate: &StudioGeneratedArtifactPayload,
) -> Option<&'static str> {
    let primary_file = candidate.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    })?;

    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            let lower = primary_file.body.to_ascii_lowercase();
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                Some("HTML sectioning regions are empty shells on first paint.")
            } else if html_contains_placeholder_markers(&lower) {
                Some("HTML still contains placeholder-grade copy or comments on first paint.")
            } else if html_interactions_are_navigation_only(&lower) {
                Some("HTML interactions are navigation-only and do not update shared detail state.")
            } else if html_contains_empty_chart_container_regions(&lower) {
                Some("HTML chart containers are empty placeholder shells on first paint.")
            } else if html_contains_empty_detail_regions(&lower) {
                Some("HTML shared detail or comparison regions are empty on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && html_has_static_view_mapping_markers(&lower)
                && !html_contains_view_switching_control_behavior(&lower)
            {
                Some(
                    "HTML clickable navigation renders mapped panels but does not change panel visibility or selection state."
                )
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && !html_contains_explicit_view_mapping(&lower)
            {
                Some("HTML clickable navigation does not map controls to pre-rendered views.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && count_empty_html_mapped_view_panels(&lower) > 0
            {
                Some("HTML clickable navigation maps controls to empty pre-rendered panels.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && !html_has_visible_populated_mapped_view_panel(&lower)
            {
                Some(
                    "HTML clickable navigation does not keep a populated mapped evidence panel visible on first paint."
                )
            } else if html_contains_unlabeled_chart_svg_regions(&lower) {
                Some("HTML chart SVG regions are unlabeled on first paint.")
            } else if html_contains_placeholder_svg_regions(&lower) {
                Some("HTML chart regions are empty placeholder shells on first paint.")
            } else if html_references_missing_dom_ids(&lower) {
                Some("HTML interactions target missing DOM ids in the surfaced artifact.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && !brief.required_interactions.is_empty()
                && count_populated_html_detail_regions(&lower) == 0
            {
                Some("HTML required interactions do not surface a shared detail panel on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && (count_populated_html_chart_regions(&lower) > 0
                    || count_html_svg_regions(&lower) > 0
                    || html_contains_empty_chart_container_regions(&lower))
                && brief.required_interactions.len() >= 2
                && count_populated_html_chart_regions(&lower)
                    + count_populated_html_detail_regions(&lower)
                    < 2
            {
                Some("HTML only surfaces one evidence view on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief.required_interactions.iter().any(|interaction| {
                    let lower = interaction.to_ascii_lowercase();
                    lower.contains("rollover") || lower.contains("hover")
                })
                && count_html_rollover_detail_marks(&lower) < 3
            {
                Some("HTML only surfaces sparse rollover detail targets on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief.required_interactions.iter().any(|interaction| {
                    let lower = interaction.to_ascii_lowercase();
                    lower.contains("rollover") || lower.contains("hover")
                })
                && !html_contains_rollover_detail_behavior(&lower)
            {
                Some("HTML lacks hover or focus detail behavior for rollover interactions.")
            } else {
                None
            }
        }
        StudioRendererKind::Svg => svg_primary_view_contract_failure(&primary_file.body),
        StudioRendererKind::PdfEmbed => pdf_source_contract_failure(&primary_file.body),
        _ => None,
    }
}

pub(crate) fn enforce_renderer_judge_contract(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate: &StudioGeneratedArtifactPayload,
    mut judge: StudioArtifactJudgeResult,
) -> StudioArtifactJudgeResult {
    neutralize_false_sequence_browsing_penalty(brief, &mut judge);

    let Some(contradiction) = renderer_primary_view_contract_failure(request, brief, candidate)
    else {
        return judge;
    };

    if judge.classification != StudioArtifactJudgeClassification::Blocked {
        judge.classification = StudioArtifactJudgeClassification::Repairable;
    }
    judge.interaction_relevance = judge.interaction_relevance.min(2);
    judge.layout_coherence = judge.layout_coherence.min(2);
    judge.visual_hierarchy = judge.visual_hierarchy.min(2);
    judge.completeness = judge.completeness.min(2);
    judge.trivial_shell_detected = true;
    judge.deserves_primary_artifact_view = false;
    judge.strongest_contradiction = Some(contradiction.to_string());
    judge.rationale =
        "Renderer contract failures keep the first paint from qualifying as primary output."
            .to_string();
    judge
}

fn neutralize_false_sequence_browsing_penalty(
    brief: &StudioArtifactBrief,
    judge: &mut StudioArtifactJudgeResult,
) {
    if brief_requires_sequence_browsing(brief)
        || !judge_false_positive_sequence_penalty(judge)
        || judge.generic_shell_detected
        || judge.trivial_shell_detected
        || !judge.deserves_primary_artifact_view
        || judge.request_faithfulness < 4
        || judge.concept_coverage < 4
        || judge.layout_coherence < 4
        || judge.visual_hierarchy < 4
    {
        return;
    }

    judge.classification = StudioArtifactJudgeClassification::Pass;
    judge.interaction_relevance = judge.interaction_relevance.max(4);
    judge.completeness = judge.completeness.max(4);
    judge.strongest_contradiction = None;
    if judge
        .rationale
        .to_ascii_lowercase()
        .contains("sequence browsing")
        || judge.rationale.to_ascii_lowercase().contains("timeline")
    {
        judge.rationale =
            "Complies with the interaction contract and stays request-faithful.".to_string();
    }
}

fn pdf_source_contract_failure(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    let words = artifact_word_count(body);
    let sections = count_pdf_structural_sections(body);

    if lower.contains("\\documentclass")
        || lower.contains("\\begin{document}")
        || lower.contains("\\section")
        || lower.contains("\\usepackage")
    {
        Some("PDF source content must be plain document text, not LaTeX source.")
    } else if bracket_placeholder_hits(body) > 0 {
        Some("PDF source content must not contain bracketed placeholder copy.")
    } else if words < 90 {
        Some("PDF source content is too short to lead the artifact stage.")
    } else if sections < 4 {
        Some("PDF source content needs clearer sections before it can lead the artifact stage.")
    } else {
        None
    }
}

fn svg_primary_view_contract_failure(body: &str) -> Option<&'static str> {
    if count_svg_primary_marks(body) < 6 {
        Some("SVG output is too sparse to stand as the primary visual artifact.")
    } else {
        None
    }
}

fn count_svg_primary_marks(body: &str) -> usize {
    let lower = body.to_ascii_lowercase();
    [
        "<path",
        "<rect",
        "<circle",
        "<ellipse",
        "<polygon",
        "<polyline",
        "<line",
        "<text",
    ]
    .iter()
    .map(|needle| lower.matches(needle).count())
    .sum()
}

fn artifact_word_count(text: &str) -> usize {
    text.split_whitespace()
        .filter(|word| !word.trim().is_empty())
        .count()
}

fn bracket_placeholder_hits(text: &str) -> usize {
    let mut hits = 0usize;
    let mut cursor = 0usize;

    while let Some(relative_start) = text[cursor..].find('[') {
        let start = cursor + relative_start;
        let Some(relative_end) = text[start + 1..].find(']') else {
            break;
        };
        let end = start + 1 + relative_end;
        let next_char = text[end + 1..].chars().next();
        let candidate = text[start + 1..end].trim();

        if next_char != Some('(')
            && candidate.split_whitespace().count() >= 2
            && candidate.chars().any(|ch| ch.is_ascii_alphabetic())
        {
            hits += 1;
        }

        cursor = end + 1;
    }

    hits
}

fn judge_false_positive_sequence_penalty(judge: &StudioArtifactJudgeResult) -> bool {
    let contradiction = judge
        .strongest_contradiction
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rationale = judge.rationale.to_ascii_lowercase();
    [contradiction.as_str(), rationale.as_str()]
        .iter()
        .any(|text| {
            text.contains("sequence browsing")
                || text.contains("timeline traversal")
                || text.contains("scrolling through staged evidence")
                || text.contains("progression mechanism")
                || text.contains("timeline")
        })
}

fn validate_exact_primary_file(
    file: &StudioGeneratedArtifactFile,
    extension: &str,
    mime: &str,
    renderable: bool,
) -> Result<(), String> {
    if !file.path.ends_with(extension) {
        return Err(format!(
            "Primary artifact file '{}' must end with '{}'.",
            file.path, extension
        ));
    }
    if file.mime != mime {
        return Err(format!(
            "Primary artifact file '{}' must use mime '{}'.",
            file.path, mime
        ));
    }
    if file.renderable != renderable {
        return Err(format!(
            "Primary artifact file '{}' renderable must be {}.",
            file.path, renderable
        ));
    }
    Ok(())
}

pub(crate) fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                return Some(raw[start..start + idx + 1].to_string());
            }
        }
    }
    None
}
