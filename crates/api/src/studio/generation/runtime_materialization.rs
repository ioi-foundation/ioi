use super::*;
use crate::studio::payload::{
    extract_authored_document_body, renderer_primary_view_contract_failure,
    synthesize_generated_artifact_payload_from_raw_document,
};
use ioi_types::error::VmError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum StudioDirectAuthorRecoveryMode {
    Suffix,
    FullDocument,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StudioDirectAuthorRecoveryPayload {
    mode: StudioDirectAuthorRecoveryMode,
    content: String,
}

fn parse_studio_direct_author_recovery_payload(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> Result<StudioDirectAuthorRecoveryPayload, String> {
    let parse_json =
        |candidate: &str| -> Result<StudioDirectAuthorRecoveryPayload, serde_json::Error> {
            serde_json::from_str(candidate)
        };

    let payload = match parse_json(raw).or_else(|_| {
        let extracted = super::extract_first_json_object(raw).ok_or_else(|| {
            "Studio direct-author recovery output missing JSON payload".to_string()
        })?;
        parse_json(&extracted).map_err(|error| error.to_string())
    }) {
        Ok(payload) => payload,
        Err(error) => coerce_direct_author_recovery_payload_from_raw_output(request, raw)
            .ok_or_else(|| {
                format!("Failed to parse Studio direct-author recovery payload: {error}")
            })?,
    };

    if payload.content.trim().is_empty() {
        return Err("Studio direct-author recovery payload content was empty".to_string());
    }

    Ok(payload)
}

fn coerce_direct_author_recovery_payload_from_raw_output(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> Option<StudioDirectAuthorRecoveryPayload> {
    let raw_document = strip_single_markdown_code_fence(raw).unwrap_or(raw).trim();
    if raw_document.is_empty() {
        return None;
    }

    if !direct_author_uses_raw_document(request) {
        return None;
    }

    let content = if let Some(extracted_document) =
        extract_authored_document_body(raw_document, request.renderer)
    {
        if request.renderer == StudioRendererKind::HtmlIframe {
            direct_author_renderable_html_prefix(request, &extracted_document)
                .unwrap_or(extracted_document)
        } else {
            extracted_document
        }
    } else {
        raw_document.to_string()
    };

    let mode = if content.len() != raw_document.len()
        || matches!(
            request.renderer,
            StudioRendererKind::Markdown
                | StudioRendererKind::Mermaid
                | StudioRendererKind::PdfEmbed
        )
        || matches!(request.renderer, StudioRendererKind::HtmlIframe)
            && content.to_ascii_lowercase().contains("<html")
        || matches!(request.renderer, StudioRendererKind::Svg)
            && content.to_ascii_lowercase().contains("<svg")
    {
        StudioDirectAuthorRecoveryMode::FullDocument
    } else {
        StudioDirectAuthorRecoveryMode::Suffix
    };

    if mode == StudioDirectAuthorRecoveryMode::FullDocument && content.len() != raw_document.len() {
        studio_generation_trace(format!(
            "artifact_generation:direct_author_recovery:extracted_full_document renderer={:?} raw_bytes={} extracted_bytes={}",
            request.renderer,
            raw_document.len(),
            content.len()
        ));
    }

    Some(StudioDirectAuthorRecoveryPayload { mode, content })
}

fn strip_single_markdown_code_fence(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("```") {
        return None;
    }

    let first_newline = trimmed.find('\n')?;
    let remainder = &trimmed[first_newline + 1..];
    let closing_fence = remainder.rfind("```")?;
    let suffix = remainder[closing_fence + 3..].trim();
    if !suffix.is_empty() {
        return None;
    }

    Some(remainder[..closing_fence].trim())
}

fn apply_direct_author_recovery_payload(
    existing_document: &str,
    payload: &StudioDirectAuthorRecoveryPayload,
) -> String {
    match payload.mode {
        StudioDirectAuthorRecoveryMode::Suffix => {
            merge_direct_author_document(existing_document, &payload.content)
        }
        StudioDirectAuthorRecoveryMode::FullDocument => payload.content.clone(),
    }
}

fn emit_direct_author_live_preview(
    observer: Option<&StudioArtifactLivePreviewObserver>,
    preview_id: &str,
    preview_label: &str,
    preview_language: &Option<String>,
    status: &str,
    raw: &str,
    is_final: bool,
) {
    let preview_content = live_token_stream_preview_text(raw, 2200);
    if preview_content.trim().is_empty() {
        return;
    }

    if let Some(observer) = observer {
        observer(studio_swarm_live_preview(
            preview_id.to_string(),
            ExecutionLivePreviewKind::TokenStream,
            preview_label.to_string(),
            None,
            None,
            status,
            preview_language.clone(),
            preview_content,
            is_final,
        ));
    }
}

fn direct_author_recovery_mode_label(mode: &StudioDirectAuthorRecoveryMode) -> &'static str {
    match mode {
        StudioDirectAuthorRecoveryMode::Suffix => "suffix",
        StudioDirectAuthorRecoveryMode::FullDocument => "full_document",
    }
}

fn local_runner_unexpected_stop_error(error: &str) -> bool {
    error
        .to_ascii_lowercase()
        .contains("model runner has unexpectedly stopped")
}

fn materialization_retry_options(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    options: &InferenceOptions,
) -> InferenceOptions {
    if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && options.max_tokens > 2200
    {
        let mut reduced = options.clone();
        reduced.max_tokens = 2200;
        return reduced;
    }

    options.clone()
}

fn should_skip_direct_author_continuation(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    raw: &str,
    error_message: &str,
) -> bool {
    if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && request.artifact_class == StudioArtifactClass::Document
        && direct_author_uses_raw_document(request)
    {
        return direct_author_has_completion_boundary(request, raw);
    }

    if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && direct_author_uses_raw_document(request)
        && (direct_author_local_html_interaction_failure(error_message)
            || direct_author_local_html_semantic_underbuild_failure(error_message)
            || direct_author_local_html_interaction_truth_failure(error_message))
    {
        return true;
    }

    if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && direct_author_uses_raw_document(request)
        && direct_author_document_is_incomplete(request, raw, error_message)
    {
        return direct_author_has_stream_settle_boundary(request, raw)
            && (raw.len() >= 6000
                || (raw.to_ascii_lowercase().contains("<main")
                    && count_html_nonempty_sectioning_elements(&raw.to_ascii_lowercase()) >= 3));
    }
    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != StudioRendererKind::HtmlIframe
        || !direct_author_document_is_incomplete(request, raw, error_message)
    {
        return false;
    }

    let lower = raw.to_ascii_lowercase();
    if !direct_author_has_completion_boundary(request, raw)
        && lower.contains("<main")
        && (count_html_actionable_affordances(&lower) >= 2
            || count_html_nonempty_sectioning_elements(&lower) >= 3)
    {
        return false;
    }

    raw.len() >= 6000
        || (lower.contains("<main") && count_html_nonempty_sectioning_elements(&lower) >= 3)
}

#[cfg(test)]
mod tests {
    use super::should_skip_direct_author_continuation;
    use super::*;
    use ioi_types::app::{
        StudioArtifactDeliverableShape, StudioArtifactPersistenceMode, StudioOutcomeArtifactScope,
        StudioOutcomeArtifactVerificationRequest,
    };

    fn sample_html_document_request() -> StudioOutcomeArtifactRequest {
        StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::Document,
            deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
            renderer: StudioRendererKind::HtmlIframe,
            presentation_surface: StudioPresentationSurface::SidePanel,
            persistence: StudioArtifactPersistenceMode::ArtifactScoped,
            execution_substrate: StudioExecutionSubstrate::ClientSandbox,
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: StudioOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: false,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: StudioOutcomeArtifactVerificationRequest {
                require_render: false,
                require_build: false,
                require_preview: false,
                require_export: false,
                require_diff_review: false,
            },
        }
    }

    #[test]
    fn local_document_html_with_boundary_skips_continuation() {
        let request = sample_html_document_request();
        let raw = "<!doctype html><html><body><main><section><h1>Quantum</h1></section></main></body></html>";
        let error = "HTML iframe artifacts must contain a closed <main> region.";

        assert!(should_skip_direct_author_continuation(
            &request,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            raw,
            error,
        ));
    }

    #[test]
    fn local_document_html_without_boundary_keeps_continuation_available() {
        let request = sample_html_document_request();
        let raw = "<!doctype html><html><body><main><section><h1>Quantum</h1><p>Explain qubits and superposition.";
        let error =
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.";

        assert!(!should_skip_direct_author_continuation(
            &request,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            raw,
            error,
        ));
    }
}

fn direct_author_has_stream_settle_boundary(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> bool {
    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            let lower = raw.to_ascii_lowercase();
            lower.contains("</body>")
                || lower.contains("</html>")
                || (lower.contains("</main>")
                    && count_html_nonempty_sectioning_elements(&lower) >= 2
                    && count_html_actionable_affordances(&lower) >= 1
                    && (request.artifact_class != StudioArtifactClass::InteractiveSingleFile
                        || contains_html_interaction_hooks(&lower)
                        || count_populated_html_detail_regions(&lower) >= 1
                        || count_populated_html_response_regions(&lower) >= 1))
        }
        _ => direct_author_has_completion_boundary(request, raw),
    }
}

fn direct_author_renderable_html_prefix(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }

    let lower = raw.to_ascii_lowercase();
    for boundary in ["</html>", "</body>", "</script>", "</main>"] {
        let Some(index) = lower.rfind(boundary) else {
            continue;
        };
        let candidate = raw[..index + boundary.len()].trim_end();
        if direct_author_has_stream_settle_boundary(request, candidate)
            && !direct_author_document_is_incomplete(request, candidate, "")
        {
            return Some(candidate.to_string());
        }
    }

    None
}

fn direct_author_preview_ready_document(request: &StudioOutcomeArtifactRequest, raw: &str) -> bool {
    if request.renderer != StudioRendererKind::HtmlIframe
        || request.artifact_class != StudioArtifactClass::Document
    {
        return false;
    }

    let lower = raw.to_ascii_lowercase();
    if !(lower.contains("<!doctype html") || lower.contains("<html")) || raw.len() < 1400 {
        return false;
    }

    let sectioning_regions = count_html_nonempty_sectioning_elements(&lower);
    let heading_count = ["<h1", "<h2", "<h3", "<h4"]
        .iter()
        .map(|tag| lower.matches(tag).count())
        .sum::<usize>();
    let body_copy_blocks = ["<p", "<li", "<td", "<figcaption", "<blockquote"]
        .iter()
        .map(|tag| lower.matches(tag).count())
        .sum::<usize>();
    let evidence_blocks = ["<table", "<svg", "<canvas", "<figure", "<dl"]
        .iter()
        .map(|tag| lower.matches(tag).count())
        .sum::<usize>();
    let authored_regions = sectioning_regions + lower.matches("<div class=").count().min(6);

    (lower.contains("<main") && sectioning_regions >= 1 && body_copy_blocks >= 2)
        || (heading_count >= 2 && body_copy_blocks >= 3 && authored_regions >= 2)
        || (heading_count >= 2 && body_copy_blocks >= 2 && evidence_blocks >= 1)
}

fn direct_author_completed_document_prefix(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    let boundary = direct_author_completion_boundary(request)?;
    let lower_raw = raw.to_ascii_lowercase();
    let lower_boundary = boundary.to_ascii_lowercase();
    let boundary_index = lower_raw.find(&lower_boundary)?;
    Some(raw[..boundary_index + boundary.len()].to_string())
}

fn direct_author_stream_settle_snapshot(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    direct_author_completed_document_prefix(request, raw)
        .or_else(|| direct_author_renderable_html_prefix(request, raw))
        .or_else(|| direct_author_has_stream_settle_boundary(request, raw).then(|| raw.to_string()))
}

fn direct_author_idle_settle_snapshot(request: &StudioOutcomeArtifactRequest, raw: &str) -> String {
    if let Some(completed) = direct_author_completed_document_prefix(request, raw)
        .or_else(|| direct_author_renderable_html_prefix(request, raw))
    {
        return completed.trim_end().to_string();
    }

    raw.trim_end().to_string()
}

fn direct_author_can_fast_finish_on_idle_snapshot(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> bool {
    match request.renderer {
        StudioRendererKind::HtmlIframe => !direct_author_document_is_incomplete(request, raw, ""),
        _ => direct_author_has_stream_settle_boundary(request, raw),
    }
}

fn direct_author_html_contract_debug_suffix(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }

    let lower = raw.to_ascii_lowercase();
    Some(format!(
        " html_debug hooks={} actionable={} stateful={} transitions={} response_regions={} detail_regions={} view_panels={} stage_sections={}",
        contains_html_interaction_hooks(&lower),
        count_html_actionable_affordances(&lower),
        html_contains_stateful_interaction_behavior(&lower),
        html_contains_state_transition_behavior(&lower),
        count_populated_html_response_regions(&lower),
        count_populated_html_detail_regions(&lower),
        lower.matches("data-view-panel=").count(),
        lower.matches("id=\"stage-").count()
            + lower.matches("id='stage-").count()
            + lower.matches("id=\"stage_").count()
            + lower.matches("id='stage_").count(),
    ))
}

fn direct_author_local_html_interaction_failure(error_message: &str) -> bool {
    [
        "Interactive HTML iframe artifacts must contain real interactive controls or handlers.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
        "HTML iframe briefs that call for state switching must surface at least two actionable controls on first paint.",
        "HTML iframe briefs that call for state switching must include view-switch controls wired to pre-rendered panels or a shared detail region.",
    ]
    .iter()
    .any(|needle| error_message.contains(needle))
}

fn direct_author_local_html_semantic_underbuild_failure(error_message: &str) -> bool {
    [
        "HTML sectioning regions are empty shells on first paint.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
        "HTML state switching does not keep enough authored evidence surfaces available on first paint.",
        "HTML state switching does not wire controls to produce visible state changes.",
        "HTML multi-step interaction briefs must surface at least two actionable controls on first paint.",
        "HTML only surfaces sparse inspection affordances on first paint.",
        "HTML lacks hover, focus, or equivalent inspection behavior for the requested detail interactions.",
        "HTML required interactions do not surface a visible response region on first paint.",
    ]
    .iter()
    .any(|needle| error_message.contains(needle))
}

fn direct_author_should_continue_semantically_underbuilt_document(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    raw: &str,
    error_message: &str,
    _recovered_from_partial_stream: bool,
) -> bool {
    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != StudioRendererKind::HtmlIframe
        || request.artifact_class != StudioArtifactClass::InteractiveSingleFile
        || !direct_author_uses_raw_document(request)
        || !direct_author_local_html_semantic_underbuild_failure(error_message)
    {
        return false;
    }

    let lower = raw.to_ascii_lowercase();
    (lower.contains("<main") || count_html_nonempty_sectioning_elements(&lower) >= 2)
        && (contains_html_interaction_hooks(&lower)
            || count_html_actionable_affordances(&lower) >= 2
            || count_populated_html_detail_regions(&lower) >= 1
            || count_populated_html_response_regions(&lower) >= 1)
}

fn direct_author_local_html_interaction_truth_failure(error_message: &str) -> bool {
    [
        "Surfaced controls executed without runtime errors or no-op behavior.",
        "At least one surfaced interaction produced a meaningful visible state change.",
        "A visible response or explanation region remains present during interaction.",
        "did not change visible artifact state.",
    ]
    .iter()
    .any(|needle| error_message.contains(needle))
}

fn direct_author_local_html_structural_failure(error_message: &str) -> bool {
    [
        "HTML iframe artifacts must contain a fully closed </body></html> document.",
        "HTML iframe artifacts must contain a closed <main> region.",
        "HTML iframe artifacts must not end with an unfinished tag or trailing fragment.",
        "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
    ]
    .iter()
    .any(|needle| error_message.contains(needle))
}

fn html_document_content_start(lower: &str, tag: &str) -> Option<usize> {
    let start = lower.find(tag)?;
    let tag_end = lower[start..].find('>')?;
    Some(start + tag_end + 1)
}

fn insert_html_snippet_at(document: &str, index: usize, snippet: &str) -> String {
    let safe_index = index.min(document.len());
    let mut repaired = String::with_capacity(document.len() + snippet.len());
    repaired.push_str(&document[..safe_index]);
    repaired.push_str(snippet);
    repaired.push_str(&document[safe_index..]);
    repaired
}

fn local_html_structural_rescue_candidates(document: &str) -> Vec<(&'static str, String)> {
    let normalized = normalize_html_terminal_closure(document);
    let lower = normalized.to_ascii_lowercase();
    let content_start = html_document_content_start(&lower, "<main")
        .or_else(|| html_document_content_start(&lower, "<body"))
        .unwrap_or(0);
    let mut trim_points = Vec::<(usize, &'static str)>::new();
    let trim_markers = [
        ("</script>", "trim_after_script"),
        ("</section>", "trim_after_section"),
        ("</article>", "trim_after_article"),
        ("</aside>", "trim_after_aside"),
        ("</nav>", "trim_after_nav"),
        ("</footer>", "trim_after_footer"),
        ("</figure>", "trim_after_figure"),
        ("</figcaption>", "trim_after_figcaption"),
        ("</table>", "trim_after_table"),
        ("</tbody>", "trim_after_tbody"),
        ("</thead>", "trim_after_thead"),
        ("</tr>", "trim_after_row"),
        ("</ul>", "trim_after_list"),
        ("</ol>", "trim_after_ordered_list"),
        ("</li>", "trim_after_item"),
        ("</div>", "trim_after_div"),
        ("</p>", "trim_after_paragraph"),
        ("</main>", "trim_after_main"),
    ];

    for (marker, label) in trim_markers {
        let mut search_from = content_start;
        while let Some(relative) = lower[search_from..].find(marker) {
            let end = search_from + relative + marker.len();
            trim_points.push((end, label));
            search_from = end;
        }
    }

    trim_points.sort_by(|left, right| right.0.cmp(&left.0));
    trim_points.dedup_by(|left, right| left.0 == right.0);

    let mut candidates = Vec::new();
    for (end, label) in trim_points.into_iter().take(8) {
        let trimmed = normalized[..end].trim_end();
        if trimmed.len() <= content_start {
            continue;
        }
        let repaired = normalize_html_terminal_closure(trimmed);
        if repaired != normalized {
            candidates.push((label, repaired));
        }
    }

    candidates
}

fn insert_html_snippet_before_close(document: &str, closing_tag: &str, snippet: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let closing_lower = closing_tag.to_ascii_lowercase();
    if let Some(index) = lower.rfind(&closing_lower) {
        let mut updated = document.to_string();
        updated.insert_str(index, snippet);
        updated
    } else {
        format!("{document}{snippet}")
    }
}

fn strip_inline_event_handler_attributes(document: &str) -> String {
    [
        "onclick",
        "onchange",
        "oninput",
        "onmouseover",
        "onmouseenter",
        "onfocus",
        "onkeydown",
    ]
    .iter()
    .fold(document.to_string(), |current, attribute| {
        strip_single_inline_event_handler_attribute(&current, attribute)
    })
}

fn strip_single_inline_event_handler_attribute(document: &str, attribute: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let pattern = format!("{attribute}=");
    let bytes = lower.as_bytes();
    let mut cursor = 0usize;
    let mut output = String::with_capacity(document.len());

    while let Some(relative) = lower[cursor..].find(&pattern) {
        let attribute_index = cursor + relative;
        let leading_whitespace_index = attribute_index.saturating_sub(1);
        let starts_attribute = attribute_index == 0
            || bytes
                .get(leading_whitespace_index)
                .is_some_and(|byte| byte.is_ascii_whitespace());
        if !starts_attribute {
            output.push_str(&document[cursor..attribute_index + pattern.len()]);
            cursor = attribute_index + pattern.len();
            continue;
        }

        output.push_str(&document[cursor..leading_whitespace_index]);
        let value_start = attribute_index + pattern.len();
        let Some(value_first) = bytes.get(value_start).copied() else {
            cursor = document.len();
            break;
        };
        let next_cursor = if value_first == b'"' || value_first == b'\'' {
            let mut end = value_start + 1;
            while let Some(candidate) = bytes.get(end) {
                if *candidate == value_first {
                    end += 1;
                    break;
                }
                end += 1;
            }
            end
        } else {
            let mut end = value_start;
            while let Some(candidate) = bytes.get(end) {
                if candidate.is_ascii_whitespace() || *candidate == b'>' {
                    break;
                }
                end += 1;
            }
            end
        };
        cursor = next_cursor;
    }

    output.push_str(&document[cursor..]);
    output
}

fn strip_inline_script_blocks(document: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut output = String::with_capacity(document.len());

    while let Some(relative_start) = lower[cursor..].find("<script") {
        let start = cursor + relative_start;
        output.push_str(&document[cursor..start]);
        let Some(open_end) = lower[start..].find('>') else {
            cursor = document.len();
            break;
        };
        let content_start = start + open_end + 1;
        let Some(relative_close) = lower[content_start..].find("</script>") else {
            cursor = document.len();
            break;
        };
        cursor = content_start + relative_close + "</script>".len();
    }

    output.push_str(&document[cursor..]);
    output
}

fn html_has_live_response_region_markup(lower: &str) -> bool {
    lower.contains("<aside")
        || lower.contains("aria-live=")
        || lower.contains("role=\"status\"")
        || lower.contains("role='status'")
        || lower.contains("role=\"region\"")
        || lower.contains("role='region'")
        || lower.contains("role=\"alert\"")
        || lower.contains("role='alert'")
}

fn ensure_response_region_markup(document: &str, target_ids: &[&str]) -> String {
    let lower = document.to_ascii_lowercase();
    if html_has_live_response_region_markup(&lower) {
        return document.to_string();
    }

    for id in target_ids {
        for pattern in [format!("id=\"{id}\""), format!("id='{id}'")] {
            let Some(id_index) = lower.find(&pattern) else {
                continue;
            };
            let Some(tag_start) = lower[..id_index].rfind('<') else {
                continue;
            };
            let Some(relative_tag_end) = lower[id_index..].find('>') else {
                continue;
            };
            let tag_end = id_index + relative_tag_end;
            let open_tag_lower = &lower[tag_start..tag_end];
            let has_role = open_tag_lower.contains("role=");
            let has_aria_live = open_tag_lower.contains("aria-live=");
            if has_role && has_aria_live {
                return document.to_string();
            }

            let mut attrs = String::new();
            if !has_role {
                attrs.push_str(" role=\"status\"");
            }
            if !has_aria_live {
                attrs.push_str(" aria-live=\"polite\"");
            }
            let mut repaired = String::with_capacity(document.len() + attrs.len());
            repaired.push_str(&document[..tag_end]);
            repaired.push_str(&attrs);
            repaired.push_str(&document[tag_end..]);
            return repaired;
        }
    }

    document.to_string()
}

fn try_local_html_view_switch_rescue(document: &str, lower: &str) -> Option<String> {
    if !lower.contains("data-view=")
        || !lower.contains("data-view-panel=")
        || lower.contains("data-ioi-local-rescue=\"view-switch\"")
    {
        return None;
    }

    let rescue_script = r#"<script data-ioi-local-rescue="view-switch">(function(){const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.querySelector('[id="detail-copy" i]');if(!buttons.length||!panels.length){return;}const describe=(button)=>{const explicit=button.getAttribute('data-detail');if(explicit&&explicit.trim()){return explicit.trim();}const label=(button.textContent||button.dataset.view||'Selection').trim();return `${label} selected.`;};const activate=(button)=>{const view=button.dataset.view||'';buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==view;});if(detail){detail.textContent=describe(button);}};buttons.forEach((button)=>button.addEventListener('click',()=>activate(button)));const initial=buttons.find((button)=>button.getAttribute('aria-selected')==='true')||buttons[0];if(initial){activate(initial);}})();</script>"#;
    let rescued_document = ensure_response_region_markup(document, &["detail-copy"]);
    let sanitized =
        strip_inline_script_blocks(&strip_inline_event_handler_attributes(&rescued_document));
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&sanitized, "</body>", rescue_script),
    ))
}

fn try_local_html_stage_navigation_rescue(document: &str, lower: &str) -> Option<String> {
    let has_stage_sections = lower.contains("id=\"stage-")
        || lower.contains("id='stage-")
        || lower.contains("id=\"stage_")
        || lower.contains("id='stage_'")
        || lower.contains("id=\"state-")
        || lower.contains("id='state-")
        || lower.contains("id=\"state_")
        || lower.contains("id='state_'");
    let has_stage_buttons = lower.contains("button id=\"btn-")
        || lower.contains("button id='btn-")
        || lower.contains("data-stage-target=")
        || lower.contains("data-target-stage=")
        || lower.contains("data-stage=");
    if !has_stage_sections || lower.contains("data-ioi-local-rescue=\"stage-nav\"") {
        return None;
    }

    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("role=\"status\"")
        || lower.contains("aria-live=")
        || lower.contains("<aside");

    let mut rescued_document = document.to_string();
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-local-rescue-target="detail-copy" role="status" aria-live="polite"><p id="detail-copy">Select a stage to update this explanation.</p></aside>"#;
        rescued_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&rescued_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&rescued_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        rescued_document = ensure_response_region_markup(
            &rescued_document,
            &["detail-copy", "feedback", "status-text"],
        );
    }

    let rescue_script = if has_stage_buttons {
        r#"<script data-ioi-local-rescue="stage-nav">(function(){const stages=Array.from(document.querySelectorAll('section[id^="stage-"],section[id^="stage_"],article[id^="stage-"],article[id^="stage_"],div[id^="stage-"],div[id^="stage_"],section[id^="state-"],section[id^="state_"],article[id^="state-"],article[id^="state_"],div[id^="state-"],div[id^="state_"]'));const buttons=Array.from(document.querySelectorAll('button[id^="btn-"],button[data-stage-target],button[data-target-stage],button[data-stage]'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i],[role="status"],[aria-live]');if(stages.length<2||!buttons.length){return;}let currentIndex=Math.max(stages.findIndex((node)=>!node.hidden&&node.style.display!=='none'),0);const readIndex=(value)=>{if(!value){return null;}const match=String(value).match(/(\d+)/g);if(!match||!match.length){return null;}const parsed=Number(match[match.length-1]);return Number.isFinite(parsed)?parsed:null;};const stageTitle=(node,index)=>{const heading=node.querySelector('h1,h2,h3');return (heading&&heading.textContent&&heading.textContent.trim())||`Stage ${index+1}`;};const detailTextFor=(index)=>`${stageTitle(stages[index],index)} selected.`;const targetFor=(button,index)=>{const attributed=readIndex(button.getAttribute('data-stage-target')||button.getAttribute('data-target-stage')||button.getAttribute('data-stage'));if(attributed!==null){return Math.max(0,Math.min(stages.length-1,attributed));}const inferred=readIndex(button.id)||readIndex(button.textContent||'');if(inferred!==null){return Math.max(0,Math.min(stages.length-1,inferred));}const label=((button.textContent||button.id||'').trim()).toLowerCase();if(label.includes('back')||label.includes('prev')){return Math.max(0,currentIndex-1);}return Math.max(0,Math.min(stages.length-1,index+1));};const inspect=(nextIndex)=>{if(detail){detail.textContent=detailTextFor(Math.max(0,Math.min(stages.length-1,nextIndex)));}};const activate=(nextIndex)=>{currentIndex=Math.max(0,Math.min(stages.length-1,nextIndex));stages.forEach((node,idx)=>{const active=idx===currentIndex;node.hidden=!active;node.style.display=active?'':'none';});buttons.forEach((button,idx)=>button.setAttribute('aria-pressed',String(targetFor(button,idx)===currentIndex)));inspect(currentIndex);};buttons.forEach((button,index)=>{const targetIndex=targetFor(button,index);button.setAttribute('data-detail',detailTextFor(targetIndex));button.addEventListener('click',()=>activate(targetIndex));button.addEventListener('focus',()=>inspect(targetIndex));button.addEventListener('mouseenter',()=>inspect(targetIndex));});activate(currentIndex);})();</script>"#
    } else {
        r#"<script data-ioi-local-rescue="stage-nav">(function(){const stages=Array.from(document.querySelectorAll('section[id^="stage-"],section[id^="stage_"],article[id^="stage-"],article[id^="stage_"],div[id^="stage-"],div[id^="stage_"],section[id^="state-"],section[id^="state_"],article[id^="state-"],article[id^="state_"],div[id^="state-"],div[id^="state_"]'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i],[role="status"],[aria-live]');const buttons=Array.from(document.querySelectorAll('[data-ioi-local-rescue-target="stage-controls"] button,[data-ioi-local-rescue-target="stage-controls"] [data-stage-target]'));if(stages.length<2||!buttons.length){return;}const stageTitle=(node,index)=>{const heading=node.querySelector('h1,h2,h3');return (heading&&heading.textContent&&heading.textContent.trim())||`Stage ${index+1}`;};const detailTextFor=(index)=>`${stageTitle(stages[index],index)} selected.`;let currentIndex=Math.max(stages.findIndex((node)=>!node.hidden&&node.style.display!=='none'),0);const inspect=(nextIndex)=>{if(detail){detail.textContent=detailTextFor(Math.max(0,Math.min(stages.length-1,nextIndex)));}};const activate=(nextIndex)=>{currentIndex=Math.max(0,Math.min(stages.length-1,nextIndex));stages.forEach((node,idx)=>{const active=idx===currentIndex;node.hidden=!active;node.style.display=active?'':'none';node.setAttribute('aria-hidden', String(!active));});buttons.forEach((button,idx)=>button.setAttribute('aria-pressed', String(idx===currentIndex)));inspect(currentIndex);};buttons.forEach((button,index)=>{button.setAttribute('data-detail',detailTextFor(index));button.addEventListener('click',()=>activate(index));button.addEventListener('focus',()=>inspect(index));button.addEventListener('mouseenter',()=>inspect(index));});activate(currentIndex);})();</script>"#
    };
    let rescued_document = if has_stage_buttons {
        rescued_document
    } else {
        let stage_count = lower.matches("id=\"stage-").count()
            + lower.matches("id='stage-'").count()
            + lower.matches("id=\"stage_").count()
            + lower.matches("id='stage_'").count()
            + lower.matches("id=\"state-").count()
            + lower.matches("id='state-'").count()
            + lower.matches("id=\"state_").count()
            + lower.matches("id='state_'").count();
        let nav_markup = format!(
            "<nav data-ioi-local-rescue-target=\"stage-controls\" aria-label=\"Stage navigation\" style=\"display:flex;flex-wrap:wrap;gap:0.75rem;margin:1rem 0;\">{}</nav>",
            (0..stage_count.max(2))
                .map(|index| format!(
                    "<button type=\"button\" data-stage-target=\"{index}\">Stage {}</button>",
                    index + 1
                ))
                .collect::<Vec<_>>()
                .join("")
        );
        let insertion_index =
            html_document_content_start(&rescued_document.to_ascii_lowercase(), "<main")
                .or_else(|| {
                    html_document_content_start(&rescued_document.to_ascii_lowercase(), "<body")
                })
                .unwrap_or(0);
        insert_html_snippet_at(&rescued_document, insertion_index, &nav_markup)
    };
    let sanitized =
        strip_inline_script_blocks(&strip_inline_event_handler_attributes(&rescued_document));
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&sanitized, "</body>", rescue_script),
    ))
}

fn try_local_html_generic_button_rescue(document: &str, lower: &str) -> Option<String> {
    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("id=\"progress-bar\"")
        || lower.contains("id='progress-bar'");
    let has_buttons = lower.contains("<button");
    if lower.contains("data-ioi-local-rescue=\"button-response\"") || !has_buttons {
        return None;
    }

    let mut rescued_document = document.to_string();
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-local-rescue-target="detail-copy"><p id="detail-copy">Select a control to update this explanation.</p></aside>"#;
        rescued_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&rescued_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&rescued_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        rescued_document = ensure_response_region_markup(
            &rescued_document,
            &["detail-copy", "feedback", "status-text"],
        );
    }

    let rescue_script = r#"<script data-ioi-local-rescue="button-response">(function(){const buttons=Array.from(document.querySelectorAll('button'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i]');const progress=document.querySelector('[id="progress-bar" i]');if(!buttons.length||(!detail&&!progress)){return;}const region=(detail&&detail.closest('aside,[role="status"],[aria-live],[role="region"],[role="alert"]'))||detail;if(region){if(!region.getAttribute('role')){region.setAttribute('role','status');}if(!region.getAttribute('aria-live')){region.setAttribute('aria-live','polite');}}const activate=(button,index)=>{buttons.forEach((entry)=>entry.setAttribute('aria-pressed',String(entry===button)));if(detail){const label=(button.textContent||button.getAttribute('aria-label')||`Action ${index+1}`).trim();detail.textContent=`${label} activated.`;}if(progress){const percent=Math.max(0,Math.min(100,Math.round(((index+1)/buttons.length)*100)));progress.textContent=`${percent}%`;}};buttons.forEach((button,index)=>button.addEventListener('click',()=>activate(button,index)));activate(buttons[0],0);})();</script>"#;
    let sanitized =
        strip_inline_script_blocks(&strip_inline_event_handler_attributes(&rescued_document));
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&sanitized, "</body>", rescue_script),
    ))
}

fn try_local_html_form_control_rescue(document: &str, lower: &str) -> Option<String> {
    let has_form_controls = lower.contains("<select")
        || (lower.contains("<input")
            && (lower.contains("type=\"range\"") || lower.contains("type='range'")));
    if !has_form_controls || lower.contains("data-ioi-local-rescue=\"form-response\"") {
        return None;
    }

    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("id=\"sim-result\"")
        || lower.contains("id='sim-result'")
        || lower.contains("id=\"complexity-val\"")
        || lower.contains("id='complexity-val'");

    let mut rescued_document = document.to_string();
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-local-rescue-target="detail-copy"><p id="detail-copy">Adjust a control to update this explanation.</p></aside>"#;
        rescued_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&rescued_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&rescued_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        rescued_document = ensure_response_region_markup(
            &rescued_document,
            &[
                "detail-copy",
                "feedback",
                "status-text",
                "sim-result",
                "complexity-val",
            ],
        );
    }

    let rescue_script = r##"<script data-ioi-local-rescue="form-response">(function(){const selects=Array.from(document.querySelectorAll('select'));const ranges=Array.from(document.querySelectorAll('input[type="range"]'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i],[id="sim-result" i],[id="complexity-val" i]');const statusRegion=(detail&&detail.closest('aside,[role="status"],[aria-live],[role="region"],[role="alert"]'))||detail;if(statusRegion){if(!statusRegion.getAttribute('role')){statusRegion.setAttribute('role','status');}if(!statusRegion.getAttribute('aria-live')){statusRegion.setAttribute('aria-live','polite');}}const labelFor=(control)=>{const explicit=control.getAttribute('aria-label');if(explicit&&explicit.trim()){return explicit.trim();}const id=control.id||'';if(id){const label=document.querySelector(`label[for="${id}"]`);if(label&&label.textContent){return label.textContent.trim();}}return (control.name||control.id||control.tagName||'Control').trim();};const updateSelect=(control)=>{const option=control.options&&control.selectedIndex>=0?control.options[control.selectedIndex]:null;const optionText=option&&option.textContent?option.textContent.trim():control.value;const label=labelFor(control);if(detail){detail.textContent=`${label}: ${optionText}`;}};const updateRange=(control)=>{const value=Number(control.value||control.min||0);const label=labelFor(control);const simResult=document.querySelector('[id="sim-result" i],[id="resultbox" i]');const complexityVal=document.querySelector('[id="complexity-val" i]');if(simResult&&control.id==='n-qubits'){const states=Math.pow(2, Math.max(0, value));simResult.textContent=`${value} Qubit${value===1?'':'s'} = ${states} States`; }else if(simResult){simResult.textContent=`${label}: ${value}`;}if(complexityVal){complexityVal.textContent=value<=1?'Simple':value===2?'Moderate':value===3?'Advanced':value===4?'Complex':'Maximum';}control.setAttribute('aria-valuetext', `${label}: ${value}`);if(detail){detail.textContent=`${label} adjusted to ${value}.`;}};selects.forEach((control)=>control.addEventListener('change',()=>updateSelect(control)));ranges.forEach((control)=>control.addEventListener('input',()=>updateRange(control)));if(selects[0]){updateSelect(selects[0]);}if(ranges[0]){updateRange(ranges[0]);}})();</script>"##;
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&rescued_document, "</body>", rescue_script),
    ))
}

fn try_local_html_scroll_nav_rescue(document: &str, lower: &str) -> Option<String> {
    let has_scroll_nav = lower.contains("scrollintoview(")
        || lower.contains("href=\"#")
        || lower.contains("aria-controls=")
        || lower.contains("data-target=");
    if !has_scroll_nav || lower.contains("data-ioi-local-rescue=\"scroll-nav\"") {
        return None;
    }

    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("id=\"scenario-status\"")
        || lower.contains("id='scenario-status'")
        || lower.contains("role=\"status\"")
        || lower.contains("aria-live=")
        || lower.contains("<aside");

    let mut rescued_document = document.to_string();
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-local-rescue-target="detail-copy" role="status" aria-live="polite"><p id="detail-copy">Select a section to update this explanation.</p></aside>"#;
        rescued_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&rescued_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&rescued_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        rescued_document = ensure_response_region_markup(
            &rescued_document,
            &["detail-copy", "feedback", "status-text", "scenario-status"],
        );
    }

    let rescue_script = r##"<script data-ioi-local-rescue="scroll-nav">(function(){const controls=Array.from(document.querySelectorAll('button[onclick*="scrollIntoView"],a[href^="#"],button[aria-controls],button[data-target],button[data-section],nav button,nav a[href]'));if(!controls.length){return;}const detailCandidates=[document.querySelector('[id="detail-copy" i]'),document.querySelector('[id="feedback" i]'),document.querySelector('[id="status-text" i]'),document.querySelector('[id="scenario-status" i]'),document.querySelector('[role="status"]'),document.querySelector('[aria-live]'),document.querySelector('.status'),document.querySelector('aside p')].filter(Boolean);const detail=detailCandidates[0]||null;const region=(detail&&detail.closest('aside,[role="status"],[aria-live],[role="region"],[role="alert"]'))||detail;if(region){if(!region.getAttribute('role')){region.setAttribute('role','status');}if(!region.getAttribute('aria-live')){region.setAttribute('aria-live','polite');}}if(detail&&!detail.id){detail.id='detail-copy';}const sections=Array.from(document.querySelectorAll('main section[id],main article[id],main div[id],section[data-view-panel],article[data-view-panel],[role="region"][id]'));const readTarget=(control)=>{const ariaTarget=control.getAttribute('aria-controls');if(ariaTarget&&ariaTarget.trim()){return ariaTarget.trim().replace(/^#/,'');}const dataTarget=control.getAttribute('data-target')||control.getAttribute('data-section')||'';if(dataTarget&&dataTarget.trim()){return dataTarget.trim().replace(/^#/,'');}if(control.matches('a[href^="#"]')){return (control.getAttribute('href')||'').trim().replace(/^#/,'');}const onclick=control.getAttribute('onclick')||'';const match=onclick.match(/getElementById\\((['"])([^'"]+)\\1\\)/i);return match&&match[2]?match[2]:'';};const summarize=(target,label)=>{if(!target){return label?`${label} selected.`:'Section selected.';}const heading=target.querySelector('h1,h2,h3,strong,figcaption');const detailText=target.querySelector('p,li,td');const headingValue=heading&&heading.textContent?heading.textContent.trim():'';const detailValue=detailText&&detailText.textContent?detailText.textContent.trim():'';if(headingValue&&detailValue){return `${headingValue}: ${detailValue}`;}if(headingValue){return `${headingValue} selected.`;}if(detailValue){return detailValue;}return label?`${label} selected.`:'Section selected.';};const activate=(control)=>{const targetId=readTarget(control);const target=targetId?document.getElementById(targetId):null;controls.forEach((entry)=>{entry.setAttribute('aria-pressed',String(entry===control));entry.setAttribute('aria-selected',String(entry===control));});sections.forEach((section)=>{const active=Boolean(targetId)&&(section.id===targetId||section.dataset.viewPanel===targetId);section.classList.toggle('active',active);if(active){section.removeAttribute('hidden');section.setAttribute('aria-hidden','false');}});if(detail){const label=(control.textContent||control.getAttribute('aria-label')||targetId||'Section').trim();detail.textContent=summarize(target,label);}if(target&&typeof target.scrollIntoView==='function'){target.scrollIntoView({behavior:'smooth',block:'start'});}};controls.forEach((control)=>control.addEventListener('click',(event)=>{if(control.matches('a[href^="#"]')){event.preventDefault();}activate(control);}));const initial=controls.find((control)=>control.getAttribute('aria-pressed')==='true'||control.getAttribute('aria-selected')==='true')||controls[0];if(initial){activate(initial);}})();</script>"##;
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&rescued_document, "</body>", rescue_script),
    ))
}

fn try_local_html_interaction_rescue(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != StudioRendererKind::HtmlIframe
        || request.artifact_class != StudioArtifactClass::InteractiveSingleFile
        || !direct_author_local_html_interaction_failure(error_message)
        || !direct_author_has_completion_boundary(request, document)
    {
        return None;
    }

    let normalized = normalize_html_terminal_closure(document);
    let lower = normalized.to_ascii_lowercase();
    if html_contains_stateful_interaction_behavior(&lower) {
        return None;
    }

    if let Some(repaired) = try_local_html_view_switch_rescue(&normalized, &lower) {
        return Some((repaired, "view_switch"));
    }

    if let Some(repaired) = try_local_html_stage_navigation_rescue(&normalized, &lower) {
        return Some((repaired, "stage_navigation"));
    }

    if let Some(repaired) = try_local_html_form_control_rescue(&normalized, &lower) {
        return Some((repaired, "form_response"));
    }

    try_local_html_generic_button_rescue(&normalized, &lower)
        .map(|repaired| (repaired, "button_response"))
}

pub(crate) fn try_local_html_interaction_truth_rescue_document(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != StudioRendererKind::HtmlIframe
        || request.artifact_class != StudioArtifactClass::InteractiveSingleFile
        || !direct_author_local_html_interaction_truth_failure(error_message)
        || !direct_author_has_completion_boundary(request, document)
    {
        return None;
    }

    let normalized = normalize_html_terminal_closure(document);
    let lower = normalized.to_ascii_lowercase();
    try_local_html_scroll_nav_rescue(&normalized, &lower).map(|repaired| (repaired, "scroll_nav"))
}

fn try_local_html_structural_rescue(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Vec<(&'static str, String)> {
    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != StudioRendererKind::HtmlIframe
        || !direct_author_uses_raw_document(request)
        || !direct_author_local_html_structural_failure(error_message)
        || direct_author_local_html_semantic_underbuild_failure(error_message)
        || !direct_author_has_completion_boundary(request, document)
    {
        return Vec::new();
    }

    local_html_structural_rescue_candidates(document)
}

fn configured_direct_author_stream_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_STUDIO_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
        "IOI_STUDIO_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn direct_author_stream_timeout_for_request(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_stream_timeout() {
        return Some(timeout);
    }

    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        StudioRendererKind::HtmlIframe => Some(Duration::from_secs(150)),
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::Svg
        | StudioRendererKind::PdfEmbed => Some(Duration::from_secs(30)),
        _ => None,
    }
}

fn configured_direct_author_follow_up_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
        "IOI_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn configured_direct_author_idle_settle_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_STUDIO_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS",
        "IOI_STUDIO_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn direct_author_follow_up_timeout_for_request(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_follow_up_timeout() {
        return Some(timeout);
    }

    let local_runtime = runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime;
    match request.renderer {
        StudioRendererKind::HtmlIframe => Some(if local_runtime {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(90)
        }),
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::Svg
        | StudioRendererKind::PdfEmbed => Some(if local_runtime {
            Duration::from_secs(15)
        } else {
            Duration::from_secs(30)
        }),
        _ => Some(if local_runtime {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(40)
        }),
    }
}

fn direct_author_terminal_boundary_settle_timeout_for_request(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        StudioRendererKind::HtmlIframe => Some(Duration::from_millis(650)),
        StudioRendererKind::Svg => Some(Duration::from_millis(400)),
        _ => None,
    }
}

fn direct_author_terminal_idle_settle_timeout_for_request(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_idle_settle_timeout() {
        return Some(timeout);
    }

    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        StudioRendererKind::HtmlIframe => Some(Duration::from_millis(1800)),
        StudioRendererKind::Svg => Some(Duration::from_millis(900)),
        _ => None,
    }
}

fn configured_materialization_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS",
        "IOI_STUDIO_MATERIALIZATION_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn configured_materialization_follow_up_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_STUDIO_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS",
        "IOI_STUDIO_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn materialization_timeout_for_request(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    follow_up: bool,
) -> Option<Duration> {
    let configured_timeout = if follow_up {
        configured_materialization_follow_up_timeout()
    } else {
        configured_materialization_timeout()
    };

    if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
    {
        let capped = Duration::from_secs(45);
        return Some(
            configured_timeout
                .map(|timeout| timeout.min(capped))
                .unwrap_or(capped),
        );
    }

    if follow_up {
        if let Some(timeout) = configured_materialization_follow_up_timeout() {
            return Some(timeout);
        }
    } else if let Some(timeout) = configured_materialization_timeout() {
        return Some(timeout);
    }

    if runtime_kind != StudioRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match (request.renderer, follow_up) {
        (StudioRendererKind::HtmlIframe, true) => Some(Duration::from_secs(45)),
        (StudioRendererKind::HtmlIframe, false) => Some(Duration::from_secs(90)),
        (
            StudioRendererKind::Markdown
            | StudioRendererKind::Mermaid
            | StudioRendererKind::Svg
            | StudioRendererKind::PdfEmbed,
            true,
        ) => Some(Duration::from_secs(15)),
        (
            StudioRendererKind::Markdown
            | StudioRendererKind::Mermaid
            | StudioRendererKind::Svg
            | StudioRendererKind::PdfEmbed,
            false,
        ) => Some(Duration::from_secs(25)),
        (_, true) => Some(Duration::from_secs(20)),
        (_, false) => Some(Duration::from_secs(45)),
    }
}

async fn execute_materialization_inference(
    runtime: Arc<dyn InferenceRuntime>,
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    input: &[u8],
    options: InferenceOptions,
    activity_observer: Option<StudioArtifactActivityObserver>,
    trace_label: &str,
    follow_up: bool,
) -> Result<Vec<u8>, String> {
    let retry_limit = if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
    {
        2usize
    } else {
        1usize
    };
    let timeout = materialization_timeout_for_request(request, runtime_kind, follow_up);
    let mut attempt_options = options;

    for attempt in 0..retry_limit {
        let inference = runtime.execute_inference([0u8; 32], input, attempt_options.clone());
        let result = match timeout {
            Some(limit) => {
                match await_with_activity_heartbeat(
                    tokio::time::timeout(limit, inference),
                    activity_observer.clone(),
                    Duration::from_millis(125),
                )
                .await
                {
                    Ok(Ok(output)) => Ok(output),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => {
                        studio_generation_trace(format!(
                            "artifact_generation:{trace_label}:timeout renderer={:?} timeout_ms={}",
                            request.renderer,
                            limit.as_millis()
                        ));
                        Err(format!(
                            "Studio artifact {trace_label} timed out after {}ms",
                            limit.as_millis()
                        ))
                    }
                }
            }
            None => await_with_activity_heartbeat(
                inference,
                activity_observer.clone(),
                Duration::from_millis(125),
            )
            .await
            .map_err(|error| error.to_string()),
        };

        match result {
            Ok(output) => return Ok(output),
            Err(error)
                if attempt + 1 < retry_limit && local_runner_unexpected_stop_error(&error) =>
            {
                let next_options =
                    materialization_retry_options(request, runtime_kind, &attempt_options);
                studio_generation_trace(format!(
                    "artifact_generation:{trace_label}:retry runner_restart attempt={} renderer={:?} max_tokens={} next_max_tokens={}",
                    attempt + 1,
                    request.renderer,
                    attempt_options.max_tokens,
                    next_options.max_tokens
                ));
                attempt_options = next_options;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    }

    Err(format!(
        "Studio artifact {trace_label} failed without returning an output payload"
    ))
}

async fn await_direct_author_inference_output<F>(
    inference: F,
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    collector: Option<&StudioTokenStreamPreviewCollector>,
    candidate_id: &str,
) -> Result<Vec<u8>, VmError>
where
    F: std::future::Future<Output = Result<Vec<u8>, VmError>> + Send + 'static,
{
    let Some(limit) = direct_author_stream_timeout_for_request(request, runtime_kind) else {
        return inference.await;
    };

    let boundary_settle_timeout =
        direct_author_terminal_boundary_settle_timeout_for_request(request, runtime_kind);
    let idle_settle_timeout =
        direct_author_terminal_idle_settle_timeout_for_request(request, runtime_kind);
    let started_at = tokio::time::Instant::now();
    let mut boundary_seen_at = None;
    let mut boundary_snapshot = String::new();
    let mut idle_snapshot = String::new();
    let mut idle_snapshot_seen_at = None;
    let mut last_progress_trace_len = 0usize;
    let mut last_settle_trace_len = 0usize;
    let mut last_progress_trace_at = started_at;
    let mut ticker = tokio::time::interval(Duration::from_millis(125));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut inference_task = tokio::spawn(inference);

    loop {
        let elapsed = started_at.elapsed();
        if elapsed >= limit {
            if let Some(snapshot) = collector.and_then(|collector| {
                let snapshot = snapshot_token_stream_preview_collector(Some(collector));
                if direct_author_has_stream_settle_boundary(request, &snapshot)
                    || direct_author_can_fast_finish_on_idle_snapshot(request, &snapshot)
                {
                    Some(snapshot)
                } else {
                    None
                }
            }) {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_inference:boundary_fast_finish id={} bytes={} settle_ms=timeout_edge",
                    candidate_id,
                    snapshot.len()
                ));
                inference_task.abort();
                return Ok(snapshot.into_bytes());
            }

            studio_generation_trace(format!(
                "artifact_generation:direct_author_inference:timeout id={} timeout_ms={}",
                candidate_id,
                limit.as_millis()
            ));
            inference_task.abort();
            return Err(VmError::HostError(format!(
                "Studio direct-author artifact inference timed out after {}s",
                limit.as_secs()
            )));
        }

        let remaining = limit.saturating_sub(elapsed);
        tokio::select! {
            result = &mut inference_task => {
                return result
                    .map_err(|error| VmError::HostError(format!("Studio direct-author inference task failed: {error}")))?
            }
            _ = tokio::time::sleep(remaining) => {}
            _ = ticker.tick(), if collector.is_some() && (boundary_settle_timeout.is_some() || idle_settle_timeout.is_some()) => {
                let snapshot = snapshot_token_stream_preview_collector(collector);
                let now = tokio::time::Instant::now();
                let settle_snapshot = direct_author_stream_settle_snapshot(request, &snapshot);
                let settle_len = settle_snapshot.as_ref().map(|value| value.len()).unwrap_or(0);

                if !snapshot.trim().is_empty()
                    && (snapshot.len() >= last_progress_trace_len.saturating_add(512)
                        || now.duration_since(last_progress_trace_at) >= Duration::from_secs(10))
                {
                    studio_generation_trace(format!(
                        "artifact_generation:direct_author_inference:stream_progress id={} bytes={} settle_candidate_bytes={}",
                        candidate_id,
                        snapshot.len(),
                        settle_len
                    ));
                    last_progress_trace_len = snapshot.len();
                    last_progress_trace_at = now;
                }

                if settle_len > 0 && settle_len != last_settle_trace_len {
                    studio_generation_trace(format!(
                        "artifact_generation:direct_author_inference:settle_candidate id={} bytes={} total_bytes={}",
                        candidate_id,
                        settle_len,
                        snapshot.len()
                    ));
                    last_settle_trace_len = settle_len;
                }

                let idle_snapshot_candidate =
                    direct_author_idle_settle_snapshot(request, &snapshot);
                if idle_snapshot_candidate != idle_snapshot {
                    idle_snapshot = idle_snapshot_candidate;
                    idle_snapshot_seen_at = Some(now);
                }

                if let Some(settled) = settle_snapshot {
                    if settled != boundary_snapshot {
                        boundary_snapshot = settled.clone();
                        boundary_seen_at = Some(now);
                    } else if boundary_seen_at.is_some_and(|instant| instant.elapsed() >= boundary_settle_timeout.expect("guarded above")) {
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_inference:boundary_fast_finish id={} bytes={} settle_ms={}",
                            candidate_id,
                            boundary_snapshot.len(),
                            boundary_settle_timeout.expect("guarded above").as_millis()
                        ));
                        inference_task.abort();
                        return Ok(boundary_snapshot.into_bytes());
                    }
                } else {
                    boundary_snapshot.clear();
                    boundary_seen_at = None;
                }

                if !snapshot.trim().is_empty()
                    && direct_author_can_fast_finish_on_idle_snapshot(request, &idle_snapshot)
                    && idle_snapshot_seen_at.is_some_and(|instant| {
                        instant.elapsed() >= idle_settle_timeout.expect("guarded above")
                    })
                {
                    studio_generation_trace(format!(
                        "artifact_generation:direct_author_inference:idle_fast_finish id={} bytes={} settle_ms={}",
                        candidate_id,
                        idle_snapshot.len(),
                        idle_settle_timeout.expect("guarded above").as_millis()
                    ));
                    inference_task.abort();
                    return Ok(idle_snapshot.into_bytes());
                }
            }
        }
    }
}

fn direct_author_follow_up_max_tokens(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    trace_label: &str,
) -> u32 {
    let local_runtime = runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime;
    match (request.renderer, trace_label) {
        (StudioRendererKind::HtmlIframe, "continuation") => {
            if local_runtime {
                1800
            } else {
                2400
            }
        }
        (StudioRendererKind::HtmlIframe, _) => {
            if local_runtime {
                2400
            } else {
                3800
            }
        }
        (
            StudioRendererKind::Markdown
            | StudioRendererKind::Mermaid
            | StudioRendererKind::Svg
            | StudioRendererKind::PdfEmbed,
            "continuation",
        ) => {
            if local_runtime {
                900
            } else {
                1400
            }
        }
        _ => {
            if local_runtime {
                1800
            } else {
                2400
            }
        }
    }
}

fn direct_author_follow_up_prefers_raw_output(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && direct_author_uses_raw_document(request)
}

fn salvage_interrupted_direct_author_document(
    _request: &StudioOutcomeArtifactRequest,
    raw: &str,
) -> String {
    let trimmed = raw.trim_end();
    if trimmed.is_empty() {
        return String::new();
    }

    let candidate = match trimmed.rfind('>') {
        Some(last_gt) if !trimmed[last_gt + 1..].trim().is_empty() => &trimmed[..=last_gt],
        _ => trimmed,
    };

    candidate.to_string()
}

async fn execute_direct_author_follow_up_inference(
    runtime: Arc<dyn InferenceRuntime>,
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    input: &[u8],
    options: InferenceOptions,
    activity_observer: Option<StudioArtifactActivityObserver>,
    trace_label: &str,
) -> Result<Vec<u8>, String> {
    let prompt_bytes = input.len();
    let max_tokens = options.max_tokens;
    studio_generation_trace(format!(
        "artifact_generation:direct_author_{}:start renderer={:?} prompt_bytes={} max_tokens={}",
        trace_label, request.renderer, prompt_bytes, max_tokens
    ));
    let retry_limit = if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
    {
        2usize
    } else {
        1usize
    };
    let follow_up_timeout = direct_author_follow_up_timeout_for_request(request, runtime_kind);

    for attempt in 0..retry_limit {
        let inference = runtime.execute_inference([0u8; 32], input, options.clone());
        let result = match follow_up_timeout {
            Some(limit) => {
                match await_with_activity_heartbeat(
                    tokio::time::timeout(limit, inference),
                    activity_observer.clone(),
                    Duration::from_millis(125),
                )
                .await
                {
                    Ok(Ok(output)) => Ok(output),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => {
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_{}:timeout renderer={:?} timeout_ms={}",
                            trace_label,
                            request.renderer,
                            limit.as_millis()
                        ));
                        Err(format!(
                            "Studio direct-author {trace_label} timed out after {}ms",
                            limit.as_millis()
                        ))
                    }
                }
            }
            None => await_with_activity_heartbeat(
                inference,
                activity_observer.clone(),
                Duration::from_millis(125),
            )
            .await
            .map_err(|error| error.to_string()),
        };

        match result {
            Ok(output) => {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_{}:ok renderer={:?} bytes={}",
                    trace_label,
                    request.renderer,
                    output.len()
                ));
                return Ok(output);
            }
            Err(error)
                if attempt + 1 < retry_limit && local_runner_unexpected_stop_error(&error) =>
            {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_{}:retry runner_restart attempt={} renderer={:?}",
                    trace_label,
                    attempt + 1,
                    request.renderer
                ));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    }

    Err(format!(
        "Studio direct-author {trace_label} failed without returning a follow-up payload"
    ))
}

fn parse_direct_author_generated_candidate(
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate_id: &str,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let mut generated = match super::parse_and_validate_generated_artifact_payload(raw, request) {
        Ok(generated) => generated,
        Err(error)
            if request.renderer == StudioRendererKind::HtmlIframe
                && request.artifact_class == StudioArtifactClass::Document
                && error.contains(
                    "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
                )
                && direct_author_has_completion_boundary(request, raw) =>
        {
            let Some(mut generated) = synthesize_generated_artifact_payload_from_raw_document(raw, request) else {
                return Err(error.into());
            };
            super::normalize_generated_artifact_payload(&mut generated, request);
            if let Err(remaining_error) = super::validate_generated_artifact_payload(&generated, request)
            {
                if !remaining_error.contains(
                    "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
                ) {
                    return Err(remaining_error.into());
                }
            }
            studio_generation_trace(format!(
                "artifact_generation:direct_author_browser_html_lenient_accept id={} raw_bytes={}",
                candidate_id,
                raw.len()
            ));
            generated
        }
        Err(error) => return Err(error.into()),
    };
    trace_html_contract_state(
        "artifact_generation:direct_author_contract_state:parsed",
        request,
        candidate_id,
        &generated,
    );
    super::enrich_generated_artifact_payload(&mut generated, request, brief);
    trace_html_contract_state(
        "artifact_generation:direct_author_contract_state:enriched",
        request,
        candidate_id,
        &generated,
    );
    super::validate_generated_artifact_payload_against_brief_with_edit_intent(
        &generated,
        request,
        brief,
        edit_intent,
    )?;
    if let Some(contradiction) = renderer_primary_view_contract_failure(request, brief, &generated)
    {
        return Err(StudioCandidateMaterializationError {
            message: contradiction.to_string(),
            raw_output_preview: truncate_candidate_failure_preview(raw, 2000),
        });
    }
    Ok(generated)
}

fn parse_direct_author_provisional_candidate_from_snapshot(
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate_id: &str,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let snapshot = direct_author_stream_settle_snapshot(request, raw)
        .or_else(|| direct_author_preview_ready_document(request, raw).then(|| raw.to_string()))
        .ok_or_else(|| StudioCandidateMaterializationError {
            message: "direct-author provisional snapshot missing a stable renderable preview"
                .to_string(),
            raw_output_preview: truncate_candidate_failure_preview(raw, 2000),
        })?;
    let has_stable_boundary = direct_author_stream_settle_snapshot(request, raw).is_some();
    let mut generated = synthesize_generated_artifact_payload_from_raw_document(&snapshot, request)
        .ok_or_else(|| StudioCandidateMaterializationError {
            message: "direct-author provisional snapshot could not be synthesized into an artifact payload".to_string(),
            raw_output_preview: truncate_candidate_failure_preview(&snapshot, 2000),
        })?;
    super::normalize_generated_artifact_payload(&mut generated, request);
    if has_stable_boundary {
        super::validate_generated_artifact_payload(&generated, request).map_err(|error| {
            StudioCandidateMaterializationError {
                message: error,
                raw_output_preview: truncate_candidate_failure_preview(&snapshot, 2000),
            }
        })?;
    }
    trace_html_contract_state(
        "artifact_generation:direct_author_contract_state:provisional",
        request,
        candidate_id,
        &generated,
    );
    super::enrich_generated_artifact_payload(&mut generated, request, brief);
    generated.notes.push(
        "provisional preview surfaced from the streamed draft before continuation/repair"
            .to_string(),
    );
    Ok(generated)
}

pub(crate) async fn repair_direct_author_generated_candidate_with_runtime_error(
    repair_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    selected_skills: &[StudioArtifactSelectedSkill],
    edit_intent: Option<&StudioArtifactEditIntent>,
    _refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    _candidate_seed: u64,
    candidate: &StudioGeneratedArtifactPayload,
    latest_error: &str,
    activity_observer: Option<StudioArtifactActivityObserver>,
) -> Result<StudioGeneratedArtifactPayload, String> {
    if !direct_author_uses_raw_document(request) {
        return Err("direct-author runtime repair requires a raw-document renderer".to_string());
    }

    let latest_raw = candidate
        .files
        .iter()
        .find(|file| file.renderable)
        .or_else(|| candidate.files.first())
        .map(|file| file.body.clone())
        .ok_or_else(|| {
            "direct-author runtime repair requires a surfaced renderable document".to_string()
        })?;
    let repair_runtime_kind = repair_runtime.studio_runtime_provenance().kind;
    let repair_payload = build_studio_artifact_direct_author_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        selected_skills,
        &latest_raw,
        latest_error,
        repair_runtime_kind,
    );
    let repair_input = serde_json::to_vec(&repair_payload)
        .map_err(|error| format!("Failed to encode Studio direct-author repair prompt: {error}"))?;
    let repair_output = execute_direct_author_follow_up_inference(
        repair_runtime,
        request,
        repair_runtime_kind,
        &repair_input,
        InferenceOptions {
            temperature: 0.0,
            json_mode: !direct_author_follow_up_prefers_raw_output(request, repair_runtime_kind),
            max_tokens: direct_author_follow_up_max_tokens(
                request,
                repair_runtime_kind,
                "runtime_repair",
            ),
            ..Default::default()
        },
        activity_observer,
        "runtime_repair",
    )
    .await
    .map_err(|error| format!("Studio direct-author runtime repair inference failed: {error}"))?;
    let repair_raw = String::from_utf8(repair_output).map_err(|error| {
        format!("Studio direct-author runtime repair utf8 decode failed: {error}")
    })?;
    let recovery_payload = parse_studio_direct_author_recovery_payload(request, &repair_raw)?;
    let repaired_document = apply_direct_author_recovery_payload(&latest_raw, &recovery_payload);
    if recovery_payload.mode != StudioDirectAuthorRecoveryMode::FullDocument {
        studio_generation_trace(format!(
            "artifact_generation:direct_author_runtime_repair:mode_fallback renderer={:?} mode={} existing_bytes={} repaired_bytes={}",
            request.renderer,
            direct_author_recovery_mode_label(&recovery_payload.mode),
            latest_raw.len(),
            repaired_document.len()
        ));
    }
    parse_direct_author_generated_candidate(
        &repaired_document,
        request,
        brief,
        edit_intent,
        candidate_id,
    )
    .map_err(|error| error.message)
    .map(|mut generated| {
        if generated.summary.trim().is_empty() {
            generated.summary = candidate.summary.clone();
        }
        if generated.notes.is_empty() {
            generated.notes = candidate.notes.clone();
        } else {
            generated
                .notes
                .push(format!("runtime repair applied after: {latest_error}"));
        }
        if generated.files.is_empty() {
            generated.files = candidate.files.clone();
        }
        generated
    })
}

pub async fn materialize_studio_artifact_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    materialize_studio_artifact_candidate_with_runtime(
        runtime,
        title,
        intent,
        request,
        &StudioArtifactBrief {
            audience: "general audience".to_string(),
            job_to_be_done: "deliver the requested artifact".to_string(),
            subject_domain: title.to_string(),
            artifact_thesis: intent.to_string(),
            required_concepts: Vec::new(),
            required_interactions: Vec::new(),
            query_profile: None,
            visual_tone: Vec::new(),
            factual_anchors: Vec::new(),
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        },
        None,
        None,
        "candidate-1",
        candidate_seed_for(title, intent, 0),
        0.0,
    )
    .await
}

pub(crate) async fn materialize_studio_artifact_candidate_with_runtime_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
    activity_observer: Option<StudioArtifactActivityObserver>,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    if compact_local_html_materialization_prompt(request.renderer, runtime_kind) {
        let hybrid_temperature =
            effective_direct_author_temperature(request.renderer, runtime_kind, temperature);
        studio_generation_trace(format!(
            "artifact_generation:materialization_strategy_override id={} requested=typed_json resolved=hybrid_raw_document temperature={}",
            candidate_id,
            hybrid_temperature
        ));
        return materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
            runtime,
            repair_runtime,
            title,
            intent,
            request,
            brief,
            selected_skills,
            edit_intent,
            refinement,
            candidate_id,
            candidate_seed,
            hybrid_temperature,
            None,
            activity_observer,
        )
        .await;
    }
    let parse_candidate = |raw: &str| -> Result<
        StudioGeneratedArtifactPayload,
        StudioCandidateMaterializationError,
    > {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:materialization_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:materialization_contract_state:enriched",
            request,
            candidate_id,
            &generated,
        );
        super::validate_generated_artifact_payload_against_brief_with_edit_intent(
            &generated,
            request,
            brief,
            edit_intent,
        )?;
        Ok(generated)
    };
    let payload = build_studio_artifact_materialization_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        runtime_kind,
    )
    .map_err(|message| StudioCandidateMaterializationError {
        message,
        raw_output_preview: None,
    })?;
    let input =
        serde_json::to_vec(&payload).map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Failed to encode Studio artifact materialization prompt: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    studio_generation_trace(format!(
        "artifact_generation:materialization_inference:start id={} prompt_bytes={} temperature={} max_tokens={}",
        candidate_id,
        input.len(),
        temperature,
        materialization_max_tokens_for_runtime(request.renderer, runtime_kind)
    ));
    let output = match execute_materialization_inference(
        runtime.clone(),
        request,
        runtime_kind,
        &input,
        InferenceOptions {
            temperature,
            json_mode: true,
            max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
            ..Default::default()
        },
        activity_observer.clone(),
        "materialization_inference",
        false,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            let message = format!(
                "Studio artifact materialization inference failed: {}",
                error
            );
            return Err(StudioCandidateMaterializationError {
                message,
                raw_output_preview: None,
            });
        }
    };
    studio_generation_trace(format!(
        "artifact_generation:materialization_inference:ok id={} bytes={}",
        candidate_id,
        output.len()
    ));
    let raw = String::from_utf8(output).map_err(|error| StudioCandidateMaterializationError {
        message: format!(
            "Studio artifact materialization utf8 decode failed: {}",
            error
        ),
        raw_output_preview: None,
    })?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            studio_generation_trace(format!(
                "artifact_generation:materialization_parse_error id={} error={} preview={}",
                candidate_id,
                first_error.message,
                truncate_candidate_failure_preview(&raw, 4000)
                    .unwrap_or_else(|| "(empty)".to_string())
            ));
            let mut latest_error = first_error.message;
            let mut latest_raw = raw;

            let repair_runtime = materialization_repair_runtime_for_request(
                request,
                &runtime,
                repair_runtime.as_ref(),
            );
            let repair_runtime_kind = repair_runtime.studio_runtime_provenance().kind;
            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
            {
                let repair_payload =
                    build_studio_artifact_materialization_repair_prompt_for_runtime(
                        title,
                        intent,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        selected_skills,
                        retrieved_exemplars,
                        edit_intent,
                        refinement,
                        candidate_id,
                        candidate_seed,
                        &latest_raw,
                        &latest_error,
                        repair_runtime_kind,
                    )
                    .map_err(|message| {
                        StudioCandidateMaterializationError {
                            message,
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        }
                    })?;
                let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                    StudioCandidateMaterializationError {
                        message: format!(
                            "Failed to encode Studio artifact materialization repair prompt: {}",
                            error
                        ),
                        raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                    }
                })?;
                studio_generation_trace(format!(
                    "artifact_generation:materialization_repair:start id={} attempt={} model={:?} prompt_bytes={} max_tokens={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_runtime.studio_runtime_provenance().model,
                    repair_input.len(),
                    materialization_max_tokens_for_runtime(
                        request.renderer,
                        repair_runtime_kind,
                    )
                ));
                let repair_output = execute_materialization_inference(
                    repair_runtime.clone(),
                    request,
                    repair_runtime_kind,
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: materialization_max_tokens_for_runtime(
                            request.renderer,
                            repair_runtime_kind,
                        ),
                        ..Default::default()
                    },
                    activity_observer.clone(),
                    "materialization_repair",
                    true,
                )
                .await
                .map_err(|error| StudioCandidateMaterializationError {
                    message: format!(
                        "{latest_error}; repair attempt {} inference failed: {error}",
                        repair_attempt + 1
                    ),
                    raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                })?;
                studio_generation_trace(format!(
                    "artifact_generation:materialization_repair:ok id={} attempt={} bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_output.len()
                ));
                let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                    StudioCandidateMaterializationError {
                        message: format!(
                            "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                            repair_attempt + 1
                        ),
                        raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                    }
                })?;
                match parse_candidate(&repair_raw) {
                    Ok(generated) => return Ok(generated),
                    Err(repair_error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:materialization_repair_parse_error id={} attempt={} error={} preview={}",
                            candidate_id,
                            repair_attempt + 1,
                            repair_error.message,
                            truncate_candidate_failure_preview(&repair_raw, 4000)
                                .unwrap_or_else(|| "(empty)".to_string())
                        ));
                        latest_raw = repair_raw;
                        latest_error = format!(
                            "{latest_error}; repair attempt {} failed: {}",
                            repair_attempt + 1,
                            repair_error.message
                        );
                    }
                }
            }

            Err(StudioCandidateMaterializationError {
                message: latest_error,
                raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
            })
        }
    }
}

pub(crate) async fn repair_materialized_candidate_with_runtime_error(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    payload: &StudioGeneratedArtifactPayload,
    failure: &str,
    activity_observer: Option<StudioArtifactActivityObserver>,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<
        StudioGeneratedArtifactPayload,
        StudioCandidateMaterializationError,
    > {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:render_sanity_repair_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:render_sanity_repair_contract_state:enriched",
            request,
            candidate_id,
            &generated,
        );
        super::validate_generated_artifact_payload_against_brief_with_edit_intent(
            &generated,
            request,
            brief,
            edit_intent,
        )?;
        Ok(generated)
    };
    let raw_payload =
        serde_json::to_string(payload).map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Failed to serialize Studio artifact payload for render-sanity repair: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    let repair_payload = build_studio_artifact_materialization_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        &raw_payload,
        failure,
        runtime_kind,
    )
    .map_err(|message| StudioCandidateMaterializationError {
        message,
        raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
    })?;
    let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
        StudioCandidateMaterializationError {
            message: format!(
                "Failed to encode Studio render-sanity repair prompt: {}",
                error
            ),
            raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
        }
    })?;
    studio_generation_trace(format!(
        "artifact_generation:render_sanity_repair:start id={} model={:?} prompt_bytes={} max_tokens={}",
        candidate_id,
        runtime.studio_runtime_provenance().model,
        repair_input.len(),
        materialization_max_tokens_for_runtime(request.renderer, runtime_kind)
    ));
    let repair_output = execute_materialization_inference(
        runtime.clone(),
        request,
        runtime_kind,
        &repair_input,
        InferenceOptions {
            temperature: 0.0,
            json_mode: true,
            max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
            ..Default::default()
        },
        activity_observer,
        "render_sanity_repair",
        true,
    )
    .await
    .map_err(|error| StudioCandidateMaterializationError {
        message: format!("Studio render-sanity repair inference failed: {}", error),
        raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
    })?;
    studio_generation_trace(format!(
        "artifact_generation:render_sanity_repair:ok id={} bytes={}",
        candidate_id,
        repair_output.len()
    ));
    let repair_raw =
        String::from_utf8(repair_output).map_err(|error| StudioCandidateMaterializationError {
            message: format!("Studio render-sanity repair utf8 decode failed: {}", error),
            raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
        })?;
    parse_candidate(&repair_raw).map_err(|error| {
        studio_generation_trace(format!(
            "artifact_generation:render_sanity_repair_parse_error id={} error={} preview={}",
            candidate_id,
            error.message,
            truncate_candidate_failure_preview(&repair_raw, 4000)
                .unwrap_or_else(|| "(empty)".to_string())
        ));
        StudioCandidateMaterializationError {
            message: error.message,
            raw_output_preview: truncate_candidate_failure_preview(&repair_raw, 2000),
        }
    })
}

pub(crate) async fn materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    selected_skills: &[StudioArtifactSelectedSkill],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
    live_preview_observer: Option<StudioArtifactLivePreviewObserver>,
    activity_observer: Option<StudioArtifactActivityObserver>,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let returns_raw_document = direct_author_uses_raw_document(request);
    let max_tokens = materialization_max_tokens_for_execution_strategy(
        request.renderer,
        StudioExecutionStrategy::DirectAuthor,
        runtime_kind,
    );
    let parse_candidate = |raw: &str| {
        parse_direct_author_generated_candidate(raw, request, brief, edit_intent, candidate_id)
    };
    let payload = build_studio_artifact_direct_author_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        selected_skills,
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        runtime_kind,
        returns_raw_document,
    )
    .map_err(|message| StudioCandidateMaterializationError {
        message,
        raw_output_preview: None,
    })?;
    let input =
        serde_json::to_vec(&payload).map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Failed to encode Studio direct-author artifact prompt: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    studio_generation_trace(format!(
        "artifact_generation:direct_author_inference:start id={} prompt_bytes={} temperature={} max_tokens={} raw_document={}",
        candidate_id,
        input.len(),
        temperature,
        max_tokens,
        returns_raw_document
    ));
    let preview_language = studio_swarm_preview_language(request);
    let preview_id = format!("{candidate_id}-live-output");
    let preview_label = "Direct author output".to_string();
    let stop_sequences = direct_author_stop_sequences(request);
    let (token_tx, collector) = spawn_token_stream_preview_collector(
        live_preview_observer.clone(),
        preview_id.clone(),
        preview_label.clone(),
        None,
        None,
        preview_language.clone(),
    );
    let token_stream = Some(token_tx);
    let stream_collector = Some(collector);
    let streaming_runtime = runtime.clone();
    let inference_input = input.clone();
    let inference = async move {
        streaming_runtime
            .execute_inference_streaming(
                [0u8; 32],
                &inference_input,
                InferenceOptions {
                    temperature,
                    json_mode: !returns_raw_document,
                    max_tokens,
                    stop_sequences,
                    ..Default::default()
                },
                token_stream,
            )
            .await
    };
    let output_result = await_direct_author_inference_output(
        inference,
        request,
        runtime_kind,
        stream_collector.as_ref(),
        candidate_id,
    )
    .await;
    let streamed_preview = finish_token_stream_preview_collector(stream_collector).await;
    let inference_error_message = output_result
        .as_ref()
        .err()
        .map(|error| format!("Studio direct-author artifact inference failed: {error}"));
    let recovered_from_partial_stream =
        output_result.is_err() && !streamed_preview.trim().is_empty();
    let raw = match output_result {
        Ok(output) => {
            String::from_utf8(output).map_err(|error| StudioCandidateMaterializationError {
                message: format!(
                    "Studio direct-author artifact utf8 decode failed: {}",
                    error
                ),
                raw_output_preview: truncate_candidate_failure_preview(&streamed_preview, 2000),
            })?
        }
        Err(error) => {
            if streamed_preview.trim().is_empty() {
                return Err(StudioCandidateMaterializationError {
                    message: format!("Studio direct-author artifact inference failed: {}", error),
                    raw_output_preview: None,
                });
            }
            studio_generation_trace(format!(
                "artifact_generation:direct_author_inference:partial_stream_salvage id={} bytes={} error={}",
                candidate_id,
                streamed_preview.len(),
                error
            ));
            emit_direct_author_live_preview(
                live_preview_observer.as_ref(),
                &preview_id,
                &preview_label,
                &preview_language,
                "interrupted",
                &streamed_preview,
                false,
            );
            let salvaged = salvage_interrupted_direct_author_document(request, &streamed_preview);
            if salvaged != streamed_preview {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_inference:interrupted_salvage_normalized id={} original_bytes={} salvaged_bytes={}",
                    candidate_id,
                    streamed_preview.len(),
                    salvaged.len()
                ));
            }
            if returns_raw_document {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
                    && request.renderer == StudioRendererKind::HtmlIframe
                    && request.artifact_class == StudioArtifactClass::Document
                    && direct_author_preview_ready_document(request, &salvaged)
                {
                    if let Some(mut generated) =
                        synthesize_generated_artifact_payload_from_raw_document(&salvaged, request)
                    {
                        super::normalize_generated_artifact_payload(&mut generated, request);
                        super::enrich_generated_artifact_payload(&mut generated, request, brief);
                        generated.notes.push(
                            "provisional preview surfaced from the interrupted streamed draft before continuation/repair"
                                .to_string(),
                        );
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_inference:interrupted_provisional_accept id={} bytes={}",
                            candidate_id,
                            salvaged.len()
                        ));
                        emit_direct_author_live_preview(
                            live_preview_observer.as_ref(),
                            &preview_id,
                            &preview_label,
                            &preview_language,
                            "preview_ready",
                            &salvaged,
                            true,
                        );
                        return Ok(generated);
                    }
                }
                if let Ok(generated) = parse_candidate(&salvaged) {
                    emit_direct_author_live_preview(
                        live_preview_observer.as_ref(),
                        &preview_id,
                        &preview_label,
                        &preview_language,
                        "recovered",
                        &salvaged,
                        true,
                    );
                    return Ok(generated);
                }
                salvaged
            } else {
                salvaged
            }
        }
    };
    match parse_candidate(&raw) {
        Ok(generated) => {
            emit_direct_author_live_preview(
                live_preview_observer.as_ref(),
                &preview_id,
                &preview_label,
                &preview_language,
                if recovered_from_partial_stream {
                    "recovered"
                } else {
                    "completed"
                },
                &raw,
                true,
            );
            Ok(generated)
        }
        Err(first_error) => {
            let mut latest_error = if let Some(inference_error) = inference_error_message {
                format!("{inference_error}; {}", first_error.message)
            } else {
                first_error.message
            };
            let mut latest_raw = raw;
            let mut document_is_incomplete =
                direct_author_document_is_incomplete(request, &latest_raw, &latest_error);
            let mut prefer_semantic_continuation =
                direct_author_should_continue_semantically_underbuilt_document(
                    request,
                    runtime_kind,
                    &latest_raw,
                    &latest_error,
                    recovered_from_partial_stream,
                );
            let mut continuation_needed = document_is_incomplete || prefer_semantic_continuation;
            let mut skip_continuation = returns_raw_document
                && should_skip_direct_author_continuation(
                    request,
                    runtime_kind,
                    &latest_raw,
                    &latest_error,
                );
            studio_generation_trace(format!(
                "artifact_generation:direct_author_inference:parse_failed id={} boundary={} incomplete={} continuation_needed={} skip_continuation={} recovered_partial={} raw_bytes={} error={}{}",
                candidate_id,
                direct_author_has_completion_boundary(request, &latest_raw),
                document_is_incomplete,
                continuation_needed,
                skip_continuation,
                recovered_from_partial_stream,
                latest_raw.len(),
                latest_error.replace('\n', " ").chars().take(220).collect::<String>(),
                direct_author_html_contract_debug_suffix(request, &latest_raw).unwrap_or_default(),
            ));
            if returns_raw_document && !recovered_from_partial_stream && document_is_incomplete {
                let salvaged = salvage_interrupted_direct_author_document(request, &latest_raw);
                if salvaged != latest_raw {
                    studio_generation_trace(format!(
                        "artifact_generation:direct_author_inference:completed_salvage_normalized id={} original_bytes={} salvaged_bytes={}",
                        candidate_id,
                        latest_raw.len(),
                        salvaged.len()
                    ));
                    latest_raw = salvaged;
                    match parse_candidate(&latest_raw) {
                        Ok(generated) => {
                            emit_direct_author_live_preview(
                                live_preview_observer.as_ref(),
                                &preview_id,
                                &preview_label,
                                &preview_language,
                                "recovered",
                                &latest_raw,
                                true,
                            );
                            return Ok(generated);
                        }
                        Err(salvage_error) => {
                            if direct_author_local_html_structural_failure(&salvage_error.message) {
                                latest_error = format!(
                                    "{latest_error}; local closure salvage failed: {}",
                                    salvage_error.message
                                );
                            } else {
                                latest_error = format!(
                                    "{latest_error}; salvaged document remained invalid: {}",
                                    salvage_error.message
                                );
                            }
                        }
                    }
                    document_is_incomplete =
                        direct_author_document_is_incomplete(request, &latest_raw, &latest_error);
                    prefer_semantic_continuation =
                        direct_author_should_continue_semantically_underbuilt_document(
                            request,
                            runtime_kind,
                            &latest_raw,
                            &latest_error,
                            recovered_from_partial_stream,
                        );
                    continuation_needed = document_is_incomplete || prefer_semantic_continuation;
                    skip_continuation = returns_raw_document
                        && should_skip_direct_author_continuation(
                            request,
                            runtime_kind,
                            &latest_raw,
                            &latest_error,
                        );
                }
            }
            for (rescue_strategy, rescued_document) in
                try_local_html_structural_rescue(request, runtime_kind, &latest_raw, &latest_error)
            {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_inference:local_structural_rescue id={} strategy={} existing_bytes={} repaired_bytes={}",
                    candidate_id,
                    rescue_strategy,
                    latest_raw.len(),
                    rescued_document.len()
                ));
                match parse_candidate(&rescued_document) {
                    Ok(generated) => {
                        emit_direct_author_live_preview(
                            live_preview_observer.as_ref(),
                            &preview_id,
                            &preview_label,
                            &preview_language,
                            "recovered",
                            &rescued_document,
                            true,
                        );
                        return Ok(generated);
                    }
                    Err(rescue_error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_inference:local_structural_rescue_failed id={} strategy={} error={}",
                            candidate_id,
                            rescue_strategy,
                            rescue_error.message.replace('\n', " ")
                        ));
                        latest_error = format!(
                            "{latest_error}; local structural rescue ({rescue_strategy}) failed: {}",
                            rescue_error.message
                        );
                        latest_raw = rescued_document;
                        document_is_incomplete = direct_author_document_is_incomplete(
                            request,
                            &latest_raw,
                            &latest_error,
                        );
                        prefer_semantic_continuation =
                            direct_author_should_continue_semantically_underbuilt_document(
                                request,
                                runtime_kind,
                                &latest_raw,
                                &latest_error,
                                recovered_from_partial_stream,
                            );
                        continuation_needed =
                            document_is_incomplete || prefer_semantic_continuation;
                        skip_continuation = returns_raw_document
                            && should_skip_direct_author_continuation(
                                request,
                                runtime_kind,
                                &latest_raw,
                                &latest_error,
                            );
                    }
                }
            }
            if let Some((rescued_document, rescue_strategy)) =
                try_local_html_interaction_rescue(request, runtime_kind, &latest_raw, &latest_error)
            {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_inference:local_interaction_rescue id={} strategy={} existing_bytes={} repaired_bytes={}",
                    candidate_id,
                    rescue_strategy,
                    latest_raw.len(),
                    rescued_document.len()
                ));
                match parse_candidate(&rescued_document) {
                    Ok(generated) => {
                        emit_direct_author_live_preview(
                            live_preview_observer.as_ref(),
                            &preview_id,
                            &preview_label,
                            &preview_language,
                            "recovered",
                            &rescued_document,
                            true,
                        );
                        return Ok(generated);
                    }
                    Err(rescue_error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_inference:local_interaction_rescue_failed id={} strategy={} error={}",
                            candidate_id,
                            rescue_strategy,
                            rescue_error.message.replace('\n', " ")
                        ));
                        latest_error = format!(
                            "{latest_error}; local interaction rescue ({rescue_strategy}) failed: {}",
                            rescue_error.message
                        );
                        latest_raw = rescued_document;
                        document_is_incomplete = direct_author_document_is_incomplete(
                            request,
                            &latest_raw,
                            &latest_error,
                        );
                        prefer_semantic_continuation =
                            direct_author_should_continue_semantically_underbuilt_document(
                                request,
                                runtime_kind,
                                &latest_raw,
                                &latest_error,
                                recovered_from_partial_stream,
                            );
                        continuation_needed =
                            document_is_incomplete || prefer_semantic_continuation;
                        skip_continuation = returns_raw_document
                            && should_skip_direct_author_continuation(
                                request,
                                runtime_kind,
                                &latest_raw,
                                &latest_error,
                            );
                    }
                }
            }
            if skip_continuation {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_inference:skip_continuation id={} raw_bytes={} reason=prefer_full_document_repair",
                    candidate_id,
                    latest_raw.len()
                ));
            }
            let mut preview_status =
                if returns_raw_document && continuation_needed && !skip_continuation {
                    "continuing"
                } else {
                    "repairing"
                };
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
                && request.renderer == StudioRendererKind::HtmlIframe
                && request.artifact_class == StudioArtifactClass::Document
                && returns_raw_document
            {
                match parse_direct_author_provisional_candidate_from_snapshot(
                    &latest_raw,
                    request,
                    brief,
                    candidate_id,
                ) {
                    Ok(generated) => {
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_inference:provisional_snapshot_accept id={} bytes={} continuation_needed={} skip_continuation={}",
                            candidate_id,
                            latest_raw.len(),
                            continuation_needed,
                            skip_continuation
                        ));
                        emit_direct_author_live_preview(
                            live_preview_observer.as_ref(),
                            &preview_id,
                            &preview_label,
                            &preview_language,
                            "preview_ready",
                            &latest_raw,
                            true,
                        );
                        return Ok(generated);
                    }
                    Err(error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:direct_author_inference:provisional_snapshot_rejected id={} bytes={} reason={}",
                            candidate_id,
                            latest_raw.len(),
                            error.message
                        ));
                    }
                }
            }
            emit_direct_author_live_preview(
                live_preview_observer.as_ref(),
                &preview_id,
                &preview_label,
                &preview_language,
                preview_status,
                &latest_raw,
                false,
            );
            let repair_runtime = materialization_repair_runtime_for_request(
                request,
                &runtime,
                repair_runtime.as_ref(),
            );
            let repair_runtime_kind = repair_runtime.studio_runtime_provenance().kind;
            if returns_raw_document {
                for continuation_attempt in
                    0..direct_author_continuation_pass_limit(request, runtime_kind)
                {
                    if !continuation_needed || skip_continuation {
                        break;
                    }
                    emit_direct_author_live_preview(
                        live_preview_observer.as_ref(),
                        &preview_id,
                        &preview_label,
                        &preview_language,
                        "continuing",
                        &latest_raw,
                        false,
                    );
                    let continuation_payload =
                        build_studio_artifact_direct_author_continuation_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            brief,
                            selected_skills,
                            &latest_raw,
                            &latest_error,
                            runtime_kind,
                        );
                    let continuation_input =
                        serde_json::to_vec(&continuation_payload).map_err(|error| {
                            StudioCandidateMaterializationError {
                                message: format!(
                                    "Failed to encode Studio direct-author continuation prompt: {}",
                                    error
                                ),
                                raw_output_preview: truncate_candidate_failure_preview(
                                    &latest_raw,
                                    2000,
                                ),
                            }
                        })?;
                    let continuation_output = execute_direct_author_follow_up_inference(
                        runtime.clone(),
                        request,
                        runtime_kind,
                        &continuation_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: !direct_author_follow_up_prefers_raw_output(
                                request,
                                runtime_kind,
                            ),
                            max_tokens: direct_author_follow_up_max_tokens(
                                request,
                                runtime_kind,
                                "continuation",
                            ),
                            ..Default::default()
                        },
                        activity_observer.clone(),
                        "continuation",
                    )
                    .await;
                    let continuation_output = match continuation_output {
                        Ok(output) => output,
                        Err(error) => {
                            latest_error = format!(
                                "{latest_error}; continuation attempt {} inference failed: {error}",
                                continuation_attempt + 1
                            );
                            break;
                        }
                    };
                    let continuation_raw = match String::from_utf8(continuation_output) {
                        Ok(raw) => raw,
                        Err(error) => {
                            latest_error = format!(
                                "{latest_error}; continuation attempt {} utf8 decode failed: {error}",
                                continuation_attempt + 1
                            );
                            break;
                        }
                    };
                    match parse_studio_direct_author_recovery_payload(request, &continuation_raw) {
                        Ok(recovery_payload) => {
                            latest_raw = apply_direct_author_recovery_payload(
                                &latest_raw,
                                &recovery_payload,
                            );
                            emit_direct_author_live_preview(
                                live_preview_observer.as_ref(),
                                &preview_id,
                                &preview_label,
                                &preview_language,
                                "continuing",
                                &latest_raw,
                                false,
                            );
                            match parse_candidate(&latest_raw) {
                                Ok(generated) => {
                                    emit_direct_author_live_preview(
                                        live_preview_observer.as_ref(),
                                        &preview_id,
                                        &preview_label,
                                        &preview_language,
                                        "recovered",
                                        &latest_raw,
                                        true,
                                    );
                                    return Ok(generated);
                                }
                                Err(continuation_error) => {
                                    latest_error = format!(
                                        "{latest_error}; continuation attempt {} failed: {}",
                                        continuation_attempt + 1,
                                        continuation_error.message
                                    );
                                    document_is_incomplete = direct_author_document_is_incomplete(
                                        request,
                                        &latest_raw,
                                        &latest_error,
                                    );
                                    prefer_semantic_continuation =
                                        direct_author_should_continue_semantically_underbuilt_document(
                                            request,
                                            runtime_kind,
                                            &latest_raw,
                                            &latest_error,
                                            recovered_from_partial_stream,
                                        );
                                    continuation_needed =
                                        document_is_incomplete || prefer_semantic_continuation;
                                    skip_continuation = should_skip_direct_author_continuation(
                                        request,
                                        runtime_kind,
                                        &latest_raw,
                                        &latest_error,
                                    );
                                }
                            }
                        }
                        Err(recovery_error) => {
                            latest_error = format!(
                                "{latest_error}; continuation attempt {} failed: {}",
                                continuation_attempt + 1,
                                recovery_error
                            );
                        }
                    }
                }
            }

            if returns_raw_document {
                for repair_attempt in
                    0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
                {
                    preview_status = "repairing";
                    emit_direct_author_live_preview(
                        live_preview_observer.as_ref(),
                        &preview_id,
                        &preview_label,
                        &preview_language,
                        preview_status,
                        &latest_raw,
                        false,
                    );
                    let repair_payload =
                        build_studio_artifact_direct_author_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            brief,
                            selected_skills,
                            &latest_raw,
                            &latest_error,
                            repair_runtime_kind,
                        );
                    let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Studio direct-author repair prompt: {}",
                                error
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        }
                    })?;
                    let repair_output = execute_direct_author_follow_up_inference(
                        repair_runtime.clone(),
                        request,
                        repair_runtime_kind,
                        &repair_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: !direct_author_follow_up_prefers_raw_output(
                                request,
                                repair_runtime_kind,
                            ),
                            max_tokens: direct_author_follow_up_max_tokens(
                                request,
                                repair_runtime_kind,
                                "repair",
                            ),
                            ..Default::default()
                        },
                        activity_observer.clone(),
                        "repair",
                    )
                    .await;
                    let repair_output = match repair_output {
                        Ok(output) => output,
                        Err(error) => {
                            latest_error = format!(
                                "{latest_error}; repair attempt {} inference failed: {error}",
                                repair_attempt + 1
                            );
                            continue;
                        }
                    };
                    let repair_raw = match String::from_utf8(repair_output) {
                        Ok(raw) => raw,
                        Err(error) => {
                            latest_error = format!(
                                "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                                repair_attempt + 1
                            );
                            continue;
                        }
                    };
                    match parse_studio_direct_author_recovery_payload(request, &repair_raw) {
                        Ok(recovery_payload) => {
                            let repaired_document = apply_direct_author_recovery_payload(
                                &latest_raw,
                                &recovery_payload,
                            );
                            let repair_mode =
                                direct_author_recovery_mode_label(&recovery_payload.mode);
                            if recovery_payload.mode != StudioDirectAuthorRecoveryMode::FullDocument
                            {
                                studio_generation_trace(format!(
                                    "artifact_generation:direct_author_inference:repair_mode_fallback id={} attempt={} mode={} existing_bytes={} repaired_bytes={}",
                                    candidate_id,
                                    repair_attempt + 1,
                                    repair_mode,
                                    latest_raw.len(),
                                    repaired_document.len()
                                ));
                            }
                            emit_direct_author_live_preview(
                                live_preview_observer.as_ref(),
                                &preview_id,
                                &preview_label,
                                &preview_language,
                                preview_status,
                                &repaired_document,
                                false,
                            );
                            match parse_candidate(&repaired_document) {
                                Ok(generated) => {
                                    emit_direct_author_live_preview(
                                        live_preview_observer.as_ref(),
                                        &preview_id,
                                        &preview_label,
                                        &preview_language,
                                        "recovered",
                                        &repaired_document,
                                        true,
                                    );
                                    return Ok(generated);
                                }
                                Err(repair_error) => {
                                    latest_raw = repaired_document;
                                    latest_error = format!(
                                        "{latest_error}; repair attempt {} failed after mode={}: {}",
                                        repair_attempt + 1,
                                        repair_mode,
                                        repair_error.message
                                    );
                                }
                            }
                        }
                        Err(recovery_error) => {
                            latest_error = format!(
                                "{latest_error}; repair attempt {} failed: {}",
                                repair_attempt + 1,
                                recovery_error
                            );
                        }
                    }
                }
            } else {
                for repair_attempt in
                    0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
                {
                    preview_status = "repairing";
                    emit_direct_author_live_preview(
                        live_preview_observer.as_ref(),
                        &preview_id,
                        &preview_label,
                        &preview_language,
                        preview_status,
                        &latest_raw,
                        false,
                    );
                    let repair_payload =
                        build_studio_artifact_materialization_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            brief,
                            None,
                            None,
                            &[],
                            &[],
                            None,
                            refinement,
                            candidate_id,
                            candidate_seed,
                            &latest_raw,
                            &latest_error,
                            repair_runtime_kind,
                        )
                        .map_err(|message| {
                            StudioCandidateMaterializationError {
                                message,
                                raw_output_preview: truncate_candidate_failure_preview(
                                    &latest_raw,
                                    2000,
                                ),
                            }
                        })?;
                    let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Studio direct-author repair prompt: {}",
                                error
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        }
                    })?;
                    let repair_output = execute_direct_author_follow_up_inference(
                        repair_runtime.clone(),
                        request,
                        repair_runtime_kind,
                        &repair_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: true,
                            max_tokens: direct_author_follow_up_max_tokens(
                                request,
                                repair_runtime_kind,
                                "repair",
                            ),
                            ..Default::default()
                        },
                        activity_observer.clone(),
                        "repair",
                    )
                    .await;
                    let repair_output = match repair_output {
                        Ok(output) => output,
                        Err(error) => {
                            latest_error = format!(
                                "{latest_error}; repair attempt {} inference failed: {error}",
                                repair_attempt + 1
                            );
                            continue;
                        }
                    };
                    let repair_raw = match String::from_utf8(repair_output) {
                        Ok(raw) => raw,
                        Err(error) => {
                            latest_error = format!(
                                "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                                repair_attempt + 1
                            );
                            continue;
                        }
                    };
                    match parse_candidate(&repair_raw) {
                        Ok(generated) => {
                            emit_direct_author_live_preview(
                                live_preview_observer.as_ref(),
                                &preview_id,
                                &preview_label,
                                &preview_language,
                                "recovered",
                                &repair_raw,
                                true,
                            );
                            return Ok(generated);
                        }
                        Err(repair_error) => {
                            latest_raw = repair_raw;
                            latest_error = format!(
                                "{latest_error}; repair attempt {} failed: {}",
                                repair_attempt + 1,
                                repair_error.message
                            );
                        }
                    }
                }
            }

            emit_direct_author_live_preview(
                live_preview_observer.as_ref(),
                &preview_id,
                &preview_label,
                &preview_language,
                "failed",
                &latest_raw,
                true,
            );

            Err(StudioCandidateMaterializationError {
                message: latest_error,
                raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
            })
        }
    }
}

pub async fn materialize_studio_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
) -> Result<StudioGeneratedArtifactPayload, String> {
    materialize_studio_artifact_candidate_with_runtime_detailed(
        runtime,
        None,
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        temperature,
        None,
    )
    .await
    .map_err(|error| error.message)
}

pub(crate) async fn refine_studio_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    validation: &StudioArtifactValidationResult,
    candidate_id: &str,
    candidate_seed: u64,
    refinement_temperature: f32,
    activity_observer: Option<StudioArtifactActivityObserver>,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<StudioGeneratedArtifactPayload, String> {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:refine_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:refine_contract_state:enriched",
            request,
            candidate_id,
            &generated,
        );
        super::validate_generated_artifact_payload_against_brief_with_edit_intent(
            &generated,
            request,
            brief,
            edit_intent,
        )?;
        Ok(generated)
    };
    let payload = build_studio_artifact_candidate_refinement_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        candidate,
        render_evaluation,
        validation,
        candidate_id,
        candidate_seed,
        runtime_kind,
    )?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Studio artifact refinement prompt: {error}"))?;
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    studio_generation_trace(format!(
        "artifact_generation:refine_inference:start id={} prompt_bytes={} temperature={} max_tokens={}",
        candidate_id,
        input.len(),
        refinement_temperature,
        materialization_max_tokens_for_runtime(request.renderer, runtime_kind)
    ));
    let output = execute_materialization_inference(
        runtime.clone(),
        request,
        runtime_kind,
        &input,
        InferenceOptions {
            temperature: refinement_temperature,
            json_mode: true,
            max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
            ..Default::default()
        },
        activity_observer.clone(),
        "refine_inference",
        false,
    )
    .await
    .map_err(|error| format!("Studio artifact refinement inference failed: {error}"))?;
    studio_generation_trace(format!(
        "artifact_generation:refine_inference:ok id={} bytes={}",
        candidate_id,
        output.len()
    ));
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio artifact refinement utf8 decode failed: {error}"))?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            studio_generation_trace(format!(
                "artifact_generation:refine_parse_error id={} error={} preview={}",
                candidate_id,
                first_error,
                truncate_candidate_failure_preview(&raw, 1200)
                    .unwrap_or_else(|| "(empty)".to_string())
            ));
            let mut latest_error = first_error;
            let mut latest_raw = raw;

            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, runtime_kind)
            {
                let repair_payload =
                    build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
                        title,
                        intent,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        selected_skills,
                        retrieved_exemplars,
                        edit_intent,
                        refinement,
                        candidate,
                        validation,
                        candidate_id,
                        candidate_seed,
                        &latest_raw,
                        &latest_error,
                        runtime_kind,
                    )?;
                let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                    format!("Failed to encode Studio artifact refinement repair prompt: {error}")
                })?;
                studio_generation_trace(format!(
                    "artifact_generation:refine_repair:start id={} attempt={} prompt_bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_input.len()
                ));
                let repair_output = execute_materialization_inference(
                    runtime.clone(),
                    request,
                    runtime_kind,
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: materialization_max_tokens_for_runtime(
                            request.renderer,
                            runtime_kind,
                        ),
                        ..Default::default()
                    },
                    activity_observer.clone(),
                    "refine_repair",
                    true,
                )
                .await
                .map_err(|error| {
                    format!(
                        "{latest_error}; refinement repair attempt {} inference failed: {error}",
                        repair_attempt + 1
                    )
                })?;
                studio_generation_trace(format!(
                    "artifact_generation:refine_repair:ok id={} attempt={} bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_output.len()
                ));
                let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                    format!(
                        "{latest_error}; refinement repair attempt {} utf8 decode failed: {error}",
                        repair_attempt + 1
                    )
                })?;
                match parse_candidate(&repair_raw) {
                    Ok(generated) => return Ok(generated),
                    Err(repair_error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:refine_repair_parse_error id={} attempt={} error={} preview={}",
                            candidate_id,
                            repair_attempt + 1,
                            repair_error,
                            truncate_candidate_failure_preview(&repair_raw, 1200)
                                .unwrap_or_else(|| "(empty)".to_string())
                        ));
                        latest_raw = repair_raw;
                        latest_error = format!(
                            "{latest_error}; refinement repair attempt {} failed: {repair_error}",
                            repair_attempt + 1
                        );
                    }
                }
            }

            Err(latest_error)
        }
    }
}
