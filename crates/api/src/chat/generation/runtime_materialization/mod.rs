use super::*;
use crate::chat::payload::{
    extract_authored_document_body, renderer_document_completeness_failure,
    renderer_primary_view_contract_failure,
    synthesize_generated_artifact_payload_from_raw_document,
};
use ioi_types::error::VmError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChatDirectAuthorRecoveryMode {
    Suffix,
    FullDocument,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ChatDirectAuthorRecoveryPayload {
    mode: ChatDirectAuthorRecoveryMode,
    content: String,
}

fn parse_chat_direct_author_recovery_payload(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Result<ChatDirectAuthorRecoveryPayload, String> {
    let parse_json =
        |candidate: &str| -> Result<ChatDirectAuthorRecoveryPayload, serde_json::Error> {
            serde_json::from_str(candidate)
        };

    let payload = match parse_json(raw).or_else(|_| {
        let extracted = super::extract_first_json_object(raw)
            .ok_or_else(|| "Chat direct-author recovery output missing JSON payload".to_string())?;
        parse_json(&extracted).map_err(|error| error.to_string())
    }) {
        Ok(payload) => payload,
        Err(error) => coerce_direct_author_recovery_payload_from_raw_output(request, raw)
            .ok_or_else(|| {
                format!("Failed to parse Chat direct-author recovery payload: {error}")
            })?,
    };

    if payload.content.trim().is_empty() {
        return Err("Chat direct-author recovery payload content was empty".to_string());
    }

    Ok(payload)
}

fn coerce_direct_author_recovery_payload_from_raw_output(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Option<ChatDirectAuthorRecoveryPayload> {
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
        if request.renderer == ChatRendererKind::HtmlIframe {
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
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed
        )
        || matches!(request.renderer, ChatRendererKind::HtmlIframe)
            && content.to_ascii_lowercase().contains("<html")
        || matches!(request.renderer, ChatRendererKind::Svg)
            && content.to_ascii_lowercase().contains("<svg")
    {
        ChatDirectAuthorRecoveryMode::FullDocument
    } else {
        ChatDirectAuthorRecoveryMode::Suffix
    };

    if mode == ChatDirectAuthorRecoveryMode::FullDocument && content.len() != raw_document.len() {
        chat_generation_trace(format!(
            "artifact_generation:direct_author_recovery:extracted_full_document renderer={:?} raw_bytes={} extracted_bytes={}",
            request.renderer,
            raw_document.len(),
            content.len()
        ));
    }

    Some(ChatDirectAuthorRecoveryPayload { mode, content })
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
    payload: &ChatDirectAuthorRecoveryPayload,
) -> String {
    match payload.mode {
        ChatDirectAuthorRecoveryMode::Suffix => {
            merge_direct_author_document(existing_document, &payload.content)
        }
        ChatDirectAuthorRecoveryMode::FullDocument => payload.content.clone(),
    }
}

fn emit_direct_author_live_preview(
    observer: Option<&ChatArtifactLivePreviewObserver>,
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
        observer(chat_swarm_live_preview(
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

fn direct_author_recovery_mode_label(mode: &ChatDirectAuthorRecoveryMode) -> &'static str {
    match mode {
        ChatDirectAuthorRecoveryMode::Suffix => "suffix",
        ChatDirectAuthorRecoveryMode::FullDocument => "full_document",
    }
}

fn local_runner_unexpected_stop_error(error: &str) -> bool {
    error
        .to_ascii_lowercase()
        .contains("model runner has unexpectedly stopped")
}

fn materialization_retry_options(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    options: &InferenceOptions,
) -> InferenceOptions {
    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && options.max_tokens > 2200
    {
        let mut reduced = options.clone();
        reduced.max_tokens = 2200;
        return reduced;
    }

    options.clone()
}

fn should_skip_direct_author_continuation(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    raw: &str,
    error_message: &str,
) -> bool {
    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && request.artifact_class == ChatArtifactClass::Document
        && direct_author_uses_raw_document(request)
    {
        return direct_author_has_completion_boundary(request, raw);
    }

    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && direct_author_uses_raw_document(request)
        && (direct_author_local_html_interaction_failure(error_message)
            || direct_author_local_html_semantic_underbuild_failure(error_message)
            || direct_author_local_html_interaction_truth_failure(error_message))
    {
        return true;
    }

    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && direct_author_uses_raw_document(request)
        && direct_author_document_is_incomplete(request, raw, error_message)
    {
        return direct_author_has_stream_settle_boundary(request, raw)
            && (raw.len() >= 6000
                || (raw.to_ascii_lowercase().contains("<main")
                    && count_html_nonempty_sectioning_elements(&raw.to_ascii_lowercase()) >= 3));
    }
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
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
        ChatArtifactDeliverableShape, ChatArtifactPersistenceMode, ChatOutcomeArtifactScope,
        ChatOutcomeArtifactVerificationRequest,
    };

    fn sample_html_document_request() -> ChatOutcomeArtifactRequest {
        ChatOutcomeArtifactRequest {
            artifact_class: ChatArtifactClass::Document,
            deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
            renderer: ChatRendererKind::HtmlIframe,
            presentation_surface: ChatPresentationSurface::SidePanel,
            persistence: ChatArtifactPersistenceMode::ArtifactScoped,
            execution_substrate: ChatExecutionSubstrate::ClientSandbox,
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: ChatOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: false,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: ChatOutcomeArtifactVerificationRequest {
                require_render: false,
                require_build: false,
                require_preview: false,
                require_export: false,
                require_diff_review: false,
            },
        }
    }

    fn sample_brief() -> ChatArtifactBrief {
        ChatArtifactBrief {
            audience: "General users".to_string(),
            job_to_be_done: "Explain the requested concept.".to_string(),
            subject_domain: "Education".to_string(),
            artifact_thesis: "A compact explanatory artifact.".to_string(),
            required_concepts: vec!["Quantum computers".to_string()],
            required_interactions: Vec::new(),
            query_profile: None,
            visual_tone: Vec::new(),
            factual_anchors: Vec::new(),
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        }
    }

    #[test]
    fn local_document_html_with_boundary_skips_continuation() {
        let request = sample_html_document_request();
        let raw = "<!doctype html><html><body><main><section><h1>Quantum</h1></section></main></body></html>";
        let error = "HTML iframe artifacts must contain a closed <main> region.";

        assert!(should_skip_direct_author_continuation(
            &request,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
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
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            raw,
            error,
        ));
    }

    #[test]
    fn local_interactive_html_closed_main_settles_without_full_html_stop() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computers</h1><p>Compare qubits, gates, and measurement.</p></section>
          <section><h2>Explore</h2><p id="detail-content">Use this authored response region to explain the selected quantum idea, including how superposition keeps a qubit in a blend of possible outcomes until measurement, how gates rotate that state, and why a small interaction can still be added by repair if the first local stream stopped after the visible main region. The important runtime behavior is that a clearly closed, request-shaped main document should not keep the user staring at Stop while the model waits for a final html token that may never arrive. This paragraph intentionally keeps the stream substantial enough to represent the local model artifact observed in the GUI probe.</p><p>The runtime can normalize the terminal body and html tags after the stream settles, then pass the document through the usual validation and repair path.</p></section>
        </main>"#;

        assert!(
            direct_author_stream_settle_snapshot(&request, raw).is_some(),
            "a closed, complete-enough <main> stream should settle instead of holding the Stop state open until </html>"
        );
    }

    #[test]
    fn local_interactive_html_closed_main_ignores_trailing_script_start_for_stream_settle() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Understanding quantum computers</h1><p>Qubits, gates, superposition, and measurement are introduced with enough authored copy to preview the artifact.</p></section>
          <section><h2>Explore</h2><p id="detail-content">This visible response region is populated before script repair. It explains how qubits keep probability amplitudes, how gates transform state, and how measurement collapses a distribution into a classical result. The authored copy is already substantial enough for a first preview, and a local repair pass can still add controls or rescue script wiring after the stream settles. That is the important behavior for desktop local GPU runs: the chat UI should not keep showing Stop only because the model began a trailing script tag after completing the visible main artifact.</p></section>
        </main>

        <script>"#;

        let settled = direct_author_stream_settle_snapshot(&request, raw)
            .expect("closed main should settle even when the stream already started a script tag");

        assert!(
            settled.ends_with("</body></html>"),
            "settled snapshot should normalize terminal body/html closure: {settled}"
        );
        assert!(
            !settled.to_ascii_lowercase().contains("<script"),
            "settled snapshot should drop the unfinished script fragment: {settled}"
        );
    }

    #[test]
    fn local_interactive_html_salvage_prefers_renderable_main_over_partial_script() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computer playground</h1><p>Explore qubits, gates, amplitudes, and measurement with a visible first paint.</p></section>
          <section><h2>Live evidence</h2><p id="feedback-text">The response region already explains that measuring a qubit collapses probability amplitudes into one classical state, while gates transform the probability distribution before measurement. This is enough authored content for a safe local preview.</p></section>
        </main>
        <div class="overlay" id="overlay"><div class="modal"><p id="overlay-text">Select a tab to learn more.</p></div></div>
        <script>
          const content = {
            intro: {
              heading: "What is a Qubit?",
              text: `Classical computers use bits that are either 0 or 1.<br/>A qubit is a quantum"#;

        let salvaged = salvage_interrupted_direct_author_document(&request, raw);

        assert!(
            salvaged.ends_with("</body></html>"),
            "salvage should normalize a closed renderable prefix: {salvaged}"
        );
        assert!(
            !salvaged.to_ascii_lowercase().contains("<script"),
            "salvage should discard the unfinished script tail: {salvaged}"
        );
        assert!(
            !direct_author_document_is_incomplete(&request, &salvaged, ""),
            "salvaged prefix should be structurally complete enough for validation/repair"
        );
    }

    #[test]
    fn local_interactive_html_raw_document_accepts_without_semantic_repair_heuristics() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computer playground</h1><p>Explore qubits, gates, amplitudes, and measurement with a compact authored surface.</p></section>
        </main></body></html>"#;

        let generated =
            parse_direct_author_generated_candidate(raw, &request, &sample_brief(), None, "clean")
                .expect(
                    "raw direct-author HTML should package without interaction-count heuristics",
                );
        let body = &generated.files[0].body;

        assert!(body.contains("Quantum computer playground"));
        assert!(
            !body.contains("data-ioi-local-rescue"),
            "clean direct-author mode must not inject local heuristic rescue wiring"
        );
        assert!(generated
            .notes
            .iter()
            .any(|note| note.contains("without semantic repair heuristics")));
    }

    #[test]
    fn local_interactive_html_direct_author_budget_allows_structural_completion() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;

        assert_eq!(
            materialization_max_tokens_for_execution_strategy(
                request.renderer,
                ChatExecutionStrategy::DirectAuthor,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            3600
        );
        assert_eq!(
            direct_author_stream_timeout_for_request(
                &request,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            Some(Duration::from_secs(220))
        );
    }

    #[test]
    fn local_interactive_html_prefers_complete_stream_buffer_over_return_buffer() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let returned_raw =
            "<!doctype html><html><body><main><section><h1>Quantum</h1><p>unfinished";
        let streamed_raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computers</h1><p>Explore qubits, gates, amplitudes, and measurement.</p></section>
        </main></body></html>"#;

        let candidates =
            direct_author_raw_document_parse_candidates(&request, returned_raw, streamed_raw);

        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.contains("</main></body></html>")),
            "stream collector should remain available as a raw structural candidate"
        );
        assert!(candidates.iter().any(|candidate| {
            parse_direct_author_generated_candidate(
                candidate,
                &request,
                &sample_brief(),
                None,
                "stream",
            )
            .is_ok()
        }));
    }
}

fn direct_author_has_stream_settle_boundary(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> bool {
    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            let normalized = normalize_html_terminal_closure(raw);
            !direct_author_document_is_incomplete(request, &normalized, "")
        }
        _ => direct_author_has_completion_boundary(request, raw),
    }
}

fn direct_author_renderable_html_prefix(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return None;
    }

    let lower = raw.to_ascii_lowercase();
    for boundary in ["</html>", "</body>", "</script>", "</main>"] {
        let Some(index) = lower.rfind(boundary) else {
            continue;
        };
        let candidate = raw[..index + boundary.len()].trim_end();
        let normalized_candidate = normalize_html_terminal_closure(candidate);
        if !direct_author_document_is_incomplete(request, &normalized_candidate, "") {
            return Some(normalized_candidate);
        }
    }

    None
}

fn direct_author_preview_ready_document(request: &ChatOutcomeArtifactRequest, raw: &str) -> bool {
    if request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::Document
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
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    let boundary = direct_author_completion_boundary(request)?;
    let lower_raw = raw.to_ascii_lowercase();
    let lower_boundary = boundary.to_ascii_lowercase();
    let boundary_index = lower_raw.find(&lower_boundary)?;
    Some(raw[..boundary_index + boundary.len()].to_string())
}

fn direct_author_stream_settle_snapshot(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    direct_author_completed_document_prefix(request, raw)
        .or_else(|| direct_author_renderable_html_prefix(request, raw))
        .or_else(|| direct_author_has_stream_settle_boundary(request, raw).then(|| raw.to_string()))
}

fn direct_author_idle_settle_snapshot(request: &ChatOutcomeArtifactRequest, raw: &str) -> String {
    if let Some(completed) = direct_author_completed_document_prefix(request, raw)
        .or_else(|| direct_author_renderable_html_prefix(request, raw))
    {
        return completed.trim_end().to_string();
    }

    raw.trim_end().to_string()
}

fn direct_author_can_fast_finish_on_idle_snapshot(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> bool {
    match request.renderer {
        ChatRendererKind::HtmlIframe => !direct_author_document_is_incomplete(request, raw, ""),
        _ => direct_author_has_stream_settle_boundary(request, raw),
    }
}

fn direct_author_html_contract_debug_suffix(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Option<String> {
    if request.renderer != ChatRendererKind::HtmlIframe {
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    raw: &str,
    error_message: &str,
    _recovered_from_partial_stream: bool,
) -> bool {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::InteractiveSingleFile
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::InteractiveSingleFile
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::InteractiveSingleFile
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Vec<(&'static str, String)> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
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
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
        "IOI_CHAT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_stream_timeout() {
        return Some(timeout);
    }

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_secs(220)),
        ChatRendererKind::Svg => Some(Duration::from_secs(90)),
        ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed => {
            Some(Duration::from_secs(30))
        }
        _ => None,
    }
}

fn configured_direct_author_follow_up_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
        "IOI_CHAT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
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
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS",
        "IOI_CHAT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS",
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_follow_up_timeout() {
        return Some(timeout);
    }

    let local_runtime = runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime;
    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(if local_runtime {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(90)
        }),
        ChatRendererKind::Svg => Some(if local_runtime {
            Duration::from_secs(45)
        } else {
            Duration::from_secs(60)
        }),
        ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed => {
            Some(if local_runtime {
                Duration::from_secs(15)
            } else {
                Duration::from_secs(30)
            })
        }
        _ => Some(if local_runtime {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(40)
        }),
    }
}

fn direct_author_terminal_boundary_settle_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_millis(650)),
        ChatRendererKind::Svg => Some(Duration::from_millis(400)),
        _ => None,
    }
}

fn direct_author_terminal_idle_settle_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_idle_settle_timeout() {
        return Some(timeout);
    }

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_millis(1800)),
        ChatRendererKind::Svg => Some(Duration::from_millis(900)),
        _ => None,
    }
}

fn configured_materialization_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_MATERIALIZATION_TIMEOUT_MS",
        "IOI_CHAT_MATERIALIZATION_TIMEOUT_MS",
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
        "AUTOPILOT_CHAT_ARTIFACT_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS",
        "IOI_CHAT_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS",
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    follow_up: bool,
) -> Option<Duration> {
    let configured_timeout = if follow_up {
        configured_materialization_follow_up_timeout()
    } else {
        configured_materialization_timeout()
    };

    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
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

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match (request.renderer, follow_up) {
        (ChatRendererKind::HtmlIframe, true) => Some(Duration::from_secs(45)),
        (ChatRendererKind::HtmlIframe, false) => Some(Duration::from_secs(90)),
        (ChatRendererKind::Svg, true) => Some(Duration::from_secs(45)),
        (ChatRendererKind::Svg, false) => Some(Duration::from_secs(75)),
        (
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed,
            true,
        ) => Some(Duration::from_secs(15)),
        (
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed,
            false,
        ) => Some(Duration::from_secs(25)),
        (_, true) => Some(Duration::from_secs(20)),
        (_, false) => Some(Duration::from_secs(45)),
    }
}

async fn execute_materialization_inference(
    runtime: Arc<dyn InferenceRuntime>,
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    input: &[u8],
    options: InferenceOptions,
    activity_observer: Option<ChatArtifactActivityObserver>,
    trace_label: &str,
    follow_up: bool,
) -> Result<Vec<u8>, String> {
    let retry_limit = if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
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
                        chat_generation_trace(format!(
                            "artifact_generation:{trace_label}:timeout renderer={:?} timeout_ms={}",
                            request.renderer,
                            limit.as_millis()
                        ));
                        Err(format!(
                            "Chat artifact {trace_label} timed out after {}ms",
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
                chat_generation_trace(format!(
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
        "Chat artifact {trace_label} failed without returning an output payload"
    ))
}

async fn await_direct_author_inference_output<F>(
    inference: F,
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    collector: Option<&ChatTokenStreamPreviewCollector>,
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
                chat_generation_trace(format!(
                    "artifact_generation:direct_author_inference:boundary_fast_finish id={} bytes={} settle_ms=timeout_edge",
                    candidate_id,
                    snapshot.len()
                ));
                inference_task.abort();
                return Ok(snapshot.into_bytes());
            }

            chat_generation_trace(format!(
                "artifact_generation:direct_author_inference:timeout id={} timeout_ms={}",
                candidate_id,
                limit.as_millis()
            ));
            inference_task.abort();
            return Err(VmError::HostError(format!(
                "Chat direct-author artifact inference timed out after {}s",
                limit.as_secs()
            )));
        }

        let remaining = limit.saturating_sub(elapsed);
        tokio::select! {
            result = &mut inference_task => {
                return result
                    .map_err(|error| VmError::HostError(format!("Chat direct-author inference task failed: {error}")))?
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
                    chat_generation_trace(format!(
                        "artifact_generation:direct_author_inference:stream_progress id={} bytes={} settle_candidate_bytes={}",
                        candidate_id,
                        snapshot.len(),
                        settle_len
                    ));
                    last_progress_trace_len = snapshot.len();
                    last_progress_trace_at = now;
                }

                if settle_len > 0 && settle_len != last_settle_trace_len {
                    chat_generation_trace(format!(
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
                        chat_generation_trace(format!(
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
                    chat_generation_trace(format!(
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    trace_label: &str,
) -> u32 {
    let local_runtime = runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime;
    match (request.renderer, trace_label) {
        (ChatRendererKind::HtmlIframe, "continuation") => {
            if local_runtime {
                1800
            } else {
                2400
            }
        }
        (ChatRendererKind::HtmlIframe, _) => {
            if local_runtime {
                2400
            } else {
                3800
            }
        }
        (
            ChatRendererKind::Markdown
            | ChatRendererKind::Mermaid
            | ChatRendererKind::Svg
            | ChatRendererKind::PdfEmbed,
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
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && direct_author_uses_raw_document(request)
}

fn salvage_interrupted_direct_author_document(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> String {
    let trimmed = raw.trim_end();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Some(settled) = direct_author_stream_settle_snapshot(request, trimmed) {
        return settled.trim_end().to_string();
    }

    let candidate = match trimmed.rfind('>') {
        Some(last_gt) if !trimmed[last_gt + 1..].trim().is_empty() => &trimmed[..=last_gt],
        _ => trimmed,
    };

    candidate.to_string()
}

async fn execute_direct_author_follow_up_inference(
    runtime: Arc<dyn InferenceRuntime>,
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    input: &[u8],
    options: InferenceOptions,
    activity_observer: Option<ChatArtifactActivityObserver>,
    trace_label: &str,
) -> Result<Vec<u8>, String> {
    let prompt_bytes = input.len();
    let max_tokens = options.max_tokens;
    chat_generation_trace(format!(
        "artifact_generation:direct_author_{}:start renderer={:?} prompt_bytes={} max_tokens={}",
        trace_label, request.renderer, prompt_bytes, max_tokens
    ));
    let retry_limit = if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
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
                        chat_generation_trace(format!(
                            "artifact_generation:direct_author_{}:timeout renderer={:?} timeout_ms={}",
                            trace_label,
                            request.renderer,
                            limit.as_millis()
                        ));
                        Err(format!(
                            "Chat direct-author {trace_label} timed out after {}ms",
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
                chat_generation_trace(format!(
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
                chat_generation_trace(format!(
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
        "Chat direct-author {trace_label} failed without returning a follow-up payload"
    ))
}

fn parse_direct_author_generated_candidate(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate_id: &str,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    if direct_author_uses_raw_document(request) {
        return parse_direct_author_raw_document_candidate(raw, request, candidate_id);
    }

    let mut generated = match super::parse_and_validate_generated_artifact_payload(raw, request) {
        Ok(generated) => generated,
        Err(error)
            if request.renderer == ChatRendererKind::HtmlIframe
                && request.artifact_class == ChatArtifactClass::Document
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
            chat_generation_trace(format!(
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
        return Err(ChatCandidateMaterializationError {
            message: contradiction.to_string(),
            raw_output_preview: truncate_candidate_failure_preview(raw, 2000),
        });
    }
    Ok(generated)
}

fn parse_direct_author_raw_document_candidate(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
    candidate_id: &str,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    let document = direct_author_stream_settle_snapshot(request, raw).unwrap_or_else(|| {
        if request.renderer == ChatRendererKind::HtmlIframe {
            normalize_html_terminal_closure(raw)
        } else {
            raw.trim().to_string()
        }
    });

    let mut generated = synthesize_generated_artifact_payload_from_raw_document(&document, request)
        .ok_or_else(|| ChatCandidateMaterializationError {
            message: "Chat direct-author raw document output could not be packaged as an artifact"
                .to_string(),
            raw_output_preview: truncate_candidate_failure_preview(&document, 2000),
        })?;

    validate_direct_author_raw_document_payload(&generated, request).map_err(|message| {
        ChatCandidateMaterializationError {
            message,
            raw_output_preview: truncate_candidate_failure_preview(&document, 2000),
        }
    })?;
    generated.notes.push(
        "accepted clean direct-author raw document without semantic repair heuristics".to_string(),
    );
    trace_html_contract_state(
        "artifact_generation:direct_author_raw_document_accept",
        request,
        candidate_id,
        &generated,
    );
    Ok(generated)
}

fn direct_author_raw_document_parse_candidates(
    request: &ChatOutcomeArtifactRequest,
    returned_raw: &str,
    streamed_raw: &str,
) -> Vec<String> {
    let mut candidates = Vec::<String>::new();
    for raw in [returned_raw, streamed_raw] {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let salvaged = salvage_interrupted_direct_author_document(request, trimmed);
        for candidate in [salvaged, trimmed.to_string()] {
            if candidate.trim().is_empty() {
                continue;
            }
            if !candidates.iter().any(|existing| existing == &candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

fn validate_direct_author_raw_document_payload(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) -> Result<(), String> {
    let primary_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
            )
        })
        .ok_or_else(|| "Direct-author artifact must include a primary file.".to_string())?;

    if primary_file.body.trim().is_empty() {
        return Err("Direct-author artifact primary file is empty.".to_string());
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if primary_file.mime != "text/html" || !primary_file.path.ends_with(".html") {
                return Err("Direct-author HTML artifact must package an .html file.".to_string());
            }
            let html = primary_file.body.as_str();
            let lower = html.to_ascii_lowercase();
            if !(lower.contains("<html") || lower.contains("<!doctype html")) {
                return Err(
                    "Direct-author HTML artifact must contain an HTML document.".to_string()
                );
            }
            if let Some(failure) =
                renderer_document_completeness_failure(request.renderer, html, &lower)
            {
                return Err(failure.to_string());
            }
        }
        ChatRendererKind::Svg => {
            if primary_file.mime != "image/svg+xml" || !primary_file.path.ends_with(".svg") {
                return Err("Direct-author SVG artifact must package an .svg file.".to_string());
            }
            let svg = primary_file.body.as_str();
            let lower = svg.to_ascii_lowercase();
            if !lower.contains("<svg") {
                return Err(
                    "Direct-author SVG artifact must contain an <svg> document.".to_string()
                );
            }
            if let Some(failure) =
                renderer_document_completeness_failure(request.renderer, svg, &lower)
            {
                return Err(failure.to_string());
            }
        }
        ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed => {}
        _ => {}
    }

    Ok(())
}

fn parse_direct_author_provisional_candidate_from_snapshot(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate_id: &str,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    let snapshot = direct_author_stream_settle_snapshot(request, raw)
        .or_else(|| direct_author_preview_ready_document(request, raw).then(|| raw.to_string()))
        .ok_or_else(|| ChatCandidateMaterializationError {
            message: "direct-author provisional snapshot missing a stable renderable preview"
                .to_string(),
            raw_output_preview: truncate_candidate_failure_preview(raw, 2000),
        })?;
    let has_stable_boundary = direct_author_stream_settle_snapshot(request, raw).is_some();
    let mut generated = synthesize_generated_artifact_payload_from_raw_document(&snapshot, request)
        .ok_or_else(|| ChatCandidateMaterializationError {
            message: "direct-author provisional snapshot could not be synthesized into an artifact payload".to_string(),
            raw_output_preview: truncate_candidate_failure_preview(&snapshot, 2000),
        })?;
    super::normalize_generated_artifact_payload(&mut generated, request);
    if has_stable_boundary {
        super::validate_generated_artifact_payload(&generated, request).map_err(|error| {
            ChatCandidateMaterializationError {
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
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    selected_skills: &[ChatArtifactSelectedSkill],
    edit_intent: Option<&ChatArtifactEditIntent>,
    _refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    _candidate_seed: u64,
    candidate: &ChatGeneratedArtifactPayload,
    latest_error: &str,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatGeneratedArtifactPayload, String> {
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
    let repair_runtime_kind = repair_runtime.chat_runtime_provenance().kind;
    let repair_payload = build_chat_artifact_direct_author_repair_prompt_for_runtime(
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
        .map_err(|error| format!("Failed to encode Chat direct-author repair prompt: {error}"))?;
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
    .map_err(|error| format!("Chat direct-author runtime repair inference failed: {error}"))?;
    let repair_raw = String::from_utf8(repair_output).map_err(|error| {
        format!("Chat direct-author runtime repair utf8 decode failed: {error}")
    })?;
    let recovery_payload = parse_chat_direct_author_recovery_payload(request, &repair_raw)?;
    let repaired_document = apply_direct_author_recovery_payload(&latest_raw, &recovery_payload);
    if recovery_payload.mode != ChatDirectAuthorRecoveryMode::FullDocument {
        chat_generation_trace(format!(
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

pub async fn materialize_chat_artifact_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatGeneratedArtifactPayload, String> {
    materialize_chat_artifact_candidate_with_runtime(
        runtime,
        title,
        intent,
        request,
        &ChatArtifactBrief {
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

pub(crate) async fn materialize_chat_artifact_candidate_with_runtime_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    if compact_local_html_materialization_prompt(request.renderer, runtime_kind) {
        let hybrid_temperature =
            effective_direct_author_temperature(request.renderer, runtime_kind, temperature);
        chat_generation_trace(format!(
            "artifact_generation:materialization_strategy_override id={} requested=typed_json resolved=hybrid_raw_document temperature={}",
            candidate_id,
            hybrid_temperature
        ));
        return materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
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
    let parse_candidate =
        |raw: &str| -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
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
    let payload = build_chat_artifact_materialization_prompt_for_runtime(
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
    .map_err(|message| ChatCandidateMaterializationError {
        message,
        raw_output_preview: None,
    })?;
    let input =
        serde_json::to_vec(&payload).map_err(|error| ChatCandidateMaterializationError {
            message: format!(
                "Failed to encode Chat artifact materialization prompt: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    chat_generation_trace(format!(
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
            let message = format!("Chat artifact materialization inference failed: {}", error);
            return Err(ChatCandidateMaterializationError {
                message,
                raw_output_preview: None,
            });
        }
    };
    chat_generation_trace(format!(
        "artifact_generation:materialization_inference:ok id={} bytes={}",
        candidate_id,
        output.len()
    ));
    let raw = String::from_utf8(output).map_err(|error| ChatCandidateMaterializationError {
        message: format!(
            "Chat artifact materialization utf8 decode failed: {}",
            error
        ),
        raw_output_preview: None,
    })?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            chat_generation_trace(format!(
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
            let repair_runtime_kind = repair_runtime.chat_runtime_provenance().kind;
            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
            {
                let repair_payload = build_chat_artifact_materialization_repair_prompt_for_runtime(
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
                .map_err(|message| ChatCandidateMaterializationError {
                    message,
                    raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                })?;
                let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                    ChatCandidateMaterializationError {
                        message: format!(
                            "Failed to encode Chat artifact materialization repair prompt: {}",
                            error
                        ),
                        raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                    }
                })?;
                chat_generation_trace(format!(
                    "artifact_generation:materialization_repair:start id={} attempt={} model={:?} prompt_bytes={} max_tokens={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_runtime.chat_runtime_provenance().model,
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
                .map_err(|error| ChatCandidateMaterializationError {
                    message: format!(
                        "{latest_error}; repair attempt {} inference failed: {error}",
                        repair_attempt + 1
                    ),
                    raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                })?;
                chat_generation_trace(format!(
                    "artifact_generation:materialization_repair:ok id={} attempt={} bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_output.len()
                ));
                let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                    ChatCandidateMaterializationError {
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
                        chat_generation_trace(format!(
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

            Err(ChatCandidateMaterializationError {
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
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    payload: &ChatGeneratedArtifactPayload,
    failure: &str,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    let parse_candidate =
        |raw: &str| -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
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
        serde_json::to_string(payload).map_err(|error| ChatCandidateMaterializationError {
            message: format!(
                "Failed to serialize Chat artifact payload for render-sanity repair: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    let repair_payload = build_chat_artifact_materialization_repair_prompt_for_runtime(
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
    .map_err(|message| ChatCandidateMaterializationError {
        message,
        raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
    })?;
    let repair_input =
        serde_json::to_vec(&repair_payload).map_err(|error| ChatCandidateMaterializationError {
            message: format!(
                "Failed to encode Chat render-sanity repair prompt: {}",
                error
            ),
            raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
        })?;
    chat_generation_trace(format!(
        "artifact_generation:render_sanity_repair:start id={} model={:?} prompt_bytes={} max_tokens={}",
        candidate_id,
        runtime.chat_runtime_provenance().model,
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
    .map_err(|error| ChatCandidateMaterializationError {
        message: format!("Chat render-sanity repair inference failed: {}", error),
        raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
    })?;
    chat_generation_trace(format!(
        "artifact_generation:render_sanity_repair:ok id={} bytes={}",
        candidate_id,
        repair_output.len()
    ));
    let repair_raw =
        String::from_utf8(repair_output).map_err(|error| ChatCandidateMaterializationError {
            message: format!("Chat render-sanity repair utf8 decode failed: {}", error),
            raw_output_preview: truncate_candidate_failure_preview(&raw_payload, 2000),
        })?;
    parse_candidate(&repair_raw).map_err(|error| {
        chat_generation_trace(format!(
            "artifact_generation:render_sanity_repair_parse_error id={} error={} preview={}",
            candidate_id,
            error.message,
            truncate_candidate_failure_preview(&repair_raw, 4000)
                .unwrap_or_else(|| "(empty)".to_string())
        ));
        ChatCandidateMaterializationError {
            message: error.message,
            raw_output_preview: truncate_candidate_failure_preview(&repair_raw, 2000),
        }
    })
}

pub(crate) async fn materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    selected_skills: &[ChatArtifactSelectedSkill],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
    live_preview_observer: Option<ChatArtifactLivePreviewObserver>,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    let returns_raw_document = direct_author_uses_raw_document(request);
    let max_tokens = materialization_max_tokens_for_execution_strategy(
        request.renderer,
        ChatExecutionStrategy::DirectAuthor,
        runtime_kind,
    );
    let parse_candidate = |raw: &str| {
        parse_direct_author_generated_candidate(raw, request, brief, edit_intent, candidate_id)
    };
    let payload = build_chat_artifact_direct_author_prompt_for_runtime(
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
    .map_err(|message| ChatCandidateMaterializationError {
        message,
        raw_output_preview: None,
    })?;
    let input =
        serde_json::to_vec(&payload).map_err(|error| ChatCandidateMaterializationError {
            message: format!(
                "Failed to encode Chat direct-author artifact prompt: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    chat_generation_trace(format!(
        "artifact_generation:direct_author_inference:start id={} prompt_bytes={} temperature={} max_tokens={} raw_document={}",
        candidate_id,
        input.len(),
        temperature,
        max_tokens,
        returns_raw_document
    ));
    let preview_language = chat_swarm_preview_language(request);
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
        .map(|error| format!("Chat direct-author artifact inference failed: {error}"));
    let recovered_from_partial_stream =
        output_result.is_err() && !streamed_preview.trim().is_empty();
    let raw = match output_result {
        Ok(output) => {
            String::from_utf8(output).map_err(|error| ChatCandidateMaterializationError {
                message: format!("Chat direct-author artifact utf8 decode failed: {}", error),
                raw_output_preview: truncate_candidate_failure_preview(&streamed_preview, 2000),
            })?
        }
        Err(error) => {
            if streamed_preview.trim().is_empty() {
                return Err(ChatCandidateMaterializationError {
                    message: format!("Chat direct-author artifact inference failed: {}", error),
                    raw_output_preview: None,
                });
            }
            chat_generation_trace(format!(
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
                chat_generation_trace(format!(
                    "artifact_generation:direct_author_inference:interrupted_salvage_normalized id={} original_bytes={} salvaged_bytes={}",
                    candidate_id,
                    streamed_preview.len(),
                    salvaged.len()
                ));
            }
            if returns_raw_document {
                if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
                    && request.renderer == ChatRendererKind::HtmlIframe
                    && request.artifact_class == ChatArtifactClass::Document
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
                        chat_generation_trace(format!(
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
            if returns_raw_document {
                let mut latest_error = first_error;
                let mut latest_raw = raw.clone();
                for candidate_raw in
                    direct_author_raw_document_parse_candidates(request, &raw, &streamed_preview)
                {
                    match parse_candidate(&candidate_raw) {
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
                                &candidate_raw,
                                true,
                            );
                            return Ok(generated);
                        }
                        Err(error) => {
                            latest_error = error;
                            latest_raw = candidate_raw;
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
                return Err(ChatCandidateMaterializationError {
                    message: format!(
                        "Chat direct-author raw document output was not structurally complete: {}",
                        latest_error.message
                    ),
                    raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                });
            }

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
            chat_generation_trace(format!(
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
                    chat_generation_trace(format!(
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
                chat_generation_trace(format!(
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
                        chat_generation_trace(format!(
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
                chat_generation_trace(format!(
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
                        chat_generation_trace(format!(
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
                chat_generation_trace(format!(
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
            if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
                && request.renderer == ChatRendererKind::HtmlIframe
                && request.artifact_class == ChatArtifactClass::Document
                && returns_raw_document
            {
                match parse_direct_author_provisional_candidate_from_snapshot(
                    &latest_raw,
                    request,
                    brief,
                    candidate_id,
                ) {
                    Ok(generated) => {
                        chat_generation_trace(format!(
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
                        chat_generation_trace(format!(
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
            let repair_runtime_kind = repair_runtime.chat_runtime_provenance().kind;
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
                        build_chat_artifact_direct_author_continuation_prompt_for_runtime(
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
                            ChatCandidateMaterializationError {
                                message: format!(
                                    "Failed to encode Chat direct-author continuation prompt: {}",
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
                    match parse_chat_direct_author_recovery_payload(request, &continuation_raw) {
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
                        build_chat_artifact_direct_author_repair_prompt_for_runtime(
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
                        ChatCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Chat direct-author repair prompt: {}",
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
                    match parse_chat_direct_author_recovery_payload(request, &repair_raw) {
                        Ok(recovery_payload) => {
                            let repaired_document = apply_direct_author_recovery_payload(
                                &latest_raw,
                                &recovery_payload,
                            );
                            let repair_mode =
                                direct_author_recovery_mode_label(&recovery_payload.mode);
                            if recovery_payload.mode != ChatDirectAuthorRecoveryMode::FullDocument {
                                chat_generation_trace(format!(
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
                        build_chat_artifact_materialization_repair_prompt_for_runtime(
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
                            ChatCandidateMaterializationError {
                                message,
                                raw_output_preview: truncate_candidate_failure_preview(
                                    &latest_raw,
                                    2000,
                                ),
                            }
                        })?;
                    let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                        ChatCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Chat direct-author repair prompt: {}",
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

            Err(ChatCandidateMaterializationError {
                message: latest_error,
                raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
            })
        }
    }
}

pub async fn materialize_chat_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
) -> Result<ChatGeneratedArtifactPayload, String> {
    materialize_chat_artifact_candidate_with_runtime_detailed(
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

pub(crate) async fn refine_chat_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
    validation: &ChatArtifactValidationResult,
    candidate_id: &str,
    candidate_seed: u64,
    refinement_temperature: f32,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatGeneratedArtifactPayload, String> {
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<ChatGeneratedArtifactPayload, String> {
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
    let payload = build_chat_artifact_candidate_refinement_prompt_for_runtime(
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
        .map_err(|error| format!("Failed to encode Chat artifact refinement prompt: {error}"))?;
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    chat_generation_trace(format!(
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
    .map_err(|error| format!("Chat artifact refinement inference failed: {error}"))?;
    chat_generation_trace(format!(
        "artifact_generation:refine_inference:ok id={} bytes={}",
        candidate_id,
        output.len()
    ));
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Chat artifact refinement utf8 decode failed: {error}"))?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            chat_generation_trace(format!(
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
                    build_chat_artifact_candidate_refinement_repair_prompt_for_runtime(
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
                    format!("Failed to encode Chat artifact refinement repair prompt: {error}")
                })?;
                chat_generation_trace(format!(
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
                chat_generation_trace(format!(
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
                        chat_generation_trace(format!(
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
