fn parse_direct_author_generated_candidate(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate_id: &str,
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    if direct_author_uses_raw_document(request) {
        let mut generated = parse_direct_author_raw_document_candidate(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:direct_author_raw_document_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:direct_author_raw_document_contract_state:enriched",
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
        if let Some(contradiction) =
            renderer_primary_view_contract_failure(request, brief, &generated)
        {
            return Err(ChatCandidateMaterializationError {
                message: contradiction.to_string(),
                raw_output_preview: truncate_candidate_failure_preview(raw, 2000),
            });
        }
        generated.notes.push(
            "accepted direct-author raw document after typed renderer contract checks".to_string(),
        );
        trace_html_contract_state(
            "artifact_generation:direct_author_raw_document_accept",
            request,
            candidate_id,
            &generated,
        );
        return Ok(generated);
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
) -> Result<ChatGeneratedArtifactPayload, ChatCandidateMaterializationError> {
    let document = direct_author_stream_settle_snapshot(request, raw).unwrap_or_else(|| {
        if request.renderer == ChatRendererKind::HtmlIframe {
            normalize_html_terminal_closure(raw)
        } else {
            raw.trim().to_string()
        }
    });

    let generated = synthesize_generated_artifact_payload_from_raw_document(&document, request)
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
            if lower.contains("chart-shell\"></div>")
                || lower.contains("chart-shell'></div>")
                || lower.contains("chart-shell\"></canvas>")
                || lower.contains("chart-shell'></canvas>")
            {
                return Err(
                    "HTML chart containers are empty placeholder shells on first paint."
                        .to_string(),
                );
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
