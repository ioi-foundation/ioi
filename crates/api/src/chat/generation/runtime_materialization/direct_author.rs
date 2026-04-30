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
            let (mut latest_error, mut latest_raw) = if returns_raw_document {
                let mut raw_error = first_error;
                let mut raw_candidate = raw.clone();
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
                            raw_error = error;
                            raw_candidate = candidate_raw;
                        }
                    }
                }

                let raw_structural_error = format!(
                    "Chat direct-author raw document output was not structurally complete: {}",
                    raw_error.message
                );
                let error_message = if let Some(inference_error) = inference_error_message {
                    format!("{inference_error}; {raw_structural_error}")
                } else {
                    raw_structural_error
                };
                (error_message, raw_candidate)
            } else if let Some(inference_error) = inference_error_message {
                (format!("{inference_error}; {}", first_error.message), raw)
            } else {
                (first_error.message, raw)
            };
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
            for (repair_strategy, repaired_document) in
                try_local_html_structural_repair(request, runtime_kind, &latest_raw, &latest_error)
            {
                chat_generation_trace(format!(
                    "artifact_generation:direct_author_inference:local_structural_repair id={} strategy={} existing_bytes={} repaired_bytes={}",
                    candidate_id,
                    repair_strategy,
                    latest_raw.len(),
                    repaired_document.len()
                ));
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
                        chat_generation_trace(format!(
                            "artifact_generation:direct_author_inference:local_structural_repair_failed id={} strategy={} error={}",
                            candidate_id,
                            repair_strategy,
                            repair_error.message.replace('\n', " ")
                        ));
                        latest_error = format!(
                            "{latest_error}; local structural deterministic repair ({repair_strategy}) failed: {}",
                            repair_error.message
                        );
                        latest_raw = repaired_document;
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
            if let Some((repaired_document, repair_strategy)) =
                try_local_html_primary_view_contract_repair(
                    request,
                    runtime_kind,
                    &latest_raw,
                    &latest_error,
                )
            {
                chat_generation_trace(format!(
                    "artifact_generation:direct_author_inference:local_primary_view_repair id={} strategy={} existing_bytes={} repaired_bytes={}",
                    candidate_id,
                    repair_strategy,
                    latest_raw.len(),
                    repaired_document.len()
                ));
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
                        chat_generation_trace(format!(
                            "artifact_generation:direct_author_inference:local_primary_view_repair_failed id={} strategy={} error={}",
                            candidate_id,
                            repair_strategy,
                            repair_error.message.replace('\n', " ")
                        ));
                        latest_error = format!(
                            "{latest_error}; local primary-view deterministic repair ({repair_strategy}) failed: {}",
                            repair_error.message
                        );
                        latest_raw = repaired_document;
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
            if let Some((repaired_document, repair_strategy)) =
                try_local_html_interaction_repair(request, runtime_kind, &latest_raw, &latest_error)
            {
                chat_generation_trace(format!(
                    "artifact_generation:direct_author_inference:local_interaction_repair id={} strategy={} existing_bytes={} repaired_bytes={}",
                    candidate_id,
                    repair_strategy,
                    latest_raw.len(),
                    repaired_document.len()
                ));
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
                        chat_generation_trace(format!(
                            "artifact_generation:direct_author_inference:local_interaction_repair_failed id={} strategy={} error={}",
                            candidate_id,
                            repair_strategy,
                            repair_error.message.replace('\n', " ")
                        ));
                        latest_error = format!(
                            "{latest_error}; local interaction deterministic repair ({repair_strategy}) failed: {}",
                            repair_error.message
                        );
                        latest_raw = repaired_document;
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
