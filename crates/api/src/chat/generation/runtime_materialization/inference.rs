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
