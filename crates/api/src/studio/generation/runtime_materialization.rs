use super::*;

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

pub(super) async fn materialize_studio_artifact_candidate_with_runtime_detailed(
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
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
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
    let output = runtime
        .clone()
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature,
                json_mode: true,
                max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Studio artifact materialization inference failed: {}",
                error
            ),
            raw_output_preview: None,
        })?;
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
                let repair_output = repair_runtime
                    .execute_inference(
                        [0u8; 32],
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

pub(crate) async fn materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
    live_preview_observer: Option<StudioArtifactLivePreviewObserver>,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let returns_raw_document = direct_author_uses_raw_document(request);
    let max_tokens = materialization_max_tokens_for_execution_strategy(
        request.renderer,
        StudioExecutionStrategy::DirectAuthor,
        runtime_kind,
    );
    let parse_candidate = |raw: &str| -> Result<
        StudioGeneratedArtifactPayload,
        StudioCandidateMaterializationError,
    > {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
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
            &generated, request, brief, None,
        )?;
        Ok(generated)
    };
    let payload = build_studio_artifact_direct_author_prompt_for_runtime(
        title,
        intent,
        request,
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
    let output_result = runtime
        .clone()
        .execute_inference_streaming(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature,
                json_mode: !returns_raw_document,
                max_tokens,
                stop_sequences: direct_author_stop_sequences(request),
                ..Default::default()
            },
            token_stream,
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
            if let Some(observer) = live_preview_observer.as_ref() {
                observer(studio_swarm_live_preview(
                    preview_id.clone(),
                    ExecutionLivePreviewKind::TokenStream,
                    preview_label.clone(),
                    None,
                    None,
                    "interrupted",
                    preview_language.clone(),
                    live_token_stream_preview_text(&streamed_preview, 2200),
                    true,
                ));
            }
            streamed_preview.clone()
        }
    };
    match parse_candidate(&raw) {
        Ok(generated) => {
            if let Some(observer) = live_preview_observer.as_ref() {
                observer(studio_swarm_live_preview(
                    preview_id,
                    ExecutionLivePreviewKind::TokenStream,
                    preview_label,
                    None,
                    None,
                    if recovered_from_partial_stream {
                        "recovered"
                    } else {
                        "completed"
                    },
                    preview_language,
                    live_token_stream_preview_text(
                        if streamed_preview.trim().is_empty() {
                            &raw
                        } else {
                            &streamed_preview
                        },
                        2200,
                    ),
                    true,
                ));
            }
            Ok(generated)
        }
        Err(first_error) => {
            let mut latest_error = if let Some(inference_error) = inference_error_message {
                format!("{inference_error}; {}", first_error.message)
            } else {
                first_error.message
            };
            let mut latest_raw = raw;
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
                    if !direct_author_document_is_incomplete(request, &latest_raw, &latest_error) {
                        break;
                    }
                    let continuation_payload =
                        build_studio_artifact_direct_author_continuation_prompt_for_runtime(
                            title,
                            intent,
                            request,
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
                    let continuation_output = runtime
                        .clone()
                        .execute_inference(
                            [0u8; 32],
                            &continuation_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: false,
                                max_tokens,
                                stop_sequences: direct_author_stop_sequences(request),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; continuation attempt {} inference failed: {error}",
                                continuation_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        })?;
                    let continuation_raw = String::from_utf8(continuation_output).map_err(
                        |error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; continuation attempt {} utf8 decode failed: {error}",
                                continuation_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        },
                    )?;
                    latest_raw = merge_direct_author_document(&latest_raw, &continuation_raw);
                    match parse_candidate(&latest_raw) {
                        Ok(generated) => return Ok(generated),
                        Err(continuation_error) => {
                            latest_error = format!(
                                "{latest_error}; continuation attempt {} failed: {}",
                                continuation_attempt + 1,
                                continuation_error.message
                            );
                        }
                    }
                }
            }

            if returns_raw_document {
                for repair_attempt in
                    0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
                {
                    let repair_payload =
                        build_studio_artifact_direct_author_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
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
                    let repair_output = repair_runtime
                        .execute_inference(
                            [0u8; 32],
                            &repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: false,
                                max_tokens: materialization_max_tokens_for_execution_strategy(
                                    request.renderer,
                                    StudioExecutionStrategy::DirectAuthor,
                                    repair_runtime_kind,
                                ),
                                stop_sequences: direct_author_stop_sequences(request),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} inference failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        })?;
                    let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        }
                    })?;
                    match parse_candidate(&repair_raw) {
                        Ok(generated) => return Ok(generated),
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
            } else {
                for repair_attempt in
                    0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
                {
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
                    let repair_output = repair_runtime
                        .execute_inference(
                            [0u8; 32],
                            &repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: true,
                                max_tokens: materialization_max_tokens_for_execution_strategy(
                                    request.renderer,
                                    StudioExecutionStrategy::DirectAuthor,
                                    repair_runtime_kind,
                                ),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} inference failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        })?;
                    let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        }
                    })?;
                    match parse_candidate(&repair_raw) {
                        Ok(generated) => return Ok(generated),
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
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    refinement_temperature: f32,
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
        judge,
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
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: refinement_temperature,
                json_mode: true,
                max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
                ..Default::default()
            },
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
                        judge,
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
                let repair_output = runtime
                    .execute_inference(
                        [0u8; 32],
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
