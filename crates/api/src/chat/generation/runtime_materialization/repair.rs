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
