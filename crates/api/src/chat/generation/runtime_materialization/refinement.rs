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
