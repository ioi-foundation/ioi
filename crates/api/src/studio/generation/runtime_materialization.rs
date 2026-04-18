use super::*;
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
    raw: &str,
) -> Result<StudioDirectAuthorRecoveryPayload, String> {
    let parse_json =
        |candidate: &str| -> Result<StudioDirectAuthorRecoveryPayload, serde_json::Error> {
            serde_json::from_str(candidate)
        };

    let payload = parse_json(raw)
        .or_else(|_| {
            let extracted = super::extract_first_json_object(raw).ok_or_else(|| {
                "Studio direct-author recovery output missing JSON payload".to_string()
            })?;
            parse_json(&extracted).map_err(|error| error.to_string())
        })
        .map_err(|error| {
            format!("Failed to parse Studio direct-author recovery payload: {error}")
        })?;

    if payload.content.trim().is_empty() {
        return Err("Studio direct-author recovery payload content was empty".to_string());
    }

    Ok(payload)
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
    let inference = runtime.execute_inference([0u8; 32], input, options);
    match materialization_timeout_for_request(request, runtime_kind, follow_up) {
        Some(limit) => {
            match await_with_activity_heartbeat(
                tokio::time::timeout(limit, inference),
                activity_observer,
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
        None => {
            await_with_activity_heartbeat(inference, activity_observer, Duration::from_millis(125))
                .await
                .map_err(|error| error.to_string())
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
                3200
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

fn salvage_interrupted_direct_author_document(
    request: &StudioOutcomeArtifactRequest,
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

    match request.renderer {
        StudioRendererKind::HtmlIframe => normalize_html_terminal_closure(candidate),
        StudioRendererKind::Svg => {
            let lower = candidate.to_ascii_lowercase();
            if lower.contains("<svg") && !lower.contains("</svg>") {
                format!("{candidate}</svg>")
            } else {
                candidate.to_string()
            }
        }
        _ => candidate.to_string(),
    }
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
    let inference = runtime.execute_inference([0u8; 32], input, options);
    match direct_author_follow_up_timeout_for_request(request, runtime_kind) {
        Some(limit) => {
            match await_with_activity_heartbeat(
                tokio::time::timeout(limit, inference),
                activity_observer,
                Duration::from_millis(125),
            )
            .await
            {
                Ok(Ok(output)) => {
                    studio_generation_trace(format!(
                        "artifact_generation:direct_author_{}:ok renderer={:?} bytes={}",
                        trace_label,
                        request.renderer,
                        output.len()
                    ));
                    Ok(output)
                }
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
        None => {
            await_with_activity_heartbeat(inference, activity_observer, Duration::from_millis(125))
                .await
                .map(|output| {
                    studio_generation_trace(format!(
                        "artifact_generation:direct_author_{}:ok renderer={:?} bytes={}",
                        trace_label,
                        request.renderer,
                        output.len()
                    ));
                    output
                })
                .map_err(|error| error.to_string())
        }
    }
}

fn parse_direct_author_generated_candidate(
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate_id: &str,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
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
}

pub(crate) async fn repair_direct_author_generated_candidate_with_runtime_error(
    repair_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    selected_skills: &[StudioArtifactSelectedSkill],
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
            json_mode: true,
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
    let recovery_payload = parse_studio_direct_author_recovery_payload(&repair_raw)?;
    if recovery_payload.mode != StudioDirectAuthorRecoveryMode::FullDocument {
        return Err(
            "Studio direct-author runtime repair payload must use mode=full_document".to_string(),
        );
    }
    parse_direct_author_generated_candidate(&recovery_payload.content, request, brief, candidate_id)
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

pub(crate) async fn materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    selected_skills: &[StudioArtifactSelectedSkill],
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
    let parse_candidate =
        |raw: &str| parse_direct_author_generated_candidate(raw, request, brief, candidate_id);
    let payload = build_studio_artifact_direct_author_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        selected_skills,
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
    let streaming_runtime = runtime.clone();
    let inference = streaming_runtime.execute_inference_streaming(
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
    );
    let output_result = match direct_author_stream_timeout_for_request(request, runtime_kind) {
        Some(limit) => match tokio::time::timeout(limit, inference).await {
            Ok(output) => output,
            Err(_) => {
                studio_generation_trace(format!(
                    "artifact_generation:direct_author_inference:timeout id={} timeout_ms={}",
                    candidate_id,
                    limit.as_millis()
                ));
                Err(VmError::HostError(format!(
                    "Studio direct-author artifact inference timed out after {}s",
                    limit.as_secs()
                )))
            }
        },
        None => inference.await,
    };
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
            salvaged
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
            let mut preview_status = if returns_raw_document
                && direct_author_document_is_incomplete(request, &latest_raw, &latest_error)
            {
                "continuing"
            } else {
                "repairing"
            };
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
                    if !direct_author_document_is_incomplete(request, &latest_raw, &latest_error) {
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
                            json_mode: true,
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
                    match parse_studio_direct_author_recovery_payload(&continuation_raw) {
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
                    match parse_studio_direct_author_recovery_payload(&repair_raw) {
                        Ok(recovery_payload) => {
                            if recovery_payload.mode != StudioDirectAuthorRecoveryMode::FullDocument
                            {
                                latest_error = format!(
                                    "{latest_error}; repair attempt {} failed: Studio direct-author repair payload must use mode=full_document",
                                    repair_attempt + 1
                                );
                                continue;
                            }
                            let repaired_document = recovery_payload.content;
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
                                        "{latest_error}; repair attempt {} failed: {}",
                                        repair_attempt + 1,
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
