use super::*;
use crate::chat::payload::{
    download_bundle_export_body_looks_complete, download_bundle_export_format_label,
    infer_download_bundle_export_format_from_path_and_mime, is_download_bundle_readme_file,
};
use std::time::Duration;

fn renderable_paths_for_payload(payload: &ChatGeneratedArtifactPayload) -> Vec<String> {
    payload
        .files
        .iter()
        .filter(|file| file.renderable)
        .map(|file| file.path.clone())
        .collect()
}

fn validation_status_rank(status: ChatArtifactValidationStatus) -> i32 {
    match status {
        ChatArtifactValidationStatus::Pass => 300,
        ChatArtifactValidationStatus::Repairable => 200,
        ChatArtifactValidationStatus::Blocked => 100,
    }
}

pub(crate) fn validation_total_score(validation: &ChatArtifactValidationResult) -> i32 {
    validation.score_total
}

#[allow(dead_code)]
pub(crate) fn validation_clears_primary_view(validation: &ChatArtifactValidationResult) -> bool {
    validation.primary_view_cleared
        && validation.classification == ChatArtifactValidationStatus::Pass
}

fn validation_score(
    status: ChatArtifactValidationStatus,
    renderable_paths: &[String],
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> i32 {
    let render_score = render_evaluation
        .map(|evaluation| i32::from(evaluation.overall_score))
        .unwrap_or_else(|| if renderable_paths.is_empty() { 0 } else { 24 });
    validation_status_rank(status) + render_score + (renderable_paths.len().min(3) as i32 * 4)
}

fn build_validation_result(
    classification: ChatArtifactValidationStatus,
    proof_kind: impl Into<String>,
    primary_view_cleared: bool,
    validated_paths: Vec<String>,
    issue_codes: Vec<String>,
    repair_hints: Vec<String>,
    blocked_reasons: Vec<String>,
    summary: impl Into<String>,
    rationale: impl Into<String>,
) -> ChatArtifactValidationResult {
    let summary = summary.into();
    let rationale = rationale.into();
    let strongest_contradiction = blocked_reasons
        .first()
        .cloned()
        .or_else(|| repair_hints.first().cloned());
    let default_score = match classification {
        ChatArtifactValidationStatus::Pass => 5,
        ChatArtifactValidationStatus::Repairable => 3,
        ChatArtifactValidationStatus::Blocked => 1,
    };
    ChatArtifactValidationResult {
        classification,
        request_faithfulness: default_score,
        concept_coverage: default_score,
        interaction_relevance: default_score,
        layout_coherence: default_score,
        visual_hierarchy: default_score,
        completeness: default_score,
        generic_shell_detected: false,
        trivial_shell_detected: validated_paths.is_empty()
            && classification == ChatArtifactValidationStatus::Blocked,
        deserves_primary_artifact_view: primary_view_cleared,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        score_total: validation_score(classification, &validated_paths, None),
        proof_kind: proof_kind.into(),
        primary_view_cleared,
        validated_paths: validated_paths.clone(),
        issue_codes: issue_codes.clone(),
        repair_hints: repair_hints.clone(),
        blocked_reasons: blocked_reasons.clone(),
        issue_classes: issue_codes,
        strengths: if classification == ChatArtifactValidationStatus::Pass {
            vec![summary.clone()]
        } else {
            Vec::new()
        },
        file_findings: validated_paths
            .iter()
            .map(|path| format!("validated: {path}"))
            .collect(),
        aesthetic_verdict: summary.clone(),
        interaction_verdict: rationale.clone(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some(
            match classification {
                ChatArtifactValidationStatus::Pass => "accept",
                ChatArtifactValidationStatus::Repairable => "structural_repair",
                ChatArtifactValidationStatus::Blocked => "hold_block",
            }
            .to_string(),
        ),
        strongest_contradiction,
        summary,
        rationale,
    }
}

fn hydrate_validation_result(
    validation: &ChatArtifactValidationResult,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
    patched_existing_artifact: Option<bool>,
    continuity_revision_ux: Option<u8>,
) -> ChatArtifactValidationResult {
    let classification = validation.classification;
    let default_score = match validation.classification {
        ChatArtifactValidationStatus::Pass => 5,
        ChatArtifactValidationStatus::Repairable => 3,
        ChatArtifactValidationStatus::Blocked => 1,
    };
    let layout_score = render_evaluation
        .map(|evaluation| ((u16::from(evaluation.layout_density_score) + 19) / 20) as u8)
        .unwrap_or(default_score)
        .clamp(1, 5);
    let hierarchy_score = render_evaluation
        .map(|evaluation| ((u16::from(evaluation.visual_hierarchy_score) + 19) / 20) as u8)
        .unwrap_or(default_score)
        .clamp(1, 5);
    let completeness_score = render_evaluation
        .map(|evaluation| ((u16::from(evaluation.overall_score) + 19) / 20) as u8)
        .unwrap_or(default_score)
        .clamp(1, 5);
    let contradiction = validation
        .blocked_reasons
        .first()
        .cloned()
        .or_else(|| validation.repair_hints.first().cloned());

    ChatArtifactValidationResult {
        classification,
        request_faithfulness: default_score,
        concept_coverage: default_score,
        interaction_relevance: default_score,
        layout_coherence: layout_score,
        visual_hierarchy: hierarchy_score,
        completeness: completeness_score,
        generic_shell_detected: false,
        trivial_shell_detected: validation.validated_paths.is_empty()
            && validation.classification == ChatArtifactValidationStatus::Blocked,
        deserves_primary_artifact_view: validation.primary_view_cleared,
        patched_existing_artifact,
        continuity_revision_ux,
        issue_classes: validation.issue_codes.clone(),
        repair_hints: validation.repair_hints.clone(),
        strengths: if validation.classification == ChatArtifactValidationStatus::Pass {
            vec![validation.summary.clone()]
        } else {
            Vec::new()
        },
        blocked_reasons: validation.blocked_reasons.clone(),
        file_findings: validation
            .validated_paths
            .iter()
            .map(|path| format!("validated: {path}"))
            .collect(),
        aesthetic_verdict: validation.summary.clone(),
        interaction_verdict: validation.rationale.clone(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some(
            match validation.classification {
                ChatArtifactValidationStatus::Pass => "accept",
                ChatArtifactValidationStatus::Repairable => "structural_repair",
                ChatArtifactValidationStatus::Blocked => "hold_block",
            }
            .to_string(),
        ),
        score_total: validation.score_total,
        proof_kind: validation.proof_kind.clone(),
        primary_view_cleared: validation.primary_view_cleared,
        validated_paths: validation.validated_paths.clone(),
        issue_codes: validation.issue_codes.clone(),
        strongest_contradiction: contradiction,
        summary: validation.summary.clone(),
        rationale: validation.rationale.clone(),
    }
}

fn local_html_interaction_truth_block_reason(
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| {
            matches!(
                obligation.status,
                ChatArtifactAcceptanceObligationStatus::Failed
                    | ChatArtifactAcceptanceObligationStatus::Blocked
            ) && matches!(
                obligation.obligation_id.as_str(),
                "response_region_present" | "controls_execute_cleanly" | "interaction_witnessed"
            )
        })
        .map(|obligation| {
            obligation
                .detail
                .as_ref()
                .map(|detail| format!("{} {}", obligation.summary, detail))
                .unwrap_or_else(|| obligation.summary.clone())
        })
}

fn try_local_html_interaction_truth_rescue_candidate(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    payload: &ChatGeneratedArtifactPayload,
    error_message: &str,
) -> Option<(ChatGeneratedArtifactPayload, &'static str)> {
    let latest_raw = payload
        .files
        .iter()
        .find(|file| file.renderable)
        .or_else(|| payload.files.first())
        .map(|file| file.body.clone())?;
    let (rescued_document, strategy) = try_local_html_interaction_truth_rescue_document(
        request,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        &latest_raw,
        error_message,
    )?;
    let mut generated =
        super::parse_and_validate_generated_artifact_payload(&rescued_document, request).ok()?;
    super::enrich_generated_artifact_payload(&mut generated, request, brief);
    super::validate_generated_artifact_payload_against_brief_with_edit_intent(
        &generated,
        request,
        brief,
        edit_intent,
    )
    .ok()?;
    if generated.summary.trim().is_empty() {
        generated.summary = payload.summary.clone();
    }
    generated.notes.push(format!(
        "local interaction-truth rescue ({strategy}) applied after: {error_message}"
    ));
    Some((generated, strategy))
}

pub(crate) fn blocked_candidate_generation_validation(
    message: &str,
) -> ChatArtifactValidationResult {
    build_validation_result(
        ChatArtifactValidationStatus::Blocked,
        "materialization",
        false,
        Vec::new(),
        vec!["generation_failure".to_string()],
        vec![
            "Repair the materialization failure and rerun validation before surfacing the artifact."
                .to_string(),
        ],
        vec![message.to_string()],
        "Candidate failed during materialization.",
        message.to_string(),
    )
}

pub(crate) async fn materialize_and_locally_validation_candidate(
    production_runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Arc<dyn InferenceRuntime>,
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
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
    seed: u64,
    temperature: f32,
    strategy: &str,
    origin: ChatArtifactOutputOrigin,
    model: &str,
    production_provenance: &ChatRuntimeProvenance,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<
    (ChatArtifactCandidateSummary, ChatGeneratedArtifactPayload),
    ChatArtifactCandidateSummary,
> {
    chat_generation_trace(format!(
        "artifact_generation:candidate_materialize:start id={} seed={}",
        candidate_id, seed
    ));
    let mut payload = match materialize_chat_artifact_candidate_with_runtime_detailed(
        production_runtime.clone(),
        Some(repair_runtime.clone()),
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
        seed,
        temperature,
        activity_observer.clone(),
    )
    .await
    {
        Ok(payload) => {
            chat_generation_trace(format!(
                "artifact_generation:candidate_materialize:ok id={} files={}",
                candidate_id,
                payload.files.len()
            ));
            payload
        }
        Err(error) => {
            chat_generation_trace(format!(
                "artifact_generation:candidate_materialize:error id={} error={}",
                candidate_id, error.message
            ));
            let validation = blocked_candidate_generation_validation(&error.message);
            let validation = hydrate_validation_result(&validation, None, None, None);
            return Err(ChatArtifactCandidateSummary {
                candidate_id: candidate_id.to_string(),
                seed,
                model: model.to_string(),
                temperature,
                strategy: strategy.to_string(),
                origin,
                provenance: Some(production_provenance.clone()),
                summary: "Candidate failed during materialization.".to_string(),
                renderable_paths: Vec::new(),
                selected: false,
                fallback: false,
                failure: Some(error.message.clone()),
                raw_output_preview: error.raw_output_preview.clone(),
                convergence: Some(initial_candidate_convergence_trace(
                    candidate_id,
                    "generation_failure",
                    validation_total_score(&validation),
                )),
                render_evaluation: None,
                validation,
            });
        }
    };

    let render_eval_future = evaluate_candidate_render_with_fallback(
        render_evaluator,
        request,
        brief,
        blueprint,
        artifact_ir,
        edit_intent,
        &payload,
        production_provenance.kind,
    );
    let mut render_evaluation = if render_eval_timeout_for_runtime(
        request.renderer,
        production_provenance.kind,
    )
    .is_some()
    {
        await_with_activity_heartbeat(
            render_eval_future,
            activity_observer.clone(),
            Duration::from_millis(125),
        )
        .await
    } else {
        render_eval_future.await
    };

    if request.renderer == ChatRendererKind::HtmlIframe
        && production_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        if let Some(interaction_truth_reason) =
            local_html_interaction_truth_block_reason(render_evaluation.as_ref())
        {
            if let Some((rescued_payload, strategy)) =
                try_local_html_interaction_truth_rescue_candidate(
                    request,
                    brief,
                    edit_intent,
                    &payload,
                    &interaction_truth_reason,
                )
            {
                chat_generation_trace(format!(
                    "artifact_generation:candidate_local_interaction_truth_rescue:ok id={} strategy={}",
                    candidate_id, strategy
                ));
                payload = rescued_payload;
                let rescued_eval_future = evaluate_candidate_render_with_fallback(
                    render_evaluator,
                    request,
                    brief,
                    blueprint,
                    artifact_ir,
                    edit_intent,
                    &payload,
                    production_provenance.kind,
                );
                render_evaluation = if render_eval_timeout_for_runtime(
                    request.renderer,
                    production_provenance.kind,
                )
                .is_some()
                {
                    await_with_activity_heartbeat(
                        rescued_eval_future,
                        activity_observer.clone(),
                        Duration::from_millis(125),
                    )
                    .await
                } else {
                    rescued_eval_future.await
                };
            }
        }

        if let Some(runtime_failure_reason) = render_sanity_block_reason(render_evaluation.as_ref())
        {
            let resolved_repair_runtime = materialization_repair_runtime_for_request(
                request,
                &production_runtime,
                Some(&repair_runtime),
            );
            let repair_result = if compact_local_html_materialization_prompt(
                request.renderer,
                production_provenance.kind,
            ) {
                repair_direct_author_generated_candidate_with_runtime_error(
                    resolved_repair_runtime,
                    title,
                    intent,
                    request,
                    brief,
                    selected_skills,
                    edit_intent,
                    refinement,
                    candidate_id,
                    seed,
                    &payload,
                    &runtime_failure_reason,
                    activity_observer.clone(),
                )
                .await
                .map_err(|error| ChatCandidateMaterializationError {
                    message: error,
                    raw_output_preview: None,
                })
            } else {
                repair_materialized_candidate_with_runtime_error(
                    resolved_repair_runtime,
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
                    seed,
                    &payload,
                    &runtime_failure_reason,
                    activity_observer.clone(),
                )
                .await
            };
            match repair_result {
                Ok(repaired_payload) => {
                    chat_generation_trace(format!(
                        "artifact_generation:candidate_runtime_repair:ok id={}",
                        candidate_id
                    ));
                    payload = repaired_payload;
                    let repaired_eval_future = evaluate_candidate_render_with_fallback(
                        render_evaluator,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        edit_intent,
                        &payload,
                        production_provenance.kind,
                    );
                    render_evaluation = if render_eval_timeout_for_runtime(
                        request.renderer,
                        production_provenance.kind,
                    )
                    .is_some()
                    {
                        await_with_activity_heartbeat(
                            repaired_eval_future,
                            activity_observer.clone(),
                            Duration::from_millis(125),
                        )
                        .await
                    } else {
                        repaired_eval_future.await
                    };
                }
                Err(error) => {
                    chat_generation_trace(format!(
                        "artifact_generation:candidate_runtime_repair:error id={} error={}",
                        candidate_id, error.message
                    ));
                }
            }
        }

        if let Some(interaction_truth_reason) =
            local_html_interaction_truth_block_reason(render_evaluation.as_ref())
        {
            if let Some((rescued_payload, strategy)) =
                try_local_html_interaction_truth_rescue_candidate(
                    request,
                    brief,
                    edit_intent,
                    &payload,
                    &interaction_truth_reason,
                )
            {
                chat_generation_trace(format!(
                    "artifact_generation:candidate_local_interaction_truth_rescue:post_runtime_repair id={} strategy={}",
                    candidate_id, strategy
                ));
                payload = rescued_payload;
                let rescued_eval_future = evaluate_candidate_render_with_fallback(
                    render_evaluator,
                    request,
                    brief,
                    blueprint,
                    artifact_ir,
                    edit_intent,
                    &payload,
                    production_provenance.kind,
                );
                render_evaluation = if render_eval_timeout_for_runtime(
                    request.renderer,
                    production_provenance.kind,
                )
                .is_some()
                {
                    await_with_activity_heartbeat(
                        rescued_eval_future,
                        activity_observer.clone(),
                        Duration::from_millis(125),
                    )
                    .await
                } else {
                    rescued_eval_future.await
                };
            }
        }
    }

    if production_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && matches!(
            request.renderer,
            ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest
        )
    {
        let validation = local_download_bundle_candidate_validation(request, brief, &payload);
        let validation =
            hydrate_validation_result(&validation, render_evaluation.as_ref(), None, None);
        chat_generation_trace(format!(
            "artifact_generation:candidate_validation:deterministic id={} status={:?}",
            candidate_id, validation.classification
        ));
        return Ok((
            ChatArtifactCandidateSummary {
                candidate_id: candidate_id.to_string(),
                seed,
                model: model.to_string(),
                temperature,
                strategy: strategy.to_string(),
                origin,
                provenance: Some(production_provenance.clone()),
                summary: payload.summary.clone(),
                renderable_paths: payload
                    .files
                    .iter()
                    .filter(|file| file.renderable)
                    .map(|file| file.path.clone())
                    .collect(),
                selected: false,
                fallback: false,
                failure: None,
                raw_output_preview: None,
                convergence: Some(initial_candidate_convergence_trace(
                    candidate_id,
                    "initial_generation",
                    validation_total_score(&validation),
                )),
                render_evaluation,
                validation,
            },
            payload,
        ));
    }

    chat_generation_trace(format!(
        "artifact_generation:candidate_validation:render_sanity id={}",
        candidate_id
    ));
    let validation =
        render_sanity_candidate_validation(request, brief, &payload, render_evaluation.as_ref());
    let validation = hydrate_validation_result(&validation, render_evaluation.as_ref(), None, None);
    chat_generation_trace(format!(
        "artifact_generation:candidate_validation:ok id={} status={:?}",
        candidate_id, validation.classification
    ));

    Ok((
        ChatArtifactCandidateSummary {
            candidate_id: candidate_id.to_string(),
            seed,
            model: model.to_string(),
            temperature,
            strategy: strategy.to_string(),
            origin,
            provenance: Some(production_provenance.clone()),
            summary: payload.summary.clone(),
            renderable_paths: payload
                .files
                .iter()
                .filter(|file| file.renderable)
                .map(|file| file.path.clone())
                .collect(),
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(initial_candidate_convergence_trace(
                candidate_id,
                "initial_generation",
                validation_total_score(&validation),
            )),
            render_evaluation,
            validation,
        },
        payload,
    ))
}

pub(crate) fn local_download_bundle_candidate_validation(
    _request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    payload: &ChatGeneratedArtifactPayload,
) -> ChatArtifactValidationResult {
    let has_readme = payload
        .files
        .iter()
        .any(|file| file.path.eq_ignore_ascii_case("README.md") && !file.body.trim().is_empty());
    let export_files = payload
        .files
        .iter()
        .filter(|file| file.downloadable)
        .collect::<Vec<_>>();
    let recognized_exports = export_files
        .iter()
        .filter_map(|file| {
            if is_download_bundle_readme_file(&file.path, &file.mime) {
                None
            } else {
                infer_download_bundle_export_format_from_path_and_mime(&file.path, &file.mime)
                    .map(|format| (file, format))
            }
        })
        .collect::<Vec<_>>();
    let has_usable_export = recognized_exports
        .iter()
        .any(|(file, format)| download_bundle_export_body_looks_complete(*format, &file.body));
    let all_downloadable = payload.files.iter().all(|file| file.downloadable);
    let required_terms = brief
        .required_concepts
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let body = payload
        .files
        .iter()
        .map(|file| file.body.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let body_lower = body.to_ascii_lowercase();
    let concept_hits = required_terms
        .iter()
        .filter(|term| !term.is_empty() && body_lower.contains(term.as_str()))
        .count();
    let status = if has_readme && has_usable_export && all_downloadable {
        ChatArtifactValidationStatus::Pass
    } else if has_readme || has_usable_export {
        ChatArtifactValidationStatus::Repairable
    } else {
        ChatArtifactValidationStatus::Blocked
    };
    let mut issue_codes = Vec::new();
    let mut blocked_reasons = Vec::new();
    if !has_readme {
        issue_codes.push("missing_readme".to_string());
        blocked_reasons.push("Bundle is missing a usable README.md.".to_string());
    }
    if !has_usable_export {
        issue_codes.push("missing_usable_export".to_string());
        blocked_reasons
            .push("Bundle is missing a usable request-grounded export file.".to_string());
    }
    if !all_downloadable {
        issue_codes.push("non_downloadable_file".to_string());
        blocked_reasons.push("All bundle files must remain downloadable.".to_string());
    }
    if concept_hits == 0 && !brief.required_concepts.is_empty() {
        issue_codes.push("concept_coverage_thin".to_string());
    }
    let export_labels = recognized_exports
        .iter()
        .map(|(_, format)| download_bundle_export_format_label(*format))
        .collect::<Vec<_>>();
    let repair_hints = blocked_reasons.clone();
    let summary = match status {
        ChatArtifactValidationStatus::Pass => {
            "Bundle contract validated with a usable README and export file.".to_string()
        }
        ChatArtifactValidationStatus::Repairable => {
            "Bundle contract is close, but one required file is thin or incomplete.".to_string()
        }
        ChatArtifactValidationStatus::Blocked => {
            "Bundle contract is missing a required usable file.".to_string()
        }
    };
    let rationale = if export_labels.is_empty() {
        summary.clone()
    } else {
        format!("Validated bundle exports: {}.", export_labels.join(" + "))
    };
    let validated_paths = payload
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();

    build_validation_result(
        status,
        "bundle_contract",
        status == ChatArtifactValidationStatus::Pass,
        validated_paths,
        issue_codes,
        repair_hints,
        blocked_reasons,
        summary,
        rationale,
    )
}

#[allow(dead_code)]
pub(crate) fn local_download_bundle_candidate_prevalidation(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    payload: &ChatGeneratedArtifactPayload,
) -> ChatArtifactValidationResult {
    let validation = local_download_bundle_candidate_validation(request, brief, payload);
    hydrate_validation_result(&validation, None, None, None)
}

fn render_sanity_issue_snapshot(
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> (Vec<String>, Vec<String>) {
    let Some(render_evaluation) = render_evaluation else {
        return (Vec::new(), Vec::new());
    };

    let mut issue_classes = Vec::new();
    let mut repair_hints = Vec::new();

    for finding in render_evaluation.findings.iter().take(3) {
        if !finding.code.is_empty() && !issue_classes.contains(&finding.code) {
            issue_classes.push(finding.code.clone());
        }
        if repair_hints.len() < 3 {
            repair_hints.push(finding.summary.clone());
        }
    }

    for obligation in render_evaluation
        .acceptance_obligations
        .iter()
        .filter(|obligation| {
            matches!(
                obligation.status,
                ChatArtifactAcceptanceObligationStatus::Failed
                    | ChatArtifactAcceptanceObligationStatus::Blocked
            )
        })
    {
        if !issue_classes.contains(&obligation.obligation_id) {
            issue_classes.push(obligation.obligation_id.clone());
        }
        if repair_hints.len() < 3 {
            repair_hints.push(
                obligation
                    .detail
                    .clone()
                    .unwrap_or_else(|| obligation.summary.clone()),
            );
        }
    }

    (issue_classes, repair_hints)
}

pub(super) fn render_sanity_block_reason(
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    if !render_evaluation.supported {
        return None;
    }
    if render_sanity_warning_only_primary_ready(render_evaluation) {
        return None;
    }

    if let Some(reason) = direct_author_runtime_failure_reason(Some(render_evaluation)) {
        return Some(reason);
    }

    if let Some(obligation) = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| {
            matches!(
                obligation.status,
                ChatArtifactAcceptanceObligationStatus::Failed
                    | ChatArtifactAcceptanceObligationStatus::Blocked
            )
        })
    {
        return Some(
            obligation
                .detail
                .clone()
                .unwrap_or_else(|| obligation.summary.clone()),
        );
    }

    render_evaluation
        .findings
        .iter()
        .find(|finding| finding.severity == ChatArtifactRenderFindingSeverity::Blocked)
        .map(|finding| finding.summary.clone())
}

pub(super) fn render_sanity_repair_reason(
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    if !render_evaluation.supported {
        return None;
    }
    if render_sanity_warning_only_primary_ready(render_evaluation) {
        return None;
    }

    if let Some(reason) = render_sanity_block_reason(Some(render_evaluation)) {
        return Some(reason);
    }

    render_evaluation
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.severity,
                ChatArtifactRenderFindingSeverity::Info
                    | ChatArtifactRenderFindingSeverity::Warning
            )
        })
        .map(|finding| finding.summary.clone())
}

fn render_sanity_warning_only_primary_ready(
    render_evaluation: &ChatArtifactRenderEvaluation,
) -> bool {
    render_evaluation.first_paint_captured
        && !render_evaluation.has_failed_required_obligations()
        && render_evaluation.overall_score >= render_evaluation.primary_view_score_threshold()
        && render_evaluation
            .findings
            .iter()
            .all(|finding| finding.severity != ChatArtifactRenderFindingSeverity::Blocked)
}

pub(super) fn render_sanity_candidate_validation_preview(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    payload: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    let validation = render_sanity_candidate_validation(request, brief, payload, render_evaluation);
    hydrate_validation_result(&validation, render_evaluation, None, None)
}

pub(super) fn candidate_supports_fast_surface(summary: &ChatArtifactCandidateSummary) -> bool {
    if summary.validation.classification == ChatArtifactValidationStatus::Blocked
        || summary.validation.generic_shell_detected
        || summary.validation.trivial_shell_detected
    {
        return false;
    }

    if summary.renderable_paths.is_empty()
        && !summary.validation.primary_view_cleared
        && !summary.validation.deserves_primary_artifact_view
    {
        return false;
    }

    summary
        .render_evaluation
        .as_ref()
        .map(|evaluation| {
            !evaluation.supported
                || (evaluation.first_paint_captured
                    && evaluation.findings.iter().all(|finding| {
                        finding.severity != ChatArtifactRenderFindingSeverity::Blocked
                    }))
        })
        .unwrap_or(true)
}

pub(super) fn render_sanity_candidate_validation(
    _request: &ChatOutcomeArtifactRequest,
    _brief: &ChatArtifactBrief,
    payload: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    let renderable_paths = renderable_paths_for_payload(payload);
    let blocked_reason = render_sanity_block_reason(render_evaluation);
    let repair_reason = render_sanity_repair_reason(render_evaluation);
    let (mut issue_codes, mut repair_hints) = render_sanity_issue_snapshot(render_evaluation);
    let status = if renderable_paths.is_empty() || blocked_reason.is_some() {
        ChatArtifactValidationStatus::Blocked
    } else if repair_reason.is_some()
        || render_evaluation.is_some_and(|evaluation| {
            evaluation.supported && !evaluation.clears_primary_view_by_policy()
        })
    {
        ChatArtifactValidationStatus::Repairable
    } else {
        ChatArtifactValidationStatus::Pass
    };
    let mut blocked_reasons = Vec::new();
    if renderable_paths.is_empty() {
        blocked_reasons.push("Artifact did not surface a renderable file.".to_string());
    }
    if let Some(reason) = blocked_reason.as_ref() {
        blocked_reasons.push(reason.clone());
    }
    if let Some(reason) = repair_reason.as_ref() {
        if !repair_hints.iter().any(|hint| hint == reason) {
            repair_hints.insert(0, reason.clone());
        }
        if blocked_reason.is_none() && !issue_codes.iter().any(|code| code == "render_warning") {
            issue_codes.push("render_warning".to_string());
        }
    }
    let summary = match status {
        ChatArtifactValidationStatus::Pass => {
            "Render validation cleared the artifact for presentation.".to_string()
        }
        ChatArtifactValidationStatus::Repairable => {
            "Render validation surfaced a concrete issue that should drive a bounded repair."
                .to_string()
        }
        ChatArtifactValidationStatus::Blocked => {
            "Render validation blocked the artifact from primary presentation.".to_string()
        }
    };
    let rationale = blocked_reason
        .clone()
        .or(repair_reason.clone())
        .unwrap_or_else(|| {
            "Renderable artifact passed the current validation contract.".to_string()
        });

    let primary_view_cleared = status == ChatArtifactValidationStatus::Pass
        && render_evaluation
            .map(|evaluation| !evaluation.supported || evaluation.clears_primary_view_by_policy())
            .unwrap_or(true);
    let mut validation = build_validation_result(
        status,
        if render_evaluation.is_some() {
            "render_evaluation"
        } else {
            "artifact_contract"
        },
        primary_view_cleared,
        renderable_paths,
        issue_codes,
        repair_hints,
        blocked_reasons,
        summary,
        rationale,
    );
    validation.score_total =
        validation_score(status, &validation.validated_paths, render_evaluation);
    validation
}

pub(super) fn direct_author_provisional_candidate_validation_preview(
    payload: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    let validation = direct_author_provisional_candidate_validation(payload, render_evaluation);
    hydrate_validation_result(&validation, render_evaluation, None, None)
}

pub(super) fn direct_author_provisional_candidate_validation(
    payload: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    let renderable_paths = renderable_paths_for_payload(payload);
    let blocked_render_finding = render_evaluation.and_then(|evaluation| {
        evaluation
            .findings
            .iter()
            .find(|finding| finding.severity == ChatArtifactRenderFindingSeverity::Blocked)
    });
    let status = if renderable_paths.is_empty() {
        ChatArtifactValidationStatus::Blocked
    } else if blocked_render_finding.is_some() {
        ChatArtifactValidationStatus::Repairable
    } else {
        ChatArtifactValidationStatus::Pass
    };
    let mut issue_codes = Vec::new();
    let mut repair_hints = Vec::new();
    if let Some(evaluation) = render_evaluation {
        for finding in evaluation.findings.iter().take(3) {
            if !issue_codes.contains(&finding.code) {
                issue_codes.push(finding.code.clone());
            }
            if repair_hints.len() < 3 {
                repair_hints.push(finding.summary.clone());
            }
        }
    }
    let mut blocked_reasons = Vec::new();
    if renderable_paths.is_empty() {
        blocked_reasons.push("Direct authoring did not surface a renderable document.".to_string());
    }
    if let Some(finding) = blocked_render_finding {
        blocked_reasons.push(finding.summary.clone());
    }
    let summary = match status {
        ChatArtifactValidationStatus::Pass => {
            "Direct-author validation surfaced a renderable artifact immediately.".to_string()
        }
        ChatArtifactValidationStatus::Repairable => {
            "Direct-author validation surfaced a renderable artifact, but repair is still warranted."
                .to_string()
        }
        ChatArtifactValidationStatus::Blocked => {
            "Direct-author validation could not clear the surfaced artifact.".to_string()
        }
    };
    let rationale = blocked_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| summary.clone());

    let mut validation = build_validation_result(
        status,
        if render_evaluation.is_some() {
            "direct_author_render"
        } else {
            "artifact_contract"
        },
        status == ChatArtifactValidationStatus::Pass,
        renderable_paths,
        issue_codes,
        repair_hints,
        blocked_reasons,
        summary,
        rationale,
    );
    validation.score_total =
        validation_score(status, &validation.validated_paths, render_evaluation);
    validation
}

pub(super) fn direct_author_fast_runtime_sanity_enabled(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && (request.artifact_class == ChatArtifactClass::InteractiveSingleFile
            || request.verification.require_render
            || request.verification.require_preview)
}

pub(super) fn direct_author_fast_runtime_sanity_timeout(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if direct_author_fast_runtime_sanity_enabled(request, runtime_kind) {
        Some(Duration::from_secs(8))
    } else {
        None
    }
}

pub(crate) fn direct_author_runtime_failure_reason(
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    let has_passing_stateful_witness =
        render_evaluation.execution_witnesses.iter().any(|witness| {
            witness.status == ChatArtifactExecutionWitnessStatus::Passed && witness.state_changed
        }) || render_evaluation
            .observation
            .as_ref()
            .is_some_and(|observation| observation.interaction_state_changed);
    if has_passing_stateful_witness {
        return None;
    }

    if let Some(obligation) = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| {
            obligation.obligation_id == "runtime_boot_clean"
                && matches!(
                    obligation.status,
                    ChatArtifactAcceptanceObligationStatus::Failed
                        | ChatArtifactAcceptanceObligationStatus::Blocked
                )
        })
    {
        if !has_passing_stateful_witness {
            return Some(
                obligation
                    .detail
                    .clone()
                    .unwrap_or_else(|| obligation.summary.clone()),
            );
        }
    }

    if let Some(witness) = render_evaluation
        .execution_witnesses
        .iter()
        .find(|witness| {
            !witness.console_errors.is_empty()
                && witness.status != ChatArtifactExecutionWitnessStatus::Passed
        })
    {
        return Some(
            witness
                .detail
                .clone()
                .unwrap_or_else(|| witness.console_errors.join(" | ")),
        );
    }

    render_evaluation
        .findings
        .iter()
        .find(|finding| {
            let summary = finding.summary.to_ascii_lowercase();
            summary.contains("runtime error")
                || summary.contains("unhandledrejection")
                || summary.contains("referenceerror")
                || summary.contains("typeerror")
        })
        .map(|finding| finding.summary.clone())
}

pub(super) fn direct_author_runtime_sanity_validation_preview(
    payload: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    let validation = direct_author_runtime_sanity_validation(payload, render_evaluation);
    hydrate_validation_result(&validation, render_evaluation, None, None)
}

pub(super) fn direct_author_runtime_sanity_validation(
    payload: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    let renderable_paths = renderable_paths_for_payload(payload);
    let runtime_failure = direct_author_runtime_failure_reason(render_evaluation);
    let status = if renderable_paths.is_empty() {
        ChatArtifactValidationStatus::Blocked
    } else if runtime_failure.is_some() {
        ChatArtifactValidationStatus::Repairable
    } else {
        ChatArtifactValidationStatus::Pass
    };
    let mut issue_codes = Vec::new();
    let mut repair_hints = Vec::new();
    if let Some(render_evaluation) = render_evaluation {
        for finding in render_evaluation.findings.iter().take(3) {
            if !issue_codes.contains(&finding.code) {
                issue_codes.push(finding.code.clone());
            }
            if repair_hints.len() < 3 {
                repair_hints.push(finding.summary.clone());
            }
        }
    }
    if runtime_failure.is_some() && !issue_codes.iter().any(|issue| issue == "runtime_error") {
        issue_codes.push("runtime_error".to_string());
    }
    if let Some(reason) = runtime_failure.as_ref() {
        if !repair_hints.iter().any(|hint| hint == reason) {
            repair_hints.insert(0, reason.clone());
        }
    }
    let blocked_reasons = if renderable_paths.is_empty() {
        vec!["Direct-authored draft could not be surfaced.".to_string()]
    } else {
        runtime_failure.clone().into_iter().collect()
    };
    let summary = match status {
        ChatArtifactValidationStatus::Pass => {
            "Runtime sanity cleared the direct-authored draft for presentation.".to_string()
        }
        ChatArtifactValidationStatus::Repairable => {
            "Runtime sanity found a concrete issue that should drive a bounded repair.".to_string()
        }
        ChatArtifactValidationStatus::Blocked => {
            "Runtime sanity could not clear the direct-authored draft.".to_string()
        }
    };
    let rationale = blocked_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| summary.clone());

    let mut validation = build_validation_result(
        status,
        "runtime_sanity",
        status == ChatArtifactValidationStatus::Pass,
        renderable_paths,
        issue_codes,
        repair_hints,
        blocked_reasons,
        summary,
        rationale,
    );
    validation.score_total =
        validation_score(status, &validation.validated_paths, render_evaluation);
    validation
}

pub(super) fn record_adaptive_search_signal(
    signals: &mut Vec<ChatAdaptiveSearchSignal>,
    signal: ChatAdaptiveSearchSignal,
) {
    if !signals.contains(&signal) {
        signals.push(signal);
    }
}

#[cfg(test)]
#[path = "candidate_materialization/tests.rs"]
mod tests;
