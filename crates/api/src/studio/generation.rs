use super::judging::{
    candidate_generation_config, candidate_seed_for, html_first_paint_section_blueprint,
    judge_clears_primary_view, judge_total_score, materialization_max_tokens,
    output_origin_from_provenance, refined_candidate_root, renderer_supports_semantic_refinement,
    runtime_model_label, semantic_refinement_pass_limit, studio_artifact_refinement_candidate_view,
    studio_artifact_refinement_context_view, summarized_guidance_terms,
};
use super::*;
use std::collections::HashSet;

fn studio_generation_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

#[derive(Debug, Clone)]
struct StudioCandidateMaterializationError {
    message: String,
    raw_output_preview: Option<String>,
}

impl From<String> for StudioCandidateMaterializationError {
    fn from(message: String) -> Self {
        Self {
            message,
            raw_output_preview: None,
        }
    }
}

fn truncate_candidate_failure_preview(raw: &str, max_chars: usize) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut preview = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        preview.push_str("...");
    }
    Some(preview)
}

fn compact_local_html_materialization_prompt(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
}

fn serialize_materialization_prompt_json<T: serde::Serialize>(
    value: &T,
    label: &str,
    compact: bool,
) -> Result<String, String> {
    if compact {
        serde_json::to_string(value)
            .map_err(|error| format!("Failed to serialize {label}: {error}"))
    } else {
        serde_json::to_string_pretty(value)
            .map_err(|error| format!("Failed to serialize {label}: {error}"))
    }
}

fn materialization_repair_candidate_view(
    raw_output: &str,
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    match super::parse_studio_generated_artifact_payload(raw_output) {
        Ok(mut candidate) => {
            super::normalize_generated_artifact_payload(&mut candidate, request);
            studio_artifact_refinement_candidate_view(&candidate)
        }
        Err(_) => json!({
            "rawOutputPreview": truncate_candidate_failure_preview(raw_output, 3600),
        }),
    }
}

fn merged_candidate_summaries(
    current: &[StudioArtifactCandidateSummary],
    failed: &[StudioArtifactCandidateSummary],
) -> Vec<StudioArtifactCandidateSummary> {
    let mut combined = current.to_vec();
    combined.extend(failed.iter().cloned());
    combined
}

fn blocked_candidate_generation_judge(message: &str) -> StudioArtifactJudgeResult {
    StudioArtifactJudgeResult {
        classification: StudioArtifactJudgeClassification::Blocked,
        request_faithfulness: 1,
        concept_coverage: 1,
        interaction_relevance: 1,
        layout_coherence: 1,
        visual_hierarchy: 1,
        completeness: 1,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: false,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        strongest_contradiction: Some(message.to_string()),
        rationale: message.to_string(),
    }
}

fn local_draft_fast_path_enabled(
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    production_kind: StudioRuntimeProvenanceKind,
    acceptance_kind: StudioRuntimeProvenanceKind,
) -> bool {
    refinement.is_none()
        && production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && acceptance_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe
                | StudioRendererKind::JsxSandbox
                | StudioRendererKind::Svg
        )
}

fn judge_supports_local_draft_surface(judge: &StudioArtifactJudgeResult) -> bool {
    judge.classification != StudioArtifactJudgeClassification::Blocked
        && judge.deserves_primary_artifact_view
        && !judge.generic_shell_detected
        && !judge.trivial_shell_detected
}

fn local_draft_pending_acceptance_judge(
    judge: &StudioArtifactJudgeResult,
) -> StudioArtifactJudgeResult {
    let mut draft_judge = judge.clone();
    draft_judge.classification = StudioArtifactJudgeClassification::Repairable;
    draft_judge.strongest_contradiction =
        Some("Acceptance judging is still pending for this draft.".to_string());
    draft_judge.rationale =
        "Production surfaced a request-faithful local draft while stronger acceptance judging remains pending."
            .to_string();
    draft_judge
}

struct SemanticRefinementProgress {
    selected_winner_index: Option<usize>,
    best_acceptance_index: Option<usize>,
    best_acceptance_score: i32,
}

async fn attempt_semantic_refinement_for_candidate(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    strategy: &str,
    origin: StudioArtifactOutputOrigin,
    model: &str,
    production_provenance: &StudioRuntimeProvenance,
    source_index: usize,
    candidate_rows: &mut Vec<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>,
    candidate_summaries: &mut Vec<StudioArtifactCandidateSummary>,
    refined_candidate_roots: &mut std::collections::HashSet<String>,
    mut best_acceptance_index: Option<usize>,
    mut best_acceptance_score: i32,
) -> Result<SemanticRefinementProgress, StudioArtifactGenerationError> {
    let mut refinement_source_index = source_index;
    let refinement_root = candidate_summaries
        .get(refinement_source_index)
        .map(|summary| refined_candidate_root(&summary.candidate_id).to_string())
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio best candidate summary is missing for refinement.".to_string(),
            brief: Some(brief.clone()),
            edit_intent: edit_intent.cloned(),
            candidate_summaries: candidate_summaries.clone(),
        })?;
    if !refined_candidate_roots.insert(refinement_root) {
        return Ok(SemanticRefinementProgress {
            selected_winner_index: None,
            best_acceptance_index,
            best_acceptance_score,
        });
    }

    for refinement_pass in
        0..semantic_refinement_pass_limit(request.renderer, production_provenance.kind)
    {
        let source_summary = candidate_summaries
            .get(refinement_source_index)
            .cloned()
            .ok_or_else(|| StudioArtifactGenerationError {
                message: "Studio best candidate summary is missing for refinement.".to_string(),
                brief: Some(brief.clone()),
                edit_intent: edit_intent.cloned(),
                candidate_summaries: candidate_summaries.clone(),
            })?;
        let source_payload = candidate_rows
            .get(refinement_source_index)
            .map(|(_, payload)| payload.clone())
            .ok_or_else(|| StudioArtifactGenerationError {
                message: "Studio best candidate payload is missing for refinement.".to_string(),
                brief: Some(brief.clone()),
                edit_intent: edit_intent.cloned(),
                candidate_summaries: candidate_summaries.clone(),
            })?;
        let refined_candidate_id = format!(
            "{}-refine-{}",
            refined_candidate_root(&source_summary.candidate_id),
            refinement_pass + 1
        );
        studio_generation_trace(format!(
            "artifact_generation:refine:start id={} source={}",
            refined_candidate_id, source_summary.candidate_id
        ));
        let refined_payload = match refine_studio_artifact_candidate_with_runtime(
            production_runtime.clone(),
            title,
            intent,
            request,
            brief,
            edit_intent,
            refinement,
            &source_payload,
            &source_summary.judge,
            &refined_candidate_id,
            source_summary.seed,
        )
        .await
        {
            Ok(payload) => payload,
            Err(error) => {
                studio_generation_trace(format!(
                    "artifact_generation:refine:error id={} error={}",
                    refined_candidate_id, error
                ));
                break;
            }
        };
        studio_generation_trace(format!(
            "artifact_generation:refine:ok id={} files={}",
            refined_candidate_id,
            refined_payload.files.len()
        ));
        studio_generation_trace(format!(
            "artifact_generation:refine_acceptance:start id={}",
            refined_candidate_id
        ));
        let refined_acceptance_judge = judge_studio_artifact_candidate_with_runtime(
            acceptance_runtime.clone(),
            title,
            request,
            brief,
            edit_intent,
            &refined_payload,
        )
        .await
        .map_err(|message| StudioArtifactGenerationError {
            message,
            brief: Some(brief.clone()),
            edit_intent: edit_intent.cloned(),
            candidate_summaries: candidate_summaries.clone(),
        })?;
        studio_generation_trace(format!(
            "artifact_generation:refine_acceptance:ok id={} classification={:?}",
            refined_candidate_id, refined_acceptance_judge.classification
        ));
        let refined_score = judge_total_score(&refined_acceptance_judge);
        let source_score = judge_total_score(&source_summary.judge);
        let refined_summary = StudioArtifactCandidateSummary {
            candidate_id: refined_candidate_id,
            seed: source_summary.seed,
            model: model.to_string(),
            temperature: 0.18,
            strategy: format!("{strategy}.refinement"),
            origin,
            provenance: Some(production_provenance.clone()),
            summary: refined_payload.summary.clone(),
            renderable_paths: refined_payload
                .files
                .iter()
                .filter(|file| file.renderable)
                .map(|file| file.path.clone())
                .collect(),
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            judge: refined_acceptance_judge.clone(),
        };
        let refined_index = candidate_rows.len();
        candidate_summaries.push(refined_summary.clone());
        candidate_rows.push((refined_summary, refined_payload));
        if refined_score > best_acceptance_score {
            best_acceptance_score = refined_score;
            best_acceptance_index = Some(refined_index);
        }
        if judge_clears_primary_view(&refined_acceptance_judge) {
            return Ok(SemanticRefinementProgress {
                selected_winner_index: Some(refined_index),
                best_acceptance_index,
                best_acceptance_score,
            });
        }
        if refined_score > source_score {
            refinement_source_index = refined_index;
            continue;
        }
        break;
    }

    Ok(SemanticRefinementProgress {
        selected_winner_index: None,
        best_acceptance_index,
        best_acceptance_score,
    })
}

pub async fn generate_studio_artifact_bundle_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtimes(
        runtime.clone(),
        runtime,
        title,
        intent,
        request,
        refinement,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtimes(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let production_provenance = production_runtime.studio_runtime_provenance();
    let final_acceptance_runtime = acceptance_runtime.clone();
    let acceptance_provenance = acceptance_runtime.studio_runtime_provenance();
    let origin = output_origin_from_provenance(&production_provenance);
    let model = runtime_model_label(&production_runtime);
    studio_generation_trace(format!(
        "artifact_generation:start renderer={:?} production_model={:?} acceptance_model={:?} refinement={}",
        request.renderer,
        production_provenance.model,
        acceptance_provenance.model,
        refinement.is_some()
    ));
    let brief = plan_studio_artifact_brief_with_runtime(
        production_runtime.clone(),
        title,
        intent,
        request,
        refinement,
    )
    .await
    .map_err(|message| StudioArtifactGenerationError {
        message,
        brief: None,
        edit_intent: None,
        candidate_summaries: Vec::new(),
    })?;
    studio_generation_trace("artifact_generation:brief_ready");
    let edit_intent = match refinement {
        Some(refinement) => Some(hydrate_edit_intent_with_refinement_selection(
            plan_studio_artifact_edit_intent_with_runtime(
                production_runtime.clone(),
                intent,
                request,
                &brief,
                refinement,
            )
            .await
            .map_err(|message| StudioArtifactGenerationError {
                message,
                brief: Some(brief.clone()),
                edit_intent: None,
                candidate_summaries: Vec::new(),
            })?,
            refinement,
        )),
        None => None,
    };
    studio_generation_trace(format!(
        "artifact_generation:edit_intent_ready present={}",
        edit_intent.is_some()
    ));
    let (candidate_count, temperature, strategy) =
        candidate_generation_config(request.renderer, production_provenance.kind);
    studio_generation_trace(format!(
        "artifact_generation:candidate_config count={} temperature={} strategy={}",
        candidate_count, temperature, strategy
    ));
    let mut candidate_rows = Vec::<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>::new();
    let mut failed_candidate_summaries = Vec::<StudioArtifactCandidateSummary>::new();
    let mut candidate_generation_errors = Vec::<String>::new();

    for candidate_index in 0..candidate_count.max(1) {
        let candidate_id = format!("candidate-{}", candidate_index + 1);
        let seed = candidate_seed_for(title, intent, candidate_index);
        studio_generation_trace(format!(
            "artifact_generation:candidate_materialize:start id={} seed={}",
            candidate_id, seed
        ));
        let payload = match materialize_studio_artifact_candidate_with_runtime_detailed(
            production_runtime.clone(),
            title,
            intent,
            request,
            &brief,
            edit_intent.as_ref(),
            refinement,
            &candidate_id,
            seed,
            temperature,
        )
        .await
        {
            Ok(payload) => {
                studio_generation_trace(format!(
                    "artifact_generation:candidate_materialize:ok id={} files={}",
                    candidate_id,
                    payload.files.len()
                ));
                payload
            }
            Err(error) => {
                studio_generation_trace(format!(
                    "artifact_generation:candidate_materialize:error id={} error={}",
                    candidate_id, error.message
                ));
                candidate_generation_errors.push(format!("{candidate_id}: {}", error.message));
                failed_candidate_summaries.push(StudioArtifactCandidateSummary {
                    candidate_id,
                    seed,
                    model: model.clone(),
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
                    judge: blocked_candidate_generation_judge(&error.message),
                });
                continue;
            }
        };
        studio_generation_trace(format!(
            "artifact_generation:candidate_judge:start id={}",
            candidate_id
        ));
        let judge = match judge_studio_artifact_candidate_with_runtime(
            production_runtime.clone(),
            title,
            request,
            &brief,
            edit_intent.as_ref(),
            &payload,
        )
        .await
        {
            Ok(judge) => {
                studio_generation_trace(format!(
                    "artifact_generation:candidate_judge:ok id={} classification={:?}",
                    candidate_id, judge.classification
                ));
                judge
            }
            Err(error) => {
                studio_generation_trace(format!(
                    "artifact_generation:candidate_judge:error id={} error={}",
                    candidate_id, error
                ));
                candidate_generation_errors.push(format!("{candidate_id}: judge failed: {error}"));
                failed_candidate_summaries.push(StudioArtifactCandidateSummary {
                    candidate_id,
                    seed,
                    model: model.clone(),
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
                    failure: Some(format!("judge failed: {error}")),
                    raw_output_preview: None,
                    judge: blocked_candidate_generation_judge(&format!("judge failed: {error}")),
                });
                continue;
            }
        };
        candidate_rows.push((
            StudioArtifactCandidateSummary {
                candidate_id,
                seed,
                model: model.clone(),
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
                judge,
            },
            payload,
        ));
    }

    if candidate_rows.is_empty() {
        return Err(StudioArtifactGenerationError {
            message: if candidate_generation_errors.is_empty() {
                "Studio artifact generation did not produce any candidates.".to_string()
            } else {
                format!(
                    "Studio artifact generation did not produce a valid candidate. {}",
                    candidate_generation_errors.join(" | ")
                )
            },
            brief: Some(brief),
            edit_intent,
            candidate_summaries: failed_candidate_summaries,
        });
    }

    let mut candidate_summaries = candidate_rows
        .iter()
        .map(|(summary, _)| summary.clone())
        .collect::<Vec<_>>();
    let ranked_candidate_indices = {
        let mut ranked = candidate_rows
            .iter()
            .enumerate()
            .map(|(index, (summary, _))| (index, judge_total_score(&summary.judge)))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        ranked
            .into_iter()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    };
    let mut shortlisted_candidate_indices = ranked_candidate_indices
        .iter()
        .copied()
        .filter(|index| {
            candidate_summaries
                .get(*index)
                .map(|summary| judge_clears_primary_view(&summary.judge))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if shortlisted_candidate_indices.is_empty() {
        if let Some(best_stage_index) = ranked_candidate_indices.first().copied() {
            shortlisted_candidate_indices.push(best_stage_index);
        }
    }
    studio_generation_trace(format!(
        "artifact_generation:shortlist size={}",
        shortlisted_candidate_indices.len()
    ));

    if local_draft_fast_path_enabled(
        request,
        refinement,
        production_provenance.kind,
        acceptance_provenance.kind,
    ) {
        if let Some(winner_index) = ranked_candidate_indices.iter().copied().find(|index| {
            candidate_summaries
                .get(*index)
                .map(|summary| judge_supports_local_draft_surface(&summary.judge))
                .unwrap_or(false)
        }) {
            let draft_judge = candidate_summaries
                .get(winner_index)
                .map(|summary| local_draft_pending_acceptance_judge(&summary.judge))
                .ok_or_else(|| StudioArtifactGenerationError {
                    message: "Studio winning draft candidate summary is missing.".to_string(),
                    brief: Some(brief.clone()),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: merged_candidate_summaries(
                        &candidate_summaries,
                        &failed_candidate_summaries,
                    ),
                })?;
            if let Some(selected) = candidate_summaries.get_mut(winner_index) {
                selected.selected = true;
                selected.judge = draft_judge.clone();
            }
            let winner_summary = candidate_summaries
                .get(winner_index)
                .cloned()
                .ok_or_else(|| StudioArtifactGenerationError {
                    message: "Studio winning draft candidate summary is missing.".to_string(),
                    brief: Some(brief.clone()),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: merged_candidate_summaries(
                        &candidate_summaries,
                        &failed_candidate_summaries,
                    ),
                })?;
            let winner = candidate_rows
                .get(winner_index)
                .map(|(_, payload)| payload.clone())
                .ok_or_else(|| StudioArtifactGenerationError {
                    message: "Studio winning draft artifact payload is missing.".to_string(),
                    brief: Some(brief.clone()),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: merged_candidate_summaries(
                        &candidate_summaries,
                        &failed_candidate_summaries,
                    ),
                })?;
            let final_candidate_summaries =
                merged_candidate_summaries(&candidate_summaries, &failed_candidate_summaries);
            studio_generation_trace(format!(
                "artifact_generation:local_draft_fast_path winner={}",
                winner_summary.candidate_id
            ));

            return Ok(StudioArtifactGenerationBundle {
                brief,
                edit_intent,
                candidate_summaries: final_candidate_summaries,
                winning_candidate_id: winner_summary.candidate_id.clone(),
                winning_candidate_rationale: draft_judge.rationale.clone(),
                judge: draft_judge,
                winner,
                origin,
                production_provenance,
                acceptance_provenance,
                fallback_used: false,
                ux_lifecycle: StudioArtifactUxLifecycle::Draft,
                taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
                failure: None,
            });
        }
    }

    let mut evaluated_acceptance_indices = std::collections::HashSet::<usize>::new();
    let mut refined_candidate_roots = std::collections::HashSet::<String>::new();
    let mut best_acceptance_index = None;
    let mut best_acceptance_score = i32::MIN;
    let mut selected_winner_index = None;

    for candidate_index in shortlisted_candidate_indices {
        let candidate_id = candidate_summaries
            .get(candidate_index)
            .map(|summary| summary.candidate_id.clone())
            .unwrap_or_else(|| format!("candidate-index-{candidate_index}"));
        studio_generation_trace(format!(
            "artifact_generation:acceptance:start id={}",
            candidate_id
        ));
        let acceptance_judge = judge_studio_artifact_candidate_with_runtime(
            final_acceptance_runtime.clone(),
            title,
            request,
            &brief,
            edit_intent.as_ref(),
            &candidate_rows[candidate_index].1,
        )
        .await
        .map_err(|message| StudioArtifactGenerationError {
            message,
            brief: Some(brief.clone()),
            edit_intent: edit_intent.clone(),
            candidate_summaries: candidate_summaries.clone(),
        })?;
        studio_generation_trace(format!(
            "artifact_generation:acceptance:ok id={} classification={:?}",
            candidate_id, acceptance_judge.classification
        ));
        evaluated_acceptance_indices.insert(candidate_index);
        if let Some(summary) = candidate_summaries.get_mut(candidate_index) {
            summary.judge = acceptance_judge.clone();
        }
        let acceptance_score = judge_total_score(&acceptance_judge);
        if acceptance_score > best_acceptance_score {
            best_acceptance_score = acceptance_score;
            best_acceptance_index = Some(candidate_index);
        }
        if judge_clears_primary_view(&acceptance_judge) {
            selected_winner_index = Some(candidate_index);
            break;
        }
    }

    if selected_winner_index.is_none()
        && renderer_supports_semantic_refinement(request.renderer)
        && best_acceptance_index.is_some()
    {
        let progress = attempt_semantic_refinement_for_candidate(
            production_runtime.clone(),
            final_acceptance_runtime.clone(),
            title,
            intent,
            request,
            &brief,
            edit_intent.as_ref(),
            refinement,
            strategy,
            origin,
            &model,
            &production_provenance,
            best_acceptance_index.expect("best acceptance index"),
            &mut candidate_rows,
            &mut candidate_summaries,
            &mut refined_candidate_roots,
            best_acceptance_index,
            best_acceptance_score,
        )
        .await?;
        best_acceptance_index = progress.best_acceptance_index;
        best_acceptance_score = progress.best_acceptance_score;
        selected_winner_index = progress.selected_winner_index;
    }

    if selected_winner_index.is_none() {
        for candidate_index in ranked_candidate_indices {
            if evaluated_acceptance_indices.contains(&candidate_index) {
                continue;
            }
            let candidate_id = candidate_summaries
                .get(candidate_index)
                .map(|summary| summary.candidate_id.clone())
                .unwrap_or_else(|| format!("candidate-index-{candidate_index}"));
            studio_generation_trace(format!(
                "artifact_generation:acceptance_fallback:start id={}",
                candidate_id
            ));
            let acceptance_judge = judge_studio_artifact_candidate_with_runtime(
                final_acceptance_runtime.clone(),
                title,
                request,
                &brief,
                edit_intent.as_ref(),
                &candidate_rows[candidate_index].1,
            )
            .await
            .map_err(|message| StudioArtifactGenerationError {
                message,
                brief: Some(brief.clone()),
                edit_intent: edit_intent.clone(),
                candidate_summaries: merged_candidate_summaries(
                    &candidate_summaries,
                    &failed_candidate_summaries,
                ),
            })?;
            studio_generation_trace(format!(
                "artifact_generation:acceptance_fallback:ok id={} classification={:?}",
                candidate_id, acceptance_judge.classification
            ));
            evaluated_acceptance_indices.insert(candidate_index);
            if let Some(summary) = candidate_summaries.get_mut(candidate_index) {
                summary.judge = acceptance_judge.clone();
            }
            let acceptance_score = judge_total_score(&acceptance_judge);
            if acceptance_score > best_acceptance_score {
                best_acceptance_score = acceptance_score;
                best_acceptance_index = Some(candidate_index);
            }
            if judge_clears_primary_view(&acceptance_judge) {
                selected_winner_index = Some(candidate_index);
                break;
            }
            if renderer_supports_semantic_refinement(request.renderer) {
                let progress = attempt_semantic_refinement_for_candidate(
                    production_runtime.clone(),
                    final_acceptance_runtime.clone(),
                    title,
                    intent,
                    request,
                    &brief,
                    edit_intent.as_ref(),
                    refinement,
                    strategy,
                    origin,
                    &model,
                    &production_provenance,
                    candidate_index,
                    &mut candidate_rows,
                    &mut candidate_summaries,
                    &mut refined_candidate_roots,
                    best_acceptance_index,
                    best_acceptance_score,
                )
                .await?;
                best_acceptance_index = progress.best_acceptance_index;
                best_acceptance_score = progress.best_acceptance_score;
                if let Some(winner_index) = progress.selected_winner_index {
                    selected_winner_index = Some(winner_index);
                    break;
                }
            }
        }
    }

    let winner_index = selected_winner_index
        .or(best_acceptance_index)
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    if let Some(selected) = candidate_summaries.get_mut(winner_index) {
        selected.selected = true;
    }
    let winner_summary = candidate_summaries
        .get(winner_index)
        .cloned()
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    let acceptance_judge = winner_summary.judge.clone();
    let winner = candidate_rows
        .into_iter()
        .nth(winner_index)
        .map(|(_, payload)| payload)
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning artifact payload is missing.".to_string(),
            brief: Some(brief.clone()),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    let final_candidate_summaries =
        merged_candidate_summaries(&candidate_summaries, &failed_candidate_summaries);
    studio_generation_trace(format!(
        "artifact_generation:winner id={}",
        winner_summary.candidate_id
    ));

    Ok(StudioArtifactGenerationBundle {
        brief,
        edit_intent,
        candidate_summaries: final_candidate_summaries,
        winning_candidate_id: winner_summary.candidate_id.clone(),
        winning_candidate_rationale: winner_summary.judge.rationale.clone(),
        judge: acceptance_judge,
        winner,
        origin,
        production_provenance,
        acceptance_provenance,
        fallback_used: false,
        ux_lifecycle: StudioArtifactUxLifecycle::Judged,
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}

fn hydrate_edit_intent_with_refinement_selection(
    mut edit_intent: StudioArtifactEditIntent,
    refinement: &StudioArtifactRefinementContext,
) -> StudioArtifactEditIntent {
    if edit_intent.selected_targets.is_empty() && !refinement.selected_targets.is_empty() {
        edit_intent.selected_targets = refinement.selected_targets.clone();
    }
    if edit_intent.target_paths.is_empty() {
        let mut target_paths = edit_intent
            .selected_targets
            .iter()
            .filter_map(|target| target.path.clone())
            .collect::<Vec<_>>();
        target_paths.sort();
        target_paths.dedup();
        edit_intent.target_paths = target_paths;
    }
    edit_intent
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

async fn materialize_studio_artifact_candidate_with_runtime_detailed(
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
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<
        StudioGeneratedArtifactPayload,
        StudioCandidateMaterializationError,
    > {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
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
    studio_generation_trace(format!(
        "artifact_generation:materialization_inference:start id={} temperature={} max_tokens={}",
        candidate_id,
        temperature,
        materialization_max_tokens(request.renderer)
    ));
    let output = runtime
        .clone()
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature,
                json_mode: true,
                max_tokens: materialization_max_tokens(request.renderer),
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
            let mut latest_error = first_error.message;
            let mut latest_raw = raw;

            let runtime_kind = runtime.studio_runtime_provenance().kind;
            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, runtime_kind)
            {
                studio_generation_trace(format!(
                    "artifact_generation:materialization_repair:start id={} attempt={}",
                    candidate_id,
                    repair_attempt + 1
                ));
                let repair_payload = build_studio_artifact_materialization_repair_prompt_for_runtime(
                    title,
                    intent,
                    request,
                    brief,
                    edit_intent,
                    refinement,
                    candidate_id,
                    candidate_seed,
                    &latest_raw,
                    &latest_error,
                    runtime_kind,
                )
                .map_err(|message| StudioCandidateMaterializationError {
                    message,
                    raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
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
                let repair_output = runtime
                    .execute_inference(
                        [0u8; 32],
                        &repair_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: true,
                            max_tokens: materialization_max_tokens(request.renderer),
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
        title,
        intent,
        request,
        brief,
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
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<StudioGeneratedArtifactPayload, String> {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
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
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.18,
                json_mode: true,
                max_tokens: materialization_max_tokens(request.renderer),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio artifact refinement inference failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio artifact refinement utf8 decode failed: {error}"))?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            let mut latest_error = first_error;
            let mut latest_raw = raw;

            let runtime_kind = runtime.studio_runtime_provenance().kind;
            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, runtime_kind)
            {
                let repair_payload =
                    build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
                    title,
                    intent,
                    request,
                    brief,
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
                let repair_output = runtime
                    .execute_inference(
                        [0u8; 32],
                        &repair_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: true,
                            max_tokens: materialization_max_tokens(request.renderer),
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
                let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                    format!(
                        "{latest_error}; refinement repair attempt {} utf8 decode failed: {error}",
                        repair_attempt + 1
                    )
                })?;
                match parse_candidate(&repair_raw) {
                    Ok(generated) => return Ok(generated),
                    Err(repair_error) => {
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

pub(super) fn materialization_repair_pass_limit(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            1
        }
        StudioRendererKind::HtmlIframe => 3,
        StudioRendererKind::PdfEmbed => 3,
        _ => 1,
    }
}

pub fn build_studio_artifact_materialization_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_materialization_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_materialization_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let refinement_wrapper_directive = if refinement.is_some() {
        "\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object."
    } else {
        ""
    };
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact materializer. Produce exactly one JSON object. The typed brief, edit intent, and current artifact context are authoritative. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                refinement_wrapper_directive,
                renderer_guidance,
                schema_contract,
            )
        }
    ]))
}

fn studio_artifact_materialization_schema_contract() -> &'static str {
    "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) markdown => one renderable .md file.\n3) html_iframe => one renderable .html file with inline CSS/JS only.\n4) html_iframe must use semantic HTML structure: include <main> plus at least three sectioning elements drawn from <section>, <article>, <nav>, <aside>, or <footer>.\n5) html_iframe must ground requiredInteractions in real controls or interactive regions, not just static headings.\n6) html_iframe must realize required interactions as on-page state changes, revealed detail, filtering, comparison, tutorial stepping, or comparable DOM behavior.\n7) html_iframe must ship interactive regions with actual first-paint content and data; empty containers, comment-only handlers, or explanation-only scripts do not count as implementation.\n8) html_iframe must include a first-paint control set plus a shared detail, comparison, or explanation region when requiredInteractions are non-empty.\n9) html_iframe view-switching or navigation interactions must change inline content or shared detail state; anchor-only jump links do not count as sufficient implementation.\n10) html_iframe must render the default selected chart, label, and detail state directly in the markup before any script runs; scripts may enhance or switch it, but must not create the only visible first-paint content from empty shells.\n11) html_iframe must not use alert(), dead buttons, submit-to-nowhere forms, or navigation-only controls as the main interaction.\n12) html_iframe must not invent custom element tags like <toolbox> or <demo>; use standard HTML elements, classes, and data-* attributes.\n13) html_iframe must not depend on external libraries, undefined globals, or remote placeholder media; render charts and diagrams with inline SVG, canvas, or DOM/CSS.\n14) html_iframe must prefer inline SVG or DOM data marks over blank canvas shells; a canvas-only placeholder does not count as first-paint implementation.\n15) html_iframe chart or diagram regions rendered with SVG must contain real marks plus visible labels, legend text, or accessible labels on first paint; abstract geometry alone does not count.\n16) html_iframe chart or diagram controls should update a shared detail, comparison, or explanation region instead of acting as decorative navigation.\n17) html_iframe must not include placeholder comments, TODO markers, or script references to DOM ids that do not exist in the document.\n18) jsx_sandbox => one renderable .jsx file with a default export.\n19) svg => one renderable .svg file.\n20) mermaid => one renderable .mermaid file.\n21) pdf_embed => one .pdf file whose body is the document text that Studio will compile into PDF bytes, and the document text must still be returned inside this JSON object as files[0].body rather than as raw prose outside JSON.\n22) download_card => downloadable export files only; do not mark them renderable.\n23) bundle_manifest => a .json manifest plus any supporting files required by the bundle.\n24) workspace_surface must not be used here.\n25) The visible composition must surface the differentiating request concepts from artifactThesis and requiredConcepts, not just the broad category.\n26) Do not use placeholder image URLs, placeholder copy, or generic stock filler. Prefer typographic, diagrammatic, or CSS-native composition over fake media placeholders.\n27) If the artifact could fit many unrelated prompts by only swapping the heading, it is not acceptable.\n28) Honor refinement continuity when editIntent.mode is patch or branch.\n29) Prefer truthful partial output over invented completion.\n30) html_iframe controls that iterate across multiple buttons, cards, or marks must target collections correctly; use querySelectorAll or an equivalent collection before calling forEach or similar methods, and keep every referenced view present in the markup.\n31) html_iframe clickable navigation should use explicit static control-to-panel mappings such as data-view plus data-view-panel, aria-controls, or data-target tied to pre-rendered views. Use the literal data-view-panel attribute on the panel element itself; a CSS class like class=\"data-view-panel\" does not satisfy this contract. Do not synthesize target ids by concatenating button ids or other runtime strings.\n32) html_iframe briefs that call for charts, diagrams, metrics, or comparisons must surface at least two distinct first-paint evidence views or chart families tied to different requiredConcepts or referenceHints; one chart plus generic prose is insufficient, and blank mount divs like <div id=\"usage-chart\"></div> do not count as evidence views.\n33) html_iframe briefs that require both clickable view switching and rollover detail must satisfy both in the same document: keep at least two pre-rendered panels plus visible data-detail marks that update one shared detail region on click and hover/focus. Do not repair one interaction by deleting the other.\n34) html_iframe marks that rely on focus handlers must be focusable, such as via tabindex=\"0\" or naturally focusable elements.\n35) html_iframe view-switching briefs must not point multiple controls only at one shared detail region; each switchable control needs its own pre-rendered panel container. If you emit controls like data-view=\"overview\", data-view=\"comparison\", and data-view=\"details\", emit matching containers like <section data-view-panel=\"overview\">...</section>, <section data-view-panel=\"comparison\" hidden>...</section>, and <section data-view-panel=\"details\" hidden>...</section>, keep the literal data-view-panel attribute on those panel elements, and then toggle them through a panels collection like querySelectorAll('[data-view-panel]').\n36) Keep visible markup first: place the script tag after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n37) Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quoted fragments.\n38) Static data-view, aria-controls, or data-target attributes do not satisfy clickable navigation by themselves; wire click or change handlers that toggle hidden, aria-selected, aria-hidden, data-active, or comparable state on the mapped panel wrappers.\n39) Class names like class=\"overview-panel\" or class=\"data-view-panel\" do not establish a mapped panel; put the mapping on the wrapper itself with literal attributes such as id=\"overview-panel\" and data-view-panel=\"overview\".\n40) Apply sequence-browsing requirements only when interactionContract.sequenceBrowsingRequired is true. In that case, expose a visible progression control on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
}

fn studio_artifact_materialization_schema_contract_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> &'static str {
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <main> plus at least three sectioning elements.\n4) First paint must already show real controls, a shared detail/comparison region, and request-specific evidence content.\n5) Chart, diagram, metric, or comparison briefs must show at least two populated first-paint evidence views or evidence families tied to different brief concepts.\n6) View-switching controls must toggle pre-rendered mapped panels through literal attributes such as data-view plus data-view-panel or aria-controls; do not synthesize target ids at runtime.\n7) If rollover detail is required, include visible focusable [data-detail] marks that update the shared detail region on hover/focus while preserving any required clickable view switching.\n8) Render the default selected view, chart labels, and detail text directly in the HTML before any script runs.\n9) Use inline SVG or DOM/CSS evidence with visible labels and multiple marks/rows/items; no blank shells, placeholders, TODOs, nonexistent ids, or external libraries.\n10) Keep the artifact request-specific, refinement-faithful, and truthful rather than inventing completion.";
    }
    studio_artifact_materialization_schema_contract()
}

fn studio_artifact_renderer_authoring_guidance_for_runtime(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> String {
    if compact_local_html_materialization_prompt(request.renderer, runtime_kind) {
        let layout_recipe = match candidate_seed % 3 {
            0 => "story-led hero with a control rail and detail aside",
            1 => "dashboard-led metrics rail with mapped evidence panels",
            _ => "editorial explainer with a stepper-style control row",
        };
        let concept_focus = summarized_guidance_terms(
            &brief.required_concepts,
            "the typed request concepts",
            4,
        );
        let interaction_focus = summarized_guidance_terms(
            &brief.required_interactions,
            "the required interactions",
            3,
        );
        let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
            " Include a visible previous/next control, stepper, scrubber, or evidence rail for sequence browsing."
        } else {
            ""
        };
        let rollover_directive = if super::brief_requires_rollover_detail(brief) {
            " Use focusable visible [data-detail] marks that update the shared detail panel on hover and focus."
        } else {
            ""
        };
        return format!(
            "- Use the candidate seed to vary this layout recipe: {layout_recipe}.\n- Keep the artifact visibly grounded in these request concepts: {concept_focus}.\n- Make these interaction families tangible on first paint: {interaction_focus}.{sequence_browsing_directive}\n- Ship one self-contained .html file with inline CSS/JS, <main>, and at least three sectioning elements.\n- First paint must include a request-specific hero, a real control bar, one primary evidence surface, a second populated evidence surface, and a shared detail or comparison aside.\n- Use pre-rendered mapped panels such as {} and keep exactly one mapped panel visible in the raw HTML before script runs.\n- A valid two-view first paint can pair {}.\n- Render the default selected view, chart labels, and detail text directly in the HTML; scripts should only switch or annotate existing content.\n- Use inline SVG or DOM/CSS evidence with visible labels and at least three labeled marks, rows, or items per evidence surface.\n- Controls must toggle existing panels or rewrite the shared detail region; no jump-link navigation, placeholder media, TODOs, nonexistent ids, or external libraries.{rollover_directive}",
            super::html_prompt_exact_view_scaffold(brief),
            super::html_prompt_two_view_example(brief),
        );
    }

    studio_artifact_renderer_authoring_guidance(request, brief, candidate_seed)
}

fn studio_artifact_renderer_authoring_guidance(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate_seed: u64,
) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            let requires_rollover_detail = super::brief_requires_rollover_detail(brief);
            let requires_view_switching = super::brief_requires_view_switching(brief);
            let layout_recipe = match candidate_seed % 3 {
                0 => {
                    "story-led hero, sticky section navigation, annotated timeline, and a detail drawer"
                }
                1 => {
                    "dashboard-led metrics rail, scenario controls, comparison cards, and an evidence panel"
                }
                _ => {
                    "editorial sections, guided tutorial stepper, interactive showcase cards, and a feedback summary"
                }
            };
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                4,
            );
            let interaction_focus = summarized_guidance_terms(
                &brief.required_interactions,
                "the required interactions",
                3,
            );
            let section_blueprint = html_first_paint_section_blueprint(brief);
            let evidence_plan = html_candidate_evidence_plan(brief, candidate_seed);
            let anchor_surface_directive = html_factual_anchor_surface_directive(brief);
            let interaction_distribution_directive =
                html_interaction_distribution_directive(brief);
            let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                "\n- When a requiredInteraction implies sequence browsing, timeline traversal, or scrolling through staged evidence, give it its own visible progression mechanism on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
                    .to_string()
            } else {
                String::new()
            };
            let rollover_mark_example = super::html_prompt_rollover_mark_example(brief);
            let exact_view_scaffold = super::html_prompt_exact_view_scaffold(brief);
            let two_view_example = super::html_prompt_two_view_example(brief);
            let rollover_directive = if requires_rollover_detail {
                format!(
                    "\n- When the brief calls for rollover or hover detail, include at least three visible SVG or DOM marks with data-detail text plus mouseenter/focus handlers that rewrite one shared detail panel inline. Give focusable marks tabindex=\"0\" when needed, and wire them with one collection pattern such as querySelectorAll('[data-detail]'). Buttons alone do not satisfy rollover.\n- A concrete rollover mark can look like {}; pair it with one shared detail node such as #detail-copy that the hover/focus handlers rewrite inline.",
                    rollover_mark_example
                )
            } else {
                String::new()
            };
            let combined_interaction_directive =
                if requires_view_switching && requires_rollover_detail {
                format!(
                    "\n- When the brief combines clickable view switching with rollover detail, keep both behaviors in the same artifact: render at least two pre-rendered view panels, keep one panel active on first paint, and also render visible data-detail marks inside the evidence views so the same shared detail panel updates on both button click and mark hover/focus.\n- A strong script shape here is querySelectorAll('button[data-view]') for controls, querySelectorAll('[data-view-panel]') for panels, querySelectorAll('[data-detail]') for marks, and one shared detail node such as #detail-copy that both handlers rewrite inline.\n- A safe exact scaffold is {} plus <aside><p id=\"detail-copy\">{} is selected by default.</p></aside>.\n- Keep data-view-panel as a literal HTML attribute on each panel element; a class token like class=\"data-view-panel\" does not count as a mapped panel.\n- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark.\n- If you use Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first instead of calling array-only methods on a NodeList.\n- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden.\n- Do not trade one interaction family away while fixing the other.",
                    exact_view_scaffold,
                    brief
                        .factual_anchors
                        .first()
                        .map(|value| value.trim())
                        .filter(|value| !value.is_empty())
                        .unwrap_or("The first evidence view")
                )
                } else {
                    String::new()
                };
            format!(
                "- Use the candidate seed to vary composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Build the first paint around this section blueprint: {section_blueprint}.\n- Build the first paint around a named control bar, a primary evidence region, and a shared detail or comparison panel.\n- A strong HTML pattern here is: request-specific hero section, control nav with real buttons, primary evidence article, secondary evidence article or comparison card, populated detail aside, and a short footer note.\n{evidence_plan}\n{anchor_surface_directive}\n{interaction_distribution_directive}\n- Derive visible controls and response regions from these brief concepts: {concept_focus}.\n- Make these required interactions tangible on first paint: {interaction_focus}.\n- Realize every requiredInteraction with visible controls that change content, swap views, reveal deeper detail, or compare scenarios inline.\n- Include at least two stateful controls such as buttons, tabs, segmented toggles, or clickable cards that update one shared detail, comparison, or explanation region.{sequence_browsing_directive}\n- Keep the hero and primary heading request-specific; synthesize the thesis in your own words instead of pasting artifactThesis verbatim as the headline.\n- Surface every requiredConcept in visible headings, labels, legends, captions, or callouts, not only in the title.\n- Turn factualAnchors and referenceHints into visible annotations, labels, legends, comparison rows, or evidence notes on first paint instead of burying them in generic prose.\n- Make each sectioning region independently meaningful on first paint: every <section>, <article>, <aside>, or <footer> should contain a heading, body copy, data marks, or detail content rather than acting as an empty wrapper around future script output.\n- Ship interactive regions with actual first-paint content and data. Empty containers or comment-only handlers are not acceptable.\n- Render the default selected chart, label, detail state, and secondary evidence preview directly in the HTML markup before the script tag. JavaScript should switch, annotate, or toggle visible content, not create the only first-paint content from nothing.\n- Keep visible markup first: place the script after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n- Do not rely on DOMContentLoaded, innerHTML, appendChild, createElement, template-string HTML injection, or canvas drawing to create the first visible chart, scorecard, comparison panel, or alternate evidence view from an empty target. Those techniques may enhance an already-populated region, but they must not be the sole first-paint implementation.\n- Prefer pre-rendered evidence articles, comparison cards, legend tables, or detail blocks already present in the DOM. Controls should toggle hidden/data-active/aria-selected state or rewrite one shared detail panel rather than rebuilding the whole view with innerHTML.\n- When the artifact uses view-switching controls, pair them with matching pre-rendered panels already in the DOM, for example {} and a panels collection selected before toggling hidden state.\n- Keep data-view-panel as a literal HTML attribute on each panel element; a class token like class=\"data-view-panel\" does not satisfy the mapping.\n- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quoted fragments.\n- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark.\n- If you use Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first instead of calling array-only methods on a NodeList.\n- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden.\n- Do not point every button only at the shared detail panel with aria-controls; the shared detail panel supports the per-view panels and does not replace them.\n- Buttons that only call alert(), submit nowhere, or navigate away do not satisfy requiredInteractions.\n- Do not use fragment-jump anchors as the primary interaction model. Prefer buttons, tabs, or clickable cards that rewrite one shared detail, comparison, or explanation region inline.\n- Build charts, diagrams, or explainers with inline SVG, canvas, or DOM/CSS. Do not rely on external libraries, undefined globals, or remote placeholder media.\n- Prefer inline SVG or DOM/CSS data marks over blank canvas placeholders. If you use canvas, the first paint still needs visible drawn content or an adjacent data fallback.\n- Every chart or diagram must include visible labels, legend text, or accessible labels on first paint. Decorative rings or unlabeled shapes are not enough.\n- When charts, metrics, or data visualizations are part of the brief, first paint must show at least two distinct evidence views or chart families tied to different request concepts. Use one primary visualization with at least three labeled marks plus a second populated evidence region tied to a different brief concept or factual anchor inline. One chart plus generic prose is insufficient.\n- Each visible chart or evidence family should carry multiple request-grounded marks, rows, or milestone steps with labels or captions; a single generic bar or rect does not satisfy a chart-driven brief.\n- A populated secondary evidence surface is not a single sentence paragraph. Use a second SVG, a comparison list or table, or a metric-card rail with at least three labeled items or rows.\n- If a wrapper is labeled or styled as a chart, metric, or evidence panel, populate it with structured evidence rather than overview prose alone.\n- Shared detail updates should surface the underlying metric, milestone, or evidence sentence from the current mark or control, not just echo a raw panel id or button label.{rollover_directive}{combined_interaction_directive}\n- A valid two-view first paint can pair {} Empty mount divs like <div id=\"usage-chart\"></div> do not count as the second evidence view.\n- Keep the non-selected or secondary evidence view visible as a preview, comparison card, secondary article, legend table, or score rail so the artifact reads as multi-view before any click.\n- Never include placeholder comments such as <!-- chart goes here -->, TODO markers, malformed button markup, or references to DOM ids that are not present in the markup.\n- Prefer controls that switch or annotate a shared detail panel, comparison rail, or evidence tray instead of a top-nav list that only scrolls.\n- Each control must map to a pre-rendered view, panel, or detail payload that already exists in the markup; do not wire buttons to nonexistent future containers.\n- If you attach handlers to multiple controls, marks, or cards, select them as a collection such as querySelectorAll before using forEach or similar iteration methods.\n- Make the default selected state complete on first paint so the artifact reads as usable before any click.\n- If the brief requires both view switching and rollover detail, preserve both interaction families through every repair pass instead of rewriting the artifact around only one of them.\n- If you need illustrative values, present them as labeled rollout scenarios or comparative examples rather than fake measured facts.\n- Replace filler testimonials or stock review copy with request-specific notes, observations, or rollout evidence summaries.\n- Include a short usage cue when interactions are not obvious on first paint.\n- Keep the first visible artifact complete and request-specific for {}.",
                exact_view_scaffold,
                two_view_example,
                brief.audience,
            )
        }
        StudioRendererKind::JsxSandbox => {
            let layout_recipe = match candidate_seed % 2 {
                0 => "control panel, primary visualization, and inspectable detail tray",
                _ => "guided flow, scenario switcher, and stateful summary rail",
            };
            format!(
                "- Use the candidate seed to vary component composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Make requiredInteractions visible through real component state, not placeholder handlers.\n- Surface requiredConcepts in labels, headings, and summary copy so the artifact stays request-faithful on first paint."
            )
        }
        StudioRendererKind::Svg => {
            let composition_recipe = match candidate_seed % 2 {
                0 => "layered poster composition with a focal diagram and supporting labels",
                _ => "data-forward composition with a central motif, callout labels, and supporting legends",
            };
            format!(
                "- Use the candidate seed to vary the SVG composition. This candidate should follow the composition recipe: {composition_recipe}.\n- Surface the differentiating request concepts with labels, annotations, and hierarchy instead of a generic decorative shell.\n- Build a full composition, not a title card: use at least six visible SVG content elements drawn from text, path, rect, circle, line, polygon, or comparable marks.\n- Pair the focal motif with supporting labels, callouts, or legend rows that make multiple request concepts readable on first paint.\n- Do not stop at one background shape plus one headline; include layered supporting marks or diagrammatic structure that earns the primary visual view."
            )
        }
        StudioRendererKind::PdfEmbed => {
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                5,
            );
            let anchor_focus = summarized_guidance_terms(
                &brief.factual_anchors,
                "the typed factual anchors",
                4,
            );
            format!(
                "- Treat the PDF body as polished plain document text that Studio will compile into a PDF.\n- Do not emit LaTeX, TeX commands, markdown fences, HTML tags, or any wrapper format; write plain document text only.\n- Write at least 120 words across at least five non-empty sections, separated by blank lines.\n- Use a compact briefing structure with a title, short executive summary, explicit section headings, bullet lists, and a final next-steps or risks block.\n- Include at minimum an executive summary plus three request-grounded body sections and one closing section for next steps, risks, or decisions.\n- Put every section heading on its own short line with no trailing colon, for example Executive Summary, Project Scope, Target Audience, Marketing Strategy, Timeline and Milestones, and Next Steps and Risks.\n- Separate each heading block with a blank line so the rendered PDF keeps visible section breaks.\n- Do not use square-bracket placeholder tokens such as [Detailed description] or [List of objectives]; every bullet and row must contain concrete request-grounded content.\n- Surface these request concepts as named sections, bullets, or metric callouts: {concept_focus}.\n- Turn these factual anchors into labeled bullets, milestone rows, or a compact text table instead of dense prose: {anchor_focus}.\n- Prefer concise bullets, milestone lists, and compact comparison rows over long paragraphs.\n- If the brief asks for charts or graphs, realize them as compact metric tables, milestone grids, or labeled score rows inside the document text instead of promising unavailable graphics."
            )
        }
        StudioRendererKind::DownloadCard => {
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the request-grounded deliverables",
                4,
            );
            format!(
                "- Produce a truthful downloadable bundle with non-empty export files only; do not mark any file renderable.\n- When the request implies a README or notes file, include a non-empty README.md that explains the bundle contents and how each file maps to the request.\n- When the bundle includes a CSV export, give it a header row plus at least two data rows with request-grounded values.\n- Prefer a small bundle with clear filenames, such as README.md plus one or more exports, over placeholder shells.\n- Keep the bundle contents visibly grounded in these request concepts: {concept_focus}."
            )
        }
        _ => "- Keep the artifact request-grounded, complete on first paint, and faithful to the typed brief.".to_string(),
    }
}

fn html_candidate_evidence_plan(brief: &StudioArtifactBrief, candidate_seed: u64) -> String {
    let topics = html_brief_evidence_topics(brief);
    let rotated_topics = rotated_guidance_terms(&topics, candidate_seed as usize, 4);
    let primary_focus = rotated_topics
        .first()
        .cloned()
        .unwrap_or_else(|| "the primary rollout evidence".to_string());
    let secondary_focus = rotated_topics
        .get(1)
        .cloned()
        .unwrap_or_else(|| "a supporting comparison topic".to_string());
    let detail_focus = rotated_topics
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let detail_focus = if detail_focus.is_empty() {
        "the brief evidence topics".to_string()
    } else {
        detail_focus
    };
    let control_terms = rotated_guidance_terms(&topics, candidate_seed as usize + 1, 3);
    let control_focus = if control_terms.is_empty() {
        "the brief evidence topics".to_string()
    } else {
        control_terms.join(", ")
    };
    let secondary_surface = match candidate_seed % 3 {
        0 => "comparison article",
        1 => "metric-card rail",
        _ => "score table or evidence list",
    };
    let tertiary_focus = rotated_topics.get(2).cloned();
    let tertiary_control_directive = tertiary_focus
        .as_ref()
        .map(|focus| {
            format!(
                "- Use a third labeled control, tab, or clickable card for {focus} when the brief exposes three or more evidence topics, and keep that topic visible as a preview, secondary panel, or detail payload instead of dropping it entirely."
            )
        })
        .unwrap_or_default();
    let combined_interaction_directive = if super::brief_requires_view_switching(brief)
        && super::brief_requires_rollover_detail(brief)
    {
        "- Keep the interaction model combined on first paint: buttons or tabs should switch pre-rendered [data-view-panel] views, and visible [data-detail] marks inside those views should update the same shared detail panel on hover or focus."
                .to_string()
    } else {
        String::new()
    };

    format!(
        "- Ground this candidate in a concrete evidence plan: primary evidence on {primary_focus}; secondary evidence on {secondary_focus}; shared detail anchored in {detail_focus}.\n- Use visible control labels, section headings, legends, or comparison labels derived from these brief topics: {control_focus}.\n- Keep both the primary evidence view and a populated {secondary_surface} visible on first paint so the artifact reads as multi-view before any click.\n- Make the primary evidence view an inline SVG or DOM data-mark visualization for {primary_focus}. Use a separate populated {secondary_surface} for {secondary_focus}; it may be a second SVG, annotated comparison list, metric card grid, or score table, but it must stay visible on first paint.\n- Do not satisfy the secondary evidence surface with a bare paragraph. Use structured evidence such as multiple labeled rows, comparison bullets, metric cards, or a second SVG tied to {secondary_focus}.\n- Let the shared detail panel compare or explain {detail_focus} and update inline when buttons, cards, or marks are activated.\n- For clickable navigation, use explicit static mappings that point at pre-rendered panel ids already present in the markup. A safe pattern is {}. Keep data-view-panel as a literal HTML attribute on the panel element itself; a class token like class=\"data-view-panel\" does not satisfy the mapping. Toggle hidden, data-active, or aria-selected state instead of synthesizing target ids with string concatenation at runtime.\n- Static data-view, aria-controls, or data-target attributes do not count on their own; wire click handlers that toggle hidden, aria-selected, aria-hidden, data-active, or comparable state on the mapped panel wrappers.\n- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for literal id/data-view-panel attributes on the panel wrapper.\n{combined_interaction_directive}\n{tertiary_control_directive}",
        super::html_prompt_view_mapping_pattern(brief),
    )
}

fn html_factual_anchor_surface_directive(brief: &StudioArtifactBrief) -> String {
    let anchors = brief
        .factual_anchors
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if anchors.is_empty() {
        return String::new();
    }

    let mut directives = vec![format!(
        "- Dedicate a first-paint evidence surface directly to this factual anchor: {}. Make that anchor inspectable through visible labels, marks, annotations, captions, or comparison rows instead of generic overview prose.",
        anchors[0]
    )];
    if let Some(second_anchor) = anchors.get(1) {
        directives.push(format!(
            "- Dedicate a second named evidence surface or comparison rail directly to this factual anchor: {}. Keep that surface visible on first paint as a preview, metric rail, comparison article, or secondary evidence panel rather than collapsing it into one generic summary block.",
            second_anchor
        ));
    }
    if let Some(reference_hint) = brief
        .reference_hints
        .iter()
        .map(|item| item.trim())
        .find(|item| !item.is_empty())
    {
        directives.push(format!(
            "- Use supporting reference context like {} as annotations, comparative callouts, or provenance notes, but do not let it replace the top factual anchors as the main evidence surfaces.",
            reference_hint
        ));
    }

    directives.join("\n")
}

fn html_interaction_distribution_directive(brief: &StudioArtifactBrief) -> String {
    let interactions = brief
        .required_interactions
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if interactions.len() < 2 {
        return String::new();
    }

    format!(
        "- This brief carries multiple interaction demands ({}) so distribute them across the artifact: keep one explicit control-bar interaction, plus at least one in-evidence inspection or input behavior on visible marks, cards, chips, form fields, or list items. Do not collapse every interaction into the same button row or a single generic panel toggle.",
        interactions.join(", ")
    )
}

fn html_brief_evidence_topics(brief: &StudioArtifactBrief) -> Vec<String> {
    let mut topics = Vec::<String>::new();
    let mut seen = HashSet::<String>::new();

    for collection in [
        &brief.factual_anchors,
        &brief.required_concepts,
        &brief.reference_hints,
    ] {
        for item in collection {
            for fragment in item
                .split(|ch| matches!(ch, ',' | ';' | '\n'))
                .map(str::trim)
                .filter(|fragment| !fragment.is_empty())
            {
                let key = fragment.to_ascii_lowercase();
                if seen.insert(key) {
                    topics.push(fragment.to_string());
                }
            }
        }
    }

    topics
}

fn rotated_guidance_terms(topics: &[String], offset: usize, count: usize) -> Vec<String> {
    if topics.is_empty() || count == 0 {
        return Vec::new();
    }

    let start = offset % topics.len();
    (0..topics.len())
        .map(|index| topics[(start + index) % topics.len()].clone())
        .take(count.min(topics.len()))
        .collect()
}

pub fn build_studio_artifact_materialization_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_materialization_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_materialization_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let previous_candidate_json = serialize_materialization_prompt_json(
        &materialization_repair_candidate_view(raw_output, request),
        "Studio artifact repair candidate view",
        compact_prompt,
    )?;
    let raw_output_preview = truncate_candidate_failure_preview(raw_output, 3600)
        .unwrap_or_else(|| "(empty)".to_string());
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let failure_directives =
        super::studio_artifact_materialization_failure_directives(request, brief, failure);
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact materialization repairer. Repair the candidate into a schema-valid JSON artifact payload. If the previous output already contains a usable candidate shape, patch it instead of restarting from a fresh shell. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nThe previous artifact payload was rejected.\nFailure:\n{}\n\nPrevious candidate view JSON:\n{}\n\nPrevious raw output excerpt:\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the payload so it is fully schema-valid and request-faithful. Preserve the strongest valid content from the previous attempt when possible.\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                failure,
                previous_candidate_json,
                raw_output_preview,
                renderer_guidance,
                failure_directives,
                schema_contract,
            )
        }
    ]))
}

pub fn build_studio_artifact_candidate_refinement_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_candidate_refinement_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        edit_intent,
        refinement,
        candidate,
        judge,
        candidate_id,
        candidate_seed,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_candidate_refinement_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let candidate_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_candidate_view(candidate),
        "Studio artifact candidate",
        compact_prompt,
    )?;
    let judge_json = serialize_materialization_prompt_json(
        judge,
        "Studio artifact judge result",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let refinement_directives =
        super::studio_artifact_candidate_refinement_directives(request, brief, judge);
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact refiner. Patch the current candidate in place to resolve the judge's cited contradictions while preserving working structure and strong request-specific content. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate JSON:\n{}\n\nAcceptance judgment JSON:\n{}\n\nPatch the current candidate so it keeps the strongest working structure, but fixes the cited request-faithfulness, interaction, hierarchy, and completeness gaps. Preserve file paths unless they are actively wrong.\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object.\n\nRefinement directives:\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                candidate_json,
                judge_json,
                refinement_directives,
                renderer_guidance,
                schema_contract,
            )
        }
    ]))
}

pub fn build_studio_artifact_candidate_refinement_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        edit_intent,
        refinement,
        candidate,
        judge,
        candidate_id,
        candidate_seed,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let candidate_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_candidate_view(candidate),
        "Studio artifact candidate",
        compact_prompt,
    )?;
    let judge_json = serialize_materialization_prompt_json(
        judge,
        "Studio artifact judge result",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let failure_directives =
        super::studio_artifact_materialization_failure_directives(request, brief, failure);
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact refinement repairer. Repair the refined candidate into a schema-valid patch that resolves the cited contradictions while preserving the current artifact's strongest valid structure. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate JSON:\n{}\n\nAcceptance judgment JSON:\n{}\n\nThe previous refinement payload was rejected.\nFailure:\n{}\n\nPrevious raw refinement output:\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the refinement payload so it stays request-faithful, preserves working structure, and fully validates.\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                candidate_json,
                judge_json,
                failure,
                raw_output,
                renderer_guidance,
                failure_directives,
                schema_contract,
            )
        }
    ]))
}
