use super::*;

pub(super) struct SemanticRefinementProgress {
    pub(super) selected_winner_index: Option<usize>,
    pub(super) best_acceptance_index: Option<usize>,
    pub(super) best_acceptance_score: i32,
}

pub(super) async fn attempt_semantic_refinement_for_candidate(
    repair_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
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
    strategy: &str,
    origin: StudioArtifactOutputOrigin,
    repair_model: &str,
    repair_provenance: &StudioRuntimeProvenance,
    adaptive_search_budget: &StudioAdaptiveSearchBudget,
    source_index: usize,
    candidate_rows: &mut Vec<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>,
    candidate_summaries: &mut Vec<StudioArtifactCandidateSummary>,
    refined_candidate_roots: &mut std::collections::HashSet<String>,
    mut best_acceptance_index: Option<usize>,
    mut best_acceptance_score: i32,
    activity_observer: Option<StudioArtifactActivityObserver>,
) -> Result<SemanticRefinementProgress, StudioArtifactGenerationError> {
    let budget = semantic_convergence_budget(adaptive_search_budget);
    let mut refinement_source_index = source_index;
    let mut plateau_count = 0usize;
    let refinement_root = candidate_summaries
        .get(refinement_source_index)
        .map(|summary| refined_candidate_root(&summary.candidate_id).to_string())
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio best candidate summary is missing for refinement.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.cloned(),
            artifact_ir: artifact_ir.cloned(),
            selected_skills: selected_skills.to_vec(),
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

    for refinement_pass in 0..budget.max_passes {
        let source_summary = candidate_summaries
            .get(refinement_source_index)
            .cloned()
            .ok_or_else(|| StudioArtifactGenerationError {
                message: "Studio best candidate summary is missing for refinement.".to_string(),
                brief: Some(brief.clone()),
                blueprint: blueprint.cloned(),
                artifact_ir: artifact_ir.cloned(),
                selected_skills: selected_skills.to_vec(),
                edit_intent: edit_intent.cloned(),
                candidate_summaries: candidate_summaries.clone(),
            })?;
        let Some(pass_kind) = requested_follow_up_pass(&source_summary.judge) else {
            if let Some(summary) = candidate_summaries.get_mut(refinement_source_index) {
                set_candidate_termination_reason(summary, "judge_requested_stop");
            }
            break;
        };
        let source_payload = candidate_rows
            .get(refinement_source_index)
            .map(|(_, payload)| payload.clone())
            .ok_or_else(|| StudioArtifactGenerationError {
                message: "Studio best candidate payload is missing for refinement.".to_string(),
                brief: Some(brief.clone()),
                blueprint: blueprint.cloned(),
                artifact_ir: artifact_ir.cloned(),
                selected_skills: selected_skills.to_vec(),
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
            repair_runtime.clone(),
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
            &source_payload,
            source_summary.render_evaluation.as_ref(),
            &source_summary.judge,
            &refined_candidate_id,
            source_summary.seed,
            refinement_temperature_for_pass(pass_kind),
            activity_observer.clone(),
        )
        .await
        {
            Ok(payload) => payload,
            Err(error) => {
                if let Some(summary) = candidate_summaries.get_mut(refinement_source_index) {
                    set_candidate_termination_reason(
                        summary,
                        format!("refinement_failed: {}", error),
                    );
                }
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
        let refined_render_eval_future = evaluate_candidate_render_with_fallback(
            render_evaluator,
            request,
            brief,
            blueprint,
            artifact_ir,
            edit_intent,
            &refined_payload,
            repair_provenance.kind,
        );
        let refined_render_evaluation = if render_eval_timeout_for_runtime(
            request.renderer,
            repair_provenance.kind,
        )
        .is_some()
        {
            await_with_activity_heartbeat(
                refined_render_eval_future,
                activity_observer.clone(),
                Duration::from_millis(125),
            )
            .await
        } else {
            refined_render_eval_future.await
        };
        let refined_acceptance_judge = await_with_activity_heartbeat(
            judge_candidate_with_runtime_and_render_eval(
                acceptance_runtime.clone(),
                refined_render_evaluation.as_ref(),
                title,
                request,
                brief,
                edit_intent,
                &refined_payload,
            ),
            activity_observer.clone(),
            Duration::from_millis(125),
        )
        .await
        .map_err(|message| StudioArtifactGenerationError {
            message,
            brief: Some(brief.clone()),
            blueprint: blueprint.cloned(),
            artifact_ir: artifact_ir.cloned(),
            selected_skills: selected_skills.to_vec(),
            edit_intent: edit_intent.cloned(),
            candidate_summaries: candidate_summaries.clone(),
        })?;
        studio_generation_trace(format!(
            "artifact_generation:refine_acceptance:ok id={} classification={:?}",
            refined_candidate_id, refined_acceptance_judge.classification
        ));
        let refined_score = judge_total_score(&refined_acceptance_judge);
        let source_score = judge_total_score(&source_summary.judge);
        let score_delta_from_parent = refined_score - source_score;
        let refined_summary = StudioArtifactCandidateSummary {
            candidate_id: refined_candidate_id,
            seed: source_summary.seed,
            model: repair_model.to_string(),
            temperature: refinement_temperature_for_pass(pass_kind),
            strategy: format!("{strategy}.{pass_kind}"),
            origin,
            provenance: Some(repair_provenance.clone()),
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
            convergence: Some(refined_candidate_convergence_trace(
                &source_summary,
                pass_kind,
                refined_score,
                score_delta_from_parent,
            )),
            render_evaluation: refined_render_evaluation,
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
            if let Some(summary) = candidate_summaries.get_mut(refined_index) {
                set_candidate_termination_reason(summary, "cleared_primary_view");
            }
            return Ok(SemanticRefinementProgress {
                selected_winner_index: Some(refined_index),
                best_acceptance_index,
                best_acceptance_score,
            });
        }
        if score_delta_from_parent >= budget.min_score_delta {
            plateau_count = 0;
            refinement_source_index = refined_index;
            continue;
        }
        plateau_count += 1;
        if let Some(summary) = candidate_summaries.get_mut(refined_index) {
            let termination = if score_delta_from_parent < 0 {
                "regressed_after_rejudge"
            } else {
                "plateau_after_rejudge"
            };
            set_candidate_termination_reason(summary, termination);
        }
        if plateau_count >= budget.plateau_limit.max(1) {
            break;
        }
        refinement_source_index = refined_index;
    }

    if let Some(summary) = candidate_summaries.get_mut(refinement_source_index) {
        if summary
            .convergence
            .as_ref()
            .and_then(|trace| trace.terminated_reason.as_ref())
            .is_none()
        {
            set_candidate_termination_reason(summary, "repair_budget_exhausted");
        }
    }

    Ok(SemanticRefinementProgress {
        selected_winner_index: None,
        best_acceptance_index,
        best_acceptance_score,
    })
}
