use super::*;

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let planning_runtime = runtime_plan.planning_runtime.clone();
    let production_runtime = runtime_plan.generation_runtime.clone();
    let final_acceptance_runtime = runtime_plan.acceptance_runtime.clone();
    let repair_runtime = runtime_plan.repair_runtime.clone();
    let runtime_policy = runtime_plan.policy.clone();
    let production_provenance = production_runtime.studio_runtime_provenance();
    let acceptance_provenance = final_acceptance_runtime.studio_runtime_provenance();
    let repair_provenance = repair_runtime.studio_runtime_provenance();
    let model = runtime_model_label(&production_runtime);
    let repair_model = runtime_model_label(&repair_runtime);
    studio_generation_trace(format!(
        "artifact_generation:start renderer={:?} profile={:?} planning_model={:?} production_model={:?} acceptance_model={:?} repair_model={:?} refinement={}",
        request.renderer,
        runtime_policy.profile,
        planning_runtime.studio_runtime_provenance().model,
        production_provenance.model,
        acceptance_provenance.model,
        repair_provenance.model,
        refinement.is_some()
    ));
    let direct_author_mode = direct_authoring_enabled(execution_strategy, request, refinement);
    let planning_context = match planning_context {
        Some(existing) => existing.clone(),
        None if direct_author_mode => StudioArtifactPlanningContext {
            brief: direct_author_brief(title, intent),
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
        None => {
            let brief = plan_studio_artifact_brief_with_runtime(
                planning_runtime.clone(),
                title,
                intent,
                request,
                refinement,
            )
            .await
            .map_err(|message| StudioArtifactGenerationError {
                message,
                brief: None,
                blueprint: None,
                artifact_ir: None,
                selected_skills: Vec::new(),
                edit_intent: None,
                candidate_summaries: Vec::new(),
            })?;
            derive_planning_context_for_request(request, &brief, None, None, Vec::new())
        }
    };
    let brief = planning_context.brief.clone();
    studio_generation_trace("artifact_generation:brief_ready");
    let blueprint = planning_context.blueprint.clone();
    let artifact_ir = planning_context.artifact_ir.clone();
    let selected_skills = planning_context.selected_skills.clone();
    let retrieved_exemplars = planning_context.retrieved_exemplars.clone();
    let edit_intent = if direct_author_mode {
        None
    } else {
        match refinement {
            Some(refinement) => Some(hydrate_edit_intent_with_refinement_selection(
                plan_studio_artifact_edit_intent_with_runtime(
                    planning_runtime.clone(),
                    intent,
                    request,
                    &brief,
                    refinement,
                )
                .await
                .map_err(|message| StudioArtifactGenerationError {
                    message,
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: None,
                    candidate_summaries: Vec::new(),
                })?,
                refinement,
            )),
            None => None,
        }
    };
    studio_generation_trace(format!(
        "artifact_generation:edit_intent_ready present={}",
        edit_intent.is_some()
    ));
    studio_generation_trace(format!(
        "artifact_generation:execution_strategy {:?}",
        execution_strategy
    ));
    if studio_artifact_uses_swarm_execution(execution_strategy) {
        warm_local_html_generation_runtime_if_needed(
            request,
            &planning_runtime,
            &production_runtime,
        )
        .await;
        return generate_studio_artifact_bundle_with_swarm(
            runtime_plan.clone(),
            title,
            intent,
            request,
            refinement,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            edit_intent.as_ref(),
            execution_strategy,
            render_evaluator,
            progress_observer,
        )
        .await;
    }

    let origin = output_origin_from_provenance(&production_provenance);
    let (_, configured_temperature, candidate_strategy) =
        candidate_generation_config(request.renderer, production_provenance.kind);
    let strategy = if direct_author_mode {
        "direct_author"
    } else {
        candidate_strategy
    };
    let temperature = if direct_author_mode {
        effective_direct_author_temperature(
            request.renderer,
            production_provenance.kind,
            configured_temperature,
        )
    } else {
        effective_candidate_generation_temperature(
            request.renderer,
            production_provenance.kind,
            configured_temperature,
        )
    };
    let mut adaptive_search_budget = if direct_author_mode {
        direct_author_search_budget(request, production_provenance.kind)
    } else {
        derive_studio_adaptive_search_budget(
            request,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            refinement,
            production_provenance.kind,
            runtime_policy.profile,
            !studio_runtime_provenance_matches(&acceptance_provenance, &production_provenance),
        )
    };
    studio_generation_trace(format!(
        "artifact_generation:candidate_config initial_count={} max_count={} shortlist_limit={} max_refine={} temperature={} configured_temperature={} strategy={}",
        adaptive_search_budget.initial_candidate_count,
        adaptive_search_budget.max_candidate_count,
        adaptive_search_budget.shortlist_limit,
        adaptive_search_budget.max_semantic_refinement_passes,
        temperature,
        configured_temperature,
        strategy
    ));
    let live_preview_state = Arc::new(Mutex::new(Vec::<ExecutionLivePreview>::new()));
    if direct_author_mode {
        emit_non_swarm_generation_progress(
            progress_observer.as_ref(),
            request,
            execution_strategy,
            &snapshot_execution_live_previews(&live_preview_state),
            "Authoring artifact directly...",
            None,
            None,
            ExecutionCompletionInvariantStatus::Pending,
            Vec::new(),
        );
    }
    let mut candidate_rows = Vec::<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>::new();
    let mut failed_candidate_summaries = Vec::<StudioArtifactCandidateSummary>::new();
    let mut candidate_generation_errors = Vec::<String>::new();
    let mut next_candidate_index = 0usize;
    let mut target_candidate_count = adaptive_search_budget.initial_candidate_count.max(1);
    let (mut candidate_summaries, ranked_candidate_indices) = loop {
        while next_candidate_index < target_candidate_count {
            let candidate_id = format!("candidate-{}", next_candidate_index + 1);
            let seed = candidate_seed_for(title, intent, next_candidate_index);
            let candidate_result = if direct_author_mode {
                let direct_live_preview_observer: Option<StudioArtifactLivePreviewObserver> =
                    progress_observer.as_ref().map(|_| {
                        let progress_observer = progress_observer.clone();
                        let direct_request = request.clone();
                        let live_preview_state = live_preview_state.clone();
                        Arc::new(move |preview: ExecutionLivePreview| {
                            if let Ok(mut previews) = live_preview_state.lock() {
                                upsert_execution_live_preview(&mut previews, preview.clone());
                            }
                            let live_previews =
                                snapshot_execution_live_previews(&live_preview_state);
                            emit_non_swarm_generation_progress(
                                progress_observer.as_ref(),
                                &direct_request,
                                StudioExecutionStrategy::DirectAuthor,
                                &live_previews,
                                format!("Streaming {}.", preview.label),
                                None,
                                None,
                                ExecutionCompletionInvariantStatus::Pending,
                                Vec::new(),
                            );
                        }) as StudioArtifactLivePreviewObserver
                    });
                let payload =
                    materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
                        production_runtime.clone(),
                        Some(repair_runtime.clone()),
                        title,
                        intent,
                        request,
                        &brief,
                        refinement,
                        &candidate_id,
                        seed,
                        temperature,
                        direct_live_preview_observer,
                    )
                    .await;
                match payload {
                    Ok(payload) => {
                        if let Some(preview) =
                            non_swarm_canonical_preview(request, &payload, "draft_ready", false)
                        {
                            if let Ok(mut previews) = live_preview_state.lock() {
                                upsert_execution_live_preview(&mut previews, preview);
                            }
                        }
                        emit_non_swarm_generation_progress(
                            progress_observer.as_ref(),
                            request,
                            execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            "Direct-authored draft landed. Evaluating rendered artifact...",
                            None,
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            non_swarm_required_artifact_paths(&payload),
                        );
                        let render_evaluation = if direct_author_should_defer_render_evaluation(
                            request,
                            production_provenance.kind,
                        ) {
                            None
                        } else {
                            evaluate_candidate_render_with_fallback(
                                render_evaluator,
                                request,
                                &brief,
                                None,
                                None,
                                None,
                                &payload,
                                production_provenance.kind,
                            )
                            .await
                        };
                        emit_non_swarm_generation_progress(
                            progress_observer.as_ref(),
                            request,
                            execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            if render_evaluation.is_some() {
                                "Render evaluation complete. Preparing acceptance verification..."
                            } else {
                                "Draft landed. Deferring render capture and preparing acceptance verification..."
                            },
                            render_evaluation.as_ref(),
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            non_swarm_required_artifact_paths(&payload),
                        );
                        let judge = direct_author_provisional_candidate_judge(
                            &payload,
                            render_evaluation.as_ref(),
                        );
                        Ok((
                            StudioArtifactCandidateSummary {
                                candidate_id: candidate_id.clone(),
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
                                    &candidate_id,
                                    "direct_author",
                                    judge_total_score(&judge),
                                )),
                                render_evaluation,
                                judge,
                            },
                            payload,
                        ))
                    }
                    Err(error) => Err(StudioArtifactCandidateSummary {
                        candidate_id: candidate_id.clone(),
                        seed,
                        model: model.to_string(),
                        temperature,
                        strategy: strategy.to_string(),
                        origin,
                        provenance: Some(production_provenance.clone()),
                        summary: "Direct authoring failed during materialization.".to_string(),
                        renderable_paths: Vec::new(),
                        selected: false,
                        fallback: false,
                        failure: Some(error.message.clone()),
                        raw_output_preview: error.raw_output_preview.clone(),
                        convergence: Some(initial_candidate_convergence_trace(
                            &candidate_id,
                            "direct_author_failure",
                            judge_total_score(&blocked_candidate_generation_judge(&error.message)),
                        )),
                        render_evaluation: None,
                        judge: blocked_candidate_generation_judge(&error.message),
                    }),
                }
            } else {
                materialize_and_locally_judge_candidate(
                    production_runtime.clone(),
                    repair_runtime.clone(),
                    render_evaluator,
                    title,
                    intent,
                    request,
                    &brief,
                    blueprint.as_ref(),
                    artifact_ir.as_ref(),
                    &selected_skills,
                    &retrieved_exemplars,
                    edit_intent.as_ref(),
                    refinement,
                    &candidate_id,
                    seed,
                    temperature,
                    strategy,
                    origin,
                    &model,
                    &production_provenance,
                )
                .await
            };
            match candidate_result {
                Ok((summary, payload)) => candidate_rows.push((summary, payload)),
                Err(summary) => {
                    if let Some(failure) = summary.failure.clone() {
                        candidate_generation_errors
                            .push(format!("{}: {}", summary.candidate_id, failure));
                    }
                    failed_candidate_summaries.push(summary);
                }
            }
            next_candidate_index += 1;
        }

        if candidate_rows.is_empty() {
            if target_candidate_count < adaptive_search_budget.max_candidate_count {
                record_adaptive_search_signal(
                    &mut adaptive_search_budget.signals,
                    StudioAdaptiveSearchSignal::GenerationFailureObserved,
                );
                target_candidate_count = adaptive_search_budget.max_candidate_count;
                studio_generation_trace(format!(
                    "artifact_generation:adaptive_search_expand reason=failures_only target={}",
                    target_candidate_count
                ));
                continue;
            }
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
                blueprint,
                artifact_ir,
                selected_skills,
                edit_intent,
                candidate_summaries: failed_candidate_summaries,
            });
        }

        let candidate_summaries = candidate_rows
            .iter()
            .map(|(summary, _)| summary.clone())
            .collect::<Vec<_>>();
        let ranked_candidate_indices = ranked_candidate_indices_by_score(&candidate_summaries);
        let expanded_target = target_candidate_count_after_initial_search(
            &mut adaptive_search_budget,
            &ranked_candidate_indices,
            &candidate_summaries,
            failed_candidate_summaries.len(),
        );
        if expanded_target > target_candidate_count {
            studio_generation_trace(format!(
                "artifact_generation:adaptive_search_expand from={} to={} signals={:?}",
                target_candidate_count, expanded_target, adaptive_search_budget.signals
            ));
            target_candidate_count = expanded_target;
            continue;
        }
        break (candidate_summaries, ranked_candidate_indices);
    };
    let shortlisted_candidate_indices = shortlisted_candidate_indices_for_budget(
        &mut adaptive_search_budget,
        &ranked_candidate_indices,
        &candidate_summaries,
    );
    studio_generation_trace(format!(
        "artifact_generation:shortlist size={} limit={} signals={:?}",
        shortlisted_candidate_indices.len(),
        adaptive_search_budget.shortlist_limit,
        adaptive_search_budget.signals
    ));

    if !direct_author_mode
        && local_draft_fast_path_enabled(
            request,
            refinement,
            &production_provenance,
            &acceptance_provenance,
        )
    {
        if let Some(winner_index) = ranked_candidate_indices.iter().copied().find(|index| {
            candidate_summaries
                .get(*index)
                .map(|summary| judge_supports_local_draft_surface(&summary.judge))
                .unwrap_or(false)
        }) {
            studio_generation_trace(format!(
                "artifact_generation:local_draft_fast_path winner={}",
                candidate_summaries
                    .get(winner_index)
                    .map(|summary| summary.candidate_id.as_str())
                    .unwrap_or("missing")
            ));
            let draft_judge = candidate_summaries
                .get(winner_index)
                .map(|summary| local_draft_pending_acceptance_judge(&summary.judge, None, None))
                .ok_or_else(|| StudioArtifactGenerationError {
                    message: "Studio winning draft candidate summary is missing.".to_string(),
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: merged_candidate_summaries(
                        &candidate_summaries,
                        &failed_candidate_summaries,
                    ),
                })?;

            return build_non_swarm_draft_bundle(
                request,
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                edit_intent,
                candidate_summaries,
                &failed_candidate_summaries,
                &candidate_rows,
                winner_index,
                draft_judge,
                "draft_surface_pending_acceptance",
                execution_strategy,
                origin,
                production_provenance,
                acceptance_provenance,
                runtime_policy.clone(),
                adaptive_search_budget.clone(),
                refinement.and_then(|context| context.taste_memory.clone()),
                &snapshot_execution_live_previews(&live_preview_state),
            );
        }
    }

    let acceptance_timeout =
        acceptance_timeout_for_execution_strategy(execution_strategy, &final_acceptance_runtime);
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
        if direct_author_mode {
            emit_non_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                execution_strategy,
                &snapshot_execution_live_previews(&live_preview_state),
                "Running acceptance verification for the direct-authored draft...",
                candidate_summaries
                    .get(candidate_index)
                    .and_then(|summary| summary.render_evaluation.as_ref()),
                None,
                ExecutionCompletionInvariantStatus::Pending,
                non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
            );
        }
        studio_generation_trace(format!(
            "artifact_generation:acceptance:start id={}",
            candidate_id
        ));
        let acceptance_judge = match judge_candidate_with_runtime_and_render_eval_with_timeout(
            final_acceptance_runtime.clone(),
            acceptance_timeout,
            candidate_summaries
                .get(candidate_index)
                .and_then(|summary| summary.render_evaluation.as_ref()),
            title,
            request,
            &brief,
            edit_intent.as_ref(),
            &candidate_rows[candidate_index].1,
        )
        .await
        {
            Ok(judge) => judge,
            Err(message)
                if acceptance_timeout.is_some()
                    && message.contains("Acceptance judging timed out")
                    && direct_author_mode =>
            {
                let draft_index = std::iter::once(candidate_index)
                    .chain(ranked_candidate_indices.iter().copied())
                    .find(|index| {
                        candidate_summaries
                            .get(*index)
                            .map(candidate_supports_pending_draft_surface)
                            .unwrap_or(false)
                    });
                if let Some(winner_index) = draft_index {
                    studio_generation_trace(format!(
                        "artifact_generation:acceptance_timeout_fallback winner={} message={}",
                        candidate_summaries
                            .get(winner_index)
                            .map(|summary| summary.candidate_id.as_str())
                            .unwrap_or("missing"),
                        message
                    ));
                    let draft_judge = candidate_summaries
                        .get(winner_index)
                        .map(|summary| {
                            local_draft_pending_acceptance_judge(
                                &summary.judge,
                                Some(message.clone()),
                                Some(format!(
                                    "Studio kept a viable direct-authored draft available after {}",
                                    message.to_ascii_lowercase()
                                )),
                            )
                        })
                        .ok_or_else(|| StudioArtifactGenerationError {
                            message: "Studio winning draft candidate summary is missing."
                                .to_string(),
                            brief: Some(brief.clone()),
                            blueprint: blueprint.clone(),
                            artifact_ir: artifact_ir.clone(),
                            selected_skills: selected_skills.clone(),
                            edit_intent: edit_intent.clone(),
                            candidate_summaries: merged_candidate_summaries(
                                &candidate_summaries,
                                &failed_candidate_summaries,
                            ),
                        })?;
                    return build_non_swarm_draft_bundle(
                        request,
                        brief.clone(),
                        blueprint.clone(),
                        artifact_ir.clone(),
                        selected_skills.clone(),
                        edit_intent.clone(),
                        candidate_summaries.clone(),
                        &failed_candidate_summaries,
                        &candidate_rows,
                        winner_index,
                        draft_judge,
                        "draft_surface_acceptance_timeout",
                        execution_strategy,
                        origin,
                        production_provenance.clone(),
                        acceptance_provenance.clone(),
                        runtime_policy.clone(),
                        adaptive_search_budget.clone(),
                        refinement.and_then(|context| context.taste_memory.clone()),
                        &snapshot_execution_live_previews(&live_preview_state),
                    );
                }
                return Err(StudioArtifactGenerationError {
                    message,
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: candidate_summaries.clone(),
                });
            }
            Err(message) => {
                return Err(StudioArtifactGenerationError {
                    message,
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: candidate_summaries.clone(),
                });
            }
        };
        studio_generation_trace(format!(
            "artifact_generation:acceptance:ok id={} classification={:?}",
            candidate_id, acceptance_judge.classification
        ));
        if direct_author_mode {
            emit_non_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                execution_strategy,
                &snapshot_execution_live_previews(&live_preview_state),
                format!(
                    "Acceptance judge returned {}.",
                    judge_classification_id(acceptance_judge.classification)
                ),
                candidate_summaries
                    .get(candidate_index)
                    .and_then(|summary| summary.render_evaluation.as_ref()),
                Some(&acceptance_judge),
                if judge_clears_primary_view(&acceptance_judge) {
                    ExecutionCompletionInvariantStatus::Satisfied
                } else {
                    ExecutionCompletionInvariantStatus::Blocked
                },
                non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
            );
        }
        evaluated_acceptance_indices.insert(candidate_index);
        if let Some(summary) = candidate_summaries.get_mut(candidate_index) {
            update_candidate_summary_judge(summary, acceptance_judge.clone());
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
            repair_runtime.clone(),
            final_acceptance_runtime.clone(),
            render_evaluator,
            title,
            intent,
            request,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            edit_intent.as_ref(),
            refinement,
            strategy,
            origin,
            &repair_model,
            &repair_provenance,
            &adaptive_search_budget,
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
        for candidate_index in ranked_candidate_indices.iter().copied() {
            if evaluated_acceptance_indices.contains(&candidate_index) {
                continue;
            }
            let candidate_id = candidate_summaries
                .get(candidate_index)
                .map(|summary| summary.candidate_id.clone())
                .unwrap_or_else(|| format!("candidate-index-{candidate_index}"));
            if direct_author_mode {
                emit_non_swarm_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    execution_strategy,
                    &snapshot_execution_live_previews(&live_preview_state),
                    "Running fallback acceptance verification for the direct-authored draft...",
                    candidate_summaries
                        .get(candidate_index)
                        .and_then(|summary| summary.render_evaluation.as_ref()),
                    None,
                    ExecutionCompletionInvariantStatus::Pending,
                    non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
                );
            }
            studio_generation_trace(format!(
                "artifact_generation:acceptance_fallback:start id={}",
                candidate_id
            ));
            let acceptance_judge = match judge_candidate_with_runtime_and_render_eval_with_timeout(
                final_acceptance_runtime.clone(),
                acceptance_timeout,
                candidate_summaries
                    .get(candidate_index)
                    .and_then(|summary| summary.render_evaluation.as_ref()),
                title,
                request,
                &brief,
                edit_intent.as_ref(),
                &candidate_rows[candidate_index].1,
            )
            .await
            {
                Ok(judge) => judge,
                Err(message)
                    if acceptance_timeout.is_some()
                        && message.contains("Acceptance judging timed out")
                        && direct_author_mode =>
                {
                    let draft_index = std::iter::once(candidate_index)
                        .chain(ranked_candidate_indices.iter().copied())
                        .find(|index| {
                            candidate_summaries
                                .get(*index)
                                .map(candidate_supports_pending_draft_surface)
                                .unwrap_or(false)
                        });
                    if let Some(winner_index) = draft_index {
                        studio_generation_trace(format!(
                            "artifact_generation:acceptance_timeout_fallback winner={} message={}",
                            candidate_summaries
                                .get(winner_index)
                                .map(|summary| summary.candidate_id.as_str())
                                .unwrap_or("missing"),
                            message
                        ));
                        let draft_judge = candidate_summaries
                            .get(winner_index)
                            .map(|summary| {
                                local_draft_pending_acceptance_judge(
                                    &summary.judge,
                                    Some(message.clone()),
                                    Some(format!(
                                        "Studio kept a viable direct-authored draft available after {}",
                                        message.to_ascii_lowercase()
                                    )),
                                )
                            })
                            .ok_or_else(|| StudioArtifactGenerationError {
                                message: "Studio winning draft candidate summary is missing."
                                    .to_string(),
                                brief: Some(brief.clone()),
                                blueprint: blueprint.clone(),
                                artifact_ir: artifact_ir.clone(),
                                selected_skills: selected_skills.clone(),
                                edit_intent: edit_intent.clone(),
                                candidate_summaries: merged_candidate_summaries(
                                    &candidate_summaries,
                                    &failed_candidate_summaries,
                                ),
                            })?;
                        return build_non_swarm_draft_bundle(
                            request,
                            brief.clone(),
                            blueprint.clone(),
                            artifact_ir.clone(),
                            selected_skills.clone(),
                            edit_intent.clone(),
                            candidate_summaries.clone(),
                            &failed_candidate_summaries,
                            &candidate_rows,
                            winner_index,
                            draft_judge,
                            "draft_surface_acceptance_timeout",
                            execution_strategy,
                            origin,
                            production_provenance.clone(),
                            acceptance_provenance.clone(),
                            runtime_policy.clone(),
                            adaptive_search_budget.clone(),
                            refinement.and_then(|context| context.taste_memory.clone()),
                            &snapshot_execution_live_previews(&live_preview_state),
                        );
                    }
                    return Err(StudioArtifactGenerationError {
                        message,
                        brief: Some(brief.clone()),
                        blueprint: blueprint.clone(),
                        artifact_ir: artifact_ir.clone(),
                        selected_skills: selected_skills.clone(),
                        edit_intent: edit_intent.clone(),
                        candidate_summaries: merged_candidate_summaries(
                            &candidate_summaries,
                            &failed_candidate_summaries,
                        ),
                    });
                }
                Err(message) => {
                    return Err(StudioArtifactGenerationError {
                        message,
                        brief: Some(brief.clone()),
                        blueprint: blueprint.clone(),
                        artifact_ir: artifact_ir.clone(),
                        selected_skills: selected_skills.clone(),
                        edit_intent: edit_intent.clone(),
                        candidate_summaries: merged_candidate_summaries(
                            &candidate_summaries,
                            &failed_candidate_summaries,
                        ),
                    });
                }
            };
            studio_generation_trace(format!(
                "artifact_generation:acceptance_fallback:ok id={} classification={:?}",
                candidate_id, acceptance_judge.classification
            ));
            if direct_author_mode {
                emit_non_swarm_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    execution_strategy,
                    &snapshot_execution_live_previews(&live_preview_state),
                    format!(
                        "Fallback acceptance judge returned {}.",
                        judge_classification_id(acceptance_judge.classification)
                    ),
                    candidate_summaries
                        .get(candidate_index)
                        .and_then(|summary| summary.render_evaluation.as_ref()),
                    Some(&acceptance_judge),
                    if judge_clears_primary_view(&acceptance_judge) {
                        ExecutionCompletionInvariantStatus::Satisfied
                    } else {
                        ExecutionCompletionInvariantStatus::Blocked
                    },
                    non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
                );
            }
            evaluated_acceptance_indices.insert(candidate_index);
            if let Some(summary) = candidate_summaries.get_mut(candidate_index) {
                update_candidate_summary_judge(summary, acceptance_judge.clone());
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
                    repair_runtime.clone(),
                    final_acceptance_runtime.clone(),
                    render_evaluator,
                    title,
                    intent,
                    request,
                    &brief,
                    blueprint.as_ref(),
                    artifact_ir.as_ref(),
                    &selected_skills,
                    &retrieved_exemplars,
                    edit_intent.as_ref(),
                    refinement,
                    strategy,
                    origin,
                    &repair_model,
                    &repair_provenance,
                    &adaptive_search_budget,
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

    build_non_swarm_winner_bundle(
        request,
        refinement,
        execution_strategy,
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy,
        adaptive_search_budget,
        live_preview_state,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        edit_intent,
        candidate_rows,
        candidate_summaries,
        failed_candidate_summaries,
        selected_winner_index,
        best_acceptance_index,
    )
}
