use super::*;

const DIRECT_AUTHOR_FAST_RUNTIME_REPAIR_ATTEMPTS: usize = 2;

fn operator_status_from_runtime_status(
    status: ChatArtifactRuntimeEventStatus,
) -> ChatArtifactOperatorRunStatus {
    match status {
        ChatArtifactRuntimeEventStatus::Pending => ChatArtifactOperatorRunStatus::Pending,
        ChatArtifactRuntimeEventStatus::Active => ChatArtifactOperatorRunStatus::Active,
        ChatArtifactRuntimeEventStatus::Complete => ChatArtifactOperatorRunStatus::Complete,
        ChatArtifactRuntimeEventStatus::Blocked => ChatArtifactOperatorRunStatus::Blocked,
        ChatArtifactRuntimeEventStatus::Failed => ChatArtifactOperatorRunStatus::Failed,
        ChatArtifactRuntimeEventStatus::Interrupted => ChatArtifactOperatorRunStatus::Failed,
        ChatArtifactRuntimeEventStatus::Other => ChatArtifactOperatorRunStatus::Other,
    }
}

fn operator_attempt_id(attempt_id: &str) -> u32 {
    attempt_id
        .rsplit('-')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
}

fn operator_preview_from_execution_preview(
    preview: &ExecutionLivePreview,
) -> ChatArtifactOperatorPreview {
    let snapshot = runtime_preview_snapshot_from_execution_preview(preview);
    ChatArtifactOperatorPreview {
        origin_prompt_event_id: String::new(),
        label: snapshot.label,
        content: snapshot.content,
        status: snapshot.status,
        kind: snapshot.kind,
        language: snapshot.language,
        is_final: snapshot.is_final,
    }
}

fn artifact_operator_step(
    phase: ChatArtifactOperatorPhase,
    step_key: &str,
    attempt_id: impl AsRef<str>,
    label: impl Into<String>,
    detail: impl Into<String>,
    status: ChatArtifactRuntimeEventStatus,
    preview: Option<ChatArtifactOperatorPreview>,
) -> ChatArtifactOperatorStep {
    let attempt_id = attempt_id.as_ref().to_string();
    let status = operator_status_from_runtime_status(status);
    ChatArtifactOperatorStep {
        step_id: format!("{step_key}:{attempt_id}"),
        origin_prompt_event_id: String::new(),
        phase,
        engine: "generation_runtime".to_string(),
        status,
        label: label.into(),
        detail: detail.into(),
        started_at_ms: 0,
        finished_at_ms: matches!(
            status,
            ChatArtifactOperatorRunStatus::Complete
                | ChatArtifactOperatorRunStatus::Blocked
                | ChatArtifactOperatorRunStatus::Failed
        )
        .then_some(0),
        preview,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: operator_attempt_id(&attempt_id),
    }
}

fn author_artifact_step(
    attempt_id: impl AsRef<str>,
    detail: impl Into<String>,
    status: ChatArtifactRuntimeEventStatus,
) -> ChatArtifactOperatorStep {
    artifact_operator_step(
        ChatArtifactOperatorPhase::AuthorArtifact,
        "author_artifact",
        attempt_id,
        "Write artifact",
        detail,
        status,
        None,
    )
}

fn author_preview_step(
    attempt_id: impl AsRef<str>,
    preview: &ExecutionLivePreview,
) -> ChatArtifactOperatorStep {
    let status = match preview.status.trim().to_ascii_lowercase().as_str() {
        "completed" | "recovered" => ChatArtifactRuntimeEventStatus::Complete,
        "failed" => ChatArtifactRuntimeEventStatus::Blocked,
        _ => ChatArtifactRuntimeEventStatus::Active,
    };
    artifact_operator_step(
        ChatArtifactOperatorPhase::AuthorArtifact,
        "author_artifact",
        attempt_id,
        "Write artifact",
        author_preview_progress_detail(preview),
        status,
        Some(operator_preview_from_execution_preview(preview)),
    )
}

fn verify_artifact_step(
    attempt_id: impl AsRef<str>,
    detail: impl Into<String>,
    status: ChatArtifactRuntimeEventStatus,
) -> ChatArtifactOperatorStep {
    artifact_operator_step(
        ChatArtifactOperatorPhase::VerifyArtifact,
        "verify_artifact",
        attempt_id,
        "Run browser verification",
        detail,
        status,
        None,
    )
}

fn repair_artifact_step(
    attempt_id: impl AsRef<str>,
    detail: impl Into<String>,
    status: ChatArtifactRuntimeEventStatus,
) -> ChatArtifactOperatorStep {
    artifact_operator_step(
        ChatArtifactOperatorPhase::RepairArtifact,
        "repair_artifact",
        attempt_id,
        "Repair artifact",
        detail,
        status,
        None,
    )
}

fn author_preview_progress_detail(preview: &ExecutionLivePreview) -> String {
    match preview.status.trim().to_ascii_lowercase().as_str() {
        "streaming" => format!("Streaming {}.", preview.label),
        "interrupted" => format!(
            "{} was interrupted. Chat is recovering the streamed draft.",
            preview.label
        ),
        "continuing" => format!("Chat is completing {} after streaming.", preview.label),
        "repairing" => format!("Chat is repairing {} after streaming.", preview.label),
        "recovered" => format!(
            "Chat recovered {} and is handing it to verification.",
            preview.label
        ),
        "completed" => format!(
            "{} finished streaming and is ready for verification.",
            preview.label
        ),
        "failed" => format!("Chat could not recover {}.", preview.label),
        _ => format!("Updating {}.", preview.label),
    }
}

fn direct_author_render_eval_step_detail(fallback: bool) -> &'static str {
    if fallback {
        "Chat is evaluating the rendered fallback direct-authored draft before surfacing it."
    } else {
        "Chat is evaluating the direct-authored draft before surfacing it."
    }
}

fn direct_author_runtime_sanity_step_detail() -> &'static str {
    "Chat is checking the rendered direct-authored draft for concrete runtime errors before surfacing it."
}

fn direct_author_runtime_sanity_progress_message() -> &'static str {
    "Checking the rendered draft for runtime errors..."
}

fn direct_author_runtime_repair_step_detail() -> &'static str {
    "Chat detected a concrete runtime failure in the rendered draft and is applying a bounded repair pass before surfacing it."
}

fn direct_author_runtime_repair_progress_message() -> &'static str {
    "Repairing the rendered draft after a runtime error..."
}

async fn evaluate_direct_author_runtime_sanity(
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate: &ChatGeneratedArtifactPayload,
    runtime_kind: ChatRuntimeProvenanceKind,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Option<ChatArtifactRenderEvaluation> {
    let sanity_timeout = direct_author_fast_runtime_sanity_timeout(request, runtime_kind);
    let render_eval_future = evaluate_candidate_render_with_fallback(
        render_evaluator,
        request,
        brief,
        None,
        None,
        None,
        candidate,
        runtime_kind,
    );
    match sanity_timeout {
        Some(limit) => {
            let bounded = async move {
                match tokio::time::timeout(limit, render_eval_future).await {
                    Ok(render_evaluation) => render_evaluation,
                    Err(_) => {
                        chat_generation_trace(format!(
                            "artifact_generation:direct_author_runtime_sanity:timeout renderer={:?} timeout_ms={}",
                            request.renderer,
                            limit.as_millis()
                        ));
                        None
                    }
                }
            };
            await_with_activity_heartbeat(bounded, activity_observer, Duration::from_millis(125))
                .await
        }
        None => render_eval_future.await,
    }
}

pub async fn generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
    runtime_plan: ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: &ChatArtifactPlanningContext,
    execution_strategy: ChatExecutionStrategy,
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    let planning_runtime = runtime_plan.planning_runtime.clone();
    let production_runtime = runtime_plan.generation_runtime.clone();
    let final_acceptance_runtime = runtime_plan.acceptance_runtime.clone();
    let repair_runtime = runtime_plan.repair_runtime.clone();
    let runtime_policy = runtime_plan.policy.clone();
    let production_provenance = production_runtime.chat_runtime_provenance();
    let acceptance_provenance = final_acceptance_runtime.chat_runtime_provenance();
    let repair_provenance = repair_runtime.chat_runtime_provenance();
    let model = runtime_model_label(&production_runtime);
    chat_generation_trace(format!(
        "artifact_generation:start renderer={:?} profile={:?} planning_model={:?} production_model={:?} acceptance_model={:?} repair_model={:?} refinement={}",
        request.renderer,
        runtime_policy.profile,
        planning_runtime.chat_runtime_provenance().model,
        production_provenance.model,
        acceptance_provenance.model,
        repair_provenance.model,
        refinement.is_some()
    ));
    let planning_context = planning_context.clone();
    let brief = planning_context.brief.clone();
    chat_generation_trace("artifact_generation:brief_ready");
    let blueprint = planning_context.blueprint.clone();
    let artifact_ir = planning_context.artifact_ir.clone();
    let selected_skills = planning_context.selected_skills.clone();
    let retrieved_exemplars = planning_context.retrieved_exemplars.clone();
    let edit_intent = match refinement {
        Some(refinement) => Some(hydrate_edit_intent_with_refinement_selection(
            plan_chat_artifact_edit_intent_with_runtime(
                planning_runtime.clone(),
                intent,
                request,
                &brief,
                refinement,
            )
            .await
            .map_err(|message| ChatArtifactGenerationError {
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
    };
    chat_generation_trace(format!(
        "artifact_generation:edit_intent_ready present={}",
        edit_intent.is_some()
    ));
    let effective_execution_strategy = execution_strategy;
    let direct_author_mode = direct_authoring_enabled(
        effective_execution_strategy,
        request,
        refinement,
        production_provenance.kind,
    );
    chat_generation_trace(format!(
        "artifact_generation:execution_strategy {:?}",
        effective_execution_strategy
    ));
    if chat_artifact_uses_swarm_execution(effective_execution_strategy) {
        warm_local_html_generation_runtime_if_needed(
            request,
            &planning_runtime,
            &production_runtime,
        )
        .await;
        return generate_chat_artifact_bundle_with_swarm(
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
            effective_execution_strategy,
            render_evaluator,
            progress_observer,
            activity_observer,
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
        derive_chat_adaptive_search_budget(
            request,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            refinement,
            production_provenance.kind,
            runtime_policy.profile,
            !chat_runtime_provenance_matches(&acceptance_provenance, &production_provenance),
        )
    };
    chat_generation_trace(format!(
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
    let mut candidate_rows = Vec::<(
        ChatArtifactCandidateSummary,
        ChatGeneratedArtifactPayload,
    )>::new();
    let mut failed_candidate_summaries = Vec::<ChatArtifactCandidateSummary>::new();
    let mut candidate_generation_errors = Vec::<String>::new();
    let mut next_candidate_index = 0usize;
    let mut target_candidate_count = adaptive_search_budget.initial_candidate_count.max(1);
    let (candidate_summaries, ranked_candidate_indices) = loop {
        while next_candidate_index < target_candidate_count {
            let candidate_id = format!("candidate-{}", next_candidate_index + 1);
            let seed = candidate_seed_for(title, intent, next_candidate_index);
            let author_detail = if direct_author_mode {
                if selected_skills.is_empty() {
                    "Chat started direct authoring from the prepared brief.".to_string()
                } else {
                    format!(
                        "Chat attached {} selected guidance source(s) and started direct authoring.",
                        selected_skills.len()
                    )
                }
            } else {
                "Chat started the current authoring attempt from the prepared artifact plan."
                    .to_string()
            };
            emit_non_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                effective_execution_strategy,
                &snapshot_execution_live_previews(&live_preview_state),
                if direct_author_mode {
                    "Writing the current artifact attempt..."
                } else {
                    "Working the current artifact attempt..."
                },
                None,
                None,
                ExecutionCompletionInvariantStatus::Pending,
                Vec::new(),
                vec![author_artifact_step(
                    &candidate_id,
                    author_detail.clone(),
                    ChatArtifactRuntimeEventStatus::Active,
                )],
            );
            let candidate_result = if direct_author_mode {
                let direct_live_preview_observer: Option<ChatArtifactLivePreviewObserver> =
                    progress_observer.as_ref().map(|_| {
                        let progress_observer = progress_observer.clone();
                        let direct_request = request.clone();
                        let live_preview_state = live_preview_state.clone();
                        let preview_attempt_id = candidate_id.clone();
                        Arc::new(move |preview: ExecutionLivePreview| {
                            if let Ok(mut previews) = live_preview_state.lock() {
                                upsert_execution_live_preview(&mut previews, preview.clone());
                            }
                            let live_previews =
                                snapshot_execution_live_previews(&live_preview_state);
                            emit_non_swarm_generation_progress(
                                progress_observer.as_ref(),
                                &direct_request,
                                effective_execution_strategy,
                                &live_previews,
                                author_preview_progress_detail(&preview),
                                None,
                                None,
                                ExecutionCompletionInvariantStatus::Pending,
                                Vec::new(),
                                vec![author_preview_step(&preview_attempt_id, &preview)],
                            );
                        }) as ChatArtifactLivePreviewObserver
                    });
                let payload =
                    materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
                        production_runtime.clone(),
                        Some(repair_runtime.clone()),
                        title,
                        intent,
                        request,
                        &brief,
                        &selected_skills,
                        edit_intent.as_ref(),
                        refinement,
                        &candidate_id,
                        seed,
                        temperature,
                        direct_live_preview_observer,
                        activity_observer.clone(),
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
                            effective_execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            if direct_author_fast_runtime_sanity_enabled(
                                request,
                                production_provenance.kind,
                            ) {
                                direct_author_runtime_sanity_progress_message()
                            } else {
                                "Direct-authored draft landed. Evaluating rendered artifact..."
                            },
                            None,
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            non_swarm_required_artifact_paths(&payload),
                            vec![
                                author_artifact_step(
                                    &candidate_id,
                                    "Chat finished authoring the current artifact draft and is handing it to verification.",
                                    ChatArtifactRuntimeEventStatus::Complete,
                                ),
                                verify_artifact_step(
                                    &candidate_id,
                                    if direct_author_fast_runtime_sanity_enabled(
                                        request,
                                        production_provenance.kind,
                                    ) {
                                        direct_author_runtime_sanity_step_detail()
                                    } else {
                                        direct_author_render_eval_step_detail(false)
                                    },
                                    ChatArtifactRuntimeEventStatus::Active,
                                ),
                            ],
                        );
                        let mut payload = payload;
                        let mut render_evaluation = if direct_author_fast_runtime_sanity_enabled(
                            request,
                            production_provenance.kind,
                        ) {
                            evaluate_direct_author_runtime_sanity(
                                render_evaluator,
                                request,
                                &brief,
                                &payload,
                                production_provenance.kind,
                                activity_observer.clone(),
                            )
                            .await
                        } else {
                            let render_eval_future = evaluate_candidate_render_with_fallback(
                                render_evaluator,
                                request,
                                &brief,
                                None,
                                None,
                                None,
                                &payload,
                                production_provenance.kind,
                            );
                            if render_eval_timeout_for_runtime(
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
                            }
                        };
                        if direct_author_fast_runtime_sanity_enabled(
                            request,
                            production_provenance.kind,
                        ) {
                            for repair_attempt in 0..DIRECT_AUTHOR_FAST_RUNTIME_REPAIR_ATTEMPTS {
                                let Some(runtime_failure_reason) =
                                    direct_author_runtime_failure_reason(
                                        render_evaluation.as_ref(),
                                    )
                                else {
                                    break;
                                };
                                emit_non_swarm_generation_progress(
                                    progress_observer.as_ref(),
                                    request,
                                    effective_execution_strategy,
                                    &snapshot_execution_live_previews(&live_preview_state),
                                    direct_author_runtime_repair_progress_message(),
                                    render_evaluation.as_ref(),
                                    None,
                                    ExecutionCompletionInvariantStatus::Pending,
                                    non_swarm_required_artifact_paths(&payload),
                                    vec![repair_artifact_step(
                                        &candidate_id,
                                        direct_author_runtime_repair_step_detail(),
                                        ChatArtifactRuntimeEventStatus::Active,
                                    )],
                                );
                                let repaired_payload =
                                    match repair_direct_author_generated_candidate_with_runtime_error(
                                        repair_runtime.clone(),
                                        title,
                                        intent,
                                        request,
                                        &brief,
                                        &selected_skills,
                                        edit_intent.as_ref(),
                                        refinement,
                                        &candidate_id,
                                        seed,
                                        &payload,
                                        &runtime_failure_reason,
                                        activity_observer.clone(),
                                    )
                                    .await
                                    {
                                        Ok(repaired) => repaired,
                                        Err(error) => {
                                            chat_generation_trace(format!(
                                                "artifact_generation:direct_author_runtime_repair:error id={} attempt={} error={}",
                                                candidate_id,
                                                repair_attempt + 1,
                                                error
                                            ));
                                            break;
                                        }
                                    };
                                if let Some(preview) = non_swarm_canonical_preview(
                                    request,
                                    &repaired_payload,
                                    "repairing",
                                    false,
                                ) {
                                    if let Ok(mut previews) = live_preview_state.lock() {
                                        upsert_execution_live_preview(&mut previews, preview);
                                    }
                                }
                                payload = repaired_payload;
                                render_evaluation = evaluate_direct_author_runtime_sanity(
                                    render_evaluator,
                                    request,
                                    &brief,
                                    &payload,
                                    production_provenance.kind,
                                    activity_observer.clone(),
                                )
                                .await;
                            }
                        }
                        emit_non_swarm_generation_progress(
                            progress_observer.as_ref(),
                            request,
                            effective_execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            if direct_author_fast_runtime_sanity_enabled(
                                request,
                                production_provenance.kind,
                            ) {
                                "Runtime sanity complete. Surfacing the direct-authored artifact..."
                            } else if render_evaluation.is_some() {
                                "Render evaluation complete. Surfacing the direct-authored artifact..."
                            } else {
                                "Draft landed. Surfacing the direct-authored artifact..."
                            },
                            render_evaluation.as_ref(),
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            non_swarm_required_artifact_paths(&payload),
                            vec![verify_artifact_step(
                                &candidate_id,
                                if direct_author_fast_runtime_sanity_enabled(
                                    request,
                                    production_provenance.kind,
                                ) {
                                    "Runtime sanity is complete and Chat is surfacing the rendered artifact."
                                } else if render_evaluation.is_some() {
                                    "Render evaluation is complete and Chat is surfacing the rendered artifact."
                                } else {
                                    "Chat is surfacing the rendered artifact without waiting on the old acceptance gate."
                                },
                                ChatArtifactRuntimeEventStatus::Active,
                            )],
                        );
                        let validation = if direct_author_fast_runtime_sanity_enabled(
                            request,
                            production_provenance.kind,
                        ) {
                            direct_author_runtime_sanity_validation_preview(
                                &payload,
                                render_evaluation.as_ref(),
                            )
                        } else {
                            direct_author_provisional_candidate_validation_preview(
                                &payload,
                                render_evaluation.as_ref(),
                            )
                        };
                        Ok((
                            ChatArtifactCandidateSummary {
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
                                    validation_total_score(&validation),
                                )),
                                render_evaluation,
                                validation,
                            },
                            payload,
                        ))
                    }
                    Err(error) => Err(ChatArtifactCandidateSummary {
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
                            validation_total_score(&blocked_candidate_generation_validation(
                                &error.message,
                            )),
                        )),
                        render_evaluation: None,
                        validation: blocked_candidate_generation_validation(&error.message),
                    }),
                }
            } else {
                materialize_and_locally_validation_candidate(
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
                    activity_observer.clone(),
                )
                .await
            };
            match candidate_result {
                Ok((summary, payload)) => candidate_rows.push((summary, payload)),
                Err(summary) => {
                    if let Some(failure) = summary.failure.clone() {
                        emit_non_swarm_generation_progress(
                            progress_observer.as_ref(),
                            request,
                            effective_execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            "The current artifact attempt hit a blocker.",
                            None,
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            Vec::new(),
                            vec![author_artifact_step(
                                &summary.candidate_id,
                                failure.clone(),
                                ChatArtifactRuntimeEventStatus::Blocked,
                            )],
                        );
                    }
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
                    ChatAdaptiveSearchSignal::GenerationFailureObserved,
                );
                target_candidate_count = adaptive_search_budget.max_candidate_count;
                chat_generation_trace(format!(
                    "artifact_generation:adaptive_search_expand reason=failures_only target={}",
                    target_candidate_count
                ));
                continue;
            }
            return Err(ChatArtifactGenerationError {
                message: if candidate_generation_errors.is_empty() {
                    "Chat artifact generation did not produce any candidates.".to_string()
                } else {
                    format!(
                        "Chat artifact generation did not produce a valid candidate. {}",
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
            chat_generation_trace(format!(
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
    chat_generation_trace(format!(
        "artifact_generation:shortlist size={} limit={} signals={:?}",
        shortlisted_candidate_indices.len(),
        adaptive_search_budget.shortlist_limit,
        adaptive_search_budget.signals
    ));

    let selected_winner_index = ranked_candidate_indices.iter().copied().find(|index| {
        candidate_summaries
            .get(*index)
            .map(|summary| validation_clears_primary_view(&summary.validation))
            .unwrap_or(false)
    });
    let best_available_index = ranked_candidate_indices
        .iter()
        .copied()
        .find(|index| {
            candidate_summaries
                .get(*index)
                .map(candidate_supports_fast_surface)
                .unwrap_or(false)
        })
        .or_else(|| ranked_candidate_indices.first().copied());
    chat_generation_trace(format!(
        "artifact_generation:fast_finalize direct_author={} winner={:?} best_available={:?}",
        direct_author_mode, selected_winner_index, best_available_index
    ));
    return build_non_swarm_winner_bundle(
        request,
        refinement,
        effective_execution_strategy,
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
        best_available_index,
    );
}
