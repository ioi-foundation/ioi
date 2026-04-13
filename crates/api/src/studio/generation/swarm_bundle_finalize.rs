use super::*;

fn build_swarm_generation_error(
    message: String,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> StudioArtifactGenerationError {
    StudioArtifactGenerationError {
        message,
        brief: Some(brief.clone()),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
    }
}

pub(super) async fn finalize_swarm_bundle_after_initial_execution(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    execution_strategy: StudioExecutionStrategy,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
    activity_observer: Option<StudioArtifactActivityObserver>,
    swarm_started_at: Instant,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Arc<dyn InferenceRuntime>,
    production_provenance: StudioRuntimeProvenance,
    acceptance_provenance: StudioRuntimeProvenance,
    origin: StudioArtifactOutputOrigin,
    mut swarm_plan: StudioArtifactSwarmPlan,
    mut worker_receipts: Vec<StudioArtifactWorkerReceipt>,
    mut patch_receipts: Vec<StudioArtifactPatchReceipt>,
    mut merge_receipts: Vec<StudioArtifactMergeReceipt>,
    mut verification_receipts: Vec<StudioArtifactVerificationReceipt>,
    mut graph_mutation_receipts: Vec<ExecutionGraphMutationReceipt>,
    mut repair_receipts: Vec<ExecutionRepairReceipt>,
    mut replan_receipts: Vec<ExecutionReplanReceipt>,
    runtime_dispatch_batches: Vec<ExecutionDispatchBatch>,
    live_preview_state: Arc<Mutex<Vec<ExecutionLivePreview>>>,
    mut canonical: StudioGeneratedArtifactPayload,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let build_error = |message: String| {
        build_swarm_generation_error(
            message,
            brief,
            blueprint,
            artifact_ir,
            selected_skills,
            edit_intent,
        )
    };

    let mut final_payload =
        validate_swarm_generated_artifact_payload(&canonical, request).map_err(build_error)?;
    verification_receipts.push(StudioArtifactVerificationReceipt {
        id: "schema-validation".to_string(),
        kind: "schema_validation".to_string(),
        status: "success".to_string(),
        summary: "Canonical artifact payload validated against the renderer contract.".to_string(),
        details: final_payload
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
    });

    let initial_render_eval_future = evaluate_candidate_render_with_fallback(
        render_evaluator,
        request,
        brief,
        blueprint,
        artifact_ir,
        edit_intent,
        &final_payload,
        production_provenance.kind,
    );
    let mut render_evaluation = if render_eval_timeout_for_runtime(
        request.renderer,
        production_provenance.kind,
    )
    .is_some()
    {
        await_with_activity_heartbeat(
            initial_render_eval_future,
            activity_observer.clone(),
            Duration::from_millis(125),
        )
        .await
    } else {
        initial_render_eval_future.await
    };
    verification_receipts.push(StudioArtifactVerificationReceipt {
        id: "render-evaluation".to_string(),
        kind: "render_evaluation".to_string(),
        status: if render_evaluation.is_some() {
            "success"
        } else {
            "skipped"
        }
        .to_string(),
        summary: render_evaluation
            .as_ref()
            .map(|value| value.summary.clone())
            .unwrap_or_else(|| "Render evaluation was not required for this renderer.".to_string()),
        details: render_evaluation
            .as_ref()
            .map(|value| {
                value
                    .findings
                    .iter()
                    .map(|finding| format!("{}: {}", finding.code, finding.summary))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    });
    emit_studio_swarm_generation_progress(
        progress_observer.as_ref(),
        request,
        production_provenance.kind,
        &swarm_plan,
        &worker_receipts,
        &patch_receipts,
        &merge_receipts,
        &verification_receipts,
        &graph_mutation_receipts,
        &runtime_dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        &snapshot_execution_live_previews(&live_preview_state),
        "verify",
        Some(StudioArtifactWorkerRole::Judge),
        "running",
        studio_swarm_progress_step(
            &studio_swarm_execution_summary(
                &swarm_plan,
                "verify",
                Some(StudioArtifactWorkerRole::Judge),
                "running",
            ),
            "Render evaluation finished and acceptance judging is starting.",
        ),
        render_evaluation.as_ref(),
        None,
    );

    let judge_item = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "judge")
        .cloned()
        .ok_or_else(|| build_error("Swarm judge work item is missing.".to_string()))?;
    let mut judge = await_with_activity_heartbeat(
        judge_candidate_with_runtime_and_render_eval(
            acceptance_runtime.clone(),
            render_evaluation.as_ref(),
            title,
            request,
            brief,
            edit_intent,
            &final_payload,
        ),
        activity_observer.clone(),
        Duration::from_millis(125),
    )
    .await
    .map_err(build_error)?;
    update_swarm_work_item_status(
        &mut swarm_plan,
        &judge_item.id,
        StudioArtifactWorkItemStatus::Succeeded,
    );
    worker_receipts.push(StudioArtifactWorkerReceipt {
        work_item_id: judge_item.id,
        role: judge_item.role,
        status: StudioArtifactWorkItemStatus::Succeeded,
        result_kind: Some(SwarmWorkerResultKind::Completed),
        summary: judge.rationale.clone(),
        started_at: studio_swarm_now_iso(),
        finished_at: Some(studio_swarm_now_iso()),
        runtime: acceptance_runtime.studio_runtime_provenance(),
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: judge.strengths.clone(),
        failure: None,
    });
    verification_receipts.push(StudioArtifactVerificationReceipt {
        id: "acceptance-judge".to_string(),
        kind: "acceptance_judge".to_string(),
        status: judge_classification_id(judge.classification).to_string(),
        summary: judge.rationale.clone(),
        details: judge.issue_classes.clone(),
    });
    emit_studio_swarm_generation_progress(
        progress_observer.as_ref(),
        request,
        production_provenance.kind,
        &swarm_plan,
        &worker_receipts,
        &patch_receipts,
        &merge_receipts,
        &verification_receipts,
        &graph_mutation_receipts,
        &runtime_dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        &snapshot_execution_live_previews(&live_preview_state),
        "verify",
        Some(StudioArtifactWorkerRole::Judge),
        judge_classification_id(judge.classification),
        studio_swarm_progress_step(
            &studio_swarm_execution_summary(
                &swarm_plan,
                "verify",
                Some(StudioArtifactWorkerRole::Judge),
                judge_classification_id(judge.classification),
            ),
            format!(
                "Acceptance judge returned {}.",
                judge_classification_id(judge.classification)
            ),
        ),
        render_evaluation.as_ref(),
        Some(&judge),
    );

    let mut repair_applied = false;
    if !judge_clears_primary_view(&judge) {
        let repair_template_item = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "repair")
            .cloned()
            .ok_or_else(|| build_error("Swarm repair work item is missing.".to_string()))?;
        graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
            id: "repair-requested".to_string(),
            mutation_kind: "repair_requested".to_string(),
            status: "applied".to_string(),
            summary: "Acceptance verification requested a scoped repair pass.".to_string(),
            triggered_by_work_item_id: Some("acceptance-judge".to_string()),
            affected_work_item_ids: vec![repair_template_item.id.clone()],
            details: judge.repair_hints.clone(),
        });
        replan_receipts.push(ExecutionReplanReceipt {
            id: "repair-replan".to_string(),
            status: "requested".to_string(),
            summary: "Acceptance judge blocked the merged artifact and requested bounded repair coordination.".to_string(),
            triggered_by_work_item_id: Some("acceptance-judge".to_string()),
            spawned_work_item_ids: vec![repair_template_item.id.clone()],
            blocked_work_item_ids: vec!["acceptance-judge".to_string()],
            details: judge.repair_hints.clone(),
        });
        let repair_budget = if request.renderer == StudioRendererKind::HtmlIframe
            && production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        {
            2
        } else {
            semantic_refinement_pass_limit(request.renderer, production_provenance.kind).clamp(1, 2)
        };
        let mut spawned_repair_work_item_ids = Vec::<String>::new();
        for repair_index in 0..repair_budget {
            let prior_repair_pass_id = spawned_repair_work_item_ids.last().cloned();
            let mut repair_patch_applied = false;
            let repair_template_ids =
                if request.renderer == StudioRendererKind::HtmlIframe && repair_index == 0 {
                    html_swarm_targeted_repair_template_ids(&judge)
                } else {
                    vec!["repair"]
                };
            let repair_template_count = repair_template_ids.len();
            let mut repair_wave_work_item_ids = Vec::<String>::new();
            let mut repair_wave_dependency_id = prior_repair_pass_id.clone();

            for template_id in repair_template_ids {
                let repair_source_template = swarm_plan
                    .work_items
                    .iter()
                    .find(|item| item.id == template_id)
                    .cloned()
                    .ok_or_else(|| {
                        build_error(format!(
                            "Swarm repair follow-up work item template '{}' is missing.",
                            template_id
                        ))
                    })?;
                let repair_pass_id = if repair_template_count == 1 && template_id == "repair" {
                    format!("repair-pass-{}", repair_index + 1)
                } else {
                    format!("repair-pass-{}-{}", repair_index + 1, template_id)
                };
                let mut repair_dependency_ids = repair_source_template.dependency_ids.clone();
                if let Some(previous_id) = repair_wave_dependency_id.as_ref() {
                    repair_dependency_ids.push(previous_id.clone());
                }
                let repair_item = StudioArtifactWorkItem {
                    id: repair_pass_id.clone(),
                    title: if repair_template_count == 1 && template_id == "repair" {
                        format!("Repair pass {}", repair_index + 1)
                    } else {
                        format!(
                            "Repair pass {} · {}",
                            repair_index + 1,
                            repair_source_template.title
                        )
                    },
                    role: repair_source_template.role,
                    summary: judge
                        .strongest_contradiction
                        .as_ref()
                        .map(|value| format!("Resolve the current verification block: {value}"))
                        .unwrap_or_else(|| repair_source_template.summary.clone()),
                    spawned_from_id: Some(repair_template_item.id.clone()),
                    read_paths: repair_source_template.read_paths.clone(),
                    write_paths: repair_source_template.write_paths.clone(),
                    write_regions: repair_source_template.write_regions.clone(),
                    lease_requirements: repair_source_template.lease_requirements.clone(),
                    acceptance_criteria: repair_source_template.acceptance_criteria.clone(),
                    dependency_ids: repair_dependency_ids,
                    blocked_on_ids: repair_wave_dependency_id.clone().into_iter().collect(),
                    verification_policy: repair_source_template.verification_policy,
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                };
                spawn_follow_up_swarm_work_item(&mut swarm_plan, repair_item.clone())
                    .map_err(build_error)?;
                spawned_repair_work_item_ids.push(repair_pass_id.clone());
                repair_wave_work_item_ids.push(repair_pass_id.clone());
                update_swarm_work_item_status(
                    &mut swarm_plan,
                    &repair_item.id,
                    StudioArtifactWorkItemStatus::Running,
                );
                graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                    id: format!("{}-spawned", repair_pass_id),
                    mutation_kind: if repair_index == 0 {
                        "subtask_spawned".to_string()
                    } else {
                        "follow_up_spawned".to_string()
                    },
                    status: "applied".to_string(),
                    summary: if let Some(previous_id) = repair_wave_dependency_id.as_ref() {
                        format!(
                            "Repair coordination queued {} after {} did not clear verification.",
                            repair_pass_id, previous_id
                        )
                    } else {
                        format!(
                            "Repair coordination queued {} as the first bounded follow-up worker.",
                            repair_pass_id
                        )
                    },
                    triggered_by_work_item_id: Some(
                        repair_wave_dependency_id
                            .clone()
                            .unwrap_or_else(|| "acceptance-judge".to_string()),
                    ),
                    affected_work_item_ids: vec![
                        repair_template_item.id.clone(),
                        repair_source_template.id.clone(),
                        repair_pass_id.clone(),
                    ],
                    details: judge.repair_hints.clone(),
                });
                repair_receipts.push(ExecutionRepairReceipt {
                    id: repair_pass_id.clone(),
                    status: "running".to_string(),
                    summary: format!(
                        "{} is applying a bounded fix against the merged artifact.",
                        repair_item.title
                    ),
                    triggered_by_verification_id: Some("acceptance-judge".to_string()),
                    work_item_ids: vec![
                        repair_template_item.id.clone(),
                        repair_source_template.id.clone(),
                        repair_item.id.clone(),
                    ],
                    details: judge.repair_hints.clone(),
                });
                emit_studio_swarm_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    production_provenance.kind,
                    &swarm_plan,
                    &worker_receipts,
                    &patch_receipts,
                    &merge_receipts,
                    &verification_receipts,
                    &graph_mutation_receipts,
                    &runtime_dispatch_batches,
                    &repair_receipts,
                    &replan_receipts,
                    &snapshot_execution_live_previews(&live_preview_state),
                    "mutate",
                    Some(repair_item.role),
                    "repairing",
                    studio_swarm_progress_step(
                        &studio_swarm_execution_summary(
                            &swarm_plan,
                            "mutate",
                            Some(repair_item.role),
                            "repairing",
                        ),
                        format!("Running {} after acceptance blocking.", repair_item.title),
                    ),
                    render_evaluation.as_ref(),
                    Some(&judge),
                );

                if request.renderer == StudioRendererKind::HtmlIframe {
                    let repair_live_preview_observer: Option<StudioArtifactLivePreviewObserver> =
                        progress_observer.as_ref().map(|_| {
                            let progress_observer = progress_observer.clone();
                            let repair_request = request.clone();
                            let repair_swarm_plan = swarm_plan.clone();
                            let repair_worker_receipts = worker_receipts.clone();
                            let repair_patch_receipts = patch_receipts.clone();
                            let repair_merge_receipts = merge_receipts.clone();
                            let repair_verification_receipts = verification_receipts.clone();
                            let repair_graph_mutation_receipts = graph_mutation_receipts.clone();
                            let repair_runtime_dispatch_batches = runtime_dispatch_batches.clone();
                            let repair_receipts_snapshot = repair_receipts.clone();
                            let repair_replan_receipts = replan_receipts.clone();
                            let live_preview_state = live_preview_state.clone();
                            let repair_title = repair_item.title.clone();
                            Arc::new(move |preview: ExecutionLivePreview| {
                                if let Ok(mut previews) = live_preview_state.lock() {
                                    upsert_execution_live_preview(&mut previews, preview.clone());
                                }
                                let live_previews =
                                    snapshot_execution_live_previews(&live_preview_state);
                                emit_studio_swarm_generation_progress(
                                    progress_observer.as_ref(),
                                    &repair_request,
                                    production_provenance.kind,
                                    &repair_swarm_plan,
                                    &repair_worker_receipts,
                                    &repair_patch_receipts,
                                    &repair_merge_receipts,
                                    &repair_verification_receipts,
                                    &repair_graph_mutation_receipts,
                                    &repair_runtime_dispatch_batches,
                                    &repair_receipts_snapshot,
                                    &repair_replan_receipts,
                                    &live_previews,
                                    "mutate",
                                    Some(StudioArtifactWorkerRole::Repair),
                                    "repairing",
                                    studio_swarm_progress_step(
                                        &studio_swarm_execution_summary(
                                            &repair_swarm_plan,
                                            "mutate",
                                            Some(StudioArtifactWorkerRole::Repair),
                                            "repairing",
                                        ),
                                        format!(
                                            "Streaming {} while {} is running.",
                                            preview.label, repair_title
                                        ),
                                    ),
                                    None,
                                    None,
                                );
                            }) as StudioArtifactLivePreviewObserver
                        });
                    let (envelope, mut receipt) = execute_studio_swarm_patch_worker(
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
                        &canonical,
                        &repair_item,
                        studio_swarm_work_item_context(
                            &repair_item,
                            blueprint,
                            artifact_ir,
                            Some(&judge),
                        ),
                        candidate_seed_for(title, intent, 900 + repair_index),
                        repair_live_preview_observer,
                        activity_observer.clone(),
                    )
                    .await
                    .map_err(build_error)?;
                    let (patch_receipt, merge_receipt) = apply_studio_swarm_patch_envelope(
                        request,
                        &mut canonical,
                        &repair_item,
                        &envelope,
                    )
                    .map_err(build_error)?;
                    repair_patch_applied =
                        repair_patch_applied || patch_receipt.operation_count > 0;
                    repair_applied = repair_applied || patch_receipt.operation_count > 0;
                    update_swarm_work_item_status(
                        &mut swarm_plan,
                        &repair_item.id,
                        patch_receipt.status,
                    );
                    receipt.result_kind = Some(match patch_receipt.status {
                        StudioArtifactWorkItemStatus::Skipped => SwarmWorkerResultKind::Noop,
                        StudioArtifactWorkItemStatus::Rejected => SwarmWorkerResultKind::Conflict,
                        StudioArtifactWorkItemStatus::Blocked
                        | StudioArtifactWorkItemStatus::Failed => SwarmWorkerResultKind::Blocked,
                        _ => SwarmWorkerResultKind::Completed,
                    });
                    if let Some(summary) = envelope.summary.as_ref() {
                        canonical.summary = summary.clone();
                    }
                    canonical.notes.extend(envelope.notes.clone());
                    worker_receipts.push(receipt);
                    patch_receipts.push(patch_receipt);
                    merge_receipts.push(merge_receipt);
                } else if renderer_supports_semantic_refinement(request.renderer) {
                    let refined = await_with_activity_heartbeat(
                        refine_studio_artifact_candidate_with_runtime(
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
                            &final_payload,
                            render_evaluation.as_ref(),
                            &judge,
                            "swarm-repair",
                            candidate_seed_for(title, intent, 900 + repair_index),
                            0.18,
                            activity_observer.clone(),
                        ),
                        activity_observer.clone(),
                        Duration::from_millis(125),
                    )
                    .await
                    .map_err(build_error)?;
                    let envelope = StudioArtifactPatchEnvelope {
                        summary: Some(refined.summary.clone()),
                        notes: refined.notes.clone(),
                        operations: diff_payloads_to_patch_operations(&canonical, &refined),
                    };
                    let (patch_receipt, merge_receipt) = apply_studio_swarm_patch_envelope(
                        request,
                        &mut canonical,
                        &repair_item,
                        &envelope,
                    )
                    .map_err(build_error)?;
                    repair_patch_applied =
                        repair_patch_applied || patch_receipt.operation_count > 0;
                    repair_applied = repair_applied || patch_receipt.operation_count > 0;
                    update_swarm_work_item_status(
                        &mut swarm_plan,
                        &repair_item.id,
                        patch_receipt.status,
                    );
                    canonical.summary = refined.summary.clone();
                    canonical.notes.extend(refined.notes.clone());
                    worker_receipts.push(StudioArtifactWorkerReceipt {
                        work_item_id: repair_item.id.clone(),
                        role: repair_item.role,
                        status: StudioArtifactWorkItemStatus::Succeeded,
                        result_kind: Some(SwarmWorkerResultKind::Completed),
                        summary: refined.summary,
                        started_at: studio_swarm_now_iso(),
                        finished_at: Some(studio_swarm_now_iso()),
                        runtime: repair_runtime.studio_runtime_provenance(),
                        read_paths: repair_item.read_paths.clone(),
                        write_paths: repair_item.write_paths.clone(),
                        write_regions: repair_item.write_regions.clone(),
                        spawned_work_item_ids: Vec::new(),
                        blocked_on_ids: repair_item.blocked_on_ids.clone(),
                        prompt_bytes: None,
                        output_bytes: None,
                        output_preview: None,
                        preview_language: studio_swarm_preview_language(request),
                        notes: refined.notes,
                        failure: None,
                    });
                    patch_receipts.push(patch_receipt);
                    merge_receipts.push(merge_receipt);
                }

                if let Some(preview) = studio_swarm_canonical_preview(
                    &canonical,
                    Some(repair_item.id.clone()),
                    Some(repair_item.role),
                    "repairing",
                    false,
                ) {
                    if let Ok(mut previews) = live_preview_state.lock() {
                        upsert_execution_live_preview(&mut previews, preview);
                    }
                }

                repair_wave_dependency_id = Some(repair_pass_id);
            }

            final_payload = validate_swarm_generated_artifact_payload(&canonical, request)
                .map_err(build_error)?;
            let repair_render_eval_future = evaluate_candidate_render_with_fallback(
                render_evaluator,
                request,
                brief,
                blueprint,
                artifact_ir,
                edit_intent,
                &final_payload,
                production_provenance.kind,
            );
            render_evaluation =
                if render_eval_timeout_for_runtime(request.renderer, production_provenance.kind)
                    .is_some()
                {
                    await_with_activity_heartbeat(
                        repair_render_eval_future,
                        activity_observer.clone(),
                        Duration::from_millis(125),
                    )
                    .await
                } else {
                    repair_render_eval_future.await
                };
            judge = await_with_activity_heartbeat(
                judge_candidate_with_runtime_and_render_eval(
                    acceptance_runtime.clone(),
                    render_evaluation.as_ref(),
                    title,
                    request,
                    brief,
                    edit_intent,
                    &final_payload,
                ),
                activity_observer.clone(),
                Duration::from_millis(125),
            )
            .await
            .map_err(build_error)?;
            verification_receipts.push(StudioArtifactVerificationReceipt {
                id: format!("repair-pass-{}", repair_index + 1),
                kind: "repair_verification".to_string(),
                status: judge_classification_id(judge.classification).to_string(),
                summary: judge.rationale.clone(),
                details: judge.repair_hints.clone(),
            });
            for repair_receipt in repair_receipts.iter_mut().filter(|receipt| {
                repair_wave_work_item_ids
                    .iter()
                    .any(|work_item_id| work_item_id == &receipt.id)
            }) {
                repair_receipt.status = judge_classification_id(judge.classification).to_string();
                repair_receipt.summary = if repair_patch_applied {
                    "Scoped repair changes were merged and re-verified.".to_string()
                } else {
                    "Repair pass completed without any scoped change to merge.".to_string()
                };
                repair_receipt.details = judge.repair_hints.clone();
            }
            emit_studio_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                production_provenance.kind,
                &swarm_plan,
                &worker_receipts,
                &patch_receipts,
                &merge_receipts,
                &verification_receipts,
                &graph_mutation_receipts,
                &runtime_dispatch_batches,
                &repair_receipts,
                &replan_receipts,
                &snapshot_execution_live_previews(&live_preview_state),
                "verify",
                Some(StudioArtifactWorkerRole::Repair),
                judge_classification_id(judge.classification),
                studio_swarm_progress_step(
                    &studio_swarm_execution_summary(
                        &swarm_plan,
                        "verify",
                        Some(StudioArtifactWorkerRole::Repair),
                        judge_classification_id(judge.classification),
                    ),
                    format!("Repair pass {} re-ran verification.", repair_index + 1),
                ),
                render_evaluation.as_ref(),
                Some(&judge),
            );
            if judge_clears_primary_view(&judge) {
                break;
            }
        }
        if !spawned_repair_work_item_ids.is_empty() {
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-follow-up-graph".to_string(),
                status: if judge_clears_primary_view(&judge) {
                    "applied".to_string()
                } else {
                    "partial".to_string()
                },
                summary: format!(
                    "Repair coordination expanded the work graph with {} bounded follow-up worker(s).",
                    spawned_repair_work_item_ids.len()
                ),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: Vec::new(),
                details: judge.repair_hints.clone(),
            });
        }
        if repair_applied && judge_clears_primary_view(&judge) {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &repair_template_item.id,
                StudioArtifactWorkItemStatus::Succeeded,
            );
            worker_receipts.push(StudioArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: StudioArtifactWorkItemStatus::Succeeded,
                result_kind: Some(SwarmWorkerResultKind::SubtaskRequested),
                summary: format!(
                    "Repair coordination spawned {} bounded follow-up worker(s) and cleared verification.",
                    spawned_repair_work_item_ids.len()
                ),
                started_at: studio_swarm_now_iso(),
                finished_at: Some(studio_swarm_now_iso()),
                runtime: repair_runtime.studio_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: judge.repair_hints.clone(),
                failure: None,
            });
        } else if !repair_applied {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &repair_template_item.id,
                StudioArtifactWorkItemStatus::Blocked,
            );
            worker_receipts.push(StudioArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: StudioArtifactWorkItemStatus::Blocked,
                result_kind: Some(SwarmWorkerResultKind::Blocked),
                summary: "Judge cited issues, but no narrower repair patch was applied."
                    .to_string(),
                started_at: studio_swarm_now_iso(),
                finished_at: Some(studio_swarm_now_iso()),
                runtime: repair_runtime.studio_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: judge.repair_hints.clone(),
                failure: Some(
                    "Repair coordination completed without any scoped patch to merge.".to_string(),
                ),
            });
            graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                id: "repair-skipped".to_string(),
                mutation_kind: "repair_exhausted".to_string(),
                status: "blocked".to_string(),
                summary: "Repair coordination completed without any scoped patch to merge."
                    .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                affected_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-follow-up-blocked".to_string(),
                status: "blocked".to_string(),
                summary: "Repair coordination could not merge any bounded follow-up change."
                    .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
        } else {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &repair_template_item.id,
                StudioArtifactWorkItemStatus::Blocked,
            );
            worker_receipts.push(StudioArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: StudioArtifactWorkItemStatus::Blocked,
                result_kind: Some(SwarmWorkerResultKind::ReplanRequested),
                summary: format!(
                    "Repair coordination merged {} bounded follow-up worker(s), but verification still needs a broader replan.",
                    spawned_repair_work_item_ids.len()
                ),
                started_at: studio_swarm_now_iso(),
                finished_at: Some(studio_swarm_now_iso()),
                runtime: repair_runtime.studio_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: judge.repair_hints.clone(),
                failure: Some(judge.rationale.clone()),
            });
            graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                id: "repair-replan-requested".to_string(),
                mutation_kind: "replan_requested".to_string(),
                status: "blocked".to_string(),
                summary:
                    "Scoped repair passes improved the artifact but did not clear verification."
                        .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                affected_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-broader-replan".to_string(),
                status: "blocked".to_string(),
                summary:
                    "Bounded repair passes improved the artifact, but broader replanning is still required."
                        .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
        }
    } else {
        update_swarm_work_item_status(
            &mut swarm_plan,
            "repair",
            StudioArtifactWorkItemStatus::Skipped,
        );
        if let Some(repair_item) = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "repair")
        {
            worker_receipts.push(studio_swarm_skip_receipt(
                repair_item,
                &repair_runtime,
                "Judge cleared the merged artifact without a repair pass.",
            ));
        }
    }

    final_payload =
        validate_swarm_generated_artifact_payload(&canonical, request).map_err(build_error)?;
    let swarm_execution = studio_swarm_execution_summary(
        &swarm_plan,
        if judge_clears_primary_view(&judge) {
            "ready"
        } else if repair_applied {
            "repair_exhausted"
        } else {
            "judged"
        },
        None,
        judge_classification_id(judge.classification),
    );
    let execution_budget_summary = ExecutionBudgetSummary {
        planned_worker_count: Some(swarm_plan.work_items.len()),
        dispatched_worker_count: Some(
            worker_receipts
                .iter()
                .filter(|receipt| {
                    !matches!(
                        receipt.result_kind,
                        Some(SwarmWorkerResultKind::Noop) | Some(SwarmWorkerResultKind::Blocked)
                    )
                })
                .count(),
        ),
        token_budget: Some(studio_swarm_planned_token_budget(
            request,
            production_provenance.kind,
            &swarm_plan,
        )),
        token_usage: None,
        wall_clock_ms: Some(swarm_started_at.elapsed().as_millis() as u64),
        coordination_overhead_ms: None,
        status: if judge_clears_primary_view(&judge) {
            "completed".to_string()
        } else if repair_applied {
            "repair_exhausted".to_string()
        } else {
            "judged".to_string()
        },
    };
    let execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        Some(&swarm_plan),
        Some(&swarm_execution),
        &worker_receipts,
        &patch_receipts,
        &merge_receipts,
        &verification_receipts,
        &graph_mutation_receipts,
        &runtime_dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        Some(execution_budget_summary),
        &snapshot_execution_live_previews(&live_preview_state),
    );

    Ok(StudioArtifactGenerationBundle {
        brief: brief.clone(),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_plan: Some(swarm_plan),
        swarm_execution: Some(swarm_execution),
        swarm_worker_receipts: worker_receipts,
        swarm_change_receipts: patch_receipts,
        swarm_merge_receipts: merge_receipts,
        swarm_verification_receipts: verification_receipts,
        winner: final_payload,
        render_evaluation,
        judge,
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: Some(runtime_plan.policy),
        adaptive_search_budget: None,
        fallback_used: false,
        ux_lifecycle: if repair_applied {
            StudioArtifactUxLifecycle::Refining
        } else {
            StudioArtifactUxLifecycle::Judged
        },
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}
