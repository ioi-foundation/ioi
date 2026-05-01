use super::*;

fn build_work_graph_generation_error(
    message: String,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    edit_intent: Option<&ChatArtifactEditIntent>,
) -> ChatArtifactGenerationError {
    ChatArtifactGenerationError {
        message,
        brief: Some(brief.clone()),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
    }
}

fn require_work_graph_bounded_repair_for_render_warning(
    mut validation: ChatArtifactValidationResult,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ChatArtifactValidationResult {
    if validation.classification != ChatArtifactValidationStatus::Pass {
        return validation;
    }
    let Some(finding) = render_evaluation
        .and_then(|evaluation| {
            evaluation
                .findings
                .iter()
                .find(|finding| finding.severity == ChatArtifactRenderFindingSeverity::Warning)
        })
        .cloned()
    else {
        return validation;
    };

    validation.classification = ChatArtifactValidationStatus::Repairable;
    validation.primary_view_cleared = false;
    validation.deserves_primary_artifact_view = false;
    validation.summary =
        "Render validation surfaced a concrete issue that should drive a bounded repair."
            .to_string();
    validation.rationale = finding.summary.clone();
    validation.recommended_next_pass = Some("structural_repair".to_string());
    if !finding.code.is_empty() {
        if !validation
            .issue_codes
            .iter()
            .any(|code| code == &finding.code)
        {
            validation.issue_codes.push(finding.code.clone());
        }
        if !validation
            .issue_classes
            .iter()
            .any(|class| class == &finding.code)
        {
            validation.issue_classes.push(finding.code.clone());
        }
    }
    if !validation
        .repair_hints
        .iter()
        .any(|hint| hint == &finding.summary)
    {
        validation.repair_hints.insert(0, finding.summary);
    }
    validation.score_total = validation.score_total.min(280);
    validation
}

pub(super) async fn finalize_work_graph_bundle_after_initial_execution(
    runtime_plan: ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    edit_intent: Option<&ChatArtifactEditIntent>,
    execution_strategy: ChatExecutionStrategy,
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
    activity_observer: Option<ChatArtifactActivityObserver>,
    work_graph_started_at: Instant,
    repair_runtime: Arc<dyn InferenceRuntime>,
    production_provenance: ChatRuntimeProvenance,
    acceptance_provenance: ChatRuntimeProvenance,
    origin: ChatArtifactOutputOrigin,
    mut work_graph_plan: ChatArtifactWorkGraphPlan,
    mut worker_receipts: Vec<ChatArtifactWorkerReceipt>,
    mut patch_receipts: Vec<ChatArtifactPatchReceipt>,
    mut merge_receipts: Vec<ChatArtifactMergeReceipt>,
    mut verification_receipts: Vec<ChatArtifactVerificationReceipt>,
    mut graph_mutation_receipts: Vec<ExecutionGraphMutationReceipt>,
    mut repair_receipts: Vec<ExecutionRepairReceipt>,
    mut replan_receipts: Vec<ExecutionReplanReceipt>,
    runtime_dispatch_batches: Vec<ExecutionDispatchBatch>,
    live_preview_state: Arc<Mutex<Vec<ExecutionLivePreview>>>,
    mut canonical: ChatGeneratedArtifactPayload,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    let build_error = |message: String| {
        build_work_graph_generation_error(
            message,
            brief,
            blueprint,
            artifact_ir,
            selected_skills,
            edit_intent,
        )
    };

    let mut final_payload =
        validate_work_graph_generated_artifact_payload(&canonical, request).map_err(build_error)?;
    verification_receipts.push(ChatArtifactVerificationReceipt {
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
    verification_receipts.push(ChatArtifactVerificationReceipt {
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
    emit_chat_work_graph_generation_progress(
        progress_observer.as_ref(),
        request,
        production_provenance.kind,
        &work_graph_plan,
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
        Some(ChatArtifactWorkerRole::Validation),
        "running",
        chat_work_graph_progress_step(
            &chat_work_graph_execution_summary(
                &work_graph_plan,
                "verify",
                Some(ChatArtifactWorkerRole::Validation),
                "running",
            ),
            "Render evaluation finished and fast render sanity is starting.",
        ),
        render_evaluation.as_ref(),
        None,
    );

    let validation_item = work_graph_plan
        .work_items
        .iter()
        .find(|item| item.id == "validation")
        .cloned()
        .ok_or_else(|| build_error("WorkGraph validation work item is missing.".to_string()))?;
    let mut validation = render_sanity_candidate_validation_preview(
        request,
        brief,
        &final_payload,
        render_evaluation.as_ref(),
    );
    validation = require_work_graph_bounded_repair_for_render_warning(
        validation,
        render_evaluation.as_ref(),
    );
    update_work_graph_work_item_status(
        &mut work_graph_plan,
        &validation_item.id,
        ChatArtifactWorkItemStatus::Succeeded,
    );
    worker_receipts.push(ChatArtifactWorkerReceipt {
        work_item_id: validation_item.id,
        role: validation_item.role,
        status: ChatArtifactWorkItemStatus::Succeeded,
        result_kind: Some(WorkGraphWorkerResultKind::Completed),
        summary: validation.rationale.clone(),
        started_at: chat_work_graph_now_iso(),
        finished_at: Some(chat_work_graph_now_iso()),
        runtime: production_provenance.clone(),
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: validation.strengths.clone(),
        failure: None,
    });
    verification_receipts.push(ChatArtifactVerificationReceipt {
        id: "artifact-validation".to_string(),
        kind: "artifact_validation".to_string(),
        status: validation_status_id(validation.classification).to_string(),
        summary: validation.rationale.clone(),
        details: validation.issue_classes.clone(),
    });
    emit_chat_work_graph_generation_progress(
        progress_observer.as_ref(),
        request,
        production_provenance.kind,
        &work_graph_plan,
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
        Some(ChatArtifactWorkerRole::Validation),
        validation_status_id(validation.classification),
        chat_work_graph_progress_step(
            &chat_work_graph_execution_summary(
                &work_graph_plan,
                "verify",
                Some(ChatArtifactWorkerRole::Validation),
                validation_status_id(validation.classification),
            ),
            format!(
                "Fast render sanity returned {}.",
                validation_status_id(validation.classification)
            ),
        ),
        render_evaluation.as_ref(),
        Some(&validation),
    );

    let mut repair_applied = false;
    if !validation_clears_primary_view(&validation) {
        let repair_template_item = work_graph_plan
            .work_items
            .iter()
            .find(|item| item.id == "repair")
            .cloned()
            .ok_or_else(|| build_error("WorkGraph repair work item is missing.".to_string()))?;
        graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
            id: "repair-requested".to_string(),
            mutation_kind: "repair_requested".to_string(),
            status: "applied".to_string(),
            summary: "Render sanity requested a scoped repair pass.".to_string(),
            triggered_by_work_item_id: Some("artifact-validation".to_string()),
            affected_work_item_ids: vec![repair_template_item.id.clone()],
            details: validation.repair_hints.clone(),
        });
        replan_receipts.push(ExecutionReplanReceipt {
            id: "repair-replan".to_string(),
            status: "requested".to_string(),
            summary:
                "Render sanity found a concrete issue in the merged artifact and requested bounded repair coordination."
                    .to_string(),
            triggered_by_work_item_id: Some("artifact-validation".to_string()),
            spawned_work_item_ids: vec![repair_template_item.id.clone()],
            blocked_work_item_ids: vec!["artifact-validation".to_string()],
            details: validation.repair_hints.clone(),
        });
        let repair_budget = 2;
        let mut spawned_repair_work_item_ids = Vec::<String>::new();
        for repair_index in 0..repair_budget {
            let prior_repair_pass_id = spawned_repair_work_item_ids.last().cloned();
            let mut repair_patch_applied = false;
            let repair_template_ids =
                if request.renderer == ChatRendererKind::HtmlIframe && repair_index == 0 {
                    html_work_graph_targeted_repair_template_ids(&validation)
                } else {
                    vec!["repair"]
                };
            let repair_template_count = repair_template_ids.len();
            let mut repair_wave_work_item_ids = Vec::<String>::new();
            let mut repair_wave_dependency_id = prior_repair_pass_id.clone();

            for template_id in repair_template_ids {
                let repair_source_template = work_graph_plan
                    .work_items
                    .iter()
                    .find(|item| item.id == template_id)
                    .cloned()
                    .ok_or_else(|| {
                        build_error(format!(
                            "WorkGraph repair follow-up work item template '{}' is missing.",
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
                let repair_item = ChatArtifactWorkItem {
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
                    summary: validation
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
                    status: ChatArtifactWorkItemStatus::Pending,
                };
                spawn_follow_up_work_graph_work_item(&mut work_graph_plan, repair_item.clone())
                    .map_err(build_error)?;
                spawned_repair_work_item_ids.push(repair_pass_id.clone());
                repair_wave_work_item_ids.push(repair_pass_id.clone());
                update_work_graph_work_item_status(
                    &mut work_graph_plan,
                    &repair_item.id,
                    ChatArtifactWorkItemStatus::Running,
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
                            .unwrap_or_else(|| "artifact-validation".to_string()),
                    ),
                    affected_work_item_ids: vec![
                        repair_template_item.id.clone(),
                        repair_source_template.id.clone(),
                        repair_pass_id.clone(),
                    ],
                    details: validation.repair_hints.clone(),
                });
                repair_receipts.push(ExecutionRepairReceipt {
                    id: repair_pass_id.clone(),
                    status: "running".to_string(),
                    summary: format!(
                        "{} is applying a bounded fix against the merged artifact.",
                        repair_item.title
                    ),
                    triggered_by_verification_id: Some("artifact-validation".to_string()),
                    work_item_ids: vec![
                        repair_template_item.id.clone(),
                        repair_source_template.id.clone(),
                        repair_item.id.clone(),
                    ],
                    details: validation.repair_hints.clone(),
                });
                emit_chat_work_graph_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    production_provenance.kind,
                    &work_graph_plan,
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
                    chat_work_graph_progress_step(
                        &chat_work_graph_execution_summary(
                            &work_graph_plan,
                            "mutate",
                            Some(repair_item.role),
                            "repairing",
                        ),
                        format!(
                            "Running {} after render sanity found a concrete issue.",
                            repair_item.title
                        ),
                    ),
                    render_evaluation.as_ref(),
                    Some(&validation),
                );

                if request.renderer == ChatRendererKind::HtmlIframe {
                    let repair_live_preview_observer: Option<ChatArtifactLivePreviewObserver> =
                        progress_observer.as_ref().map(|_| {
                            let progress_observer = progress_observer.clone();
                            let repair_request = request.clone();
                            let repair_work_graph_plan = work_graph_plan.clone();
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
                                emit_chat_work_graph_generation_progress(
                                    progress_observer.as_ref(),
                                    &repair_request,
                                    production_provenance.kind,
                                    &repair_work_graph_plan,
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
                                    Some(ChatArtifactWorkerRole::Repair),
                                    "repairing",
                                    chat_work_graph_progress_step(
                                        &chat_work_graph_execution_summary(
                                            &repair_work_graph_plan,
                                            "mutate",
                                            Some(ChatArtifactWorkerRole::Repair),
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
                            }) as ChatArtifactLivePreviewObserver
                        });
                    let (envelope, mut receipt) = execute_chat_work_graph_patch_worker(
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
                        chat_work_graph_work_item_context(
                            &repair_item,
                            blueprint,
                            artifact_ir,
                            Some(&validation),
                        ),
                        candidate_seed_for(title, intent, 900 + repair_index),
                        repair_live_preview_observer,
                        activity_observer.clone(),
                    )
                    .await
                    .map_err(build_error)?;
                    let (patch_receipt, merge_receipt) = apply_chat_work_graph_patch_envelope(
                        request,
                        &mut canonical,
                        &repair_item,
                        &envelope,
                    )
                    .map_err(build_error)?;
                    repair_patch_applied =
                        repair_patch_applied || patch_receipt.operation_count > 0;
                    repair_applied = repair_applied || patch_receipt.operation_count > 0;
                    update_work_graph_work_item_status(
                        &mut work_graph_plan,
                        &repair_item.id,
                        patch_receipt.status,
                    );
                    receipt.result_kind = Some(match patch_receipt.status {
                        ChatArtifactWorkItemStatus::Skipped => WorkGraphWorkerResultKind::Noop,
                        ChatArtifactWorkItemStatus::Rejected => WorkGraphWorkerResultKind::Conflict,
                        ChatArtifactWorkItemStatus::Blocked
                        | ChatArtifactWorkItemStatus::Failed => WorkGraphWorkerResultKind::Blocked,
                        _ => WorkGraphWorkerResultKind::Completed,
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
                        refine_chat_artifact_candidate_with_runtime(
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
                            &validation,
                            "work_graph-repair",
                            candidate_seed_for(title, intent, 900 + repair_index),
                            0.18,
                            activity_observer.clone(),
                        ),
                        activity_observer.clone(),
                        Duration::from_millis(125),
                    )
                    .await
                    .map_err(build_error)?;
                    let envelope = ChatArtifactPatchEnvelope {
                        summary: Some(refined.summary.clone()),
                        notes: refined.notes.clone(),
                        operations: diff_payloads_to_patch_operations(&canonical, &refined),
                    };
                    let (patch_receipt, merge_receipt) = apply_chat_work_graph_patch_envelope(
                        request,
                        &mut canonical,
                        &repair_item,
                        &envelope,
                    )
                    .map_err(build_error)?;
                    repair_patch_applied =
                        repair_patch_applied || patch_receipt.operation_count > 0;
                    repair_applied = repair_applied || patch_receipt.operation_count > 0;
                    update_work_graph_work_item_status(
                        &mut work_graph_plan,
                        &repair_item.id,
                        patch_receipt.status,
                    );
                    canonical.summary = refined.summary.clone();
                    canonical.notes.extend(refined.notes.clone());
                    worker_receipts.push(ChatArtifactWorkerReceipt {
                        work_item_id: repair_item.id.clone(),
                        role: repair_item.role,
                        status: ChatArtifactWorkItemStatus::Succeeded,
                        result_kind: Some(WorkGraphWorkerResultKind::Completed),
                        summary: refined.summary,
                        started_at: chat_work_graph_now_iso(),
                        finished_at: Some(chat_work_graph_now_iso()),
                        runtime: repair_runtime.chat_runtime_provenance(),
                        read_paths: repair_item.read_paths.clone(),
                        write_paths: repair_item.write_paths.clone(),
                        write_regions: repair_item.write_regions.clone(),
                        spawned_work_item_ids: Vec::new(),
                        blocked_on_ids: repair_item.blocked_on_ids.clone(),
                        prompt_bytes: None,
                        output_bytes: None,
                        output_preview: None,
                        preview_language: chat_work_graph_preview_language(request),
                        notes: refined.notes,
                        failure: None,
                    });
                    patch_receipts.push(patch_receipt);
                    merge_receipts.push(merge_receipt);
                }

                if let Some(preview) = chat_work_graph_canonical_preview(
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

            final_payload = validate_work_graph_generated_artifact_payload(&canonical, request)
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
            validation = render_sanity_candidate_validation_preview(
                request,
                brief,
                &final_payload,
                render_evaluation.as_ref(),
            );
            validation = require_work_graph_bounded_repair_for_render_warning(
                validation,
                render_evaluation.as_ref(),
            );
            verification_receipts.push(ChatArtifactVerificationReceipt {
                id: format!("repair-pass-{}", repair_index + 1),
                kind: "repair_verification".to_string(),
                status: validation_status_id(validation.classification).to_string(),
                summary: validation.rationale.clone(),
                details: validation.repair_hints.clone(),
            });
            for repair_receipt in repair_receipts.iter_mut().filter(|receipt| {
                repair_wave_work_item_ids
                    .iter()
                    .any(|work_item_id| work_item_id == &receipt.id)
            }) {
                repair_receipt.status = validation_status_id(validation.classification).to_string();
                repair_receipt.summary = if repair_patch_applied {
                    "Scoped repair changes were merged and re-verified.".to_string()
                } else {
                    "Repair pass completed without any scoped change to merge.".to_string()
                };
                repair_receipt.details = validation.repair_hints.clone();
            }
            emit_chat_work_graph_generation_progress(
                progress_observer.as_ref(),
                request,
                production_provenance.kind,
                &work_graph_plan,
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
                Some(ChatArtifactWorkerRole::Repair),
                validation_status_id(validation.classification),
                chat_work_graph_progress_step(
                    &chat_work_graph_execution_summary(
                        &work_graph_plan,
                        "verify",
                        Some(ChatArtifactWorkerRole::Repair),
                        validation_status_id(validation.classification),
                    ),
                    format!("Repair pass {} re-ran verification.", repair_index + 1),
                ),
                render_evaluation.as_ref(),
                Some(&validation),
            );
            if validation_clears_primary_view(&validation) {
                break;
            }
        }
        if !spawned_repair_work_item_ids.is_empty() {
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-follow-up-graph".to_string(),
                status: if validation_clears_primary_view(&validation) {
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
                details: validation.repair_hints.clone(),
            });
        }
        if repair_applied && validation_clears_primary_view(&validation) {
            update_work_graph_work_item_status(
                &mut work_graph_plan,
                &repair_template_item.id,
                ChatArtifactWorkItemStatus::Succeeded,
            );
            worker_receipts.push(ChatArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: ChatArtifactWorkItemStatus::Succeeded,
                result_kind: Some(WorkGraphWorkerResultKind::SubtaskRequested),
                summary: format!(
                    "Repair coordination spawned {} bounded follow-up worker(s) and cleared verification.",
                    spawned_repair_work_item_ids.len()
                ),
                started_at: chat_work_graph_now_iso(),
                finished_at: Some(chat_work_graph_now_iso()),
                runtime: repair_runtime.chat_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: validation.repair_hints.clone(),
                failure: None,
            });
        } else if !repair_applied {
            update_work_graph_work_item_status(
                &mut work_graph_plan,
                &repair_template_item.id,
                ChatArtifactWorkItemStatus::Blocked,
            );
            worker_receipts.push(ChatArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: ChatArtifactWorkItemStatus::Blocked,
                result_kind: Some(WorkGraphWorkerResultKind::Blocked),
                summary: "Validation cited issues, but no narrower repair patch was applied."
                    .to_string(),
                started_at: chat_work_graph_now_iso(),
                finished_at: Some(chat_work_graph_now_iso()),
                runtime: repair_runtime.chat_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: validation.repair_hints.clone(),
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
                details: validation.repair_hints.clone(),
            });
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-follow-up-blocked".to_string(),
                status: "blocked".to_string(),
                summary: "Repair coordination could not merge any bounded follow-up change."
                    .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: vec![repair_template_item.id.clone()],
                details: validation.repair_hints.clone(),
            });
        } else {
            update_work_graph_work_item_status(
                &mut work_graph_plan,
                &repair_template_item.id,
                ChatArtifactWorkItemStatus::Blocked,
            );
            worker_receipts.push(ChatArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: ChatArtifactWorkItemStatus::Blocked,
                result_kind: Some(WorkGraphWorkerResultKind::ReplanRequested),
                summary: format!(
                    "Repair coordination merged {} bounded follow-up worker(s), but verification still needs a broader replan.",
                    spawned_repair_work_item_ids.len()
                ),
                started_at: chat_work_graph_now_iso(),
                finished_at: Some(chat_work_graph_now_iso()),
                runtime: repair_runtime.chat_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: validation.repair_hints.clone(),
                failure: Some(validation.rationale.clone()),
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
                details: validation.repair_hints.clone(),
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
                details: validation.repair_hints.clone(),
            });
        }
    } else {
        update_work_graph_work_item_status(
            &mut work_graph_plan,
            "repair",
            ChatArtifactWorkItemStatus::Skipped,
        );
        if let Some(repair_item) = work_graph_plan
            .work_items
            .iter()
            .find(|item| item.id == "repair")
        {
            worker_receipts.push(chat_work_graph_skip_receipt(
                repair_item,
                &repair_runtime,
                "Validation cleared the merged artifact without a repair pass.",
            ));
        }
    }

    final_payload =
        validate_work_graph_generated_artifact_payload(&canonical, request).map_err(build_error)?;
    let work_graph_execution = chat_work_graph_execution_summary(
        &work_graph_plan,
        if validation_clears_primary_view(&validation) {
            "ready"
        } else if repair_applied {
            "repair_exhausted"
        } else {
            "validated"
        },
        None,
        validation_status_id(validation.classification),
    );
    let execution_budget_summary = ExecutionBudgetSummary {
        planned_worker_count: Some(work_graph_plan.work_items.len()),
        dispatched_worker_count: Some(
            worker_receipts
                .iter()
                .filter(|receipt| {
                    !matches!(
                        receipt.result_kind,
                        Some(WorkGraphWorkerResultKind::Noop)
                            | Some(WorkGraphWorkerResultKind::Blocked)
                    )
                })
                .count(),
        ),
        token_budget: Some(chat_work_graph_planned_token_budget(
            request,
            production_provenance.kind,
            &work_graph_plan,
        )),
        token_usage: None,
        wall_clock_ms: Some(work_graph_started_at.elapsed().as_millis() as u64),
        coordination_overhead_ms: None,
        status: if validation_clears_primary_view(&validation) {
            "completed".to_string()
        } else if repair_applied {
            "repair_exhausted".to_string()
        } else {
            "validated".to_string()
        },
    };
    let execution_envelope = build_execution_envelope_from_work_graph_with_receipts(
        Some(execution_strategy),
        Some("chat_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        Some(&work_graph_plan),
        Some(&work_graph_execution),
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
    if let Some(envelope) = execution_envelope.as_ref() {
        crate::execution::validate_execution_envelope(envelope).map_err(build_error)?;
    }

    Ok(ChatArtifactGenerationBundle {
        brief: brief.clone(),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        work_graph_plan: Some(work_graph_plan),
        work_graph_execution: Some(work_graph_execution),
        work_graph_worker_receipts: worker_receipts,
        work_graph_change_receipts: patch_receipts,
        work_graph_merge_receipts: merge_receipts,
        work_graph_verification_receipts: verification_receipts,
        winner: final_payload,
        render_evaluation,
        validation,
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: Some(runtime_plan.policy),
        adaptive_search_budget: None,
        degraded_path_used: false,
        ux_lifecycle: if repair_applied {
            ChatArtifactUxLifecycle::Refining
        } else {
            ChatArtifactUxLifecycle::Validated
        },
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}
