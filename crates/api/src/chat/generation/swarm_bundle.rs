use super::*;

pub(super) async fn generate_chat_artifact_bundle_with_swarm(
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
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    let swarm_started_at = Instant::now();
    let planning_runtime = runtime_plan.planning_runtime.clone();
    let production_runtime = runtime_plan.generation_runtime.clone();
    let repair_runtime = runtime_plan.repair_runtime.clone();
    let production_provenance = production_runtime.chat_runtime_provenance();
    let acceptance_provenance = runtime_plan.acceptance_runtime.chat_runtime_provenance();
    let origin = output_origin_from_provenance(&production_provenance);
    let mut swarm_plan =
        build_chat_artifact_swarm_plan(request, blueprint, brief, execution_strategy);
    let mut worker_receipts = Vec::<ChatArtifactWorkerReceipt>::new();
    let mut patch_receipts = Vec::<ChatArtifactPatchReceipt>::new();
    let mut merge_receipts = Vec::<ChatArtifactMergeReceipt>::new();
    let verification_receipts = Vec::<ChatArtifactVerificationReceipt>::new();
    let mut graph_mutation_receipts = Vec::<ExecutionGraphMutationReceipt>::new();
    let repair_receipts = Vec::<ExecutionRepairReceipt>::new();
    let mut replan_receipts = Vec::<ExecutionReplanReceipt>::new();
    let mut runtime_dispatch_batches = Vec::<ExecutionDispatchBatch>::new();
    let live_preview_state = Arc::new(Mutex::new(Vec::<ExecutionLivePreview>::new()));
    let mut canonical = ChatGeneratedArtifactPayload {
        summary: if brief.artifact_thesis.trim().is_empty() {
            title.trim().to_string()
        } else {
            brief.artifact_thesis.clone()
        },
        notes: Vec::new(),
        files: Vec::new(),
    };
    let build_error = |message: String| ChatArtifactGenerationError {
        message,
        brief: Some(brief.clone()),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
    };

    update_swarm_work_item_status(
        &mut swarm_plan,
        "planner",
        ChatArtifactWorkItemStatus::Succeeded,
    );
    if let Some(planner_item) = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "planner")
    {
        worker_receipts.push(ChatArtifactWorkerReceipt {
            work_item_id: planner_item.id.clone(),
            role: planner_item.role,
            status: ChatArtifactWorkItemStatus::Succeeded,
            result_kind: Some(SwarmWorkerResultKind::Completed),
            summary: format!(
                "Locked {} with {} planned work item(s).",
                swarm_plan.adapter_label,
                swarm_plan.work_items.len()
            ),
            started_at: chat_swarm_now_iso(),
            finished_at: Some(chat_swarm_now_iso()),
            runtime: planning_runtime.chat_runtime_provenance(),
            read_paths: planner_item.read_paths.clone(),
            write_paths: planner_item.write_paths.clone(),
            write_regions: planner_item.write_regions.clone(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: planner_item.blocked_on_ids.clone(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: None,
            notes: Vec::new(),
            failure: None,
        });
    }

    if request.renderer == ChatRendererKind::HtmlIframe {
        let execution_work_item_ids = swarm_plan
            .work_items
            .iter()
            .filter(|item| {
                matches!(
                    item.role,
                    ChatArtifactWorkerRole::Skeleton
                        | ChatArtifactWorkerRole::SectionContent
                        | ChatArtifactWorkerRole::StyleSystem
                        | ChatArtifactWorkerRole::Interaction
                        | ChatArtifactWorkerRole::Integrator
                )
            })
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        let mut dispatch_sequence = 1u32;
        let mut execution_index = 0usize;

        while let Some(mut dispatch_batch) =
            next_swarm_dispatch_batch(&swarm_plan, &execution_work_item_ids, dispatch_sequence)
        {
            dispatch_sequence = dispatch_sequence.saturating_add(1);
            constrain_dispatch_batch_by_parallelism(
                &mut dispatch_batch,
                chat_swarm_dispatch_parallelism_cap(request, production_provenance.kind),
            );
            if dispatch_batch.work_item_ids.is_empty() {
                runtime_dispatch_batches.push(dispatch_batch);
                break;
            }

            let mut runnable_items = Vec::<ChatArtifactWorkItem>::new();
            let mut skipped_ids = Vec::<String>::new();
            for work_item_id in dispatch_batch.work_item_ids.clone() {
                let Some(work_item) = swarm_plan
                    .work_items
                    .iter()
                    .find(|item| item.id == work_item_id)
                    .cloned()
                else {
                    continue;
                };
                if let Some(skip_summary) = chat_swarm_skip_summary_for_html_work_item(
                    request,
                    brief,
                    blueprint,
                    production_provenance.kind,
                    &work_item,
                ) {
                    update_swarm_work_item_status(
                        &mut swarm_plan,
                        &work_item.id,
                        ChatArtifactWorkItemStatus::Skipped,
                    );
                    worker_receipts.push(chat_swarm_skip_receipt(
                        &work_item,
                        &production_runtime,
                        skip_summary,
                    ));
                    skipped_ids.push(work_item.id.clone());
                    continue;
                }
                update_swarm_work_item_status(
                    &mut swarm_plan,
                    &work_item.id,
                    ChatArtifactWorkItemStatus::Running,
                );
                runnable_items.push(work_item);
            }

            if !skipped_ids.is_empty() {
                dispatch_batch
                    .details
                    .push(format!("Skipped {}", skipped_ids.join(" · ")));
            }
            if runnable_items.is_empty() {
                dispatch_batch.status = "skipped".to_string();
                runtime_dispatch_batches.push(dispatch_batch);
                continue;
            }

            let batch_id = dispatch_batch.id.clone();
            let batch_preview_work_item_id = dispatch_batch.work_item_ids.last().cloned();
            let batch_active_role = runnable_items.first().map(|item| item.role);
            let batch_worker_count = runnable_items.len();
            let batch_snapshot = canonical.clone();
            let live_preview_observer: Option<ChatArtifactLivePreviewObserver> =
                progress_observer.as_ref().map(|_| {
                    let progress_observer = progress_observer.clone();
                    let batch_request = request.clone();
                    let batch_swarm_plan = swarm_plan.clone();
                    let batch_worker_receipts = worker_receipts.clone();
                    let batch_patch_receipts = patch_receipts.clone();
                    let batch_merge_receipts = merge_receipts.clone();
                    let batch_verification_receipts = verification_receipts.clone();
                    let batch_graph_mutation_receipts = graph_mutation_receipts.clone();
                    let batch_runtime_dispatch_batches = runtime_dispatch_batches.clone();
                    let batch_repair_receipts = repair_receipts.clone();
                    let batch_replan_receipts = replan_receipts.clone();
                    let live_preview_state = live_preview_state.clone();
                    let batch_id = batch_id.clone();
                    Arc::new(move |preview: ExecutionLivePreview| {
                        if let Ok(mut previews) = live_preview_state.lock() {
                            upsert_execution_live_preview(&mut previews, preview.clone());
                        }
                        let live_previews = snapshot_execution_live_previews(&live_preview_state);
                        emit_chat_swarm_generation_progress(
                            progress_observer.as_ref(),
                            &batch_request,
                            production_provenance.kind,
                            &batch_swarm_plan,
                            &batch_worker_receipts,
                            &batch_patch_receipts,
                            &batch_merge_receipts,
                            &batch_verification_receipts,
                            &batch_graph_mutation_receipts,
                            &batch_runtime_dispatch_batches,
                            &batch_repair_receipts,
                            &batch_replan_receipts,
                            &live_previews,
                            "work",
                            batch_active_role,
                            "running",
                            chat_swarm_progress_step(
                                &chat_swarm_execution_summary(
                                    &batch_swarm_plan,
                                    "work",
                                    batch_active_role,
                                    "running",
                                ),
                                format!("Streaming {} during {}.", preview.label, batch_id),
                            ),
                            None,
                            None,
                        );
                    }) as ChatArtifactLivePreviewObserver
                });
            let mut join_set = JoinSet::new();
            for work_item in &runnable_items {
                let runtime = production_runtime.clone();
                let title = title.to_string();
                let intent = intent.to_string();
                let request = request.clone();
                let brief = brief.clone();
                let blueprint = blueprint.cloned();
                let artifact_ir = artifact_ir.cloned();
                let selected_skills = selected_skills.to_vec();
                let retrieved_exemplars = retrieved_exemplars.to_vec();
                let edit_intent = edit_intent.cloned();
                let refinement = refinement.cloned();
                let current_payload = batch_snapshot.clone();
                let work_item = work_item.clone();
                let worker_context = chat_swarm_work_item_context(
                    &work_item,
                    blueprint.as_ref(),
                    artifact_ir.as_ref(),
                    None,
                );
                let seed = candidate_seed_for(title.as_str(), intent.as_str(), execution_index);
                let worker_live_preview_observer = live_preview_observer.clone();
                let worker_activity_observer = activity_observer.clone();
                execution_index += 1;
                join_set.spawn(async move {
                    execute_chat_swarm_patch_worker(
                        runtime,
                        &title,
                        &intent,
                        &request,
                        &brief,
                        blueprint.as_ref(),
                        artifact_ir.as_ref(),
                        &selected_skills,
                        &retrieved_exemplars,
                        edit_intent.as_ref(),
                        refinement.as_ref(),
                        &current_payload,
                        &work_item,
                        worker_context,
                        seed,
                        worker_live_preview_observer,
                        worker_activity_observer,
                    )
                    .await
                    .map(|(envelope, receipt)| (work_item.id.clone(), envelope, receipt))
                });
            }

            let mut batch_results =
                HashMap::<String, (ChatArtifactPatchEnvelope, ChatArtifactWorkerReceipt)>::new(
                );
            while let Some(join_result) = join_set.join_next().await {
                let execution_result = join_result.map_err(|error| {
                    build_error(format!("Chat swarm worker join failed: {error}"))
                })?;
                let (work_item_id, envelope, receipt) = execution_result.map_err(build_error)?;
                batch_results.insert(work_item_id, (envelope, receipt));
            }

            let mut batch_conflicts = Vec::<String>::new();
            for work_item in runnable_items {
                let Some((envelope, mut receipt)) = batch_results.remove(&work_item.id) else {
                    return Err(build_error(format!(
                        "Chat swarm dispatch batch '{}' lost worker '{}'.",
                        dispatch_batch.id, work_item.id
                    )));
                };
                let (patch_receipt, merge_receipt) = apply_chat_swarm_patch_envelope(
                    request,
                    &mut canonical,
                    &work_item,
                    &envelope,
                )
                .map_err(build_error)?;
                update_swarm_work_item_status(&mut swarm_plan, &work_item.id, patch_receipt.status);
                receipt.result_kind = Some(match patch_receipt.status {
                    ChatArtifactWorkItemStatus::Skipped => SwarmWorkerResultKind::Noop,
                    ChatArtifactWorkItemStatus::Rejected => SwarmWorkerResultKind::Conflict,
                    ChatArtifactWorkItemStatus::Blocked
                    | ChatArtifactWorkItemStatus::Failed => SwarmWorkerResultKind::Blocked,
                    _ => SwarmWorkerResultKind::Completed,
                });
                if let Some(summary) = envelope.summary.as_ref() {
                    canonical.summary = summary.clone();
                }
                canonical.notes.extend(envelope.notes.clone());
                if patch_receipt.status == ChatArtifactWorkItemStatus::Rejected {
                    let rejection_reason = merge_receipt
                        .rejected_reason
                        .clone()
                        .or_else(|| patch_receipt.failure.clone())
                        .unwrap_or_else(|| {
                            format!("{} emitted a bounded patch conflict.", work_item.id)
                        });
                    batch_conflicts.push(format!("{} rejected", work_item.id));
                    graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                        id: format!("{}-semantic-conflict", work_item.id),
                        mutation_kind: "semantic_conflict_detected".to_string(),
                        status: "blocked".to_string(),
                        summary: rejection_reason.clone(),
                        triggered_by_work_item_id: Some(work_item.id.clone()),
                        affected_work_item_ids: vec![work_item.id.clone()],
                        details: vec![rejection_reason.clone()],
                    });
                    replan_receipts.push(ExecutionReplanReceipt {
                        id: format!("{}-repair-replan", work_item.id),
                        status: "requested".to_string(),
                        summary: format!(
                            "Conflict from '{}' deferred to bounded repair coordination.",
                            work_item.id
                        ),
                        triggered_by_work_item_id: Some(work_item.id.clone()),
                        spawned_work_item_ids: vec!["repair".to_string()],
                        blocked_work_item_ids: vec![work_item.id.clone()],
                        details: vec![rejection_reason],
                    });
                }
                worker_receipts.push(receipt);
                patch_receipts.push(patch_receipt);
                merge_receipts.push(merge_receipt);
            }

            dispatch_batch.status = if !batch_conflicts.is_empty() {
                dispatch_batch.details.extend(batch_conflicts);
                "conflicted".to_string()
            } else if !dispatch_batch.deferred_work_item_ids.is_empty()
                || !dispatch_batch.blocked_work_item_ids.is_empty()
            {
                "constrained".to_string()
            } else {
                "executed".to_string()
            };
            runtime_dispatch_batches.push(dispatch_batch);
            if let Some(preview) = chat_swarm_canonical_preview(
                &canonical,
                batch_preview_work_item_id,
                batch_active_role,
                "running",
                false,
            ) {
                if let Ok(mut previews) = live_preview_state.lock() {
                    upsert_execution_live_preview(&mut previews, preview);
                }
            }
            emit_chat_swarm_generation_progress(
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
                "work",
                batch_active_role,
                "running",
                chat_swarm_progress_step(
                    &chat_swarm_execution_summary(
                        &swarm_plan,
                        "work",
                        batch_active_role,
                        "running",
                    ),
                    format!(
                        "Merged dispatch batch {} with {} worker result(s).",
                        batch_id, batch_worker_count
                    ),
                ),
                None,
                None,
            );
        }
    } else {
        let skeleton_item = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "skeleton")
            .cloned()
            .ok_or_else(|| build_error("Swarm skeleton work item is missing.".to_string()))?;
        let generated = materialize_chat_artifact_candidate_with_runtime_detailed(
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
            "swarm-skeleton",
            candidate_seed_for(title, intent, 0),
            chat_swarm_worker_temperature(
                request,
                ChatArtifactWorkerRole::Skeleton,
                production_provenance.kind,
            ),
            activity_observer.clone(),
        )
        .await
        .map_err(|error| build_error(error.message))?;
        let envelope = ChatArtifactPatchEnvelope {
            summary: Some(generated.summary.clone()),
            notes: generated.notes.clone(),
            operations: diff_payloads_to_patch_operations(&canonical, &generated),
        };
        let (patch_receipt, merge_receipt) =
            apply_chat_swarm_patch_envelope(request, &mut canonical, &skeleton_item, &envelope)
                .map_err(build_error)?;
        update_swarm_work_item_status(&mut swarm_plan, &skeleton_item.id, patch_receipt.status);
        canonical.summary = generated.summary.clone();
        canonical.notes.extend(generated.notes.clone());
        worker_receipts.push(ChatArtifactWorkerReceipt {
            work_item_id: skeleton_item.id.clone(),
            role: skeleton_item.role,
            status: ChatArtifactWorkItemStatus::Succeeded,
            result_kind: Some(SwarmWorkerResultKind::Completed),
            summary: generated.summary,
            started_at: chat_swarm_now_iso(),
            finished_at: Some(chat_swarm_now_iso()),
            runtime: production_runtime.chat_runtime_provenance(),
            read_paths: skeleton_item.read_paths.clone(),
            write_paths: skeleton_item.write_paths.clone(),
            write_regions: skeleton_item.write_regions.clone(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: skeleton_item.blocked_on_ids.clone(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: chat_swarm_preview_language(request),
            notes: generated.notes,
            failure: None,
        });
        patch_receipts.push(patch_receipt);
        merge_receipts.push(merge_receipt);

        if let Some(integrator_item) = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "integrator")
            .cloned()
        {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &integrator_item.id,
                ChatArtifactWorkItemStatus::Skipped,
            );
            worker_receipts.push(chat_swarm_skip_receipt(
                &integrator_item,
                &production_runtime,
                "The coarse renderer adapter completed within the initial bounded pass.",
            ));
        }
        runtime_dispatch_batches = plan_swarm_dispatch_batches(&swarm_plan);
    }

    finalize_swarm_bundle_after_initial_execution(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        execution_strategy,
        render_evaluator,
        progress_observer,
        activity_observer,
        swarm_started_at,
        repair_runtime,
        production_provenance,
        acceptance_provenance,
        origin,
        swarm_plan,
        worker_receipts,
        patch_receipts,
        merge_receipts,
        verification_receipts,
        graph_mutation_receipts,
        repair_receipts,
        replan_receipts,
        runtime_dispatch_batches,
        live_preview_state,
        canonical,
    )
    .await
}
