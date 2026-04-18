use super::*;

pub(super) fn emit_studio_swarm_generation_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    request: &StudioOutcomeArtifactRequest,
    production_provenance: StudioRuntimeProvenanceKind,
    swarm_plan: &StudioArtifactSwarmPlan,
    worker_receipts: &[StudioArtifactWorkerReceipt],
    patch_receipts: &[StudioArtifactPatchReceipt],
    merge_receipts: &[StudioArtifactMergeReceipt],
    verification_receipts: &[StudioArtifactVerificationReceipt],
    graph_mutation_receipts: &[ExecutionGraphMutationReceipt],
    runtime_dispatch_batches: &[ExecutionDispatchBatch],
    repair_receipts: &[ExecutionRepairReceipt],
    replan_receipts: &[ExecutionReplanReceipt],
    live_previews: &[ExecutionLivePreview],
    current_stage: &str,
    active_worker_role: Option<StudioArtifactWorkerRole>,
    verification_status: &str,
    current_step: impl Into<String>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    validation: Option<&StudioArtifactValidationResult>,
) {
    let Some(observer) = observer else {
        return;
    };

    let swarm_execution = studio_swarm_execution_summary(
        swarm_plan,
        current_stage,
        active_worker_role,
        verification_status,
    );
    let execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        None,
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        Some(swarm_plan),
        Some(&swarm_execution),
        worker_receipts,
        patch_receipts,
        merge_receipts,
        verification_receipts,
        graph_mutation_receipts,
        runtime_dispatch_batches,
        repair_receipts,
        replan_receipts,
        Some(studio_swarm_partial_budget_summary(
            request,
            production_provenance,
            swarm_plan,
            worker_receipts,
        )),
        live_previews,
    );

    observer(StudioArtifactGenerationProgress {
        current_step: current_step.into(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        execution_envelope,
        swarm_plan: Some(swarm_plan.clone()),
        swarm_execution: Some(swarm_execution),
        swarm_worker_receipts: worker_receipts.to_vec(),
        swarm_change_receipts: patch_receipts.to_vec(),
        swarm_merge_receipts: merge_receipts.to_vec(),
        swarm_verification_receipts: verification_receipts.to_vec(),
        render_evaluation: render_evaluation.cloned(),
        validation: validation.cloned(),
        runtime_narration_events: Vec::new(),
    });
}

pub(super) fn ensure_swarm_file_from_operation(
    request: &StudioOutcomeArtifactRequest,
    operation: &StudioArtifactPatchOperation,
) -> Result<StudioGeneratedArtifactFile, String> {
    let mut file = default_generated_artifact_file_for_renderer(request.renderer);
    file.path = operation.path.clone();
    if let Some(mime) = operation.mime.as_ref() {
        file.mime = mime.clone();
    }
    if let Some(role) = operation.role {
        file.role = role;
    }
    if let Some(renderable) = operation.renderable {
        file.renderable = renderable;
    }
    if let Some(downloadable) = operation.downloadable {
        file.downloadable = downloadable;
    }
    if let Some(encoding) = operation.encoding {
        file.encoding = Some(encoding);
    }
    file.body = operation.body.clone().ok_or_else(|| {
        format!(
            "Patch operation for '{}' is missing a body.",
            operation.path
        )
    })?;
    Ok(file)
}

pub(super) fn studio_swarm_rejected_patch_receipts(
    work_item: &StudioArtifactWorkItem,
    summary: impl Into<String>,
    operation_kinds: Vec<String>,
    touched_paths: Vec<String>,
    touched_regions: Vec<String>,
    failure: impl Into<String>,
) -> (StudioArtifactPatchReceipt, StudioArtifactMergeReceipt) {
    let summary = summary.into();
    let failure = failure.into();
    (
        StudioArtifactPatchReceipt {
            work_item_id: work_item.id.clone(),
            status: StudioArtifactWorkItemStatus::Rejected,
            summary: summary.clone(),
            operation_count: operation_kinds.len(),
            touched_paths: touched_paths.clone(),
            touched_regions: touched_regions.clone(),
            operation_kinds,
            preview: None,
            preview_language: None,
            failure: Some(failure.clone()),
        },
        StudioArtifactMergeReceipt {
            work_item_id: work_item.id.clone(),
            status: StudioArtifactWorkItemStatus::Rejected,
            summary,
            applied_operation_count: 0,
            touched_paths,
            touched_regions,
            rejected_reason: Some(failure),
        },
    )
}

pub(super) fn html_swarm_patch_contains_region_markers(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("<!-- STUDIO_REGION_START:")
            || trimmed.starts_with("<!-- STUDIO_REGION_END:")
    })
}

pub(super) fn normalize_region_owned_html_body_for_role(
    role: StudioArtifactWorkerRole,
    body: &str,
) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return body.to_string();
    }

    match role {
        StudioArtifactWorkerRole::StyleSystem => {
            if trimmed.to_ascii_lowercase().contains("<style") {
                body.to_string()
            } else {
                format!("<style>\n{}\n</style>", trimmed)
            }
        }
        StudioArtifactWorkerRole::Interaction => {
            if trimmed.to_ascii_lowercase().contains("<script") {
                body.to_string()
            } else {
                format!("<script>\n{}\n</script>", trimmed)
            }
        }
        StudioArtifactWorkerRole::SectionContent => {
            if trimmed.starts_with('<') {
                body.to_string()
            } else {
                format!("<section>\n{}\n</section>", trimmed)
            }
        }
        _ => body.to_string(),
    }
}

pub(super) fn studio_swarm_semantic_conflict_reason(
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
    operation: &StudioArtifactPatchOperation,
) -> Option<String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }
    let body = operation.body.as_deref().unwrap_or_default();
    let lowered = body.to_ascii_lowercase();

    if matches!(
        operation.kind,
        StudioArtifactPatchOperationKind::ReplaceRegion
    ) && work_item.role != StudioArtifactWorkerRole::Skeleton
        && html_swarm_patch_contains_region_markers(body)
    {
        return Some(format!(
            "Work item '{}' attempted to inject nested swarm region markers into '{}'.",
            work_item.id,
            operation.region_id.as_deref().unwrap_or("unknown-region")
        ));
    }

    match work_item.role {
        StudioArtifactWorkerRole::SectionContent => {
            if lowered.contains("<script") || lowered.contains("<style") {
                return Some(format!(
                    "Section worker '{}' crossed a semantic ownership boundary by emitting script/style payloads.",
                    work_item.id
                ));
            }
        }
        StudioArtifactWorkerRole::StyleSystem => {
            if lowered.contains("<script") {
                return Some(format!(
                    "Style worker '{}' crossed a semantic ownership boundary by emitting script payloads.",
                    work_item.id
                ));
            }
        }
        StudioArtifactWorkerRole::Interaction => {
            if lowered.contains("<style") {
                return Some(format!(
                    "Interaction worker '{}' crossed a semantic ownership boundary by emitting style payloads.",
                    work_item.id
                ));
            }
        }
        _ => {}
    }

    None
}

pub(super) fn studio_swarm_skip_receipt(
    work_item: &StudioArtifactWorkItem,
    runtime: &Arc<dyn InferenceRuntime>,
    summary: impl Into<String>,
) -> StudioArtifactWorkerReceipt {
    let summary = summary.into();
    StudioArtifactWorkerReceipt {
        work_item_id: work_item.id.clone(),
        role: work_item.role,
        status: StudioArtifactWorkItemStatus::Skipped,
        result_kind: Some(SwarmWorkerResultKind::Noop),
        summary,
        started_at: studio_swarm_now_iso(),
        finished_at: Some(studio_swarm_now_iso()),
        runtime: runtime.studio_runtime_provenance(),
        read_paths: work_item.read_paths.clone(),
        write_paths: work_item.write_paths.clone(),
        write_regions: work_item.write_regions.clone(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: work_item.blocked_on_ids.clone(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: Vec::new(),
        failure: None,
    }
}

pub(super) fn studio_swarm_skip_summary_for_html_work_item(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    production_provenance: StudioRuntimeProvenanceKind,
    work_item: &StudioArtifactWorkItem,
) -> Option<String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }

    if work_item.role == StudioArtifactWorkerRole::Interaction
        && !brief.has_required_interaction_goals()
        && blueprint.is_none_or(|value| value.interaction_plan.is_empty())
    {
        return Some(
            "The HTML artifact did not require a dedicated interaction patch.".to_string(),
        );
    }

    if work_item.role == StudioArtifactWorkerRole::Integrator
        && production_provenance == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(
            "The merged local HTML artifact now goes straight to validation; keep integrator reserve for targeted repair only."
                .to_string(),
        );
    }

    None
}

pub(crate) fn apply_studio_swarm_patch_envelope(
    request: &StudioOutcomeArtifactRequest,
    payload: &mut StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
    envelope: &StudioArtifactPatchEnvelope,
) -> Result<(StudioArtifactPatchReceipt, StudioArtifactMergeReceipt), String> {
    let mut touched_paths = Vec::new();
    let mut touched_regions = Vec::new();
    let mut operation_kinds = Vec::new();
    for operation in &envelope.operations {
        let normalized_operation = if work_item.role != StudioArtifactWorkerRole::Skeleton
            && !work_item.write_regions.is_empty()
            && !matches!(
                operation.kind,
                StudioArtifactPatchOperationKind::ReplaceRegion
            ) {
            let region_id = operation
                .region_id
                .clone()
                .or_else(|| work_item.write_regions.first().cloned())
                .ok_or_else(|| {
                    format!(
                        "Work item '{}' emitted a file-scoped patch without a scoped region.",
                        work_item.id
                    )
                })?;
            StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::ReplaceRegion,
                path: operation.path.clone(),
                region_id: Some(region_id),
                mime: Some("text/html".to_string()),
                role: Some(StudioArtifactFileRole::Primary),
                renderable: Some(true),
                downloadable: Some(true),
                encoding: operation.encoding,
                body: operation
                    .body
                    .as_deref()
                    .map(|body| normalize_region_owned_html_body_for_role(work_item.role, body)),
            }
        } else {
            operation.clone()
        };

        if !work_item.write_paths.is_empty()
            && !work_item
                .write_paths
                .iter()
                .any(|path| path == &normalized_operation.path)
        {
            return Ok(studio_swarm_rejected_patch_receipts(
                work_item,
                envelope
                    .summary
                    .clone()
                    .unwrap_or_else(|| work_item.summary.clone()),
                vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                vec![normalized_operation.path.clone()],
                Vec::new(),
                format!(
                    "Work item '{}' attempted to edit out-of-scope path '{}'.",
                    work_item.id, normalized_operation.path
                ),
            ));
        }
        if let Some(reason) =
            studio_swarm_semantic_conflict_reason(request, work_item, &normalized_operation)
        {
            return Ok(studio_swarm_rejected_patch_receipts(
                work_item,
                envelope
                    .summary
                    .clone()
                    .unwrap_or_else(|| work_item.summary.clone()),
                vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                vec![normalized_operation.path.clone()],
                normalized_operation.region_id.clone().into_iter().collect(),
                reason,
            ));
        }
        if matches!(
            normalized_operation.kind,
            StudioArtifactPatchOperationKind::ReplaceRegion
        ) {
            let Some(region_id) = normalized_operation.region_id.as_ref() else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    Vec::new(),
                    format!(
                        "Work item '{}' emitted a region patch without regionId.",
                        work_item.id
                    ),
                ));
            };
            let Some(canonical_region) = work_item
                .write_regions
                .iter()
                .find(|region| html_swarm_region_ids_match(region, region_id))
                .cloned()
            else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![region_id.clone()],
                    format!(
                        "Work item '{}' attempted to edit out-of-scope region '{}'.",
                        work_item.id, region_id
                    ),
                ));
            };
            let Some(file) = payload
                .files
                .iter_mut()
                .find(|file| file.path == normalized_operation.path)
            else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![canonical_region.clone()],
                    format!(
                        "Work item '{}' attempted to patch missing file '{}'.",
                        work_item.id, normalized_operation.path
                    ),
                ));
            };
            let Some(replacement) = normalized_operation.body.as_ref() else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![canonical_region.clone()],
                    format!(
                        "Work item '{}' emitted an empty region patch for '{}'.",
                        work_item.id, region_id
                    ),
                ));
            };
            file.body = replace_html_swarm_region(&file.body, &canonical_region, replacement)?;
            touched_regions.push(canonical_region);
        } else {
            match normalized_operation.kind {
                StudioArtifactPatchOperationKind::CreateFile => {
                    let mut file =
                        ensure_swarm_file_from_operation(request, &normalized_operation)?;
                    if work_item.role == StudioArtifactWorkerRole::Skeleton
                        && (file.mime == "text/html" || file.path.ends_with(".html"))
                        && !work_item.write_regions.is_empty()
                    {
                        file.body = normalize_html_swarm_skeleton_markers(
                            &file.body,
                            &work_item.write_regions,
                        );
                    }
                    if let Some(existing) = payload
                        .files
                        .iter_mut()
                        .find(|file| file.path == normalized_operation.path)
                    {
                        *existing = file;
                    } else {
                        payload.files.push(file);
                    }
                }
                StudioArtifactPatchOperationKind::ReplaceFile => {
                    let mut file =
                        ensure_swarm_file_from_operation(request, &normalized_operation)?;
                    if work_item.role == StudioArtifactWorkerRole::Skeleton
                        && (file.mime == "text/html" || file.path.ends_with(".html"))
                        && !work_item.write_regions.is_empty()
                    {
                        file.body = normalize_html_swarm_skeleton_markers(
                            &file.body,
                            &work_item.write_regions,
                        );
                    }
                    let Some(existing) = payload
                        .files
                        .iter_mut()
                        .find(|candidate| candidate.path == normalized_operation.path)
                    else {
                        return Ok(studio_swarm_rejected_patch_receipts(
                            work_item,
                            envelope
                                .summary
                                .clone()
                                .unwrap_or_else(|| work_item.summary.clone()),
                            vec![studio_patch_operation_kind_label(normalized_operation.kind)
                                .to_string()],
                            vec![normalized_operation.path.clone()],
                            Vec::new(),
                            format!(
                                "Work item '{}' attempted to replace missing file '{}'.",
                                work_item.id, normalized_operation.path
                            ),
                        ));
                    };
                    *existing = file;
                }
                StudioArtifactPatchOperationKind::DeleteFile => {
                    payload
                        .files
                        .retain(|file| file.path != normalized_operation.path);
                }
                StudioArtifactPatchOperationKind::ReplaceRegion => {}
            }
        }
        touched_paths.push(normalized_operation.path.clone());
        operation_kinds
            .push(studio_patch_operation_kind_label(normalized_operation.kind).to_string());
    }

    let summary = envelope
        .summary
        .clone()
        .unwrap_or_else(|| work_item.summary.clone());
    Ok((
        StudioArtifactPatchReceipt {
            work_item_id: work_item.id.clone(),
            status: if envelope.operations.is_empty() {
                StudioArtifactWorkItemStatus::Skipped
            } else {
                StudioArtifactWorkItemStatus::Succeeded
            },
            summary: summary.clone(),
            operation_count: envelope.operations.len(),
            touched_paths: touched_paths.clone(),
            touched_regions: touched_regions.clone(),
            operation_kinds,
            preview: summarize_patch_preview(&envelope.operations),
            preview_language: studio_swarm_preview_language(request),
            failure: None,
        },
        StudioArtifactMergeReceipt {
            work_item_id: work_item.id.clone(),
            status: if envelope.operations.is_empty() {
                StudioArtifactWorkItemStatus::Skipped
            } else {
                StudioArtifactWorkItemStatus::Succeeded
            },
            summary,
            applied_operation_count: envelope.operations.len(),
            touched_paths,
            touched_regions,
            rejected_reason: None,
        },
    ))
}
