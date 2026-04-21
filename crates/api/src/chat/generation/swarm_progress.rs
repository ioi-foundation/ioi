use super::*;

fn swarm_operator_status(verification_status: &str) -> ChatArtifactOperatorRunStatus {
    match verification_status.trim().to_ascii_lowercase().as_str() {
        "pending" => ChatArtifactOperatorRunStatus::Pending,
        "running" | "active" => ChatArtifactOperatorRunStatus::Active,
        "passed" | "ready" | "complete" | "completed" | "success" => {
            ChatArtifactOperatorRunStatus::Complete
        }
        "blocked" => ChatArtifactOperatorRunStatus::Blocked,
        "failed" | "failure" => ChatArtifactOperatorRunStatus::Failed,
        _ => ChatArtifactOperatorRunStatus::Active,
    }
}

fn swarm_operator_phase(current_stage: &str) -> ChatArtifactOperatorPhase {
    match current_stage.trim().to_ascii_lowercase().as_str() {
        "intake" | "requirements" | "specification" | "planner" | "plan" | "routing"
        | "dispatch" => ChatArtifactOperatorPhase::UnderstandRequest,
        "work" | "swarm_execution" | "materialization" | "execution" | "mutate" => {
            ChatArtifactOperatorPhase::AuthorArtifact
        }
        "repair" => ChatArtifactOperatorPhase::RepairArtifact,
        "verification" | "verify" | "merge" => ChatArtifactOperatorPhase::VerifyArtifact,
        "presentation" | "reply" | "finalize" | "final" => {
            ChatArtifactOperatorPhase::PresentArtifact
        }
        _ => ChatArtifactOperatorPhase::AuthorArtifact,
    }
}

fn swarm_operator_label(
    phase: ChatArtifactOperatorPhase,
    active_worker_role: Option<ChatArtifactWorkerRole>,
) -> String {
    match phase {
        ChatArtifactOperatorPhase::UnderstandRequest => "Route artifact".to_string(),
        ChatArtifactOperatorPhase::AuthorArtifact => active_worker_role
            .map(|role| format!("Run {} worker", format!("{role:?}").to_ascii_lowercase()))
            .unwrap_or_else(|| "Write artifact".to_string()),
        ChatArtifactOperatorPhase::RepairArtifact => "Repair artifact".to_string(),
        ChatArtifactOperatorPhase::VerifyArtifact => "Run browser verification".to_string(),
        ChatArtifactOperatorPhase::PresentArtifact => "Open preview".to_string(),
        _ => "Artifact step".to_string(),
    }
}

fn swarm_preview(live_previews: &[ExecutionLivePreview]) -> Option<ChatArtifactOperatorPreview> {
    let preview = live_previews.last()?;
    Some(ChatArtifactOperatorPreview {
        origin_prompt_event_id: String::new(),
        label: preview.label.clone(),
        content: preview.content.clone(),
        status: preview.status.clone(),
        kind: Some(format!("{:?}", preview.kind).to_ascii_lowercase()),
        language: preview.language.clone(),
        is_final: preview.is_final,
    })
}

fn swarm_operator_steps(
    current_stage: &str,
    active_worker_role: Option<ChatArtifactWorkerRole>,
    verification_status: &str,
    current_step: &str,
    live_previews: &[ExecutionLivePreview],
) -> Vec<ChatArtifactOperatorStep> {
    let phase = swarm_operator_phase(current_stage);
    let status = swarm_operator_status(verification_status);
    vec![ChatArtifactOperatorStep {
        step_id: format!(
            "swarm:{}:{}",
            current_stage.trim().to_ascii_lowercase(),
            active_worker_role
                .map(|role| format!("{role:?}").to_ascii_lowercase())
                .unwrap_or_else(|| "artifact".to_string())
        ),
        origin_prompt_event_id: String::new(),
        phase,
        engine: "swarm_generation".to_string(),
        status,
        label: swarm_operator_label(phase, active_worker_role),
        detail: current_step.to_string(),
        started_at_ms: 0,
        finished_at_ms: matches!(
            status,
            ChatArtifactOperatorRunStatus::Complete
                | ChatArtifactOperatorRunStatus::Blocked
                | ChatArtifactOperatorRunStatus::Failed
        )
        .then_some(0),
        preview: swarm_preview(live_previews),
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 1,
    }]
}

pub(super) fn emit_chat_swarm_generation_progress(
    observer: Option<&ChatArtifactGenerationProgressObserver>,
    request: &ChatOutcomeArtifactRequest,
    production_provenance: ChatRuntimeProvenanceKind,
    swarm_plan: &ChatArtifactSwarmPlan,
    worker_receipts: &[ChatArtifactWorkerReceipt],
    patch_receipts: &[ChatArtifactPatchReceipt],
    merge_receipts: &[ChatArtifactMergeReceipt],
    verification_receipts: &[ChatArtifactVerificationReceipt],
    graph_mutation_receipts: &[ExecutionGraphMutationReceipt],
    runtime_dispatch_batches: &[ExecutionDispatchBatch],
    repair_receipts: &[ExecutionRepairReceipt],
    replan_receipts: &[ExecutionReplanReceipt],
    live_previews: &[ExecutionLivePreview],
    current_stage: &str,
    active_worker_role: Option<ChatArtifactWorkerRole>,
    verification_status: &str,
    current_step: impl Into<String>,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
    validation: Option<&ChatArtifactValidationResult>,
) {
    let Some(observer) = observer else {
        return;
    };
    let current_step = current_step.into();

    let swarm_execution = chat_swarm_execution_summary(
        swarm_plan,
        current_stage,
        active_worker_role,
        verification_status,
    );
    let execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        None,
        Some("chat_artifact".to_string()),
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
        Some(chat_swarm_partial_budget_summary(
            request,
            production_provenance,
            swarm_plan,
            worker_receipts,
        )),
        live_previews,
    );

    observer(ChatArtifactGenerationProgress {
        current_step: current_step.clone(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        retrieved_sources: Vec::new(),
        execution_envelope,
        swarm_plan: Some(swarm_plan.clone()),
        swarm_execution: Some(swarm_execution),
        swarm_worker_receipts: worker_receipts.to_vec(),
        swarm_change_receipts: patch_receipts.to_vec(),
        swarm_merge_receipts: merge_receipts.to_vec(),
        swarm_verification_receipts: verification_receipts.to_vec(),
        render_evaluation: render_evaluation.cloned(),
        validation: validation.cloned(),
        operator_steps: swarm_operator_steps(
            current_stage,
            active_worker_role,
            verification_status,
            &current_step,
            live_previews,
        ),
    });
}

pub(super) fn ensure_swarm_file_from_operation(
    request: &ChatOutcomeArtifactRequest,
    operation: &ChatArtifactPatchOperation,
) -> Result<ChatGeneratedArtifactFile, String> {
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

pub(super) fn chat_swarm_rejected_patch_receipts(
    work_item: &ChatArtifactWorkItem,
    summary: impl Into<String>,
    operation_kinds: Vec<String>,
    touched_paths: Vec<String>,
    touched_regions: Vec<String>,
    failure: impl Into<String>,
) -> (ChatArtifactPatchReceipt, ChatArtifactMergeReceipt) {
    let summary = summary.into();
    let failure = failure.into();
    (
        ChatArtifactPatchReceipt {
            work_item_id: work_item.id.clone(),
            status: ChatArtifactWorkItemStatus::Rejected,
            summary: summary.clone(),
            operation_count: operation_kinds.len(),
            touched_paths: touched_paths.clone(),
            touched_regions: touched_regions.clone(),
            operation_kinds,
            preview: None,
            preview_language: None,
            failure: Some(failure.clone()),
        },
        ChatArtifactMergeReceipt {
            work_item_id: work_item.id.clone(),
            status: ChatArtifactWorkItemStatus::Rejected,
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
    role: ChatArtifactWorkerRole,
    body: &str,
) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return body.to_string();
    }

    match role {
        ChatArtifactWorkerRole::StyleSystem => {
            if trimmed.to_ascii_lowercase().contains("<style") {
                body.to_string()
            } else {
                format!("<style>\n{}\n</style>", trimmed)
            }
        }
        ChatArtifactWorkerRole::Interaction => {
            if trimmed.to_ascii_lowercase().contains("<script") {
                body.to_string()
            } else {
                format!("<script>\n{}\n</script>", trimmed)
            }
        }
        ChatArtifactWorkerRole::SectionContent => {
            if trimmed.starts_with('<') {
                body.to_string()
            } else {
                format!("<section>\n{}\n</section>", trimmed)
            }
        }
        _ => body.to_string(),
    }
}

pub(super) fn chat_swarm_semantic_conflict_reason(
    request: &ChatOutcomeArtifactRequest,
    work_item: &ChatArtifactWorkItem,
    operation: &ChatArtifactPatchOperation,
) -> Option<String> {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return None;
    }
    let body = operation.body.as_deref().unwrap_or_default();
    let lowered = body.to_ascii_lowercase();

    if matches!(
        operation.kind,
        ChatArtifactPatchOperationKind::ReplaceRegion
    ) && work_item.role != ChatArtifactWorkerRole::Skeleton
        && html_swarm_patch_contains_region_markers(body)
    {
        return Some(format!(
            "Work item '{}' attempted to inject nested swarm region markers into '{}'.",
            work_item.id,
            operation.region_id.as_deref().unwrap_or("unknown-region")
        ));
    }

    match work_item.role {
        ChatArtifactWorkerRole::SectionContent => {
            if lowered.contains("<script") || lowered.contains("<style") {
                return Some(format!(
                    "Section worker '{}' crossed a semantic ownership boundary by emitting script/style payloads.",
                    work_item.id
                ));
            }
        }
        ChatArtifactWorkerRole::StyleSystem => {
            if lowered.contains("<script") {
                return Some(format!(
                    "Style worker '{}' crossed a semantic ownership boundary by emitting script payloads.",
                    work_item.id
                ));
            }
        }
        ChatArtifactWorkerRole::Interaction => {
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

pub(super) fn chat_swarm_skip_receipt(
    work_item: &ChatArtifactWorkItem,
    runtime: &Arc<dyn InferenceRuntime>,
    summary: impl Into<String>,
) -> ChatArtifactWorkerReceipt {
    let summary = summary.into();
    ChatArtifactWorkerReceipt {
        work_item_id: work_item.id.clone(),
        role: work_item.role,
        status: ChatArtifactWorkItemStatus::Skipped,
        result_kind: Some(SwarmWorkerResultKind::Noop),
        summary,
        started_at: chat_swarm_now_iso(),
        finished_at: Some(chat_swarm_now_iso()),
        runtime: runtime.chat_runtime_provenance(),
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

pub(super) fn chat_swarm_skip_summary_for_html_work_item(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    production_provenance: ChatRuntimeProvenanceKind,
    work_item: &ChatArtifactWorkItem,
) -> Option<String> {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return None;
    }

    if work_item.role == ChatArtifactWorkerRole::Interaction
        && !brief.has_required_interaction_goals()
        && blueprint.is_none_or(|value| value.interaction_plan.is_empty())
    {
        return Some(
            "The HTML artifact did not require a dedicated interaction patch.".to_string(),
        );
    }

    if work_item.role == ChatArtifactWorkerRole::Integrator
        && production_provenance == ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(
            "The merged local HTML artifact now goes straight to validation; keep integrator reserve for targeted repair only."
                .to_string(),
        );
    }

    None
}

pub(crate) fn apply_chat_swarm_patch_envelope(
    request: &ChatOutcomeArtifactRequest,
    payload: &mut ChatGeneratedArtifactPayload,
    work_item: &ChatArtifactWorkItem,
    envelope: &ChatArtifactPatchEnvelope,
) -> Result<(ChatArtifactPatchReceipt, ChatArtifactMergeReceipt), String> {
    let mut touched_paths = Vec::new();
    let mut touched_regions = Vec::new();
    let mut operation_kinds = Vec::new();
    for operation in &envelope.operations {
        let normalized_operation = if work_item.role != ChatArtifactWorkerRole::Skeleton
            && !work_item.write_regions.is_empty()
            && !matches!(
                operation.kind,
                ChatArtifactPatchOperationKind::ReplaceRegion
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
            ChatArtifactPatchOperation {
                kind: ChatArtifactPatchOperationKind::ReplaceRegion,
                path: operation.path.clone(),
                region_id: Some(region_id),
                mime: Some("text/html".to_string()),
                role: Some(ChatArtifactFileRole::Primary),
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
            return Ok(chat_swarm_rejected_patch_receipts(
                work_item,
                envelope
                    .summary
                    .clone()
                    .unwrap_or_else(|| work_item.summary.clone()),
                vec![chat_patch_operation_kind_label(normalized_operation.kind).to_string()],
                vec![normalized_operation.path.clone()],
                Vec::new(),
                format!(
                    "Work item '{}' attempted to edit out-of-scope path '{}'.",
                    work_item.id, normalized_operation.path
                ),
            ));
        }
        if let Some(reason) =
            chat_swarm_semantic_conflict_reason(request, work_item, &normalized_operation)
        {
            return Ok(chat_swarm_rejected_patch_receipts(
                work_item,
                envelope
                    .summary
                    .clone()
                    .unwrap_or_else(|| work_item.summary.clone()),
                vec![chat_patch_operation_kind_label(normalized_operation.kind).to_string()],
                vec![normalized_operation.path.clone()],
                normalized_operation.region_id.clone().into_iter().collect(),
                reason,
            ));
        }
        if matches!(
            normalized_operation.kind,
            ChatArtifactPatchOperationKind::ReplaceRegion
        ) {
            let Some(region_id) = normalized_operation.region_id.as_ref() else {
                return Ok(chat_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![chat_patch_operation_kind_label(normalized_operation.kind).to_string()],
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
                return Ok(chat_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![chat_patch_operation_kind_label(normalized_operation.kind).to_string()],
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
                return Ok(chat_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![chat_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![canonical_region.clone()],
                    format!(
                        "Work item '{}' attempted to patch missing file '{}'.",
                        work_item.id, normalized_operation.path
                    ),
                ));
            };
            let Some(replacement) = normalized_operation.body.as_ref() else {
                return Ok(chat_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![chat_patch_operation_kind_label(normalized_operation.kind).to_string()],
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
                ChatArtifactPatchOperationKind::CreateFile => {
                    let mut file =
                        ensure_swarm_file_from_operation(request, &normalized_operation)?;
                    if work_item.role == ChatArtifactWorkerRole::Skeleton
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
                ChatArtifactPatchOperationKind::ReplaceFile => {
                    let mut file =
                        ensure_swarm_file_from_operation(request, &normalized_operation)?;
                    if work_item.role == ChatArtifactWorkerRole::Skeleton
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
                        return Ok(chat_swarm_rejected_patch_receipts(
                            work_item,
                            envelope
                                .summary
                                .clone()
                                .unwrap_or_else(|| work_item.summary.clone()),
                            vec![chat_patch_operation_kind_label(normalized_operation.kind)
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
                ChatArtifactPatchOperationKind::DeleteFile => {
                    payload
                        .files
                        .retain(|file| file.path != normalized_operation.path);
                }
                ChatArtifactPatchOperationKind::ReplaceRegion => {}
            }
        }
        touched_paths.push(normalized_operation.path.clone());
        operation_kinds
            .push(chat_patch_operation_kind_label(normalized_operation.kind).to_string());
    }

    let summary = envelope
        .summary
        .clone()
        .unwrap_or_else(|| work_item.summary.clone());
    Ok((
        ChatArtifactPatchReceipt {
            work_item_id: work_item.id.clone(),
            status: if envelope.operations.is_empty() {
                ChatArtifactWorkItemStatus::Skipped
            } else {
                ChatArtifactWorkItemStatus::Succeeded
            },
            summary: summary.clone(),
            operation_count: envelope.operations.len(),
            touched_paths: touched_paths.clone(),
            touched_regions: touched_regions.clone(),
            operation_kinds,
            preview: summarize_patch_preview(&envelope.operations),
            preview_language: chat_swarm_preview_language(request),
            failure: None,
        },
        ChatArtifactMergeReceipt {
            work_item_id: work_item.id.clone(),
            status: if envelope.operations.is_empty() {
                ChatArtifactWorkItemStatus::Skipped
            } else {
                ChatArtifactWorkItemStatus::Succeeded
            },
            summary,
            applied_operation_count: envelope.operations.len(),
            touched_paths,
            touched_regions,
            rejected_reason: None,
        },
    ))
}
