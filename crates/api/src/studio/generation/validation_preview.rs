use super::*;

pub(super) fn diff_payloads_to_patch_operations(
    current: &StudioGeneratedArtifactPayload,
    next: &StudioGeneratedArtifactPayload,
) -> Vec<StudioArtifactPatchOperation> {
    let mut operations = Vec::new();
    for file in &next.files {
        let current_file = current
            .files
            .iter()
            .find(|candidate| candidate.path == file.path);
        if current_file.is_none() {
            operations.push(StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::CreateFile,
                path: file.path.clone(),
                region_id: None,
                mime: Some(file.mime.clone()),
                role: Some(file.role),
                renderable: Some(file.renderable),
                downloadable: Some(file.downloadable),
                encoding: file.encoding,
                body: Some(file.body.clone()),
            });
            continue;
        }
        let current_file = current_file.expect("checked above");
        if current_file.mime != file.mime
            || current_file.role != file.role
            || current_file.renderable != file.renderable
            || current_file.downloadable != file.downloadable
            || current_file.encoding != file.encoding
            || current_file.body != file.body
        {
            operations.push(StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::ReplaceFile,
                path: file.path.clone(),
                region_id: None,
                mime: Some(file.mime.clone()),
                role: Some(file.role),
                renderable: Some(file.renderable),
                downloadable: Some(file.downloadable),
                encoding: file.encoding,
                body: Some(file.body.clone()),
            });
        }
    }
    for file in &current.files {
        if next
            .files
            .iter()
            .all(|candidate| candidate.path != file.path)
        {
            operations.push(StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::DeleteFile,
                path: file.path.clone(),
                region_id: None,
                mime: None,
                role: None,
                renderable: None,
                downloadable: None,
                encoding: None,
                body: None,
            });
        }
    }
    operations
}

pub(super) fn sanitize_swarm_payload_for_validation(
    payload: &StudioGeneratedArtifactPayload,
) -> StudioGeneratedArtifactPayload {
    let mut sanitized = payload.clone();
    for file in &mut sanitized.files {
        if file.mime == "text/html" || file.path.ends_with(".html") {
            file.body = normalize_html_swarm_document(&strip_html_swarm_region_markers(&file.body));
        }
    }
    sanitized
}

pub(super) fn repair_swarm_primary_file_assignment(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) -> StudioGeneratedArtifactPayload {
    let mut repaired = payload.clone();
    let default_file = default_generated_artifact_file_for_renderer(request.renderer);
    if let Some(file) = repaired
        .files
        .iter_mut()
        .find(|file| file.path == default_file.path)
    {
        file.role = default_file.role;
        file.renderable = default_file.renderable;
        file.downloadable = default_file.downloadable;
        if file.encoding.is_none() {
            file.encoding = default_file.encoding;
        }
        return repaired;
    }

    if repaired.files.iter().any(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    }) {
        return repaired;
    }

    if let Some(file) = repaired.files.iter_mut().find(|file| file.renderable) {
        file.role = default_file.role;
    }

    repaired
}

pub(crate) fn validate_swarm_generated_artifact_payload(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let sanitized = sanitize_swarm_payload_for_validation(payload);
    let repaired = repair_swarm_primary_file_assignment(&sanitized, request);
    if let Err(error) = super::validate_generated_artifact_payload(&repaired, request) {
        if request.renderer == StudioRendererKind::HtmlIframe
            && studio_swarm_soft_validation_error(&error)
        {
            return Ok(repaired);
        }
        return Err(error);
    }
    Ok(repaired)
}

pub type StudioArtifactGenerationProgressObserver =
    Arc<dyn Fn(StudioArtifactGenerationProgress) + Send + Sync>;
pub type StudioArtifactActivityObserver = Arc<dyn Fn() + Send + Sync>;
pub(super) type StudioArtifactLivePreviewObserver = Arc<dyn Fn(ExecutionLivePreview) + Send + Sync>;

pub(super) async fn await_with_activity_heartbeat<T, F>(
    future: F,
    activity_observer: Option<StudioArtifactActivityObserver>,
    interval: Duration,
) -> T
where
    F: std::future::Future<Output = T>,
{
    let Some(activity_observer) = activity_observer else {
        return future.await;
    };

    tokio::pin!(future);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            output = &mut future => return output,
            _ = ticker.tick() => activity_observer(),
        }
    }
}

pub(super) fn runtime_preview_snapshot_from_execution_preview(
    preview: &ExecutionLivePreview,
) -> StudioArtifactRuntimePreviewSnapshot {
    StudioArtifactRuntimePreviewSnapshot {
        label: preview.label.clone(),
        content: preview.content.clone(),
        status: preview.status.clone(),
        kind: Some(format!("{:?}", preview.kind).to_ascii_lowercase()),
        language: preview.language.clone(),
        is_final: preview.is_final,
    }
}

pub(super) struct StudioTokenStreamPreviewCollector {
    receiver_task: JoinHandle<String>,
    emitter_task: JoinHandle<()>,
}

pub(super) fn studio_swarm_progress_step(
    swarm_execution: &StudioArtifactSwarmExecutionSummary,
    summary: impl Into<String>,
) -> String {
    format!(
        "{} Swarm is at {}/{} completed work items.",
        summary.into(),
        swarm_execution.completed_work_items,
        swarm_execution.total_work_items
    )
}

pub(super) fn studio_swarm_preview_language(
    request: &StudioOutcomeArtifactRequest,
) -> Option<String> {
    let language = match request.renderer {
        StudioRendererKind::HtmlIframe => "html",
        StudioRendererKind::Markdown => "markdown",
        StudioRendererKind::JsxSandbox | StudioRendererKind::WorkspaceSurface => "tsx",
        StudioRendererKind::Svg => "svg",
        StudioRendererKind::Mermaid => "mermaid",
        StudioRendererKind::PdfEmbed => "text",
        StudioRendererKind::BundleManifest | StudioRendererKind::DownloadCard => "json",
    };
    Some(language.to_string())
}

pub(super) fn studio_swarm_live_preview(
    id: impl Into<String>,
    kind: ExecutionLivePreviewKind,
    label: impl Into<String>,
    work_item_id: Option<String>,
    role: Option<StudioArtifactWorkerRole>,
    status: impl Into<String>,
    language: Option<String>,
    content: impl Into<String>,
    is_final: bool,
) -> ExecutionLivePreview {
    ExecutionLivePreview {
        id: id.into(),
        kind,
        label: label.into(),
        work_item_id,
        role,
        status: status.into(),
        language,
        content: content.into(),
        is_final,
        updated_at: studio_swarm_now_iso(),
    }
}

pub(super) fn spawn_token_stream_preview_collector(
    observer: Option<StudioArtifactLivePreviewObserver>,
    preview_id: String,
    preview_label: String,
    work_item_id: Option<String>,
    role: Option<StudioArtifactWorkerRole>,
    language: Option<String>,
) -> (mpsc::Sender<String>, StudioTokenStreamPreviewCollector) {
    let (token_tx, mut token_rx) = mpsc::channel::<String>(256);
    let combined_state = Arc::new(Mutex::new(String::new()));
    let stream_closed = Arc::new(AtomicBool::new(false));

    let receiver_state = combined_state.clone();
    let receiver_closed = stream_closed.clone();
    let receiver_task = tokio::spawn(async move {
        while let Some(chunk) = token_rx.recv().await {
            if chunk.is_empty() {
                continue;
            }
            if let Ok(mut combined) = receiver_state.lock() {
                combined.push_str(&chunk);
            }
        }
        receiver_closed.store(true, Ordering::SeqCst);
        receiver_state
            .lock()
            .map(|combined| combined.clone())
            .unwrap_or_default()
    });

    let emitter_task = match observer {
        Some(observer) => {
            let emitter_state = combined_state.clone();
            let emitter_closed = stream_closed.clone();
            tokio::spawn(async move {
                let mut last_emitted = String::new();
                let mut ticker = tokio::time::interval(Duration::from_millis(180));
                ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

                loop {
                    ticker.tick().await;
                    let snapshot = emitter_state
                        .lock()
                        .map(|combined| combined.clone())
                        .unwrap_or_default();
                    if !snapshot.trim().is_empty() && snapshot != last_emitted {
                        observer(studio_swarm_live_preview(
                            preview_id.clone(),
                            ExecutionLivePreviewKind::TokenStream,
                            preview_label.clone(),
                            work_item_id.clone(),
                            role,
                            "streaming",
                            language.clone(),
                            live_token_stream_preview_text(&snapshot, 2200),
                            false,
                        ));
                        last_emitted = snapshot;
                    }

                    if emitter_closed.load(Ordering::SeqCst) {
                        let final_snapshot = emitter_state
                            .lock()
                            .map(|combined| combined.clone())
                            .unwrap_or_default();
                        if final_snapshot.trim().is_empty() || final_snapshot == last_emitted {
                            break;
                        }
                    }
                }
            })
        }
        None => tokio::spawn(async {}),
    };

    (
        token_tx,
        StudioTokenStreamPreviewCollector {
            receiver_task,
            emitter_task,
        },
    )
}

pub(super) async fn finish_token_stream_preview_collector(
    collector: Option<StudioTokenStreamPreviewCollector>,
) -> String {
    let Some(collector) = collector else {
        return String::new();
    };
    let combined = collector.receiver_task.await.unwrap_or_default();
    let _ = collector.emitter_task.await;
    combined
}

pub(super) fn upsert_execution_live_preview(
    previews: &mut Vec<ExecutionLivePreview>,
    preview: ExecutionLivePreview,
) {
    if let Some(existing) = previews.iter_mut().find(|entry| entry.id == preview.id) {
        *existing = preview;
        return;
    }
    previews.push(preview);
}

pub(super) fn snapshot_execution_live_previews(
    live_preview_state: &Arc<Mutex<Vec<ExecutionLivePreview>>>,
) -> Vec<ExecutionLivePreview> {
    live_preview_state
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

pub(super) fn summarize_patch_preview(
    operations: &[StudioArtifactPatchOperation],
) -> Option<String> {
    let preview_body = operations.iter().find_map(|operation| {
        operation
            .body
            .as_ref()
            .map(|body| truncate_materialization_focus_text(body, 900))
            .filter(|body| !body.is_empty())
    })?;
    Some(preview_body)
}

pub(super) fn studio_swarm_canonical_preview(
    payload: &StudioGeneratedArtifactPayload,
    work_item_id: Option<String>,
    work_item_role: Option<StudioArtifactWorkerRole>,
    status: &str,
    is_final: bool,
) -> Option<ExecutionLivePreview> {
    let preview_file = payload
        .files
        .iter()
        .find(|file| {
            (file.path.ends_with(".html") || file.mime == "text/html")
                && !file.body.trim().is_empty()
        })
        .or_else(|| {
            payload
                .files
                .iter()
                .find(|file| !file.body.trim().is_empty())
        })?;
    Some(studio_swarm_live_preview(
        "canonical-artifact-preview".to_string(),
        ExecutionLivePreviewKind::ChangePreview,
        format!("Live artifact code · {}", preview_file.path),
        work_item_id,
        work_item_role,
        status,
        Some(preview_file.mime.clone()),
        preview_file.body.clone(),
        is_final,
    ))
}

pub(super) fn studio_swarm_partial_budget_summary(
    request: &StudioOutcomeArtifactRequest,
    production_provenance: StudioRuntimeProvenanceKind,
    swarm_plan: &StudioArtifactSwarmPlan,
    worker_receipts: &[StudioArtifactWorkerReceipt],
) -> ExecutionBudgetSummary {
    let dispatched_worker_count = worker_receipts
        .iter()
        .filter(|receipt| {
            !matches!(
                receipt.result_kind,
                Some(SwarmWorkerResultKind::Noop) | Some(SwarmWorkerResultKind::Blocked)
            )
        })
        .count();
    let conflict_count = worker_receipts
        .iter()
        .filter(|receipt| matches!(receipt.result_kind, Some(SwarmWorkerResultKind::Conflict)))
        .count();
    ExecutionBudgetSummary {
        planned_worker_count: Some(swarm_plan.work_items.len()),
        dispatched_worker_count: Some(dispatched_worker_count),
        token_budget: Some(studio_swarm_planned_token_budget(
            request,
            production_provenance,
            swarm_plan,
        )),
        token_usage: None,
        wall_clock_ms: None,
        coordination_overhead_ms: None,
        status: if conflict_count > 0 {
            "conflicted".to_string()
        } else if dispatched_worker_count > 0 {
            "running".to_string()
        } else {
            "planned".to_string()
        },
    }
}

pub(super) fn non_swarm_required_artifact_paths(
    payload: &StudioGeneratedArtifactPayload,
) -> Vec<String> {
    let mut paths = payload
        .files
        .iter()
        .filter(|file| {
            file.renderable
                || matches!(
                    file.role,
                    StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
                )
        })
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        paths = payload
            .files
            .iter()
            .filter(|file| !file.body.trim().is_empty())
            .map(|file| file.path.clone())
            .collect();
    }
    paths.sort();
    paths.dedup();
    paths
}

pub(super) fn non_swarm_canonical_preview(
    request: &StudioOutcomeArtifactRequest,
    payload: &StudioGeneratedArtifactPayload,
    status: &str,
    is_final: bool,
) -> Option<ExecutionLivePreview> {
    let preview_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
            ) && !file.body.trim().is_empty()
        })
        .or_else(|| {
            payload
                .files
                .iter()
                .find(|file| !file.body.trim().is_empty())
        })?;
    Some(studio_swarm_live_preview(
        "canonical-artifact-preview".to_string(),
        ExecutionLivePreviewKind::ChangePreview,
        format!("Live artifact code · {}", preview_file.path),
        None,
        None,
        status,
        studio_swarm_preview_language(request),
        preview_file.body.clone(),
        is_final,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(renderer: StudioRendererKind) -> StudioOutcomeArtifactRequest {
        StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::InteractiveSingleFile,
            deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
            renderer,
            presentation_surface: StudioPresentationSurface::SidePanel,
            persistence: StudioArtifactPersistenceMode::ArtifactScoped,
            execution_substrate: match renderer {
                StudioRendererKind::HtmlIframe
                | StudioRendererKind::JsxSandbox
                | StudioRendererKind::Svg
                | StudioRendererKind::Mermaid => StudioExecutionSubstrate::ClientSandbox,
                StudioRendererKind::PdfEmbed => StudioExecutionSubstrate::BinaryGenerator,
                StudioRendererKind::WorkspaceSurface => StudioExecutionSubstrate::WorkspaceRuntime,
                _ => StudioExecutionSubstrate::None,
            },
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: StudioOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: renderer == StudioRendererKind::WorkspaceSurface,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: StudioOutcomeArtifactVerificationRequest {
                require_render: true,
                require_build: renderer == StudioRendererKind::WorkspaceSurface,
                require_preview: renderer == StudioRendererKind::WorkspaceSurface,
                require_export: true,
                require_diff_review: false,
            },
        }
    }

    fn sample_payload(body: String, mime: &str, path: &str) -> StudioGeneratedArtifactPayload {
        StudioGeneratedArtifactPayload {
            summary: "sample preview payload".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: path.to_string(),
                mime: mime.to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body,
            }],
        }
    }

    #[test]
    fn non_swarm_canonical_preview_preserves_full_primary_file_body() {
        let request = sample_request(StudioRendererKind::HtmlIframe);
        let long_body = format!(
            "<!doctype html><html><body>{}<!-- preview tail marker --></body></html>",
            "a".repeat(5000)
        );
        let payload = sample_payload(long_body.clone(), "text/html", "index.html");

        let preview = non_swarm_canonical_preview(&request, &payload, "draft_ready", false)
            .expect("non-swarm canonical preview");

        assert_eq!(preview.kind, ExecutionLivePreviewKind::ChangePreview);
        assert_eq!(preview.content, long_body);
        assert!(preview.content.contains("preview tail marker"));
    }

    #[test]
    fn swarm_canonical_preview_preserves_full_primary_file_body() {
        let long_body = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\">{}<!-- preview tail marker --></svg>",
            "<g><text>quantum</text></g>".repeat(350)
        );
        let payload = sample_payload(long_body.clone(), "image/svg+xml", "index.svg");

        let preview = studio_swarm_canonical_preview(
            &payload,
            Some("repair-pass-1".to_string()),
            Some(StudioArtifactWorkerRole::Repair),
            "repairing",
            false,
        )
        .expect("swarm canonical preview");

        assert_eq!(preview.kind, ExecutionLivePreviewKind::ChangePreview);
        assert_eq!(preview.content, long_body);
        assert!(preview.content.contains("preview tail marker"));
    }
}

pub(super) fn build_non_swarm_execution_envelope(
    request: &StudioOutcomeArtifactRequest,
    execution_strategy: StudioExecutionStrategy,
    live_previews: &[ExecutionLivePreview],
    invariant_status: ExecutionCompletionInvariantStatus,
    required_artifact_paths: Vec<String>,
) -> Option<ExecutionEnvelope> {
    let mut execution_envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &[],
        &[],
        &[],
        &[],
    );
    annotate_execution_envelope(
        &mut execution_envelope,
        Some(committed_execution_mode_decision(
            StudioOutcomeKind::Artifact,
            Some(request),
            execution_strategy,
        )),
        Some(completion_invariant_for_direct_execution(
            execution_strategy,
            required_artifact_paths,
            vec!["verify".to_string()],
            invariant_status,
        )),
    );
    if let Some(envelope) = execution_envelope.as_mut() {
        envelope.live_previews = live_previews.to_vec();
    }
    execution_envelope
}

pub(super) fn emit_non_swarm_generation_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    request: &StudioOutcomeArtifactRequest,
    execution_strategy: StudioExecutionStrategy,
    live_previews: &[ExecutionLivePreview],
    current_step: impl Into<String>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    judge: Option<&StudioArtifactJudgeResult>,
    invariant_status: ExecutionCompletionInvariantStatus,
    required_artifact_paths: Vec<String>,
    runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>,
) {
    let Some(observer) = observer else {
        return;
    };

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
        execution_envelope: build_non_swarm_execution_envelope(
            request,
            execution_strategy,
            live_previews,
            invariant_status,
            required_artifact_paths,
        ),
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: render_evaluation.cloned(),
        judge: judge.cloned(),
        runtime_narration_events,
    });
}
