use super::*;

pub(super) fn diff_payloads_to_patch_operations(
    current: &ChatGeneratedArtifactPayload,
    next: &ChatGeneratedArtifactPayload,
) -> Vec<ChatArtifactPatchOperation> {
    let mut operations = Vec::new();
    for file in &next.files {
        let current_file = current
            .files
            .iter()
            .find(|candidate| candidate.path == file.path);
        if current_file.is_none() {
            operations.push(ChatArtifactPatchOperation {
                kind: ChatArtifactPatchOperationKind::CreateFile,
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
            operations.push(ChatArtifactPatchOperation {
                kind: ChatArtifactPatchOperationKind::ReplaceFile,
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
            operations.push(ChatArtifactPatchOperation {
                kind: ChatArtifactPatchOperationKind::DeleteFile,
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
    payload: &ChatGeneratedArtifactPayload,
) -> ChatGeneratedArtifactPayload {
    let mut sanitized = payload.clone();
    for file in &mut sanitized.files {
        if file.mime == "text/html" || file.path.ends_with(".html") {
            file.body = normalize_html_swarm_document(&strip_html_swarm_region_markers(&file.body));
        }
    }
    sanitized
}

pub(super) fn repair_swarm_primary_file_assignment(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) -> ChatGeneratedArtifactPayload {
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
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
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
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatGeneratedArtifactPayload, String> {
    let sanitized = sanitize_swarm_payload_for_validation(payload);
    let repaired = repair_swarm_primary_file_assignment(&sanitized, request);
    if let Err(error) = super::validate_generated_artifact_payload(&repaired, request) {
        if request.renderer == ChatRendererKind::HtmlIframe
            && chat_swarm_soft_validation_error(&error)
        {
            return Ok(repaired);
        }
        return Err(error);
    }
    Ok(repaired)
}

pub type ChatArtifactGenerationProgressObserver =
    Arc<dyn Fn(ChatArtifactGenerationProgress) + Send + Sync>;
pub type ChatArtifactActivityObserver = Arc<dyn Fn() + Send + Sync>;
pub(super) type ChatArtifactLivePreviewObserver = Arc<dyn Fn(ExecutionLivePreview) + Send + Sync>;

pub(super) async fn await_with_activity_heartbeat<T, F>(
    future: F,
    activity_observer: Option<ChatArtifactActivityObserver>,
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
) -> ChatArtifactRuntimePreviewSnapshot {
    ChatArtifactRuntimePreviewSnapshot {
        label: preview.label.clone(),
        content: preview.content.clone(),
        status: preview.status.clone(),
        kind: Some(format!("{:?}", preview.kind).to_ascii_lowercase()),
        language: preview.language.clone(),
        origin_prompt_event_id: None,
        is_final: preview.is_final,
    }
}

pub(super) struct ChatTokenStreamPreviewCollector {
    receiver_task: JoinHandle<String>,
    emitter_task: JoinHandle<()>,
    combined_state: Arc<Mutex<String>>,
}

pub(super) fn chat_swarm_progress_step(
    swarm_execution: &ChatArtifactSwarmExecutionSummary,
    summary: impl Into<String>,
) -> String {
    format!(
        "{} Swarm is at {}/{} completed work items.",
        summary.into(),
        swarm_execution.completed_work_items,
        swarm_execution.total_work_items
    )
}

pub(super) fn chat_swarm_preview_language(request: &ChatOutcomeArtifactRequest) -> Option<String> {
    let language = match request.renderer {
        ChatRendererKind::HtmlIframe => "html",
        ChatRendererKind::Markdown => "markdown",
        ChatRendererKind::JsxSandbox | ChatRendererKind::WorkspaceSurface => "tsx",
        ChatRendererKind::Svg => "svg",
        ChatRendererKind::Mermaid => "mermaid",
        ChatRendererKind::PdfEmbed => "text",
        ChatRendererKind::BundleManifest | ChatRendererKind::DownloadCard => "json",
    };
    Some(language.to_string())
}

pub(super) fn chat_swarm_live_preview(
    id: impl Into<String>,
    kind: ExecutionLivePreviewKind,
    label: impl Into<String>,
    work_item_id: Option<String>,
    role: Option<ChatArtifactWorkerRole>,
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
        updated_at: chat_swarm_now_iso(),
    }
}

pub(super) fn spawn_token_stream_preview_collector(
    observer: Option<ChatArtifactLivePreviewObserver>,
    preview_id: String,
    preview_label: String,
    work_item_id: Option<String>,
    role: Option<ChatArtifactWorkerRole>,
    language: Option<String>,
) -> (mpsc::Sender<String>, ChatTokenStreamPreviewCollector) {
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
                        observer(chat_swarm_live_preview(
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
        ChatTokenStreamPreviewCollector {
            receiver_task,
            emitter_task,
            combined_state,
        },
    )
}

pub(super) fn snapshot_token_stream_preview_collector(
    collector: Option<&ChatTokenStreamPreviewCollector>,
) -> String {
    collector
        .and_then(|collector| {
            collector
                .combined_state
                .lock()
                .ok()
                .map(|combined| combined.clone())
        })
        .unwrap_or_default()
}

pub(super) async fn finish_token_stream_preview_collector(
    collector: Option<ChatTokenStreamPreviewCollector>,
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

pub(super) fn summarize_patch_preview(operations: &[ChatArtifactPatchOperation]) -> Option<String> {
    let preview_body = operations.iter().find_map(|operation| {
        operation
            .body
            .as_ref()
            .map(|body| truncate_materialization_focus_text(body, 900))
            .filter(|body| !body.is_empty())
    })?;
    Some(preview_body)
}

pub(super) fn chat_swarm_canonical_preview(
    payload: &ChatGeneratedArtifactPayload,
    work_item_id: Option<String>,
    work_item_role: Option<ChatArtifactWorkerRole>,
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
    Some(chat_swarm_live_preview(
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

pub(super) fn chat_swarm_partial_budget_summary(
    request: &ChatOutcomeArtifactRequest,
    production_provenance: ChatRuntimeProvenanceKind,
    swarm_plan: &ChatArtifactSwarmPlan,
    worker_receipts: &[ChatArtifactWorkerReceipt],
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
        token_budget: Some(chat_swarm_planned_token_budget(
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
    payload: &ChatGeneratedArtifactPayload,
) -> Vec<String> {
    let mut paths = payload
        .files
        .iter()
        .filter(|file| {
            file.renderable
                || matches!(
                    file.role,
                    ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
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
    request: &ChatOutcomeArtifactRequest,
    payload: &ChatGeneratedArtifactPayload,
    status: &str,
    is_final: bool,
) -> Option<ExecutionLivePreview> {
    let preview_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
            ) && !file.body.trim().is_empty()
        })
        .or_else(|| {
            payload
                .files
                .iter()
                .find(|file| !file.body.trim().is_empty())
        })?;
    Some(chat_swarm_live_preview(
        "canonical-artifact-preview".to_string(),
        ExecutionLivePreviewKind::ChangePreview,
        format!("Live artifact code · {}", preview_file.path),
        None,
        None,
        status,
        chat_swarm_preview_language(request),
        preview_file.body.clone(),
        is_final,
    ))
}

#[cfg(test)]
#[path = "validation_preview/tests.rs"]
mod tests;

pub(super) fn build_non_swarm_execution_envelope(
    request: &ChatOutcomeArtifactRequest,
    execution_strategy: ChatExecutionStrategy,
    live_previews: &[ExecutionLivePreview],
    invariant_status: ExecutionCompletionInvariantStatus,
    required_artifact_paths: Vec<String>,
) -> Option<ExecutionEnvelope> {
    let mut execution_envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("chat_artifact".to_string()),
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
            ChatOutcomeKind::Artifact,
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
    observer: Option<&ChatArtifactGenerationProgressObserver>,
    request: &ChatOutcomeArtifactRequest,
    execution_strategy: ChatExecutionStrategy,
    live_previews: &[ExecutionLivePreview],
    current_step: impl Into<String>,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
    validation: Option<&ChatArtifactValidationResult>,
    invariant_status: ExecutionCompletionInvariantStatus,
    required_artifact_paths: Vec<String>,
    operator_steps: Vec<ChatArtifactOperatorStep>,
) {
    let Some(observer) = observer else {
        return;
    };

    observer(ChatArtifactGenerationProgress {
        current_step: current_step.into(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        retrieved_sources: Vec::new(),
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
        validation: validation.cloned(),
        operator_steps,
    });
}
