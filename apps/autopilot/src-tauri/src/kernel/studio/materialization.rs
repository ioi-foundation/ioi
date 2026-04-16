use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_api::execution::{
    execution_budget_envelope_for_strategy, execution_strategy_for_outcome,
    ExecutionCompletionInvariantStatus, ExecutionEnvelope, ExecutionLivePreview,
    ExecutionLivePreviewKind,
};
use ioi_api::studio::{
    derive_request_grounded_studio_artifact_brief, derive_studio_artifact_prepared_context,
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator,
    pdf_artifact_bytes, render_eval_timeout_for_runtime, resolve_studio_artifact_runtime_plan,
    synthesize_studio_artifact_brief_for_execution_strategy_with_runtime,
    StudioArtifactActivityObserver, StudioArtifactBlueprint, StudioArtifactExemplar,
    StudioArtifactGenerationProgress, StudioArtifactGenerationProgressObserver, StudioArtifactIR,
    StudioArtifactPlanningContext, StudioArtifactRenderEvaluation, StudioArtifactRenderEvaluator,
    StudioArtifactRuntimeEventStatus, StudioArtifactRuntimeEventType,
    StudioArtifactRuntimeNarrationEvent, StudioArtifactRuntimePolicyProfile,
    StudioArtifactRuntimePreviewSnapshot, StudioArtifactRuntimeStepId, StudioArtifactSelectedSkill,
    StudioGeneratedArtifactEncoding, StudioGeneratedArtifactFile,
};
use ioi_drivers::studio_render::BrowserStudioArtifactRenderEvaluator;
use ioi_types::app::StudioExecutionStrategy;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::MissedTickBehavior;

#[cfg(test)]
use ioi_api::studio::StudioGeneratedArtifactPayload;

const LOCAL_HTML_GENERATION_TIMEOUT_SECS: u64 = 420;
const LOCAL_HTML_SPLIT_ACCEPTANCE_TIMEOUT_SECS: u64 = 1200;

fn generated_file_is_binary(file: &StudioGeneratedArtifactFile) -> bool {
    matches!(file.encoding, Some(StudioGeneratedArtifactEncoding::Base64))
}

fn generated_file_text_content(file: &StudioGeneratedArtifactFile) -> Option<String> {
    (!generated_file_is_binary(file)).then(|| file.body.clone())
}

fn generated_file_preview(file: &StudioGeneratedArtifactFile) -> Option<String> {
    if generated_file_is_binary(file) {
        Some(format!(
            "Binary {} artifact stored for download/open.",
            file.mime
        ))
    } else {
        Some(truncate_preview(&file.body))
    }
}

fn generated_file_bytes(
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    file: &StudioGeneratedArtifactFile,
) -> Result<Vec<u8>, String> {
    if request.renderer == StudioRendererKind::PdfEmbed && file.path.ends_with(".pdf") {
        return Ok(pdf_artifact_bytes(title, &file.body));
    }

    match file
        .encoding
        .unwrap_or(StudioGeneratedArtifactEncoding::Utf8)
    {
        StudioGeneratedArtifactEncoding::Utf8 => Ok(file.body.as_bytes().to_vec()),
        StudioGeneratedArtifactEncoding::Base64 => {
            STANDARD.decode(file.body.trim()).map_err(|error| {
                format!(
                    "Failed to decode binary Studio artifact {} as base64: {}",
                    file.path, error
                )
            })
        }
    }
}

fn execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn synthesize_prepared_context_with_runtime_plan(
    runtime_plan: &ioi_api::studio::StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    execution_strategy: StudioExecutionStrategy,
) -> Result<StudioArtifactPlanningContext, String> {
    let planning_timeout = Duration::from_secs(90).min(studio_generation_timeout_for_runtime(
        &runtime_plan.planning_runtime,
    ));
    let brief = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            planning_timeout,
            synthesize_studio_artifact_brief_for_execution_strategy_with_runtime(
                runtime_plan.planning_runtime.clone(),
                title,
                intent,
                request,
                refinement,
                execution_strategy,
            ),
        )
        .await
    }) {
        Ok(Ok(brief)) => brief,
        Ok(Err(error)) => {
            studio_proof_trace(format!(
                "materialize_non_workspace:brief_fallback reason={} renderer={:?}",
                error, request.renderer
            ));
            derive_request_grounded_studio_artifact_brief(title, intent, request, refinement)
        }
        Err(_) => {
            studio_proof_trace(format!(
                "materialize_non_workspace:brief_fallback reason=timeout renderer={:?}",
                request.renderer
            ));
            derive_request_grounded_studio_artifact_brief(title, intent, request, refinement)
        }
    };

    Ok(derive_studio_artifact_prepared_context(
        request,
        &brief,
        refinement.and_then(|context| context.blueprint.clone()),
        refinement.and_then(|context| context.artifact_ir.clone()),
        refinement
            .map(|context| context.selected_skills.clone())
            .unwrap_or_default(),
        refinement
            .map(|context| context.retrieved_exemplars.clone())
            .unwrap_or_default(),
    ))
}

fn prepared_context_progress_message(execution_strategy: StudioExecutionStrategy) -> String {
    if execution_strategy == StudioExecutionStrategy::DirectAuthor {
        "Prepared the artifact brief and structural context. Authoring is starting.".to_string()
    } else {
        "Prepared the artifact brief and structural context. Execution is starting.".to_string()
    }
}

fn author_artifact_blocked_event(
    attempt_id: Option<String>,
    detail: impl Into<String>,
) -> StudioArtifactRuntimeNarrationEvent {
    let event = StudioArtifactRuntimeNarrationEvent::new(
        StudioArtifactRuntimeEventType::AuthorArtifact,
        StudioArtifactRuntimeStepId::AuthorArtifact,
        "Write artifact",
        detail.into(),
        StudioArtifactRuntimeEventStatus::Blocked,
    );
    if let Some(attempt_id) = attempt_id {
        event.with_attempt_id(attempt_id)
    } else {
        event
    }
}

fn replan_execution_event(
    from: StudioExecutionStrategy,
    to: StudioExecutionStrategy,
) -> StudioArtifactRuntimeNarrationEvent {
    StudioArtifactRuntimeNarrationEvent::new(
        StudioArtifactRuntimeEventType::ReplanExecution,
        StudioArtifactRuntimeStepId::ReplanExecution,
        "Switch execution strategy",
        format!(
            "Studio hit a concrete blocker under {} and is continuing with {} so the artifact route can still finish.",
            execution_strategy_id(from).replace('_', " "),
            execution_strategy_id(to).replace('_', " ")
        ),
        StudioArtifactRuntimeEventStatus::Complete,
    )
}

fn direct_author_error_requires_replan(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("direct-author artifact inference timed out")
        || lowered.contains("direct-author continuation timed out")
        || lowered.contains("direct-author repair timed out")
}

fn present_artifact_blocked_event(error: &str) -> StudioArtifactRuntimeNarrationEvent {
    StudioArtifactRuntimeNarrationEvent::new(
        StudioArtifactRuntimeEventType::PresentArtifact,
        StudioArtifactRuntimeStepId::PresentArtifact,
        "Open artifact",
        format!("Studio could not present the artifact because {error}"),
        StudioArtifactRuntimeEventStatus::Blocked,
    )
}

fn present_artifact_complete_event() -> StudioArtifactRuntimeNarrationEvent {
    StudioArtifactRuntimeNarrationEvent::new(
        StudioArtifactRuntimeEventType::PresentArtifact,
        StudioArtifactRuntimeStepId::PresentArtifact,
        "Open artifact",
        "Studio finished materializing the artifact and can now surface it.",
        StudioArtifactRuntimeEventStatus::Complete,
    )
}

fn latest_execution_live_preview(
    execution_envelope: Option<&ExecutionEnvelope>,
) -> Option<ExecutionLivePreview> {
    execution_envelope
        .and_then(|envelope| {
            envelope
                .live_previews
                .iter()
                .filter(|preview| !preview.content.trim().is_empty())
                .max_by(|left, right| {
                    left.updated_at
                        .cmp(&right.updated_at)
                        .then_with(|| left.id.cmp(&right.id))
                })
        })
        .cloned()
}

fn terminal_preview_status_for_blocked_artifact(preview: &ExecutionLivePreview) -> &'static str {
    match preview.kind {
        ExecutionLivePreviewKind::TokenStream | ExecutionLivePreviewKind::CommandStream => {
            "interrupted"
        }
        _ => "blocked",
    }
}

fn finalize_blocked_execution_envelope(
    execution_envelope: Option<ExecutionEnvelope>,
) -> Option<ExecutionEnvelope> {
    let mut execution_envelope = execution_envelope?;
    if let Some(invariant) = execution_envelope.completion_invariant.as_mut() {
        invariant.status = ExecutionCompletionInvariantStatus::Blocked;
        if invariant.summary.trim().is_empty() {
            invariant.summary =
                "Execution blocked before Studio satisfied the artifact completion invariant."
                    .to_string();
        }
    }

    if let Some(latest_preview) =
        execution_envelope
            .live_previews
            .iter_mut()
            .max_by(|left, right| {
                left.updated_at
                    .cmp(&right.updated_at)
                    .then_with(|| left.id.cmp(&right.id))
            })
    {
        if !latest_preview.is_final || latest_preview.status.eq_ignore_ascii_case("streaming") {
            latest_preview.status =
                terminal_preview_status_for_blocked_artifact(latest_preview).to_string();
            latest_preview.is_final = true;
        }
    }

    Some(execution_envelope)
}

fn finalize_latest_execution_preview(
    execution_envelope: Option<ExecutionEnvelope>,
) -> Option<ExecutionEnvelope> {
    let mut execution_envelope = execution_envelope?;
    if let Some(latest_preview) =
        execution_envelope
            .live_previews
            .iter_mut()
            .max_by(|left, right| {
                left.updated_at
                    .cmp(&right.updated_at)
                    .then_with(|| left.id.cmp(&right.id))
            })
    {
        if !latest_preview.is_final || latest_preview.status.eq_ignore_ascii_case("streaming") {
            latest_preview.status =
                terminal_preview_status_for_blocked_artifact(latest_preview).to_string();
            latest_preview.is_final = true;
        }
    }
    Some(execution_envelope)
}

fn append_blocked_preview_runtime_event(
    runtime_narration_events: &mut Vec<StudioArtifactRuntimeNarrationEvent>,
    execution_envelope: Option<&ExecutionEnvelope>,
) {
    let Some(preview) = latest_execution_live_preview(execution_envelope) else {
        return;
    };
    if runtime_narration_events
        .iter()
        .rev()
        .filter_map(|event| event.preview.as_ref())
        .next()
        .is_some_and(|existing| {
            existing.content == preview.content
                && existing.status.eq_ignore_ascii_case(&preview.status)
                && existing.is_final == preview.is_final
        })
    {
        return;
    }

    let attempt_id = runtime_narration_events.iter().rev().find_map(|event| {
        if event.step_id == "author_artifact" {
            event.attempt_id.clone()
        } else {
            None
        }
    });
    let detail = match preview.kind {
        ExecutionLivePreviewKind::TokenStream | ExecutionLivePreviewKind::CommandStream => {
            "Studio retained the latest streamed output after the artifact attempt blocked."
        }
        _ => "Studio retained the latest preview snapshot after the artifact attempt blocked.",
    };
    let event = StudioArtifactRuntimeNarrationEvent::new(
        "author_preview_terminal",
        "author_artifact",
        "Write artifact",
        detail,
        "blocked",
    )
    .with_preview_snapshot(StudioArtifactRuntimePreviewSnapshot {
        label: preview.label,
        content: preview.content,
        status: preview.status,
        kind: Some(format!("{:?}", preview.kind).to_ascii_lowercase()),
        language: preview.language,
        is_final: preview.is_final,
    });
    runtime_narration_events.push(match attempt_id {
        Some(attempt_id) => event.with_attempt_id(attempt_id),
        None => event,
    });
}

fn emit_prepared_context_generation_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    prepared_context: &StudioArtifactPlanningContext,
    execution_strategy: StudioExecutionStrategy,
) {
    let Some(observer) = observer else {
        return;
    };

    observer(StudioArtifactGenerationProgress {
        current_step: prepared_context_progress_message(execution_strategy),
        artifact_brief: Some(prepared_context.brief.clone()),
        preparation_needs: prepared_context.preparation_needs.clone(),
        prepared_context_resolution: prepared_context.prepared_context_resolution.clone(),
        skill_discovery_resolution: prepared_context.skill_discovery_resolution.clone(),
        blueprint: prepared_context.blueprint.clone(),
        artifact_ir: prepared_context.artifact_ir.clone(),
        selected_skills: prepared_context.selected_skills.clone(),
        retrieved_exemplars: prepared_context.retrieved_exemplars.clone(),
        execution_envelope: None,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
        judge: None,
        runtime_narration_events: Vec::new(),
    });
}

fn studio_proof_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

pub(super) fn sync_workspace_manifest_file(studio_session: &StudioArtifactSession) {
    let Some(workspace_root) = studio_session.workspace_root.as_deref() else {
        return;
    };
    let manifest_path = Path::new(workspace_root).join("artifact-manifest.json");
    let Ok(json) = serde_json::to_vec_pretty(&studio_session.artifact_manifest) else {
        return;
    };
    let _ = fs::write(manifest_path, json);
}

pub(super) fn mime_for_workspace_entry(path: &str) -> String {
    if path.ends_with(".tsx") || path.ends_with(".jsx") {
        "text/jsx".to_string()
    } else if path.ends_with(".html") {
        "text/html".to_string()
    } else if path.ends_with(".md") {
        "text/markdown".to_string()
    } else if path.ends_with(".css") {
        "text/css".to_string()
    } else if path.ends_with(".svg") {
        "image/svg+xml".to_string()
    } else {
        "text/plain".to_string()
    }
}

pub(super) fn select_workspace_recipe(
    request: &StudioOutcomeArtifactRequest,
) -> StudioScaffoldRecipe {
    match request.workspace_recipe_id.as_deref() {
        Some("vite-static-html") => StudioScaffoldRecipe::StaticHtmlVite,
        Some("react-vite") => StudioScaffoldRecipe::ReactVite,
        _ => StudioScaffoldRecipe::ReactVite,
    }
}

pub(super) fn materialize_non_workspace_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_execution_strategy(
        app,
        thread_id,
        title,
        intent,
        request,
        refinement,
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(request)),
    )
}

pub(super) fn materialize_non_workspace_artifact_with_execution_strategy(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    execution_strategy: StudioExecutionStrategy,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_execution_strategy_and_progress_observer(
        app,
        thread_id,
        title,
        intent,
        request,
        refinement,
        execution_strategy,
        None,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_execution_strategy_and_progress_observer(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    let runtime_profile = configured_studio_runtime_profile();
    let (memory_runtime, inference_runtime, acceptance_inference_runtime) = {
        let app_state = app.state::<Mutex<AppState>>();
        let state = app_state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        (
            state.memory_runtime.clone().ok_or_else(|| {
                "Memory runtime is unavailable for Studio artifact materialization.".to_string()
            })?,
            state.inference_runtime.clone(),
            state.acceptance_inference_runtime.clone(),
        )
    };
    let Some(runtime) = inference_runtime.as_ref() else {
        return Ok(blocked_materialized_artifact_from_error(
            title,
            intent,
            request,
            refinement,
            "Inference runtime is unavailable for prepared artifact context synthesis.",
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
            None,
            acceptance_inference_runtime
                .as_ref()
                .map(|candidate| candidate.studio_runtime_provenance()),
        ));
    };
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        runtime.clone(),
        acceptance_inference_runtime.clone(),
        runtime_profile,
    );
    let planning_context = match super::skills::prepare_studio_artifact_planning_context(
        app,
        &memory_runtime,
        runtime_plan.planning_runtime,
        title,
        intent,
        request,
        refinement,
        execution_strategy,
        progress_observer.clone(),
    ) {
        Ok(context) => context,
        Err(message) => {
            return Ok(blocked_materialized_artifact_from_error(
                title,
                intent,
                request,
                refinement,
                &message,
                None,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                None,
                Vec::new(),
                None,
                None,
                None,
                Vec::new(),
                Some(runtime.studio_runtime_provenance()),
                acceptance_inference_runtime
                    .as_ref()
                    .map(|candidate| candidate.studio_runtime_provenance()),
            ));
        }
    };

    materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_optional_progress(
        &memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        Some(planning_context),
        execution_strategy,
        progress_observer,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<StudioArtifactPlanningContext>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_optional_progress(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        planning_context,
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(request)),
        None,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies_and_execution_strategy(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        planning_context,
        execution_strategy,
        None,
    )
}

fn materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_optional_progress(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        planning_context,
        execution_strategy,
        progress_observer,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    let generation_timeout = inference_runtime
        .as_ref()
        .map(|runtime| {
            studio_generation_timeout_for_request_and_execution_strategy(
                request,
                runtime,
                acceptance_inference_runtime.as_ref(),
                execution_strategy,
            )
        })
        .unwrap_or_else(|| Duration::from_secs(120));
    materialize_non_workspace_artifact_with_dependencies_and_timeout_and_execution_strategy(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        generation_timeout,
        planning_context,
        execution_strategy,
        progress_observer,
    )
}

pub(super) fn studio_generation_timeout_for_runtime(
    runtime: &Arc<dyn InferenceRuntime>,
) -> Duration {
    let seconds = [
        "AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS",
        "IOI_STUDIO_GENERATION_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    })
    .unwrap_or_else(|| match runtime.studio_runtime_provenance().kind {
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime => 180,
        _ => 90,
    });

    Duration::from_secs(seconds)
}

pub(super) fn studio_generation_timeout_for_request(
    request: &StudioOutcomeArtifactRequest,
    runtime: &Arc<dyn InferenceRuntime>,
) -> Duration {
    let timeout = studio_generation_timeout_for_runtime(runtime);
    if request.renderer == StudioRendererKind::HtmlIframe
        && runtime.studio_runtime_provenance().kind
            == crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime
        && timeout == Duration::from_secs(180)
    {
        let runtime_profile = configured_studio_runtime_profile();
        if studio_extended_local_html_timeout_enabled(request, runtime_profile) {
            return Duration::from_secs(LOCAL_HTML_SPLIT_ACCEPTANCE_TIMEOUT_SECS);
        }
        return Duration::from_secs(LOCAL_HTML_GENERATION_TIMEOUT_SECS);
    }

    timeout
}

pub(super) fn studio_generation_timeout_for_request_and_execution_strategy(
    request: &StudioOutcomeArtifactRequest,
    runtime: &Arc<dyn InferenceRuntime>,
    _acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
    execution_strategy: StudioExecutionStrategy,
) -> Duration {
    if execution_strategy == StudioExecutionStrategy::DirectAuthor {
        let authoring_budget = Duration::from_millis(
            execution_budget_envelope_for_strategy(execution_strategy).max_wall_clock_ms as u64,
        );
        let render_eval_budget = render_eval_timeout_for_runtime(
            request.renderer,
            runtime.studio_runtime_provenance().kind,
        )
        .unwrap_or_default();
        let orchestration_slack = Duration::from_secs(5);
        return authoring_budget
            .saturating_add(render_eval_budget)
            .saturating_add(orchestration_slack);
    }

    studio_generation_timeout_for_request(request, runtime)
}

fn studio_modal_first_html_enabled_for_request(request: &StudioOutcomeArtifactRequest) -> bool {
    request.renderer == StudioRendererKind::HtmlIframe
        && ioi_api::studio::studio_modal_first_html_enabled_for_tests_and_runtime()
}

fn studio_extended_local_html_timeout_enabled(
    request: &StudioOutcomeArtifactRequest,
    runtime_profile: StudioArtifactRuntimePolicyProfile,
) -> bool {
    studio_modal_first_html_enabled_for_request(request)
        && matches!(
            runtime_profile,
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                | StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
        )
}

fn configured_studio_runtime_profile() -> StudioArtifactRuntimePolicyProfile {
    [
        "AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE",
        "IOI_STUDIO_MODEL_ROUTING_PROFILE",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .as_deref()
            .and_then(StudioArtifactRuntimePolicyProfile::parse)
    })
    .unwrap_or(StudioArtifactRuntimePolicyProfile::Auto)
}

fn format_generation_timeout(timeout: Duration) -> String {
    if timeout.as_secs() > 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
}

async fn await_generation_with_activity_timeout<T, F>(
    future: F,
    inactivity_timeout: Duration,
    last_activity: Arc<Mutex<Instant>>,
) -> Result<T, Duration>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(future);

    let poll_interval = if inactivity_timeout.is_zero() {
        Duration::from_millis(1)
    } else {
        std::cmp::min(Duration::from_millis(250), inactivity_timeout)
    };
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            output = &mut future => return Ok(output),
            _ = ticker.tick() => {
                let idle_for = last_activity
                    .lock()
                    .map(|instant| instant.elapsed())
                    .unwrap_or(inactivity_timeout);
                if idle_for >= inactivity_timeout {
                    return Err(idle_for);
                }
            }
        }
    }
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies_and_timeout(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    generation_timeout: Duration,
    planning_context: Option<StudioArtifactPlanningContext>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_dependencies_and_timeout_and_execution_strategy(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        generation_timeout,
        planning_context,
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(request)),
        None,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies_and_timeout_and_execution_strategy(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    generation_timeout: Duration,
    planning_context: Option<StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_non_workspace_artifact_with_dependencies_and_timeout_and_execution_strategy_and_render_evaluator(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        generation_timeout,
        planning_context,
        execution_strategy,
        progress_observer,
        None,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies_and_timeout_and_execution_strategy_and_render_evaluator(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    generation_timeout: Duration,
    planning_context: Option<StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
    render_evaluator_override: Option<&dyn StudioArtifactRenderEvaluator>,
) -> Result<MaterializedContentArtifact, String> {
    studio_proof_trace(format!(
        "materialize_non_workspace:start renderer={} strategy={:?} title={}",
        renderer_kind_id(request.renderer),
        execution_strategy,
        title
    ));
    let runtime_profile = configured_studio_runtime_profile();
    let prepared_context = match planning_context {
        Some(context) => context,
        None => {
            let Some(runtime) = inference_runtime.as_ref() else {
                return Ok(blocked_materialized_artifact_from_error(
                    title,
                    intent,
                    request,
                    refinement,
                    "Prepared artifact context is unavailable because no inference runtime is available for synthesis.",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    None,
                    Vec::new(),
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                    acceptance_inference_runtime
                        .as_ref()
                        .map(|candidate| candidate.studio_runtime_provenance()),
                ));
            };
            let runtime_plan = resolve_studio_artifact_runtime_plan(
                request,
                runtime.clone(),
                acceptance_inference_runtime.clone(),
                runtime_profile,
            );
            match synthesize_prepared_context_with_runtime_plan(
                &runtime_plan,
                title,
                intent,
                request,
                refinement,
                execution_strategy,
            ) {
                Ok(context) => context,
                Err(message) => {
                    return Ok(blocked_materialized_artifact_from_error(
                        title,
                        intent,
                        request,
                        refinement,
                        &message,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        refinement
                            .map(|context| context.selected_skills.clone())
                            .unwrap_or_default(),
                        refinement
                            .map(|context| context.retrieved_exemplars.clone())
                            .unwrap_or_default(),
                        None,
                        Vec::new(),
                        None,
                        None,
                        None,
                        Vec::new(),
                        Some(runtime.studio_runtime_provenance()),
                        acceptance_inference_runtime
                            .as_ref()
                            .map(|candidate| candidate.studio_runtime_provenance()),
                    ));
                }
            }
        }
    };
    emit_prepared_context_generation_progress(
        progress_observer.as_ref(),
        &prepared_context,
        execution_strategy,
    );
    let mut observed_runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>;
    let bundle = match inference_runtime {
        Some(runtime) => {
            let runtime_plan = resolve_studio_artifact_runtime_plan(
                request,
                runtime,
                acceptance_inference_runtime.clone(),
                runtime_profile,
            );
            let generation_runtime = runtime_plan.generation_runtime.clone();
            let acceptance_runtime = runtime_plan.acceptance_runtime.clone();
            let default_render_evaluator = BrowserStudioArtifactRenderEvaluator::default();
            let render_evaluator =
                render_evaluator_override.unwrap_or(&default_render_evaluator);
            let production_provenance = runtime_plan.generation_runtime.studio_runtime_provenance();
            let acceptance_provenance =
                runtime_plan.acceptance_runtime.studio_runtime_provenance();
            let last_activity = Arc::new(Mutex::new(Instant::now()));
            let last_progress_snapshot =
                Arc::new(Mutex::new(None::<StudioArtifactGenerationProgress>));
            let observed_runtime_narration_events_state = Arc::new(Mutex::new(
                Vec::<StudioArtifactRuntimeNarrationEvent>::new(),
            ));
            let observed_progress = progress_observer.as_ref().map(|observer| {
                let observer = observer.clone();
                let last_activity = last_activity.clone();
                let last_progress_snapshot = last_progress_snapshot.clone();
                let observed_runtime_narration_events_state =
                    observed_runtime_narration_events_state.clone();
                Arc::new(move |progress: StudioArtifactGenerationProgress| {
                    if let Ok(mut activity) = last_activity.lock() {
                        *activity = Instant::now();
                    }
                    if let Ok(mut events) = observed_runtime_narration_events_state.lock() {
                        merge_runtime_narration_events(
                            &mut events,
                            &progress.runtime_narration_events,
                        );
                    }
                    if let Ok(mut snapshot) = last_progress_snapshot.lock() {
                        *snapshot = Some(progress.clone());
                    }
                    observer(progress);
                }) as StudioArtifactGenerationProgressObserver
            });
            let activity_observer = {
                let last_activity = last_activity.clone();
                Arc::new(move || {
                    if let Ok(mut activity) = last_activity.lock() {
                        *activity = Instant::now();
                    }
                }) as StudioArtifactActivityObserver
            };
            match tauri::async_runtime::block_on(async {
                await_generation_with_activity_timeout(
                    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                        runtime_plan,
                        title,
                        intent,
                        request,
                        refinement,
                        &prepared_context,
                        execution_strategy,
                        Some(render_evaluator),
                        observed_progress,
                        Some(activity_observer),
                    ),
                    generation_timeout,
                    last_activity,
                ).await
            }) {
                Ok(Ok(bundle)) => {
                    observed_runtime_narration_events = observed_runtime_narration_events_state
                        .lock()
                        .map(|events| events.clone())
                        .unwrap_or_default();
                    if !observed_runtime_narration_events.iter().any(|event| {
                        event.step_id == "present_artifact"
                            && event.status.eq_ignore_ascii_case("complete")
                    }) {
                        observed_runtime_narration_events.push(present_artifact_complete_event());
                    }
                    if let Some(observer) = progress_observer.as_ref() {
                        observer(StudioArtifactGenerationProgress {
                            current_step: "Artifact ready to present.".to_string(),
                            artifact_brief: Some(prepared_context.brief.clone()),
                            preparation_needs: prepared_context.preparation_needs.clone(),
                            prepared_context_resolution: prepared_context
                                .prepared_context_resolution
                                .clone(),
                            skill_discovery_resolution: prepared_context
                                .skill_discovery_resolution
                                .clone(),
                            blueprint: bundle.blueprint.clone(),
                            artifact_ir: bundle.artifact_ir.clone(),
                            selected_skills: bundle.selected_skills.clone(),
                            retrieved_exemplars: prepared_context.retrieved_exemplars.clone(),
                            execution_envelope: bundle.execution_envelope.clone(),
                            swarm_plan: bundle.swarm_plan.clone(),
                            swarm_execution: bundle.swarm_execution.clone(),
                            swarm_worker_receipts: bundle.swarm_worker_receipts.clone(),
                            swarm_change_receipts: bundle.swarm_change_receipts.clone(),
                            swarm_merge_receipts: bundle.swarm_merge_receipts.clone(),
                            swarm_verification_receipts: bundle.swarm_verification_receipts.clone(),
                            render_evaluation: bundle.render_evaluation.clone(),
                            judge: Some(bundle.judge.clone()),
                            runtime_narration_events: vec![present_artifact_complete_event()],
                        });
                    }
                    studio_proof_trace(format!(
                        "materialize_non_workspace:bundle_ready winner={} lifecycle={:?} fallback_used={}",
                        bundle
                            .winning_candidate_id
                            .clone()
                            .unwrap_or_else(|| "swarm-merged".to_string()),
                        bundle.ux_lifecycle,
                        bundle.fallback_used
                    ));
                    bundle
                }
                Ok(Err(error)) => {
                    let last_progress = last_progress_snapshot
                        .lock()
                        .ok()
                        .and_then(|snapshot| snapshot.clone());
                    studio_proof_trace(format!(
                        "materialize_non_workspace:bundle_blocked {}",
                        error.message
                    ));
                    if execution_strategy == StudioExecutionStrategy::DirectAuthor
                        && direct_author_error_requires_replan(&error.message)
                    {
                        let terminalized_execution_envelope = finalize_latest_execution_preview(
                            last_progress
                                .as_ref()
                                .and_then(|progress| progress.execution_envelope.clone()),
                        );
                        let stalled_attempt_id = last_progress.as_ref().and_then(|progress| {
                            progress
                                .runtime_narration_events
                                .iter()
                                .rev()
                                .find(|event| {
                                    event.step_id == "author_artifact"
                                        && event.attempt_id.is_some()
                                })
                                .and_then(|event| event.attempt_id.clone())
                        });
                        let author_blocked_event = author_artifact_blocked_event(
                            stalled_attempt_id,
                            "Direct author hit a bounded model timeout. Replanning artifact execution.",
                        );
                        let replan_event = replan_execution_event(
                            StudioExecutionStrategy::DirectAuthor,
                            StudioExecutionStrategy::PlanExecute,
                        );
                        let mut prior_runtime_narration_events = last_progress
                            .as_ref()
                            .map(|progress| progress.runtime_narration_events.clone())
                            .unwrap_or_default();
                        append_blocked_preview_runtime_event(
                            &mut prior_runtime_narration_events,
                            terminalized_execution_envelope.as_ref(),
                        );
                        merge_runtime_narration_events(
                            &mut prior_runtime_narration_events,
                            &[author_blocked_event.clone(), replan_event.clone()],
                        );
                        if let Some(observer) = progress_observer.as_ref() {
                            observer(StudioArtifactGenerationProgress {
                                current_step:
                                    "Direct author timed out. Replanning artifact execution."
                                        .to_string(),
                                artifact_brief: Some(prepared_context.brief.clone()),
                                preparation_needs: prepared_context.preparation_needs.clone(),
                                prepared_context_resolution: prepared_context
                                    .prepared_context_resolution
                                    .clone(),
                                skill_discovery_resolution: prepared_context
                                    .skill_discovery_resolution
                                    .clone(),
                                blueprint: prepared_context.blueprint.clone(),
                                artifact_ir: prepared_context.artifact_ir.clone(),
                                selected_skills: prepared_context.selected_skills.clone(),
                                retrieved_exemplars: prepared_context
                                    .retrieved_exemplars
                                    .clone(),
                                execution_envelope: terminalized_execution_envelope,
                                swarm_plan: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.swarm_plan.clone()),
                                swarm_execution: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.swarm_execution.clone()),
                                swarm_worker_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_worker_receipts.clone())
                                    .unwrap_or_default(),
                                swarm_change_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_change_receipts.clone())
                                    .unwrap_or_default(),
                                swarm_merge_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_merge_receipts.clone())
                                    .unwrap_or_default(),
                                swarm_verification_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_verification_receipts.clone())
                                    .unwrap_or_default(),
                                render_evaluation: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.render_evaluation.clone()),
                                judge: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.judge.clone()),
                                runtime_narration_events: vec![
                                    author_blocked_event,
                                    replan_event.clone(),
                                ],
                            });
                        }
                        let mut replanned =
                            materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
                            memory_runtime,
                            Some(generation_runtime),
                            Some(acceptance_runtime),
                            thread_id,
                            title,
                            intent,
                            request,
                            refinement,
                            Some(prepared_context.clone()),
                            StudioExecutionStrategy::PlanExecute,
                            progress_observer.clone(),
                        )?;
                        merge_runtime_narration_events(
                            &mut prior_runtime_narration_events,
                            &replanned.runtime_narration_events,
                        );
                        replanned.runtime_narration_events = prior_runtime_narration_events;
                        return Ok(replanned);
                    }
                    return Ok(blocked_materialized_artifact_from_error(
                        title,
                        intent,
                        request,
                        refinement,
                        &error.message,
                        error.brief,
                        prepared_context.preparation_needs.clone(),
                        prepared_context.prepared_context_resolution.clone(),
                        prepared_context.skill_discovery_resolution.clone(),
                        error.blueprint,
                        error.artifact_ir,
                        error.selected_skills,
                        prepared_context.retrieved_exemplars.clone(),
                        error.edit_intent,
                        error.candidate_summaries,
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.execution_envelope.clone()),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.render_evaluation.clone()),
                        last_progress.as_ref().and_then(|progress| progress.judge.clone()),
                        last_progress
                            .as_ref()
                            .map(|progress| progress.runtime_narration_events.clone())
                            .unwrap_or_default(),
                        Some(production_provenance),
                        Some(acceptance_provenance),
                    ));
                }
                Err(idle_for) => {
                    let message = format!(
                        "Studio artifact generation timed out after {} of inactivity while {}.",
                        format_generation_timeout(idle_for),
                        if execution_strategy == StudioExecutionStrategy::DirectAuthor {
                            "authoring the artifact directly"
                        } else {
                            "running the artifact execution plan"
                        }
                    );
                    studio_proof_trace(format!(
                        "materialize_non_workspace:bundle_timeout {}",
                        message
                    ));
                    let last_progress = last_progress_snapshot
                        .lock()
                        .ok()
                        .and_then(|snapshot| snapshot.clone());
                    if execution_strategy == StudioExecutionStrategy::DirectAuthor {
                        let terminalized_execution_envelope = finalize_latest_execution_preview(
                            last_progress
                                .as_ref()
                                .and_then(|progress| progress.execution_envelope.clone()),
                        );
                        let stalled_attempt_id = last_progress.as_ref().and_then(|progress| {
                            progress
                                .runtime_narration_events
                                .iter()
                                .rev()
                                .find(|event| {
                                    event.step_id == "author_artifact"
                                        && event.attempt_id.is_some()
                                })
                                .and_then(|event| event.attempt_id.clone())
                        });
                        let author_blocked_event = author_artifact_blocked_event(
                            stalled_attempt_id,
                            format!(
                                "Direct author stalled after {} without producing enough activity to finish this attempt.",
                                format_generation_timeout(idle_for)
                            ),
                        );
                        let replan_event = replan_execution_event(
                            StudioExecutionStrategy::DirectAuthor,
                            StudioExecutionStrategy::PlanExecute,
                        );
                        let mut prior_runtime_narration_events = last_progress
                            .as_ref()
                            .map(|progress| progress.runtime_narration_events.clone())
                            .unwrap_or_default();
                        append_blocked_preview_runtime_event(
                            &mut prior_runtime_narration_events,
                            terminalized_execution_envelope.as_ref(),
                        );
                        merge_runtime_narration_events(
                            &mut prior_runtime_narration_events,
                            &[author_blocked_event.clone(), replan_event.clone()],
                        );
                        if let Some(observer) = progress_observer.as_ref() {
                            observer(StudioArtifactGenerationProgress {
                                current_step:
                                    "Direct author stalled. Replanning artifact execution."
                                        .to_string(),
                                artifact_brief: Some(prepared_context.brief.clone()),
                                preparation_needs: prepared_context.preparation_needs.clone(),
                                prepared_context_resolution: prepared_context
                                    .prepared_context_resolution
                                    .clone(),
                                skill_discovery_resolution: prepared_context
                                    .skill_discovery_resolution
                                    .clone(),
                                blueprint: prepared_context.blueprint.clone(),
                                artifact_ir: prepared_context.artifact_ir.clone(),
                                selected_skills: prepared_context.selected_skills.clone(),
                                retrieved_exemplars: prepared_context
                                    .retrieved_exemplars
                                    .clone(),
                                execution_envelope: terminalized_execution_envelope,
                                swarm_plan: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.swarm_plan.clone()),
                                swarm_execution: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.swarm_execution.clone()),
                                swarm_worker_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_worker_receipts.clone())
                                    .unwrap_or_default(),
                                swarm_change_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_change_receipts.clone())
                                    .unwrap_or_default(),
                                swarm_merge_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_merge_receipts.clone())
                                    .unwrap_or_default(),
                                swarm_verification_receipts: last_progress
                                    .as_ref()
                                    .map(|progress| progress.swarm_verification_receipts.clone())
                                    .unwrap_or_default(),
                                render_evaluation: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.render_evaluation.clone()),
                                judge: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.judge.clone()),
                                runtime_narration_events: vec![
                                    author_blocked_event,
                                    replan_event.clone(),
                                ],
                            });
                        }
                        let mut replanned =
                            materialize_non_workspace_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
                            memory_runtime,
                            Some(generation_runtime),
                            Some(acceptance_runtime),
                            thread_id,
                            title,
                            intent,
                            request,
                            refinement,
                            Some(prepared_context.clone()),
                            StudioExecutionStrategy::PlanExecute,
                            progress_observer.clone(),
                        )?;
                        merge_runtime_narration_events(
                            &mut prior_runtime_narration_events,
                            &replanned.runtime_narration_events,
                        );
                        replanned.runtime_narration_events = prior_runtime_narration_events;
                        return Ok(replanned);
                    }
                    return Ok(blocked_materialized_artifact_from_error(
                        title,
                        intent,
                        request,
                        refinement,
                        &message,
                        None,
                        prepared_context.preparation_needs.clone(),
                        prepared_context.prepared_context_resolution.clone(),
                        prepared_context.skill_discovery_resolution.clone(),
                        prepared_context.blueprint.clone(),
                        prepared_context.artifact_ir.clone(),
                        prepared_context.selected_skills.clone(),
                        prepared_context.retrieved_exemplars.clone(),
                        None,
                        Vec::new(),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.execution_envelope.clone()),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.render_evaluation.clone()),
                        last_progress.as_ref().and_then(|progress| progress.judge.clone()),
                        {
                            let mut events = last_progress
                                .as_ref()
                                .map(|progress| progress.runtime_narration_events.clone())
                                .unwrap_or_default();
                            events.push(present_artifact_blocked_event(&message));
                            events
                        },
                        Some(production_provenance),
                        Some(acceptance_provenance),
                    ));
                }
            }
        }
        None if acceptance_inference_runtime.is_some() => {
            let acceptance_provenance = acceptance_inference_runtime
                .as_ref()
                .map(|runtime| runtime.studio_runtime_provenance());
            return Ok(blocked_materialized_artifact_from_error(
                title,
                intent,
                request,
                refinement,
                "Inference runtime is unavailable for Studio artifact materialization.",
                None,
                prepared_context.preparation_needs.clone(),
                prepared_context.prepared_context_resolution.clone(),
                prepared_context.skill_discovery_resolution.clone(),
                prepared_context.blueprint.clone(),
                prepared_context.artifact_ir.clone(),
                prepared_context.selected_skills.clone(),
                prepared_context.retrieved_exemplars.clone(),
                None,
                Vec::new(),
                None,
                None,
                None,
                Vec::new(),
                None,
                acceptance_provenance,
            ));
        }
        None => {
            return Ok(blocked_materialized_artifact_from_error(
                title,
                intent,
                request,
                refinement,
                "Inference and acceptance runtimes are unavailable for Studio artifact materialization.",
                None,
                prepared_context.preparation_needs.clone(),
                prepared_context.prepared_context_resolution.clone(),
                prepared_context.skill_discovery_resolution.clone(),
                prepared_context.blueprint.clone(),
                prepared_context.artifact_ir.clone(),
                prepared_context.selected_skills.clone(),
                prepared_context.retrieved_exemplars.clone(),
                None,
                Vec::new(),
                None,
                None,
                None,
                Vec::new(),
                None,
                None,
            ))
        }
    };
    let bundle_edit_intent = bundle.edit_intent.clone();
    let derived_taste_memory = derive_studio_taste_memory(
        refinement.and_then(|context| context.taste_memory.as_ref()),
        &bundle.brief,
        bundle.blueprint.as_ref(),
        bundle.artifact_ir.as_ref(),
        bundle_edit_intent.as_ref(),
        Some(&bundle.judge),
    );
    let retrieved_exemplars = Some(prepared_context.retrieved_exemplars.clone())
        .filter(|exemplars| !exemplars.is_empty())
        .or_else(|| refinement.map(|context| context.retrieved_exemplars.clone()))
        .unwrap_or_default();
    let selected_targets = bundle_edit_intent
        .as_ref()
        .map(|edit_intent| edit_intent.selected_targets.clone())
        .filter(|targets| !targets.is_empty())
        .or_else(|| refinement.map(|context| context.selected_targets.clone()))
        .unwrap_or_default();
    let generated = bundle.winner.clone();
    let output_origin = bundle.origin;
    let fallback_used = bundle.fallback_used;

    let mut artifacts = Vec::new();
    let mut files = Vec::new();
    let mut file_writes = Vec::new();
    let mut quality_files = Vec::new();

    for generated_file in generated.files.clone() {
        studio_proof_trace(format!(
            "materialize_non_workspace:file {} mime={} renderable={} bytes={}",
            generated_file.path,
            generated_file.mime,
            generated_file.renderable,
            generated_file.body.len()
        ));
        quality_files.push(MaterializedArtifactQualityFile {
            path: generated_file.path.clone(),
            mime: generated_file.mime.clone(),
            renderable: generated_file.renderable,
            downloadable: generated_file.downloadable,
            text_content: generated_file_text_content(&generated_file),
        });
        let bytes = generated_file_bytes(title, request, &generated_file)?;
        let artifact = artifact_store::create_named_file_artifact(
            memory_runtime,
            thread_id,
            &generated_file.path,
            Some(&generated_file.mime),
            None,
            &bytes,
        );
        file_writes.push(StudioArtifactMaterializationFileWrite {
            path: generated_file.path.clone(),
            kind: format!("{:?}", generated_file.role).to_lowercase(),
            content_preview: generated_file_preview(&generated_file),
        });
        files.push(StudioArtifactManifestFile {
            path: generated_file.path.clone(),
            mime: generated_file.mime.clone(),
            role: generated_file.role,
            renderable: generated_file.renderable,
            downloadable: generated_file.downloadable,
            artifact_id: Some(artifact.artifact_id.clone()),
            external_url: None,
        });
        artifacts.push(artifact);
    }

    studio_proof_trace(format!(
        "materialize_non_workspace:files_persisted count={}",
        files.len()
    ));
    let quality_assessment = finalize_presentation_assessment(
        request,
        assess_materialized_artifact_presentation(request, &quality_files),
        &bundle.judge,
        bundle.render_evaluation.as_ref(),
        fallback_used,
        bundle.ux_lifecycle == StudioArtifactUxLifecycle::Draft,
    );
    studio_proof_trace(format!(
        "materialize_non_workspace:quality lifecycle={:?} summary={}",
        quality_assessment.lifecycle_state, quality_assessment.summary
    ));

    let mut notes = generated.notes.clone();
    notes.extend(quality_assessment.findings.iter().cloned());
    if !bundle.selected_skills.is_empty() {
        notes.push(format!(
            "Applied {} registry-backed skill guide(s) during artifact planning.",
            bundle.selected_skills.len()
        ));
    }
    if !retrieved_exemplars.is_empty() {
        notes.push(format!(
            "Grounded generation with {} high-scoring exemplar artifact(s).",
            retrieved_exemplars.len()
        ));
    }
    if let Some(swarm_execution) = bundle.swarm_execution.as_ref() {
        notes.push(format!(
            "Swarm execution completed {}/{} work item(s) via {}.",
            swarm_execution.completed_work_items,
            swarm_execution.total_work_items,
            swarm_execution.adapter_label
        ));
    } else if let Some(winner_id) = bundle.winning_candidate_id.as_ref() {
        notes.push(format!(
            "Winning candidate {} selected via typed judging.",
            winner_id
        ));
    }

    studio_proof_trace("materialize_non_workspace:return");
    Ok(MaterializedContentArtifact {
        artifacts,
        files,
        file_writes,
        notes,
        brief: bundle.brief,
        preparation_needs: prepared_context.preparation_needs.clone(),
        prepared_context_resolution: prepared_context.prepared_context_resolution.clone(),
        skill_discovery_resolution: prepared_context.skill_discovery_resolution.clone(),
        blueprint: bundle.blueprint,
        artifact_ir: bundle.artifact_ir,
        selected_skills: bundle.selected_skills,
        retrieved_exemplars,
        edit_intent: bundle_edit_intent.clone(),
        candidate_summaries: bundle.candidate_summaries,
        winning_candidate_id: bundle.winning_candidate_id,
        winning_candidate_rationale: bundle.winning_candidate_rationale,
        execution_envelope: bundle.execution_envelope,
        swarm_plan: bundle.swarm_plan,
        swarm_execution: bundle.swarm_execution,
        swarm_worker_receipts: bundle.swarm_worker_receipts,
        swarm_change_receipts: bundle.swarm_change_receipts,
        swarm_merge_receipts: bundle.swarm_merge_receipts,
        swarm_verification_receipts: bundle.swarm_verification_receipts,
        render_evaluation: bundle.render_evaluation,
        judge: Some(bundle.judge),
        output_origin,
        production_provenance: Some(bundle.production_provenance),
        acceptance_provenance: Some(bundle.acceptance_provenance),
        fallback_used,
        ux_lifecycle: if fallback_used {
            StudioArtifactUxLifecycle::Draft
        } else if bundle_edit_intent
            .as_ref()
            .is_some_and(|edit_intent| edit_intent.patch_existing_artifact)
        {
            StudioArtifactUxLifecycle::Locked
        } else {
            bundle.ux_lifecycle
        },
        failure: bundle.failure,
        taste_memory: derived_taste_memory.or(bundle.taste_memory),
        selected_targets,
        lifecycle_state: quality_assessment.lifecycle_state,
        verification_summary: quality_assessment.summary,
        runtime_narration_events: observed_runtime_narration_events,
    })
}

pub(super) fn blocked_materialized_artifact_from_error(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    error: &str,
    artifact_brief: Option<StudioArtifactBrief>,
    preparation_needs: Option<ioi_api::studio::StudioArtifactPreparationNeeds>,
    prepared_context_resolution: Option<ioi_api::studio::StudioArtifactPreparedContextResolution>,
    skill_discovery_resolution: Option<ioi_api::studio::StudioArtifactSkillDiscoveryResolution>,
    blueprint: Option<StudioArtifactBlueprint>,
    artifact_ir: Option<StudioArtifactIR>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
    retrieved_exemplars: Vec<StudioArtifactExemplar>,
    edit_intent: Option<StudioArtifactEditIntent>,
    candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    execution_envelope: Option<ExecutionEnvelope>,
    render_evaluation: Option<StudioArtifactRenderEvaluation>,
    _last_judge: Option<StudioArtifactJudgeResult>,
    mut runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>,
    production_runtime_provenance: Option<crate::models::StudioRuntimeProvenance>,
    acceptance_runtime_provenance: Option<crate::models::StudioRuntimeProvenance>,
) -> MaterializedContentArtifact {
    let production_provenance =
        production_runtime_provenance.unwrap_or(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    let acceptance_provenance =
        acceptance_runtime_provenance.unwrap_or(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    let failure_kind = if production_provenance.kind
        == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
        || acceptance_provenance.kind
            == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
    {
        crate::models::StudioArtifactFailureKind::InferenceUnavailable
    } else {
        crate::models::StudioArtifactFailureKind::GenerationFailure
    };
    let failure = crate::models::StudioArtifactFailure {
        kind: failure_kind,
        code: match failure_kind {
            crate::models::StudioArtifactFailureKind::InferenceUnavailable => {
                "inference_unavailable"
            }
            crate::models::StudioArtifactFailureKind::RoutingFailure => "routing_failure",
            crate::models::StudioArtifactFailureKind::GenerationFailure => "generation_failure",
            crate::models::StudioArtifactFailureKind::VerificationFailure => "verification_failure",
        }
        .to_string(),
        message: error.to_string(),
    };
    let judge = StudioArtifactJudgeResult {
        classification: ioi_api::studio::StudioArtifactJudgeClassification::Blocked,
        request_faithfulness: 1,
        concept_coverage: 1,
        interaction_relevance: 1,
        layout_coherence: 1,
        visual_hierarchy: 1,
        completeness: 1,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: false,
        patched_existing_artifact: refinement.map(|_| false),
        continuity_revision_ux: refinement.map(|_| 1),
        issue_classes: vec![failure.code.clone()],
        repair_hints: vec![
            "Restore runtime availability or repair the failing generation path before retrying the artifact."
                .to_string(),
        ],
        strengths: Vec::new(),
        blocked_reasons: vec![error.to_string()],
        file_findings: Vec::new(),
        aesthetic_verdict: "not_evaluated_due_to_generation_failure".to_string(),
        interaction_verdict: "not_evaluated_due_to_generation_failure".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("generation_retry".to_string()),
        strongest_contradiction: Some(error.to_string()),
        rationale: error.to_string(),
    };
    let execution_envelope = finalize_blocked_execution_envelope(execution_envelope);
    append_blocked_preview_runtime_event(
        &mut runtime_narration_events,
        execution_envelope.as_ref(),
    );
    if !runtime_narration_events.iter().any(|event| {
        event.step_id == "present_artifact" && event.status.eq_ignore_ascii_case("blocked")
    }) {
        runtime_narration_events.push(present_artifact_blocked_event(error));
    }

    MaterializedContentArtifact {
        artifacts: Vec::new(),
        files: Vec::new(),
        file_writes: Vec::new(),
        notes: vec![
            "Studio refused to substitute mock or deterministic output for a failed non-workspace artifact generation."
                .to_string(),
            error.to_string(),
        ],
        brief: artifact_brief.unwrap_or_else(|| {
            blocked_failure_brief(
                title,
                intent,
                request.renderer,
                error,
                refinement
                    .and_then(|context| context.taste_memory.as_ref())
                    .map(|memory| memory.directives.clone())
                .unwrap_or_default(),
            )
        }),
        preparation_needs,
        prepared_context_resolution,
        skill_discovery_resolution,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars: if retrieved_exemplars.is_empty() {
            refinement
                .map(|context| context.retrieved_exemplars.clone())
                .unwrap_or_default()
        } else {
            retrieved_exemplars
        },
        edit_intent,
        candidate_summaries,
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation,
        judge: Some(judge),
        output_origin: output_origin_from_runtime_provenance(&production_provenance),
        production_provenance: Some(production_provenance),
        acceptance_provenance: Some(acceptance_provenance),
        fallback_used: false,
        ux_lifecycle: StudioArtifactUxLifecycle::Draft,
        failure: Some(failure),
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        selected_targets: refinement
            .map(|context| context.selected_targets.clone())
            .unwrap_or_default(),
        lifecycle_state: StudioArtifactLifecycleState::Blocked,
        verification_summary: error.to_string(),
        runtime_narration_events,
    }
}

pub(super) fn blocked_failure_brief(
    title: &str,
    intent: &str,
    renderer: StudioRendererKind,
    failure_message: &str,
    reference_hints: Vec<String>,
) -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "artifact operators".to_string(),
        job_to_be_done: "surface the generation failure truthfully".to_string(),
        subject_domain: title.to_string(),
        artifact_thesis: intent.to_string(),
        required_concepts: vec![renderer_kind_id(renderer).to_string()],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: vec!["truthful failure".to_string()],
        factual_anchors: vec![failure_message.to_string()],
        style_directives: Vec::new(),
        reference_hints,
    }
}

pub(super) fn output_origin_from_runtime_provenance(
    provenance: &crate::models::StudioRuntimeProvenance,
) -> StudioArtifactOutputOrigin {
    match provenance.kind {
        crate::models::StudioRuntimeProvenanceKind::RealRemoteModelRuntime
        | crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime => {
            StudioArtifactOutputOrigin::LiveInference
        }
        crate::models::StudioRuntimeProvenanceKind::FixtureRuntime => {
            StudioArtifactOutputOrigin::FixtureRuntime
        }
        crate::models::StudioRuntimeProvenanceKind::MockRuntime => {
            StudioArtifactOutputOrigin::MockInference
        }
        crate::models::StudioRuntimeProvenanceKind::DeterministicContinuityFallback => {
            StudioArtifactOutputOrigin::DeterministicFallback
        }
        crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable => {
            StudioArtifactOutputOrigin::InferenceUnavailable
        }
        crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime => {
            StudioArtifactOutputOrigin::OpaqueRuntime
        }
    }
}

#[cfg(test)]
pub(super) fn generate_non_workspace_artifact_payload(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let runtime = inference_runtime.ok_or_else(|| {
        "Inference runtime is unavailable for Studio artifact materialization.".to_string()
    })?;
    tauri::async_runtime::block_on(materialize_studio_artifact_with_runtime(
        runtime, title, intent, request,
    ))
}

#[cfg(test)]
pub(super) fn generated_quality_files(
    payload: &StudioGeneratedArtifactPayload,
) -> Vec<MaterializedArtifactQualityFile> {
    payload
        .files
        .iter()
        .map(|file| MaterializedArtifactQualityFile {
            path: file.path.clone(),
            mime: file.mime.clone(),
            renderable: file.renderable,
            downloadable: file.downloadable,
            text_content: generated_file_text_content(file),
        })
        .collect()
}

pub(super) fn derive_artifact_title(intent: &str) -> String {
    let trimmed = intent.trim();
    let primary = trimmed
        .split(['.', '\n', ':'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    if primary.is_empty() {
        return "Studio artifact".to_string();
    }

    let title = primary;
    if title.len() <= 68 {
        title.to_string()
    } else {
        format!("{}...", &title[..65])
    }
}

pub(super) fn create_contract_artifact_for_memory_runtime(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    contract: &StudioArtifactMaterializationContract,
) -> Artifact {
    artifact_store::create_report_artifact(
        memory_runtime,
        thread_id,
        &format!("Studio artifact: {}", title),
        "Machine-routable Studio artifact materialization contract",
        &serde_json::to_value(contract).unwrap_or_else(|_| json!({})),
    )
}

pub(super) fn create_contract_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    contract: &StudioArtifactMaterializationContract,
) -> Option<Artifact> {
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.memory_runtime.clone())?;
    Some(create_contract_artifact_for_memory_runtime(
        &memory_runtime,
        thread_id,
        title,
        contract,
    ))
}

pub(super) fn create_receipt_report_artifact_for_memory_runtime(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    receipt: &StudioBuildReceipt,
) -> Artifact {
    artifact_store::create_report_artifact(
        memory_runtime,
        thread_id,
        &format!("{} · {}", title, receipt.title),
        "Studio build receipt",
        &serde_json::to_value(receipt).unwrap_or_else(|_| json!({})),
    )
}

pub(super) fn create_receipt_report_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    receipt: &StudioBuildReceipt,
) -> Option<Artifact> {
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.memory_runtime.clone())?;
    Some(create_receipt_report_artifact_for_memory_runtime(
        &memory_runtime,
        thread_id,
        title,
        receipt,
    ))
}

pub(super) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
