use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_api::execution::{execution_budget_envelope_for_strategy, ExecutionEnvelope};
use ioi_api::runtime_harness::{
    derive_chat_artifact_prepared_context, derive_request_grounded_chat_artifact_brief,
    extract_user_request_from_contextualized_intent,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator,
    pdf_artifact_bytes, render_eval_timeout_for_runtime, resolve_chat_artifact_runtime_plan,
    synthesize_chat_artifact_brief_for_execution_strategy_with_runtime, ArtifactOperatorPhase,
    ArtifactOperatorRunStatus, ArtifactOperatorStep,
    ArtifactPlanningContext as ChatArtifactPlanningContext,
    ArtifactRenderEvaluation as ChatArtifactRenderEvaluation, ChatArtifactActivityObserver,
    ChatArtifactBlueprint, ChatArtifactExemplar, ChatArtifactGenerationProgress,
    ChatArtifactGenerationProgressObserver, ChatArtifactIR, ChatArtifactOperatorPreview,
    ChatArtifactRenderEvaluator, ChatArtifactRuntimePolicyProfile, ChatArtifactSelectedSkill,
    ChatGeneratedArtifactEncoding, ChatGeneratedArtifactFile,
};
use ioi_drivers::chat_render::BrowserChatArtifactRenderEvaluator;
use ioi_types::app::ChatExecutionStrategy;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::MissedTickBehavior;

#[cfg(test)]
use ioi_api::runtime_harness::ChatGeneratedArtifactPayload;

#[path = "materialization/progress_steps.rs"]
mod progress_steps;

use progress_steps::{
    chat_proof_trace, direct_author_blocked_step, direct_author_error_requires_replan,
    emit_prepared_context_generation_progress, finalize_blocked_execution_envelope,
    finalize_latest_execution_preview, latest_author_attempt_id, latest_execution_live_preview,
    merge_operator_steps, present_artifact_blocked_step, present_artifact_complete_step,
    replan_execution_step,
};

const LOCAL_HTML_GENERATION_TIMEOUT_SECS: u64 = 420;
const LOCAL_HTML_SPLIT_ACCEPTANCE_TIMEOUT_SECS: u64 = 1200;

fn generated_file_is_binary(file: &ChatGeneratedArtifactFile) -> bool {
    matches!(file.encoding, Some(ChatGeneratedArtifactEncoding::Base64))
}

fn generated_file_text_content(file: &ChatGeneratedArtifactFile) -> Option<String> {
    (!generated_file_is_binary(file)).then(|| file.body.clone())
}

fn generated_file_preview(file: &ChatGeneratedArtifactFile) -> Option<String> {
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
    request: &ChatOutcomeArtifactRequest,
    file: &ChatGeneratedArtifactFile,
) -> Result<Vec<u8>, String> {
    if request.renderer == ChatRendererKind::PdfEmbed && file.path.ends_with(".pdf") {
        return Ok(pdf_artifact_bytes(title, &file.body));
    }

    match file.encoding.unwrap_or(ChatGeneratedArtifactEncoding::Utf8) {
        ChatGeneratedArtifactEncoding::Utf8 => Ok(file.body.as_bytes().to_vec()),
        ChatGeneratedArtifactEncoding::Base64 => {
            STANDARD.decode(file.body.trim()).map_err(|error| {
                format!(
                    "Failed to decode binary Chat artifact {} as base64: {}",
                    file.path, error
                )
            })
        }
    }
}

fn execution_strategy_id(strategy: ChatExecutionStrategy) -> &'static str {
    match strategy {
        ChatExecutionStrategy::SinglePass => "single_pass",
        ChatExecutionStrategy::DirectAuthor => "direct_author",
        ChatExecutionStrategy::PlanExecute => "plan_execute",
        ChatExecutionStrategy::MicroSwarm => "micro_swarm",
        ChatExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn synthesize_prepared_context_with_runtime_plan(
    runtime_plan: &ioi_api::runtime_harness::ArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    connector_grounding: Option<&ioi_api::runtime_harness::ConnectorGrounding>,
    execution_strategy: ChatExecutionStrategy,
) -> Result<ChatArtifactPlanningContext, String> {
    let planning_timeout = Duration::from_secs(90).min(chat_generation_timeout_for_runtime(
        &runtime_plan.planning_runtime,
    ));
    let mut brief = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            planning_timeout,
            synthesize_chat_artifact_brief_for_execution_strategy_with_runtime(
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
            chat_proof_trace(format!(
                "materialize_chat_artifact:brief_fallback reason={} renderer={:?}",
                error, request.renderer
            ));
            derive_request_grounded_chat_artifact_brief(title, intent, request, refinement)
        }
        Err(_) => {
            chat_proof_trace(format!(
                "materialize_chat_artifact:brief_fallback reason=timeout renderer={:?}",
                request.renderer
            ));
            derive_request_grounded_chat_artifact_brief(title, intent, request, refinement)
        }
    };

    ioi_api::runtime_harness::apply_artifact_connector_grounding_to_brief(
        &mut brief,
        connector_grounding,
    );

    Ok(derive_chat_artifact_prepared_context(
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
        Vec::new(),
    ))
}
pub(super) fn sync_workspace_manifest_file(chat_session: &ChatArtifactSession) {
    let Some(workspace_root) = chat_session.workspace_root.as_deref() else {
        return;
    };
    let manifest_path = Path::new(workspace_root).join("artifact-manifest.json");
    let Ok(json) = serde_json::to_vec_pretty(&chat_session.artifact_manifest) else {
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

pub(super) fn select_workspace_recipe(request: &ChatOutcomeArtifactRequest) -> ChatScaffoldRecipe {
    match request.workspace_recipe_id.as_deref() {
        Some("vite-static-html") => ChatScaffoldRecipe::StaticHtmlVite,
        Some("react-vite") => ChatScaffoldRecipe::ReactVite,
        _ => ChatScaffoldRecipe::ReactVite,
    }
}

pub(super) fn materialize_chat_artifact_with_execution_strategy_and_progress_observer(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    connector_grounding: Option<&ioi_api::runtime_harness::ConnectorGrounding>,
    execution_strategy: ChatExecutionStrategy,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    let runtime_profile = configured_chat_runtime_profile();
    let (memory_runtime, inference_runtime, acceptance_inference_runtime) = {
        let app_state = app.state::<Mutex<AppState>>();
        let state = app_state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        (
            state.memory_runtime.clone().ok_or_else(|| {
                "Memory runtime is unavailable for Chat artifact materialization.".to_string()
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
                .map(|candidate| candidate.chat_runtime_provenance()),
        ));
    };
    let runtime_plan = resolve_chat_artifact_runtime_plan(
        request,
        runtime.clone(),
        acceptance_inference_runtime.clone(),
        runtime_profile,
    );
    let planning_context = match super::skills::prepare_chat_artifact_planning_context(
        app,
        &memory_runtime,
        runtime_plan.planning_runtime,
        title,
        intent,
        request,
        refinement,
        connector_grounding,
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
                Vec::new(),
                None,
                Vec::new(),
                None,
                None,
                None,
                Vec::new(),
                Some(runtime.chat_runtime_provenance()),
                acceptance_inference_runtime
                    .as_ref()
                    .map(|candidate| candidate.chat_runtime_provenance()),
            ));
        }
    };

    materialize_chat_artifact_with_dependencies_and_execution_strategy_and_optional_progress(
        &memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        connector_grounding,
        Some(planning_context),
        execution_strategy,
        progress_observer,
    )
}

pub(super) fn materialize_chat_artifact_with_dependencies_and_execution_strategy(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: Option<ChatArtifactPlanningContext>,
    execution_strategy: ChatExecutionStrategy,
) -> Result<MaterializedContentArtifact, String> {
    materialize_chat_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        None,
        planning_context,
        execution_strategy,
        None,
    )
}

fn materialize_chat_artifact_with_dependencies_and_execution_strategy_and_optional_progress(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    connector_grounding: Option<&ioi_api::runtime_harness::ConnectorGrounding>,
    planning_context: Option<ChatArtifactPlanningContext>,
    execution_strategy: ChatExecutionStrategy,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_chat_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        connector_grounding,
        planning_context,
        execution_strategy,
        progress_observer,
    )
}

pub(super) fn materialize_chat_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    connector_grounding: Option<&ioi_api::runtime_harness::ConnectorGrounding>,
    planning_context: Option<ChatArtifactPlanningContext>,
    execution_strategy: ChatExecutionStrategy,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    let generation_timeout = inference_runtime
        .as_ref()
        .map(|runtime| {
            chat_generation_timeout_for_request_and_execution_strategy(
                request,
                runtime,
                acceptance_inference_runtime.as_ref(),
                execution_strategy,
            )
        })
        .unwrap_or_else(|| Duration::from_secs(120));
    materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        generation_timeout,
        connector_grounding,
        planning_context,
        execution_strategy,
        progress_observer,
    )
}

pub(super) fn chat_generation_timeout_for_runtime(runtime: &Arc<dyn InferenceRuntime>) -> Duration {
    let seconds = [
        "AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS",
        "IOI_CHAT_GENERATION_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    })
    .unwrap_or_else(|| match runtime.chat_runtime_provenance().kind {
        crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime => 180,
        _ => 90,
    });

    Duration::from_secs(seconds)
}

pub(super) fn chat_generation_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime: &Arc<dyn InferenceRuntime>,
) -> Duration {
    let timeout = chat_generation_timeout_for_runtime(runtime);
    if request.renderer == ChatRendererKind::HtmlIframe
        && runtime.chat_runtime_provenance().kind
            == crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime
        && timeout == Duration::from_secs(180)
    {
        let runtime_profile = configured_chat_runtime_profile();
        if chat_extended_local_html_timeout_enabled(request, runtime_profile) {
            return Duration::from_secs(LOCAL_HTML_SPLIT_ACCEPTANCE_TIMEOUT_SECS);
        }
        return Duration::from_secs(LOCAL_HTML_GENERATION_TIMEOUT_SECS);
    }

    timeout
}

pub(super) fn chat_generation_timeout_for_request_and_execution_strategy(
    request: &ChatOutcomeArtifactRequest,
    runtime: &Arc<dyn InferenceRuntime>,
    _acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
    execution_strategy: ChatExecutionStrategy,
) -> Duration {
    if execution_strategy == ChatExecutionStrategy::DirectAuthor {
        let authoring_budget = Duration::from_millis(
            execution_budget_envelope_for_strategy(execution_strategy).max_wall_clock_ms as u64,
        );
        let render_eval_budget = render_eval_timeout_for_runtime(
            request.renderer,
            runtime.chat_runtime_provenance().kind,
        )
        .unwrap_or_default();
        let orchestration_slack = Duration::from_secs(5);
        return authoring_budget
            .saturating_add(render_eval_budget)
            .saturating_add(orchestration_slack);
    }

    chat_generation_timeout_for_request(request, runtime)
}

fn chat_modal_first_html_enabled_for_request(request: &ChatOutcomeArtifactRequest) -> bool {
    request.renderer == ChatRendererKind::HtmlIframe
        && ioi_api::runtime_harness::chat_modal_first_html_enabled_for_tests_and_runtime()
}

fn chat_extended_local_html_timeout_enabled(
    request: &ChatOutcomeArtifactRequest,
    runtime_profile: ChatArtifactRuntimePolicyProfile,
) -> bool {
    chat_modal_first_html_enabled_for_request(request)
        && matches!(
            runtime_profile,
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                | ChatArtifactRuntimePolicyProfile::PremiumEndToEnd
        )
}

fn configured_chat_runtime_profile() -> ChatArtifactRuntimePolicyProfile {
    [
        "AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE",
        "IOI_CHAT_MODEL_ROUTING_PROFILE",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .as_deref()
            .and_then(ChatArtifactRuntimePolicyProfile::parse)
    })
    .unwrap_or(ChatArtifactRuntimePolicyProfile::Auto)
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

pub(super) fn materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    generation_timeout: Duration,
    connector_grounding: Option<&ioi_api::runtime_harness::ConnectorGrounding>,
    planning_context: Option<ChatArtifactPlanningContext>,
    execution_strategy: ChatExecutionStrategy,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
) -> Result<MaterializedContentArtifact, String> {
    materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy_and_render_evaluator(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        generation_timeout,
        connector_grounding,
        planning_context,
        execution_strategy,
        progress_observer,
        None,
    )
}

pub(super) fn materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy_and_render_evaluator(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    generation_timeout: Duration,
    connector_grounding: Option<&ioi_api::runtime_harness::ConnectorGrounding>,
    planning_context: Option<ChatArtifactPlanningContext>,
    execution_strategy: ChatExecutionStrategy,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
    render_evaluator_override: Option<&dyn ChatArtifactRenderEvaluator>,
) -> Result<MaterializedContentArtifact, String> {
    chat_proof_trace(format!(
        "materialize_chat_artifact:start renderer={} strategy={:?} title={}",
        renderer_kind_id(request.renderer),
        execution_strategy,
        title
    ));
    let runtime_profile = configured_chat_runtime_profile();
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
                        .map(|candidate| candidate.chat_runtime_provenance()),
                ));
            };
            let runtime_plan = resolve_chat_artifact_runtime_plan(
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
                connector_grounding,
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
                        Vec::new(),
                        None,
                        Vec::new(),
                        None,
                        None,
                        None,
                        Vec::new(),
                        Some(runtime.chat_runtime_provenance()),
                        acceptance_inference_runtime
                            .as_ref()
                            .map(|candidate| candidate.chat_runtime_provenance()),
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
    let mut observed_operator_steps: Vec<ArtifactOperatorStep>;
    let bundle = match inference_runtime {
        Some(runtime) => {
            let runtime_plan = resolve_chat_artifact_runtime_plan(
                request,
                runtime,
                acceptance_inference_runtime.clone(),
                runtime_profile,
            );
            let generation_runtime = runtime_plan.generation_runtime.clone();
            let acceptance_runtime = runtime_plan.acceptance_runtime.clone();
            let default_render_evaluator = BrowserChatArtifactRenderEvaluator::default();
            let render_evaluator = render_evaluator_override.unwrap_or(&default_render_evaluator);
            let production_provenance = runtime_plan.generation_runtime.chat_runtime_provenance();
            let acceptance_provenance = runtime_plan.acceptance_runtime.chat_runtime_provenance();
            let last_activity = Arc::new(Mutex::new(Instant::now()));
            let last_progress_snapshot =
                Arc::new(Mutex::new(None::<ChatArtifactGenerationProgress>));
            let last_execution_envelope_snapshot = Arc::new(Mutex::new(None::<ExecutionEnvelope>));
            let observed_operator_steps_state =
                Arc::new(Mutex::new(Vec::<ArtifactOperatorStep>::new()));
            let observed_progress = progress_observer.as_ref().map(|observer| {
                let observer = observer.clone();
                let last_activity = last_activity.clone();
                let last_progress_snapshot = last_progress_snapshot.clone();
                let last_execution_envelope_snapshot = last_execution_envelope_snapshot.clone();
                let observed_operator_steps_state = observed_operator_steps_state.clone();
                Arc::new(move |progress: ChatArtifactGenerationProgress| {
                    if let Ok(mut activity) = last_activity.lock() {
                        *activity = Instant::now();
                    }
                    if let Ok(mut steps) = observed_operator_steps_state.lock() {
                        merge_operator_steps(&mut steps, &progress.operator_steps);
                    }
                    if let Ok(mut snapshot) = last_progress_snapshot.lock() {
                        *snapshot = Some(progress.clone());
                    }
                    if let Some(envelope) = progress.execution_envelope.clone() {
                        if let Ok(mut snapshot) = last_execution_envelope_snapshot.lock() {
                            *snapshot = Some(envelope);
                        }
                    }
                    observer(progress);
                }) as ChatArtifactGenerationProgressObserver
            });
            let activity_observer = {
                let last_activity = last_activity.clone();
                Arc::new(move || {
                    if let Ok(mut activity) = last_activity.lock() {
                        *activity = Instant::now();
                    }
                }) as ChatArtifactActivityObserver
            };
            match tauri::async_runtime::block_on(async {
                await_generation_with_activity_timeout(
                    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
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
                    observed_operator_steps = observed_operator_steps_state
                        .lock()
                        .map(|steps| steps.clone())
                        .unwrap_or_default();
                    merge_operator_steps(
                        &mut observed_operator_steps,
                        &[present_artifact_complete_step()],
                    );
                    if let Some(observer) = progress_observer.as_ref() {
                        observer(ChatArtifactGenerationProgress {
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
                            retrieved_sources: prepared_context.retrieved_sources.clone(),
                            execution_envelope: bundle.execution_envelope.clone(),
                            swarm_plan: bundle.swarm_plan.clone(),
                            swarm_execution: bundle.swarm_execution.clone(),
                            swarm_worker_receipts: bundle.swarm_worker_receipts.clone(),
                            swarm_change_receipts: bundle.swarm_change_receipts.clone(),
                            swarm_merge_receipts: bundle.swarm_merge_receipts.clone(),
                            swarm_verification_receipts: bundle.swarm_verification_receipts.clone(),
                            render_evaluation: bundle.render_evaluation.clone(),
                            validation: Some(bundle.validation.clone()),
                            operator_steps: vec![present_artifact_complete_step()],
                        });
                    }
                    chat_proof_trace(format!(
                        "materialize_chat_artifact:bundle_ready winner={} lifecycle={:?} degraded_path_used={}",
                        bundle
                            .winning_candidate_id
                            .clone()
                            .unwrap_or_else(|| "swarm-merged".to_string()),
                        bundle.ux_lifecycle,
                        bundle.degraded_path_used
                    ));
                    bundle
                }
                Ok(Err(error)) => {
                    let last_progress = last_progress_snapshot
                        .lock()
                        .ok()
                        .and_then(|snapshot| snapshot.clone());
                    chat_proof_trace(format!(
                        "materialize_chat_artifact:bundle_blocked {}",
                        error.message
                    ));
                    if execution_strategy == ChatExecutionStrategy::DirectAuthor
                        && direct_author_error_requires_replan(&error.message)
                    {
                        let latest_execution_envelope = last_progress
                            .as_ref()
                            .and_then(|progress| progress.execution_envelope.clone())
                            .or_else(|| {
                                last_execution_envelope_snapshot
                                    .lock()
                                    .ok()
                                    .and_then(|snapshot| snapshot.clone())
                            });
                        let terminalized_execution_envelope =
                            finalize_latest_execution_preview(latest_execution_envelope);
                        let stalled_attempt_id = last_progress.as_ref().and_then(|progress| {
                            latest_author_attempt_id(&progress.operator_steps)
                        });
                        let mut prior_operator_steps = last_progress
                            .as_ref()
                            .map(|progress| progress.operator_steps.clone())
                            .unwrap_or_default();
                        merge_operator_steps(
                            &mut prior_operator_steps,
                            &[
                                direct_author_blocked_step(
                                    stalled_attempt_id.as_deref(),
                                    "Direct author hit a bounded model timeout. Replanning artifact execution.",
                                ),
                                replan_execution_step(
                                    ChatExecutionStrategy::DirectAuthor,
                                    ChatExecutionStrategy::PlanExecute,
                                ),
                            ],
                        );
                        if let Some(observer) = progress_observer.as_ref() {
                            let operator_steps = vec![
                                direct_author_blocked_step(
                                    stalled_attempt_id.as_deref(),
                                    "Direct author hit a bounded model timeout. Replanning artifact execution.",
                                ),
                                replan_execution_step(
                                    ChatExecutionStrategy::DirectAuthor,
                                    ChatExecutionStrategy::PlanExecute,
                                ),
                            ];
                            observer(ChatArtifactGenerationProgress {
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
                                retrieved_exemplars: prepared_context.retrieved_exemplars.clone(),
                                retrieved_sources: prepared_context.retrieved_sources.clone(),
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
                                validation: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.validation.clone()),
                                operator_steps,
                            });
                        }
                        let mut replanned =
                            materialize_chat_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
                            memory_runtime,
                            Some(generation_runtime),
                            Some(acceptance_runtime),
                            thread_id,
                            title,
                            intent,
                            request,
                            refinement,
                            None,
                            Some(prepared_context.clone()),
                            ChatExecutionStrategy::PlanExecute,
                            progress_observer.clone(),
                        )?;
                        merge_operator_steps(&mut prior_operator_steps, &replanned.operator_steps);
                        replanned.operator_steps = prior_operator_steps;
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
                        prepared_context.retrieved_sources.clone(),
                        error.edit_intent,
                        error.candidate_summaries,
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.execution_envelope.clone()),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.render_evaluation.clone()),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.validation.clone()),
                        last_progress
                            .as_ref()
                            .map(|progress| progress.operator_steps.clone())
                            .unwrap_or_default(),
                        Some(production_provenance),
                        Some(acceptance_provenance),
                    ));
                }
                Err(idle_for) => {
                    let message = format!(
                        "Chat artifact generation timed out after {} of inactivity while {}.",
                        format_generation_timeout(idle_for),
                        if execution_strategy == ChatExecutionStrategy::DirectAuthor {
                            "authoring the artifact directly"
                        } else {
                            "running the artifact execution plan"
                        }
                    );
                    chat_proof_trace(format!(
                        "materialize_chat_artifact:bundle_timeout {}",
                        message
                    ));
                    let last_progress = last_progress_snapshot
                        .lock()
                        .ok()
                        .and_then(|snapshot| snapshot.clone());
                    if execution_strategy == ChatExecutionStrategy::DirectAuthor {
                        let latest_execution_envelope = last_progress
                            .as_ref()
                            .and_then(|progress| progress.execution_envelope.clone())
                            .or_else(|| {
                                last_execution_envelope_snapshot
                                    .lock()
                                    .ok()
                                    .and_then(|snapshot| snapshot.clone())
                            });
                        let terminalized_execution_envelope =
                            finalize_latest_execution_preview(latest_execution_envelope);
                        let stalled_attempt_id = last_progress.as_ref().and_then(|progress| {
                            latest_author_attempt_id(&progress.operator_steps)
                        });
                        let mut prior_operator_steps = last_progress
                            .as_ref()
                            .map(|progress| progress.operator_steps.clone())
                            .unwrap_or_default();
                        merge_operator_steps(
                            &mut prior_operator_steps,
                            &[
                                direct_author_blocked_step(
                                    stalled_attempt_id.as_deref(),
                                    format!(
                                        "Direct author stalled after {} without producing enough activity to finish this attempt.",
                                        format_generation_timeout(idle_for)
                                    ),
                                ),
                                replan_execution_step(
                                    ChatExecutionStrategy::DirectAuthor,
                                    ChatExecutionStrategy::PlanExecute,
                                ),
                            ],
                        );
                        if let Some(observer) = progress_observer.as_ref() {
                            let operator_steps = vec![
                                direct_author_blocked_step(
                                    stalled_attempt_id.as_deref(),
                                    format!(
                                        "Direct author stalled after {} without producing enough activity to finish this attempt.",
                                        format_generation_timeout(idle_for)
                                    ),
                                ),
                                replan_execution_step(
                                    ChatExecutionStrategy::DirectAuthor,
                                    ChatExecutionStrategy::PlanExecute,
                                ),
                            ];
                            observer(ChatArtifactGenerationProgress {
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
                                retrieved_exemplars: prepared_context.retrieved_exemplars.clone(),
                                retrieved_sources: prepared_context.retrieved_sources.clone(),
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
                                validation: last_progress
                                    .as_ref()
                                    .and_then(|progress| progress.validation.clone()),
                                operator_steps,
                            });
                        }
                        let mut replanned =
                            materialize_chat_artifact_with_dependencies_and_execution_strategy_and_progress_observer(
                            memory_runtime,
                            Some(generation_runtime),
                            Some(acceptance_runtime),
                            thread_id,
                            title,
                            intent,
                            request,
                            refinement,
                            None,
                            Some(prepared_context.clone()),
                            ChatExecutionStrategy::PlanExecute,
                            progress_observer.clone(),
                        )?;
                        merge_operator_steps(&mut prior_operator_steps, &replanned.operator_steps);
                        replanned.operator_steps = prior_operator_steps;
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
                        prepared_context.retrieved_sources.clone(),
                        None,
                        Vec::new(),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.execution_envelope.clone()),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.render_evaluation.clone()),
                        last_progress
                            .as_ref()
                            .and_then(|progress| progress.validation.clone()),
                        last_progress
                            .as_ref()
                            .map(|progress| progress.operator_steps.clone())
                            .unwrap_or_default(),
                        Some(production_provenance),
                        Some(acceptance_provenance),
                    ));
                }
            }
        }
        None if acceptance_inference_runtime.is_some() => {
            let acceptance_provenance = acceptance_inference_runtime
                .as_ref()
                .map(|runtime| runtime.chat_runtime_provenance());
            return Ok(blocked_materialized_artifact_from_error(
                title,
                intent,
                request,
                refinement,
                "Inference runtime is unavailable for Chat artifact materialization.",
                None,
                prepared_context.preparation_needs.clone(),
                prepared_context.prepared_context_resolution.clone(),
                prepared_context.skill_discovery_resolution.clone(),
                prepared_context.blueprint.clone(),
                prepared_context.artifact_ir.clone(),
                prepared_context.selected_skills.clone(),
                prepared_context.retrieved_exemplars.clone(),
                prepared_context.retrieved_sources.clone(),
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
        None => return Ok(blocked_materialized_artifact_from_error(
            title,
            intent,
            request,
            refinement,
            "Inference and acceptance runtimes are unavailable for Chat artifact materialization.",
            None,
            prepared_context.preparation_needs.clone(),
            prepared_context.prepared_context_resolution.clone(),
            prepared_context.skill_discovery_resolution.clone(),
            prepared_context.blueprint.clone(),
            prepared_context.artifact_ir.clone(),
            prepared_context.selected_skills.clone(),
            prepared_context.retrieved_exemplars.clone(),
            prepared_context.retrieved_sources.clone(),
            None,
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
            None,
            None,
        )),
    };
    let bundle_edit_intent = bundle.edit_intent.clone();
    let derived_taste_memory = derive_chat_taste_memory(
        refinement.and_then(|context| context.taste_memory.as_ref()),
        &bundle.brief,
        bundle.blueprint.as_ref(),
        bundle.artifact_ir.as_ref(),
        bundle_edit_intent.as_ref(),
        Some(&bundle.validation),
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
    let degraded_path_used = bundle.degraded_path_used;

    let mut artifacts = Vec::new();
    let mut files = Vec::new();
    let mut file_writes = Vec::new();
    let mut quality_files = Vec::new();

    for generated_file in generated.files.clone() {
        chat_proof_trace(format!(
            "materialize_chat_artifact:file {} mime={} renderable={} bytes={}",
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
        file_writes.push(ChatArtifactMaterializationFileWrite {
            path: generated_file.path.clone(),
            kind: format!("{:?}", generated_file.role).to_lowercase(),
            content_preview: generated_file_preview(&generated_file),
        });
        files.push(ChatArtifactManifestFile {
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

    chat_proof_trace(format!(
        "materialize_chat_artifact:files_persisted count={}",
        files.len()
    ));
    let quality_assessment = finalize_presentation_assessment(
        request,
        assess_materialized_artifact_presentation(request, &quality_files),
        &bundle.validation,
        bundle.render_evaluation.as_ref(),
        degraded_path_used,
        bundle.ux_lifecycle == ChatArtifactUxLifecycle::Draft,
    );
    chat_proof_trace(format!(
        "materialize_chat_artifact:quality lifecycle={:?} summary={}",
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
    if !prepared_context.retrieved_sources.is_empty() {
        notes.push(format!(
            "Attached {} retrieved research source(s) to the artifact run.",
            prepared_context.retrieved_sources.len()
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
            "Winning candidate {} selected via typed validation.",
            winner_id
        ));
    }

    chat_proof_trace("materialize_chat_artifact:return");
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
        retrieved_sources: prepared_context.retrieved_sources.clone(),
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
        validation: Some(bundle.validation),
        output_origin,
        production_provenance: Some(bundle.production_provenance),
        acceptance_provenance: Some(bundle.acceptance_provenance),
        degraded_path_used,
        ux_lifecycle: if degraded_path_used {
            ChatArtifactUxLifecycle::Draft
        } else if bundle_edit_intent
            .as_ref()
            .is_some_and(|edit_intent| edit_intent.patch_existing_artifact)
        {
            ChatArtifactUxLifecycle::Locked
        } else {
            bundle.ux_lifecycle
        },
        failure: bundle.failure,
        taste_memory: derived_taste_memory.or(bundle.taste_memory),
        selected_targets,
        lifecycle_state: quality_assessment.lifecycle_state,
        verification_summary: quality_assessment.summary,
        operator_steps: observed_operator_steps,
    })
}

pub(super) fn blocked_materialized_artifact_from_error(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    error: &str,
    artifact_brief: Option<ChatArtifactBrief>,
    preparation_needs: Option<ioi_api::runtime_harness::ChatArtifactPreparationNeeds>,
    prepared_context_resolution: Option<
        ioi_api::runtime_harness::ChatArtifactPreparedContextResolution,
    >,
    skill_discovery_resolution: Option<
        ioi_api::runtime_harness::ChatArtifactSkillDiscoveryResolution,
    >,
    blueprint: Option<ChatArtifactBlueprint>,
    artifact_ir: Option<ChatArtifactIR>,
    selected_skills: Vec<ChatArtifactSelectedSkill>,
    retrieved_exemplars: Vec<ChatArtifactExemplar>,
    retrieved_sources: Vec<ioi_api::runtime_harness::ArtifactSourceReference>,
    edit_intent: Option<ChatArtifactEditIntent>,
    candidate_summaries: Vec<ChatArtifactCandidateSummary>,
    execution_envelope: Option<ExecutionEnvelope>,
    render_evaluation: Option<ChatArtifactRenderEvaluation>,
    _last_validation: Option<ChatArtifactValidationResult>,
    mut operator_steps: Vec<ArtifactOperatorStep>,
    production_runtime_provenance: Option<crate::models::ChatRuntimeProvenance>,
    acceptance_runtime_provenance: Option<crate::models::ChatRuntimeProvenance>,
) -> MaterializedContentArtifact {
    let production_provenance =
        production_runtime_provenance.unwrap_or(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    let acceptance_provenance =
        acceptance_runtime_provenance.unwrap_or(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    let failure_kind = if production_provenance.kind
        == crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable
        || acceptance_provenance.kind
            == crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable
    {
        crate::models::ChatArtifactFailureKind::InferenceUnavailable
    } else {
        crate::models::ChatArtifactFailureKind::GenerationFailure
    };
    let failure = crate::models::ChatArtifactFailure {
        kind: failure_kind,
        code: match failure_kind {
            crate::models::ChatArtifactFailureKind::InferenceUnavailable => "inference_unavailable",
            crate::models::ChatArtifactFailureKind::RoutingFailure => "routing_failure",
            crate::models::ChatArtifactFailureKind::GenerationFailure => "generation_failure",
            crate::models::ChatArtifactFailureKind::VerificationFailure => "verification_failure",
        }
        .to_string(),
        message: error.to_string(),
    };
    let validation = ChatArtifactValidationResult {
        classification: ioi_api::runtime_harness::ChatArtifactValidationStatus::Blocked,
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
        score_total: 0,
        proof_kind: "materialization".to_string(),
        primary_view_cleared: false,
        validated_paths: Vec::new(),
        issue_codes: vec![failure.code.clone()],
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
        summary: "Artifact generation failed before validation could complete.".to_string(),
        rationale: error.to_string(),
    };
    let execution_envelope = finalize_blocked_execution_envelope(execution_envelope);
    let has_author_step = operator_steps
        .iter()
        .any(|step| step.phase == ArtifactOperatorPhase::AuthorArtifact);
    let has_blocked_author_step = operator_steps.iter().any(|step| {
        step.phase == ArtifactOperatorPhase::AuthorArtifact
            && step.status == ArtifactOperatorRunStatus::Blocked
    });
    let latest_preview =
        latest_execution_live_preview(execution_envelope.as_ref()).map(|preview| {
            ChatArtifactOperatorPreview {
                origin_prompt_event_id: String::new(),
                label: preview.label,
                content: preview.content,
                status: preview.status,
                kind: Some(format!("{:?}", preview.kind).to_ascii_lowercase()),
                language: preview.language,
                is_final: preview.is_final,
            }
        });
    if has_blocked_author_step {
        if let Some(step) = operator_steps.iter_mut().rev().find(|step| {
            step.phase == ArtifactOperatorPhase::AuthorArtifact
                && step.status == ArtifactOperatorRunStatus::Blocked
        }) {
            if step.preview.is_none() {
                step.preview = latest_preview.clone();
            }
        }
    }
    if !has_blocked_author_step && (has_author_step || latest_preview.is_some()) {
        let mut blocked_step = direct_author_blocked_step(
            latest_author_attempt_id(&operator_steps).as_deref(),
            error.to_string(),
        );
        blocked_step.preview = latest_preview;
        operator_steps.push(blocked_step);
    }
    merge_operator_steps(&mut operator_steps, &[present_artifact_blocked_step(error)]);

    MaterializedContentArtifact {
        artifacts: Vec::new(),
        files: Vec::new(),
        file_writes: Vec::new(),
        notes: vec![
            "Chat refused to substitute mock or deterministic output for a failed non-workspace artifact generation."
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
        retrieved_sources,
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
        validation: Some(validation),
        output_origin: output_origin_from_runtime_provenance(&production_provenance),
        production_provenance: Some(production_provenance),
        acceptance_provenance: Some(acceptance_provenance),
        degraded_path_used: false,
        ux_lifecycle: ChatArtifactUxLifecycle::Draft,
        failure: Some(failure),
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        selected_targets: refinement
            .map(|context| context.selected_targets.clone())
            .unwrap_or_default(),
        lifecycle_state: ChatArtifactLifecycleState::Blocked,
        verification_summary: error.to_string(),
        operator_steps,
    }
}

pub(super) fn blocked_failure_brief(
    title: &str,
    intent: &str,
    renderer: ChatRendererKind,
    failure_message: &str,
    reference_hints: Vec<String>,
) -> ChatArtifactBrief {
    ChatArtifactBrief {
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
    provenance: &crate::models::ChatRuntimeProvenance,
) -> ChatArtifactOutputOrigin {
    match provenance.kind {
        crate::models::ChatRuntimeProvenanceKind::RealRemoteModelRuntime
        | crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime => {
            ChatArtifactOutputOrigin::LiveInference
        }
        crate::models::ChatRuntimeProvenanceKind::FixtureRuntime => {
            ChatArtifactOutputOrigin::FixtureRuntime
        }
        crate::models::ChatRuntimeProvenanceKind::MockRuntime => {
            ChatArtifactOutputOrigin::MockInference
        }
        crate::models::ChatRuntimeProvenanceKind::DeterministicContinuityFallback => {
            ChatArtifactOutputOrigin::DeterministicFallback
        }
        crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable => {
            ChatArtifactOutputOrigin::InferenceUnavailable
        }
        crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime => {
            ChatArtifactOutputOrigin::OpaqueRuntime
        }
    }
}

#[cfg(test)]
pub(super) fn generate_non_workspace_artifact_payload(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
) -> Result<ChatGeneratedArtifactPayload, String> {
    let runtime = inference_runtime.ok_or_else(|| {
        "Inference runtime is unavailable for Chat artifact materialization.".to_string()
    })?;
    tauri::async_runtime::block_on(materialize_chat_artifact_with_runtime(
        runtime, title, intent, request,
    ))
}

#[cfg(test)]
pub(super) fn generated_quality_files(
    payload: &ChatGeneratedArtifactPayload,
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
    let user_request = extract_user_request_from_contextualized_intent(intent);
    let trimmed = user_request.trim();
    let primary = trimmed
        .split(['.', '\n', ':'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    if primary.is_empty() {
        return "Chat artifact".to_string();
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
    contract: &ChatArtifactMaterializationContract,
) -> Artifact {
    artifact_store::create_report_artifact(
        memory_runtime,
        thread_id,
        &format!("Chat artifact: {}", title),
        "Machine-routable Chat artifact materialization contract",
        &serde_json::to_value(contract).unwrap_or_else(|_| json!({})),
    )
}

pub(super) fn create_contract_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    contract: &ChatArtifactMaterializationContract,
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
    receipt: &ChatBuildReceipt,
) -> Artifact {
    artifact_store::create_report_artifact(
        memory_runtime,
        thread_id,
        &format!("{} · {}", title, receipt.title),
        "Chat build receipt",
        &serde_json::to_value(receipt).unwrap_or_else(|_| json!({})),
    )
}

pub(super) fn create_receipt_report_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    receipt: &ChatBuildReceipt,
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
