use super::*;

async fn synthesize_prepared_context_with_runtime_plan(
    runtime_plan: &ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    execution_strategy: ChatExecutionStrategy,
) -> Result<ChatArtifactPlanningContext, ChatArtifactGenerationError> {
    let brief = synthesize_chat_artifact_brief_for_execution_strategy_with_runtime(
        runtime_plan.planning_runtime.clone(),
        title,
        intent,
        request,
        refinement,
        execution_strategy,
    )
    .await
    .map_err(|message| ChatArtifactGenerationError {
        message: format!(
            "Prepared artifact context failed during brief synthesis: {}",
            message
        ),
        brief: None,
        blueprint: refinement.and_then(|context| context.blueprint.clone()),
        artifact_ir: refinement.and_then(|context| context.artifact_ir.clone()),
        selected_skills: refinement
            .map(|context| context.selected_skills.clone())
            .unwrap_or_default(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
    })?;

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

pub async fn generate_chat_artifact_bundle_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    let runtime_plan = resolve_chat_artifact_runtime_plan(
        request,
        runtime,
        None,
        ChatArtifactRuntimePolicyProfile::FullyLocal,
    );
    let execution_strategy = default_chat_artifact_execution_strategy(request);
    let planning_context = synthesize_prepared_context_with_runtime_plan(
        &runtime_plan,
        title,
        intent,
        request,
        refinement,
        execution_strategy,
    )
    .await?;
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        &planning_context,
        execution_strategy,
        None,
    )
    .await
}

pub async fn generate_chat_artifact_bundle_with_runtimes(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    let runtime_plan = resolve_chat_artifact_runtime_plan(
        request,
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::Auto,
    );
    let execution_strategy = default_chat_artifact_execution_strategy(request);
    let planning_context = synthesize_prepared_context_with_runtime_plan(
        &runtime_plan,
        title,
        intent,
        request,
        refinement,
        execution_strategy,
    )
    .await?;
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        &planning_context,
        execution_strategy,
        None,
    )
    .await
}

pub async fn generate_chat_artifact_bundle_with_runtimes_and_planning_context(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    runtime_profile: ChatArtifactRuntimePolicyProfile,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: &ChatArtifactPlanningContext,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    generate_chat_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
        production_runtime,
        acceptance_runtime,
        runtime_profile,
        title,
        intent,
        request,
        refinement,
        planning_context,
        None,
    )
    .await
}

pub async fn generate_chat_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    runtime_profile: ChatArtifactRuntimePolicyProfile,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: &ChatArtifactPlanningContext,
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    let runtime_plan = resolve_chat_artifact_runtime_plan(
        request,
        production_runtime,
        acceptance_runtime,
        runtime_profile,
    );
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_chat_artifact_execution_strategy(request),
        render_evaluator,
        None,
        None,
    )
    .await
}

pub async fn generate_chat_artifact_bundle_with_runtime_plan_and_planning_context(
    runtime_plan: ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: &ChatArtifactPlanningContext,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_chat_artifact_execution_strategy(request),
        None,
    )
    .await
}

pub async fn generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
    runtime_plan: ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: &ChatArtifactPlanningContext,
    execution_strategy: ChatExecutionStrategy,
    progress_observer: Option<ChatArtifactGenerationProgressObserver>,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        execution_strategy,
        None,
        progress_observer,
        None,
    )
    .await
}

pub async fn generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator(
    runtime_plan: ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    planning_context: &ChatArtifactPlanningContext,
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
) -> Result<ChatArtifactGenerationBundle, ChatArtifactGenerationError> {
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_chat_artifact_execution_strategy(request),
        render_evaluator,
        None,
        None,
    )
    .await
}

pub(super) fn hydrate_edit_intent_with_refinement_selection(
    mut edit_intent: ChatArtifactEditIntent,
    refinement: &ChatArtifactRefinementContext,
) -> ChatArtifactEditIntent {
    if edit_intent.selected_targets.is_empty() && !refinement.selected_targets.is_empty() {
        edit_intent.selected_targets = refinement.selected_targets.clone();
    }
    if edit_intent.target_paths.is_empty() {
        let mut target_paths = edit_intent
            .selected_targets
            .iter()
            .filter_map(|target| target.path.clone())
            .collect::<Vec<_>>();
        target_paths.sort();
        target_paths.dedup();
        edit_intent.target_paths = target_paths;
    }
    edit_intent
}
