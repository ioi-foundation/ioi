use super::*;

async fn synthesize_prepared_context_with_runtime_plan(
    runtime_plan: &StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    execution_strategy: StudioExecutionStrategy,
) -> Result<StudioArtifactPlanningContext, StudioArtifactGenerationError> {
    let brief = synthesize_studio_artifact_brief_for_execution_strategy_with_runtime(
        runtime_plan.planning_runtime.clone(),
        title,
        intent,
        request,
        refinement,
        execution_strategy,
    )
    .await
    .map_err(|message| StudioArtifactGenerationError {
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
        Vec::new(),
    ))
}

pub async fn generate_studio_artifact_bundle_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        runtime,
        None,
        StudioArtifactRuntimePolicyProfile::FullyLocal,
    );
    let execution_strategy = default_studio_artifact_execution_strategy(request);
    let planning_context = synthesize_prepared_context_with_runtime_plan(
        &runtime_plan,
        title,
        intent,
        request,
        refinement,
        execution_strategy,
    )
    .await?;
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
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

pub async fn generate_studio_artifact_bundle_with_runtimes(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::Auto,
    );
    let execution_strategy = default_studio_artifact_execution_strategy(request);
    let planning_context = synthesize_prepared_context_with_runtime_plan(
        &runtime_plan,
        title,
        intent,
        request,
        refinement,
        execution_strategy,
    )
    .await?;
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
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

pub async fn generate_studio_artifact_bundle_with_runtimes_and_planning_context(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    runtime_profile: StudioArtifactRuntimePolicyProfile,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: &StudioArtifactPlanningContext,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
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

pub async fn generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    runtime_profile: StudioArtifactRuntimePolicyProfile,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: &StudioArtifactPlanningContext,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        production_runtime,
        acceptance_runtime,
        runtime_profile,
    );
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_studio_artifact_execution_strategy(request),
        render_evaluator,
        None,
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: &StudioArtifactPlanningContext,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_studio_artifact_execution_strategy(request),
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: &StudioArtifactPlanningContext,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
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

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: &StudioArtifactPlanningContext,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_studio_artifact_execution_strategy(request),
        render_evaluator,
        None,
        None,
    )
    .await
}

pub(super) fn hydrate_edit_intent_with_refinement_selection(
    mut edit_intent: StudioArtifactEditIntent,
    refinement: &StudioArtifactRefinementContext,
) -> StudioArtifactEditIntent {
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
