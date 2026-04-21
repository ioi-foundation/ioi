use super::*;

pub(super) fn build_non_swarm_winner_bundle(
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    execution_strategy: StudioExecutionStrategy,
    origin: StudioArtifactOutputOrigin,
    production_provenance: StudioRuntimeProvenance,
    acceptance_provenance: StudioRuntimeProvenance,
    runtime_policy: StudioArtifactRuntimePolicy,
    adaptive_search_budget: StudioAdaptiveSearchBudget,
    live_preview_state: Arc<Mutex<Vec<ExecutionLivePreview>>>,
    brief: StudioArtifactBrief,
    blueprint: Option<StudioArtifactBlueprint>,
    artifact_ir: Option<StudioArtifactIR>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
    edit_intent: Option<StudioArtifactEditIntent>,
    candidate_rows: Vec<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>,
    mut candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    failed_candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    selected_winner_index: Option<usize>,
    best_acceptance_index: Option<usize>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let winner_index = selected_winner_index
        .or(best_acceptance_index)
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    if let Some(selected) = candidate_summaries.get_mut(winner_index) {
        selected.selected = true;
        let termination = if selected_winner_index == Some(winner_index) {
            "selected_after_primary_view_clear"
        } else {
            "selected_as_best_available_candidate"
        };
        set_candidate_termination_reason(selected, termination);
    }
    let winner_summary = candidate_summaries
        .get(winner_index)
        .cloned()
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    let artifact_validation = winner_summary.validation.clone();
    let winner = candidate_rows
        .into_iter()
        .nth(winner_index)
        .map(|(_, payload)| payload)
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning artifact payload is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    let final_candidate_summaries =
        merged_candidate_summaries(&candidate_summaries, &failed_candidate_summaries);
    studio_generation_trace(format!(
        "artifact_generation:winner id={}",
        winner_summary.candidate_id
    ));
    if let Some(preview) = non_swarm_canonical_preview(request, &winner, "completed", true) {
        if let Ok(mut previews) = live_preview_state.lock() {
            upsert_execution_live_preview(&mut previews, preview);
        }
    }
    let execution_envelope = build_non_swarm_execution_envelope(
        request,
        execution_strategy,
        &snapshot_execution_live_previews(&live_preview_state),
        if validation_clears_primary_view(&artifact_validation) {
            ExecutionCompletionInvariantStatus::Satisfied
        } else {
            ExecutionCompletionInvariantStatus::Blocked
        },
        non_swarm_required_artifact_paths(&winner),
    );
    if let Some(envelope) = execution_envelope.as_ref() {
        crate::execution::validate_execution_envelope(envelope)
            .map_err(|message| StudioArtifactGenerationError {
                message,
                brief: Some(brief.clone()),
                blueprint: blueprint.clone(),
                artifact_ir: artifact_ir.clone(),
                selected_skills: selected_skills.clone(),
                edit_intent: edit_intent.clone(),
                candidate_summaries: final_candidate_summaries.clone(),
            })?;
    }

    Ok(StudioArtifactGenerationBundle {
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        edit_intent,
        candidate_summaries: final_candidate_summaries,
        winning_candidate_id: Some(winner_summary.candidate_id.clone()),
        winning_candidate_rationale: Some(winner_summary.validation.rationale.clone()),
        execution_envelope,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        validation: artifact_validation,
        winner,
        render_evaluation: winner_summary.render_evaluation.clone(),
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: Some(runtime_policy),
        adaptive_search_budget: Some(adaptive_search_budget),
        fallback_used: false,
        ux_lifecycle: StudioArtifactUxLifecycle::Validated,
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}
