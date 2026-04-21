use super::*;
use ioi_api::execution::{
    ExecutionCompletionInvariantStatus, ExecutionEnvelope, ExecutionLivePreview,
    ExecutionLivePreviewKind,
};
use ioi_api::runtime_harness::{
    ArtifactOperatorPhase, ArtifactOperatorRunStatus, ArtifactOperatorStep,
    ArtifactPlanningContext as ChatArtifactPlanningContext,
    ChatArtifactGenerationProgress as ChatArtifactGenerationProgress,
    ChatArtifactGenerationProgressObserver as ChatArtifactGenerationProgressObserver,
};

fn prepared_context_progress_message(execution_strategy: ChatExecutionStrategy) -> String {
    if execution_strategy == ChatExecutionStrategy::DirectAuthor {
        "Prepared the artifact brief and structural context. Authoring is starting.".to_string()
    } else {
        "Prepared the artifact brief and structural context. Execution is starting.".to_string()
    }
}

pub(super) fn direct_author_error_requires_replan(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("direct-author artifact inference timed out")
        || lowered.contains("direct-author continuation timed out")
        || lowered.contains("direct-author repair timed out")
        || (lowered.contains("repair attempt")
            && (lowered.contains("must contain a <main> region")
                || lowered.contains("must contain a closed <main> region")
                || lowered.contains(
                    "must not close the document while non-void html elements remain unclosed",
                )))
}

pub(super) fn present_artifact_complete_step() -> ArtifactOperatorStep {
    ArtifactOperatorStep {
        step_id: "present_artifact".to_string(),
        origin_prompt_event_id: String::new(),
        phase: ArtifactOperatorPhase::PresentArtifact,
        engine: "materialization".to_string(),
        status: ArtifactOperatorRunStatus::Complete,
        label: "Open artifact".to_string(),
        detail: "Chat finished materializing the artifact and can now surface it.".to_string(),
        started_at_ms: 0,
        finished_at_ms: Some(0),
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 1,
    }
}

pub(super) fn present_artifact_blocked_step(error: &str) -> ArtifactOperatorStep {
    ArtifactOperatorStep {
        step_id: "present_artifact".to_string(),
        origin_prompt_event_id: String::new(),
        phase: ArtifactOperatorPhase::PresentArtifact,
        engine: "materialization".to_string(),
        status: ArtifactOperatorRunStatus::Blocked,
        label: "Open artifact".to_string(),
        detail: format!("Chat could not present the artifact because {error}"),
        started_at_ms: 0,
        finished_at_ms: Some(0),
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 1,
    }
}

pub(super) fn direct_author_blocked_step(
    attempt_id: Option<&str>,
    detail: impl Into<String>,
) -> ArtifactOperatorStep {
    ArtifactOperatorStep {
        step_id: format!("author_artifact:{}", attempt_id.unwrap_or("1")),
        origin_prompt_event_id: String::new(),
        phase: ArtifactOperatorPhase::AuthorArtifact,
        engine: "materialization".to_string(),
        status: ArtifactOperatorRunStatus::Blocked,
        label: "Write artifact".to_string(),
        detail: detail.into(),
        started_at_ms: 0,
        finished_at_ms: Some(0),
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: attempt_id
            .and_then(|value| value.rsplit('-').next())
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1),
    }
}

pub(super) fn replan_execution_step(
    from: ChatExecutionStrategy,
    to: ChatExecutionStrategy,
) -> ArtifactOperatorStep {
    ArtifactOperatorStep {
        step_id: "replan_execution".to_string(),
        origin_prompt_event_id: String::new(),
        phase: ArtifactOperatorPhase::RepairArtifact,
        engine: "materialization".to_string(),
        status: ArtifactOperatorRunStatus::Complete,
        label: "Switch execution strategy".to_string(),
        detail: format!(
            "Chat hit a concrete blocker under {} and is continuing with {} so the artifact route can still finish.",
            super::execution_strategy_id(from).replace('_', " "),
            super::execution_strategy_id(to).replace('_', " ")
        ),
        started_at_ms: 0,
        finished_at_ms: Some(0),
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 1,
    }
}

pub(super) fn merge_operator_steps(
    existing: &mut Vec<ArtifactOperatorStep>,
    incoming: &[ArtifactOperatorStep],
) {
    for step in incoming {
        if let Some(current) = existing
            .iter_mut()
            .find(|candidate| candidate.step_id == step.step_id)
        {
            *current = step.clone();
        } else {
            existing.push(step.clone());
        }
    }
}

pub(super) fn latest_execution_live_preview(
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

pub(super) fn finalize_blocked_execution_envelope(
    execution_envelope: Option<ExecutionEnvelope>,
) -> Option<ExecutionEnvelope> {
    let mut execution_envelope = execution_envelope?;
    if let Some(invariant) = execution_envelope.completion_invariant.as_mut() {
        invariant.status = ExecutionCompletionInvariantStatus::Blocked;
        if invariant.summary.trim().is_empty() {
            invariant.summary =
                "Execution blocked before Chat satisfied the artifact completion invariant."
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

pub(super) fn finalize_latest_execution_preview(
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

pub(super) fn latest_author_attempt_id(steps: &[ArtifactOperatorStep]) -> Option<String> {
    steps
        .iter()
        .rev()
        .find(|step| step.phase == ArtifactOperatorPhase::AuthorArtifact)
        .map(|step| {
            if step.step_id.trim().is_empty() {
                format!("attempt-{}", step.attempt.max(1))
            } else {
                step.step_id.clone()
            }
        })
}

pub(super) fn emit_prepared_context_generation_progress(
    observer: Option<&ChatArtifactGenerationProgressObserver>,
    prepared_context: &ChatArtifactPlanningContext,
    execution_strategy: ChatExecutionStrategy,
) {
    let Some(observer) = observer else {
        return;
    };

    observer(ChatArtifactGenerationProgress {
        current_step: prepared_context_progress_message(execution_strategy),
        artifact_brief: Some(prepared_context.brief.clone()),
        preparation_needs: prepared_context.preparation_needs.clone(),
        prepared_context_resolution: prepared_context.prepared_context_resolution.clone(),
        skill_discovery_resolution: prepared_context.skill_discovery_resolution.clone(),
        blueprint: prepared_context.blueprint.clone(),
        artifact_ir: prepared_context.artifact_ir.clone(),
        selected_skills: prepared_context.selected_skills.clone(),
        retrieved_exemplars: prepared_context.retrieved_exemplars.clone(),
        retrieved_sources: prepared_context.retrieved_sources.clone(),
        execution_envelope: None,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
        validation: None,
        operator_steps: vec![ArtifactOperatorStep {
            step_id: "prepared_context".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ArtifactOperatorPhase::RouteArtifact,
            engine: "prepared_context".to_string(),
            status: ArtifactOperatorRunStatus::Complete,
            label: "Route artifact".to_string(),
            detail: prepared_context_progress_message(execution_strategy),
            started_at_ms: 0,
            finished_at_ms: Some(0),
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        }],
    });
}

pub(super) fn chat_proof_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_CHAT_PROOF_TRACE").is_some() {
        eprintln!("[chat-proof-trace] {}", message.as_ref());
    }
}
