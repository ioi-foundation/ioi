use super::*;

pub(crate) fn reset_parent_playbook_steps_from(run: &mut ParentPlaybookRun, step_idx: usize) {
    for step in run.steps.iter_mut().skip(step_idx) {
        step.status = ParentPlaybookStepStatus::Pending;
        step.child_session_id = None;
        step.template_id = None;
        step.workflow_id = None;
        step.goal = None;
        step.selected_skills.clear();
        step.prep_summary = None;
        step.artifact_generation = None;
        step.computer_use_perception = None;
        step.research_scorecard = None;
        step.artifact_quality = None;
        step.computer_use_verification = None;
        step.coding_scorecard = None;
        step.patch_synthesis = None;
        step.artifact_repair = None;
        step.computer_use_recovery = None;
        step.output_preview = None;
        step.error = None;
        step.spawned_at_ms = None;
        step.completed_at_ms = None;
        step.merged_at_ms = None;
    }
    run.completed_at_ms = None;
}

pub(crate) fn step_dependencies_satisfied(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
    step: &AgentPlaybookStepDefinition,
) -> bool {
    step.depends_on.iter().all(|dependency| {
        playbook
            .steps
            .iter()
            .position(|candidate| candidate.step_id == *dependency)
            .and_then(|index| run.steps.get(index))
            .map(|state| state.status == ParentPlaybookStepStatus::Completed)
            .unwrap_or(false)
    })
}

pub(crate) fn next_ready_playbook_step_index(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
) -> Option<usize> {
    playbook.steps.iter().enumerate().find_map(|(index, step)| {
        let current = run.steps.get(index)?;
        if current.status != ParentPlaybookStepStatus::Pending {
            return None;
        }
        step_dependencies_satisfied(playbook, run, step).then_some(index)
    })
}

pub(crate) fn compact_research_scorecard_text(scorecard: &ResearchVerificationScorecard) -> String {
    format!(
        "research_verification={} sources={} domains={} freshness={} quotes={}",
        scorecard.verdict,
        scorecard.source_count,
        scorecard.distinct_domain_count,
        scorecard.freshness_status,
        scorecard.quote_grounding_status
    )
}

pub(crate) fn compact_artifact_generation_text(summary: &ArtifactGenerationSummary) -> String {
    format!(
        "artifact_generation={} files={} verification={} presentation={}",
        summary.status,
        summary.produced_file_count,
        summary.verification_signal_status,
        summary.presentation_status
    )
}

pub(crate) fn compact_computer_use_perception_text(
    summary: &ComputerUsePerceptionSummary,
) -> String {
    format!(
        "computer_use_perception={} ui_state={} approval_risk={}",
        summary.surface_status, summary.ui_state, summary.approval_risk
    )
}

pub(crate) fn compact_artifact_quality_text(scorecard: &ArtifactQualityScorecard) -> String {
    format!(
        "artifact_quality={} fidelity={} presentation={} repair={}",
        scorecard.verdict,
        scorecard.fidelity_status,
        scorecard.presentation_status,
        scorecard.repair_status
    )
}

pub(crate) fn compact_coding_scorecard_text(scorecard: &CodingVerificationScorecard) -> String {
    format!(
        "coding_verification={} targeted_passed={}/{} widening={} regressions={}",
        scorecard.verdict,
        scorecard.targeted_pass_count,
        scorecard.targeted_command_count,
        scorecard.widening_status,
        scorecard.regression_status
    )
}

pub(crate) fn compact_computer_use_verification_text(
    scorecard: &ComputerUseVerificationScorecard,
) -> String {
    format!(
        "computer_use_verification={} postcondition={} approval={} recovery={}",
        scorecard.verdict,
        scorecard.postcondition_status,
        scorecard.approval_state,
        scorecard.recovery_status
    )
}

pub(crate) fn compact_patch_synthesis_text(summary: &PatchSynthesisSummary) -> String {
    format!(
        "patch_synthesis={} touched_files={} verification_ready={}",
        summary.status, summary.touched_file_count, summary.verification_ready
    )
}

pub(crate) fn compact_artifact_repair_text(summary: &ArtifactRepairSummary) -> String {
    format!("artifact_repair={}", summary.status)
}

pub(crate) fn compact_computer_use_recovery_text(summary: &ComputerUseRecoverySummary) -> String {
    format!("computer_use_recovery={}", summary.status)
}

pub(crate) fn parent_playbook_step_context(step: &ParentPlaybookStepRun) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(preview) = step
        .output_preview
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        parts.push(preview.trim().to_string());
    }
    if let Some(prep) = step
        .prep_summary
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        parts.push(format!("prep={}", prep.trim()));
    }
    if !step.selected_skills.is_empty() {
        parts.push(format!("skills={}", step.selected_skills.join(", ")));
    }
    if let Some(summary) = step.computer_use_perception.as_ref() {
        parts.push(compact_computer_use_perception_text(summary));
    }
    if let Some(summary) = step.artifact_generation.as_ref() {
        parts.push(compact_artifact_generation_text(summary));
    }
    if let Some(scorecard) = step.research_scorecard.as_ref() {
        parts.push(compact_research_scorecard_text(scorecard));
    }
    if let Some(scorecard) = step.artifact_quality.as_ref() {
        parts.push(compact_artifact_quality_text(scorecard));
    }
    if let Some(scorecard) = step.computer_use_verification.as_ref() {
        parts.push(compact_computer_use_verification_text(scorecard));
    }
    if let Some(scorecard) = step.coding_scorecard.as_ref() {
        parts.push(compact_coding_scorecard_text(scorecard));
    }
    if let Some(summary) = step.patch_synthesis.as_ref() {
        parts.push(compact_patch_synthesis_text(summary));
    }
    if let Some(summary) = step.artifact_repair.as_ref() {
        parts.push(compact_artifact_repair_text(summary));
    }
    if let Some(summary) = step.computer_use_recovery.as_ref() {
        parts.push(compact_computer_use_recovery_text(summary));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" | "))
    }
}

pub(crate) fn collect_completed_dependency_contexts(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
    step_id: &str,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<String>,
) {
    let Some(step_definition) = playbook.steps.iter().find(|step| step.step_id == step_id) else {
        return;
    };
    for dependency in &step_definition.depends_on {
        if !seen.insert(dependency.clone()) {
            continue;
        }
        collect_completed_dependency_contexts(playbook, run, dependency, seen, out);
        let Some(index) = playbook
            .steps
            .iter()
            .position(|candidate| candidate.step_id == *dependency)
        else {
            continue;
        };
        let Some(step_run) = run.steps.get(index) else {
            continue;
        };
        if step_run.status != ParentPlaybookStepStatus::Completed {
            continue;
        }
        let Some(context) = parent_playbook_step_context(step_run) else {
            continue;
        };
        out.push(format!(
            "- {} ({}): {}",
            step_run.label, step_run.step_id, context
        ));
    }
}

pub(crate) fn compact_parent_playbook_context(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let mut summary = trimmed.chars().take(max_chars).collect::<String>();
        summary.push_str("...");
        summary
    }
}

pub(crate) fn inject_parent_playbook_context(
    state: &dyn StateAccess,
    goal: &str,
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
    next_step: &AgentPlaybookStepDefinition,
) -> String {
    let mut dependency_lines = Vec::new();
    let mut seen = BTreeSet::new();
    collect_completed_dependency_contexts(
        playbook,
        run,
        &next_step.step_id,
        &mut seen,
        &mut dependency_lines,
    );
    if dependency_lines.is_empty() {
        return goal.to_string();
    }
    if run.playbook_id.trim() == "citation_grounded_brief"
        && next_step.worker_workflow_id.trim() == "citation_audit"
    {
        if let Some(research_handoff) = load_step_raw_output(state, run, "research")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Gather current sources full_handoff (research_full): {}",
                research_handoff
            ));
        }
    }
    if run.playbook_id.trim() == "evidence_audited_patch"
        && next_step.worker_workflow_id.trim() == "targeted_test_audit"
    {
        if let Some(implement_handoff) = load_step_raw_output(state, run, "implement")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Patch the workspace full_handoff (implement_full): {}",
                implement_handoff
            ));
        }
    }
    if run.playbook_id.trim() == "evidence_audited_patch"
        && next_step.worker_workflow_id.trim() == "patch_synthesis_handoff"
    {
        if let Some(implement_handoff) = load_step_raw_output(state, run, "implement")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Patch the workspace full_handoff (implement_full):\n{}",
                implement_handoff
            ));
        }
        if let Some(verify_handoff) = load_step_raw_output(state, run, "verify")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Verify targeted tests full_handoff (verify_full):\n{}",
                verify_handoff
            ));
        }
    }

    format!(
        "{}\n\n{}\n{}",
        goal,
        PARENT_PLAYBOOK_CONTEXT_MARKER,
        dependency_lines.join("\n")
    )
}

pub(crate) fn synthesize_parent_playbook_tool_hash(
    parent_session_id: [u8; 32],
    playbook_id: &str,
    step_id: &str,
    parent_step_index: u32,
) -> Result<[u8; 32], String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ioi::parent_playbook_step::v1::");
    payload.extend_from_slice(parent_session_id.as_slice());
    payload.extend_from_slice(playbook_id.as_bytes());
    payload.extend_from_slice(step_id.as_bytes());
    payload.extend_from_slice(&parent_step_index.to_le_bytes());
    sha256(payload).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to hash parent playbook step payload: {}",
            error
        )
    })
}

pub(crate) fn parent_playbook_completion_output(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    result: &WorkerSessionResult,
) -> String {
    if run.playbook_id.trim() == "citation_grounded_brief" {
        let research_output = load_step_raw_output(state, run, "research").unwrap_or_default();
        let verification_output = load_step_raw_output(state, run, "verify")
            .or_else(|| result.raw_output.clone())
            .unwrap_or_else(|| result.merged_output.clone());
        let research_output = research_output.trim();
        let verification_output = verification_output.trim();
        if !research_output.is_empty() {
            if verification_output.is_empty() {
                return research_output.to_string();
            }
            return format!(
                "{}\n\nVerification verdict\n{}",
                research_output, verification_output
            );
        }
    }

    playbook
        .steps
        .iter()
        .rev()
        .find_map(|step| load_step_raw_output(state, run, &step.step_id))
        .or_else(|| result.raw_output.clone())
        .unwrap_or_else(|| result.merged_output.clone())
}

pub(crate) fn mark_parent_playbook_step_completed_from_result(
    state: &dyn StateAccess,
    run: &mut ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
    timestamp_ms: u64,
) {
    let artifact_generation = build_artifact_generation_summary(run, playbook, step_idx, result);
    let computer_use_perception =
        build_computer_use_perception_summary(state, run, playbook, step_idx, result);
    let research_scorecard =
        build_research_verification_scorecard(state, run, playbook, step_idx, result);
    let artifact_quality = build_artifact_quality_scorecard(run, playbook, step_idx, result);
    let computer_use_verification =
        build_computer_use_verification_scorecard(state, run, playbook, step_idx, result);
    let coding_scorecard =
        build_coding_verification_scorecard(state, run, playbook, step_idx, result);
    let patch_synthesis = build_patch_synthesis_summary(state, run, playbook, step_idx, result);
    let artifact_repair = build_artifact_repair_summary(run, playbook, step_idx, result);
    let computer_use_recovery =
        build_computer_use_recovery_summary(state, run, playbook, step_idx, result);
    if let Some(step) = run.steps.get_mut(step_idx) {
        step.status = ParentPlaybookStepStatus::Completed;
        step.output_preview = Some(summarize_parent_playbook_text(&result.merged_output));
        step.error = result.error.clone();
        step.artifact_generation = artifact_generation;
        step.computer_use_perception = computer_use_perception;
        step.research_scorecard = research_scorecard;
        step.artifact_quality = artifact_quality;
        step.computer_use_verification = computer_use_verification;
        step.coding_scorecard = coding_scorecard;
        step.patch_synthesis = patch_synthesis;
        step.artifact_repair = artifact_repair;
        step.computer_use_recovery = computer_use_recovery;
        step.completed_at_ms = Some(result.completed_at_ms);
        step.merged_at_ms = Some(timestamp_ms);
    }
    run.current_step_index = step_idx as u32;
    run.active_child_session_id = None;
    run.updated_at_ms = timestamp_ms;
}
