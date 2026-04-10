use super::*;

pub(crate) fn emit_parent_playbook_receipt(
    service: &RuntimeAgentService,
    parent_session_id: [u8; 32],
    step_index: u32,
    playbook_id: &str,
    receipt: WorkloadParentPlaybookReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let _ = tx.send(KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
        session_id: parent_session_id,
        step_index,
        workload_id: format!("parent_playbook::{}", playbook_id),
        timestamp_ms: now_ms(),
        receipt: WorkloadReceipt::ParentPlaybook(receipt),
    }));
}

pub(crate) fn emit_parent_playbook_started_receipt(
    service: &RuntimeAgentService,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_index: u32,
) {
    let route_metadata = build_parent_playbook_route_receipt_metadata(playbook, run);
    let prep_metadata = build_parent_playbook_prep_receipt_metadata(run);
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__delegate".to_string(),
            phase: "started".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: None,
            step_label: None,
            child_session_id: None,
            template_id: None,
            workflow_id: None,
            route_family: route_metadata.route_family.clone(),
            topology: route_metadata.topology.clone(),
            planner_authority: route_metadata.planner_authority.clone(),
            verifier_state: route_metadata.verifier_state.clone(),
            verifier_role: route_metadata.verifier_role.clone(),
            verifier_outcome: route_metadata.verifier_outcome.clone(),
            selected_skills: prep_metadata.selected_skills,
            prep_summary: prep_metadata.prep_summary,
            artifact_generation: parent_playbook_artifact_generation(run),
            computer_use_perception: parent_playbook_computer_use_perception(run),
            research_scorecard: parent_playbook_research_scorecard(run),
            artifact_quality: parent_playbook_artifact_quality(run),
            computer_use_verification: parent_playbook_computer_use_verification(run),
            coding_scorecard: parent_playbook_coding_scorecard(run),
            patch_synthesis: parent_playbook_patch_synthesis(run),
            artifact_repair: parent_playbook_artifact_repair(run),
            computer_use_recovery: parent_playbook_computer_use_recovery(run),
            summary: summarize_parent_playbook_text(&format!(
                "Started parent playbook '{}' for topic '{}'.",
                run.playbook_label, run.topic
            )),
            error_class: None,
        },
    );
}

pub(crate) fn emit_parent_playbook_step_spawned_receipt(
    service: &RuntimeAgentService,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step: &ParentPlaybookStepRun,
    step_index: u32,
) {
    let route_metadata = build_parent_playbook_route_receipt_metadata(playbook, run);
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__delegate".to_string(),
            phase: "step_spawned".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: Some(step.step_id.clone()),
            step_label: Some(step.label.clone()),
            child_session_id: step.child_session_id.map(hex::encode),
            template_id: step.template_id.clone(),
            workflow_id: step.workflow_id.clone(),
            route_family: route_metadata.route_family.clone(),
            topology: route_metadata.topology.clone(),
            planner_authority: route_metadata.planner_authority.clone(),
            verifier_state: route_metadata.verifier_state.clone(),
            verifier_role: route_metadata.verifier_role.clone(),
            verifier_outcome: route_metadata.verifier_outcome.clone(),
            selected_skills: step.selected_skills.clone(),
            prep_summary: step.prep_summary.clone(),
            artifact_generation: step.artifact_generation.clone(),
            computer_use_perception: step.computer_use_perception.clone(),
            research_scorecard: step.research_scorecard.clone(),
            artifact_quality: step.artifact_quality.clone(),
            computer_use_verification: step.computer_use_verification.clone(),
            coding_scorecard: step.coding_scorecard.clone(),
            patch_synthesis: step.patch_synthesis.clone(),
            artifact_repair: step.artifact_repair.clone(),
            computer_use_recovery: step.computer_use_recovery.clone(),
            summary: summarize_parent_playbook_text(&format!(
                "Spawned '{}' step for playbook '{}' with child {}.",
                step.label,
                run.playbook_label,
                step.child_session_id
                    .map(hex::encode)
                    .unwrap_or_else(|| "unknown".to_string())
            )),
            error_class: None,
        },
    );
}

pub(crate) fn emit_parent_playbook_step_completed_receipt(
    service: &RuntimeAgentService,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step: &ParentPlaybookStepRun,
    step_index: u32,
) {
    let route_metadata = build_parent_playbook_route_receipt_metadata(playbook, run);
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "step_completed".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: Some(step.step_id.clone()),
            step_label: Some(step.label.clone()),
            child_session_id: step.child_session_id.map(hex::encode),
            template_id: step.template_id.clone(),
            workflow_id: step.workflow_id.clone(),
            route_family: route_metadata.route_family.clone(),
            topology: route_metadata.topology.clone(),
            planner_authority: route_metadata.planner_authority.clone(),
            verifier_state: route_metadata.verifier_state.clone(),
            verifier_role: route_metadata.verifier_role.clone(),
            verifier_outcome: route_metadata.verifier_outcome.clone(),
            selected_skills: step.selected_skills.clone(),
            prep_summary: step.prep_summary.clone(),
            artifact_generation: step.artifact_generation.clone(),
            computer_use_perception: step.computer_use_perception.clone(),
            research_scorecard: step.research_scorecard.clone(),
            artifact_quality: step.artifact_quality.clone(),
            computer_use_verification: step.computer_use_verification.clone(),
            coding_scorecard: step.coding_scorecard.clone(),
            patch_synthesis: step.patch_synthesis.clone(),
            artifact_repair: step.artifact_repair.clone(),
            computer_use_recovery: step.computer_use_recovery.clone(),
            summary: summarize_parent_playbook_text(
                step.output_preview
                    .as_deref()
                    .unwrap_or("Parent playbook step completed."),
            ),
            error_class: None,
        },
    );
}

pub(crate) fn emit_parent_playbook_blocked_receipt(
    service: &RuntimeAgentService,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step: Option<&ParentPlaybookStepRun>,
    step_index: u32,
    error: &str,
) {
    let route_metadata = build_parent_playbook_route_receipt_metadata(playbook, run);
    let prep_metadata = build_parent_playbook_prep_receipt_metadata(run);
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "blocked".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: false,
            step_id: step.map(|value| value.step_id.clone()),
            step_label: step.map(|value| value.label.clone()),
            child_session_id: step.and_then(|value| value.child_session_id.map(hex::encode)),
            template_id: step.and_then(|value| value.template_id.clone()),
            workflow_id: step.and_then(|value| value.workflow_id.clone()),
            route_family: route_metadata.route_family.clone(),
            topology: route_metadata.topology.clone(),
            planner_authority: route_metadata.planner_authority.clone(),
            verifier_state: route_metadata.verifier_state.clone(),
            verifier_role: route_metadata.verifier_role.clone(),
            verifier_outcome: route_metadata.verifier_outcome.clone(),
            selected_skills: step
                .map(|value| value.selected_skills.clone())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| prep_metadata.selected_skills.clone()),
            prep_summary: step
                .and_then(|value| value.prep_summary.clone())
                .or_else(|| prep_metadata.prep_summary.clone()),
            artifact_generation: step.and_then(|value| value.artifact_generation.clone()),
            computer_use_perception: step.and_then(|value| value.computer_use_perception.clone()),
            research_scorecard: step.and_then(|value| value.research_scorecard.clone()),
            artifact_quality: step.and_then(|value| value.artifact_quality.clone()),
            computer_use_verification: step
                .and_then(|value| value.computer_use_verification.clone()),
            coding_scorecard: step.and_then(|value| value.coding_scorecard.clone()),
            patch_synthesis: step.and_then(|value| value.patch_synthesis.clone()),
            artifact_repair: step.and_then(|value| value.artifact_repair.clone()),
            computer_use_recovery: step.and_then(|value| value.computer_use_recovery.clone()),
            summary: summarize_parent_playbook_text(error),
            error_class: extract_error_class_token(Some(error)).map(str::to_string),
        },
    );
}

pub(crate) fn emit_parent_playbook_completed_receipt(
    service: &RuntimeAgentService,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_index: u32,
) {
    let route_metadata = build_parent_playbook_route_receipt_metadata(playbook, run);
    let prep_metadata = build_parent_playbook_prep_receipt_metadata(run);
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "completed".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: None,
            step_label: None,
            child_session_id: None,
            template_id: None,
            workflow_id: None,
            route_family: route_metadata.route_family.clone(),
            topology: route_metadata.topology.clone(),
            planner_authority: route_metadata.planner_authority.clone(),
            verifier_state: route_metadata.verifier_state.clone(),
            verifier_role: route_metadata.verifier_role.clone(),
            verifier_outcome: route_metadata.verifier_outcome.clone(),
            selected_skills: prep_metadata.selected_skills,
            prep_summary: prep_metadata.prep_summary,
            artifact_generation: parent_playbook_artifact_generation(run),
            computer_use_perception: parent_playbook_computer_use_perception(run),
            research_scorecard: parent_playbook_research_scorecard(run),
            artifact_quality: parent_playbook_artifact_quality(run),
            computer_use_verification: parent_playbook_computer_use_verification(run),
            coding_scorecard: parent_playbook_coding_scorecard(run),
            patch_synthesis: parent_playbook_patch_synthesis(run),
            artifact_repair: parent_playbook_artifact_repair(run),
            computer_use_recovery: parent_playbook_computer_use_recovery(run),
            summary: summarize_parent_playbook_text(&format!(
                "Completed parent playbook '{}' across {} steps.",
                run.playbook_label,
                run.steps.len()
            )),
            error_class: None,
        },
    );
}

pub(crate) fn emit_worker_receipt(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
    receipt: WorkloadWorkerReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let _ = tx.send(KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
        session_id,
        step_index,
        workload_id,
        timestamp_ms: now_ms(),
        receipt: WorkloadReceipt::Worker(receipt),
    }));
}

pub(crate) fn worker_receipt_summary(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= 240 {
        trimmed.to_string()
    } else {
        let mut summary = trimmed.chars().take(240).collect::<String>();
        summary.push_str("...");
        summary
    }
}

pub(crate) fn emit_worker_completion_receipt(
    service: &RuntimeAgentService,
    result: &WorkerSessionResult,
    step_index: u32,
) {
    emit_worker_receipt(
        service,
        result.child_session_id,
        step_index,
        format!("worker::{}", hex::encode(result.child_session_id)),
        WorkloadWorkerReceipt {
            tool_name: "agent__delegate".to_string(),
            phase: "completed".to_string(),
            child_session_id: hex::encode(result.child_session_id),
            parent_session_id: hex::encode(result.parent_session_id),
            role: result.role.clone(),
            playbook_id: result.playbook_id.clone(),
            template_id: result.template_id.clone(),
            workflow_id: result.workflow_id.clone(),
            merge_mode: result.completion_contract.merge_mode.as_label().to_string(),
            status: result.status.clone(),
            success: result.success,
            summary: worker_receipt_summary(result.raw_output.as_deref().unwrap_or_else(|| {
                result
                    .error
                    .as_deref()
                    .unwrap_or("Worker completed without an explicit result.")
            })),
            verification_hint: result.completion_contract.verification_hint.clone(),
            error_class: extract_error_class_token(result.error.as_deref()).map(str::to_string),
        },
    );
}

pub(crate) fn emit_worker_merge_receipt(
    service: &RuntimeAgentService,
    result: &WorkerSessionResult,
    parent_step_index: u32,
) {
    emit_worker_receipt(
        service,
        result.parent_session_id,
        parent_step_index,
        format!("worker::{}::merge", hex::encode(result.child_session_id)),
        WorkloadWorkerReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "merged".to_string(),
            child_session_id: hex::encode(result.child_session_id),
            parent_session_id: hex::encode(result.parent_session_id),
            role: result.role.clone(),
            playbook_id: result.playbook_id.clone(),
            template_id: result.template_id.clone(),
            workflow_id: result.workflow_id.clone(),
            merge_mode: result.completion_contract.merge_mode.as_label().to_string(),
            status: result.status.clone(),
            success: result.success,
            summary: worker_receipt_summary(&result.merged_output),
            verification_hint: result.completion_contract.verification_hint.clone(),
            error_class: extract_error_class_token(result.error.as_deref()).map(str::to_string),
        },
    );
}
