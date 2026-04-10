use super::*;

fn completed_worker_supports_verifier_bootstrap_automerge(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    result: &WorkerSessionResult,
) -> Result<bool, String> {
    let child_session_id_hex = hex::encode(result.child_session_id);
    let child_state = load_child_state(
        state,
        service.memory_runtime.as_ref(),
        result.child_session_id,
        &child_session_id_hex,
    )?;
    let Some(assignment) = load_worker_assignment(state, result.child_session_id)? else {
        return Ok(false);
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return Ok(false);
    }

    Ok(
        latest_workspace_edit_step(&child_state).is_some()
            && latest_successful_goal_command_after_edit(&child_state, &assignment).is_some(),
    )
}

fn spawned_playbook_child_allows_immediate_automerge(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    next_step: &AgentPlaybookStepDefinition,
    result: &WorkerSessionResult,
) -> Result<bool, String> {
    match next_step.worker_workflow_id.trim() {
        "citation_audit" => return Ok(false),
        "targeted_test_audit" => {}
        _ => return Ok(true),
    }

    completed_worker_supports_verifier_bootstrap_automerge(service, state, result)
}

pub(crate) fn register_parent_playbook_step_spawn(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &AgentState,
    parent_step_index: u32,
    child_session_id: [u8; 32],
    assignment: &WorkerAssignment,
    prep_bundle: &DelegatedChildPrepBundle,
) -> Result<(), String> {
    let Some(playbook_id) = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let Some(playbook) = builtin_agent_playbook(Some(playbook_id)) else {
        return Ok(());
    };

    let timestamp_ms = now_ms();
    let mut started = false;
    let mut run = match load_parent_playbook_run(state, parent_state.session_id, playbook_id)? {
        Some(existing) => existing,
        None => {
            started = true;
            build_parent_playbook_run(parent_state, &playbook, timestamp_ms)
        }
    };
    let Some(step_idx) = find_playbook_step_index(
        &playbook,
        assignment.template_id.as_deref(),
        assignment.workflow_id.as_deref(),
    ) else {
        return Ok(());
    };
    let already_registered = run
        .steps
        .get(step_idx)
        .map(|step| step.child_session_id == Some(child_session_id))
        .unwrap_or(false);
    if already_registered {
        return Ok(());
    }
    if started {
        for prior_step in run.steps.iter_mut().take(step_idx) {
            prior_step.status = ParentPlaybookStepStatus::Completed;
            prior_step.output_preview =
                Some("Bootstrap assumed satisfied before active step.".to_string());
            prior_step.completed_at_ms = Some(timestamp_ms);
            prior_step.merged_at_ms = Some(timestamp_ms);
        }
    } else {
        reset_parent_playbook_steps_from(&mut run, step_idx);
    }

    run.status = ParentPlaybookStatus::Running;
    run.current_step_index = step_idx as u32;
    run.active_child_session_id = Some(child_session_id);
    run.updated_at_ms = timestamp_ms;
    if let Some(step) = run.steps.get_mut(step_idx) {
        step.status = ParentPlaybookStepStatus::Running;
        step.child_session_id = Some(child_session_id);
        step.template_id = assignment.template_id.clone();
        step.workflow_id = assignment.workflow_id.clone();
        step.goal = Some(assignment.goal.clone());
        step.selected_skills = prep_bundle.selected_skills.clone();
        step.prep_summary = prep_bundle.prep_summary.clone();
        step.artifact_generation = None;
        step.computer_use_perception = None;
        step.research_scorecard = None;
        step.artifact_quality = None;
        step.computer_use_verification = None;
        step.coding_scorecard = None;
        step.patch_synthesis = None;
        step.artifact_repair = None;
        step.computer_use_recovery = None;
        step.error = None;
        step.output_preview = None;
        step.spawned_at_ms = Some(timestamp_ms);
        step.completed_at_ms = None;
        step.merged_at_ms = None;
    }
    persist_parent_playbook_run(state, &run)?;
    if started {
        emit_parent_playbook_started_receipt(service, &run, &playbook, parent_step_index);
    }
    if let Some(step) = run.steps.get(step_idx) {
        emit_parent_playbook_step_spawned_receipt(
            service,
            &run,
            &playbook,
            step,
            parent_step_index,
        );
    }
    Ok(())
}

pub(crate) async fn advance_parent_playbook_after_worker_merge(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    result: &WorkerSessionResult,
) -> Result<Option<String>, String> {
    let Some(playbook_id) = result
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(playbook) = builtin_agent_playbook(Some(playbook_id)) else {
        return Ok(None);
    };
    let Some(mut run) = load_parent_playbook_run(state, parent_state.session_id, playbook_id)?
    else {
        return Ok(None);
    };
    let Some(step_idx) = find_run_step_index_by_child(&run, result.child_session_id) else {
        return Ok(None);
    };
    let timestamp_ms = now_ms();
    mark_parent_playbook_step_completed_from_result(
        state,
        &mut run,
        &playbook,
        step_idx,
        result,
        timestamp_ms,
    );
    persist_parent_playbook_run(state, &run)?;
    if let Some(step) = run.steps.get(step_idx) {
        emit_parent_playbook_step_completed_receipt(
            service,
            &run,
            &playbook,
            step,
            parent_step_index,
        );
    }

    let Some(next_step_idx) = next_ready_playbook_step_index(&playbook, &run) else {
        run.status = ParentPlaybookStatus::Completed;
        run.completed_at_ms = Some(timestamp_ms);
        run.updated_at_ms = timestamp_ms;
        persist_parent_playbook_run(state, &run)?;
        parent_state.status = AgentStatus::Completed(Some(parent_playbook_completion_output(
            state, &run, &playbook, result,
        )));
        emit_parent_playbook_completed_receipt(service, &run, &playbook, parent_step_index);
        return Ok(Some(format!(
            "Parent playbook '{}' completed.",
            run.playbook_label
        )));
    };

    let next_step = playbook.steps.get(next_step_idx).cloned().ok_or_else(|| {
        "ERROR_CLASS=UnexpectedState Next parent playbook step was missing.".to_string()
    })?;
    let topic = run.topic.trim();
    let goal = next_step.goal_template.replace(
        "{topic}",
        if topic.is_empty() {
            parent_state.goal.trim()
        } else {
            topic
        },
    );
    let goal = inject_parent_playbook_context(state, &goal, &playbook, &run, &next_step);
    let tool_hash = synthesize_parent_playbook_tool_hash(
        parent_state.session_id,
        &run.playbook_id,
        &next_step.step_id,
        parent_step_index,
    )?;
    match spawn_delegated_child_session(
        service,
        state,
        parent_state,
        tool_hash,
        &goal,
        playbook.default_budget,
        Some(&run.playbook_id),
        Some(&next_step.worker_template_id),
        Some(&next_step.worker_workflow_id),
        None,
        None,
        None,
        None,
        parent_step_index,
        block_height,
    )
    .await
    {
        Ok(spawned) => {
            let mut updates = vec![format!(
                "Parent playbook '{}' advanced to '{}' (child {}).",
                run.playbook_label,
                next_step.label,
                hex::encode(spawned.child_session_id)
            )];

            if spawned_playbook_child_allows_immediate_automerge(service, state, &next_step, result)?
            {
                let spawned_child_session_id_hex = hex::encode(spawned.child_session_id);
                let spawned_child_state = load_child_state(
                    state,
                    service.memory_runtime.as_ref(),
                    spawned.child_session_id,
                    &spawned_child_session_id_hex,
                )?;
                if matches!(
                    spawned_child_state.status,
                    AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Terminated
                ) {
                    let merged_output = Box::pin(
                        super::await_loop::merge_terminal_child_worker_result(
                        service,
                        state,
                        parent_state,
                        parent_step_index,
                        block_height,
                        &spawned_child_session_id_hex,
                        &spawned_child_state,
                    ),
                    )
                    .await?;
                    updates.push(merged_output);
                }
            }

            Ok(Some(updates.join("\n\n")))
        }
        Err(error) => {
            let error_text = error.to_string();
            run.status = ParentPlaybookStatus::Blocked;
            run.current_step_index = next_step_idx as u32;
            run.updated_at_ms = now_ms();
            parent_state.status = parent_playbook_terminal_status_for_block(&error_text, None);
            if let Some(step) = run.steps.get_mut(next_step_idx) {
                step.status = ParentPlaybookStepStatus::Blocked;
                step.error = Some(error_text.clone());
            }
            persist_parent_playbook_run(state, &run)?;
            emit_parent_playbook_blocked_receipt(
                service,
                &run,
                &playbook,
                run.steps.get(next_step_idx),
                parent_step_index,
                &error_text,
            );
            Ok(Some(format!(
                "Parent playbook '{}' blocked while advancing to '{}': {}",
                run.playbook_label, next_step.label, error_text
            )))
        }
    }
}

pub(crate) fn block_parent_playbook_after_worker_failure(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    result: &WorkerSessionResult,
) -> Result<Option<String>, String> {
    let Some(playbook_id) = result
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(playbook) = builtin_agent_playbook(Some(playbook_id)) else {
        return Ok(None);
    };
    let Some(mut run) = load_parent_playbook_run(state, parent_state.session_id, playbook_id)?
    else {
        return Ok(None);
    };
    let Some(step_idx) = find_run_step_index_by_child(&run, result.child_session_id) else {
        return Ok(None);
    };
    let timestamp_ms = now_ms();
    let summary_text = if result.merged_output.trim().is_empty() {
        result
            .error
            .as_deref()
            .unwrap_or("Worker failed without an explicit result.")
    } else {
        result.merged_output.as_str()
    };
    if let Some(step) = run.steps.get_mut(step_idx) {
        step.status = ParentPlaybookStepStatus::Blocked;
        step.output_preview = Some(summarize_parent_playbook_text(summary_text));
        step.error = result.error.clone();
        step.completed_at_ms = Some(result.completed_at_ms);
        step.merged_at_ms = Some(timestamp_ms);
    }
    parent_state.status = parent_playbook_terminal_status_for_block(
        result.error.as_deref().unwrap_or(summary_text),
        Some(result.status.as_str()),
    );
    run.status = ParentPlaybookStatus::Blocked;
    run.current_step_index = step_idx as u32;
    run.active_child_session_id = None;
    run.updated_at_ms = timestamp_ms;
    persist_parent_playbook_run(state, &run)?;
    emit_parent_playbook_blocked_receipt(
        service,
        &run,
        &playbook,
        run.steps.get(step_idx),
        parent_step_index,
        result.error.as_deref().unwrap_or(summary_text),
    );
    let step_label = run
        .steps
        .get(step_idx)
        .map(|step| step.label.as_str())
        .unwrap_or("delegated step");
    Ok(Some(format!(
        "Parent playbook '{}' blocked at '{}': {}",
        run.playbook_label, step_label, summary_text
    )))
}

pub(crate) fn merged_worker_output(
    assignment: &WorkerAssignment,
    success: bool,
    raw_output: Option<&str>,
    error: Option<&str>,
) -> String {
    let role = assignment
        .role
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Worker");
    let goal = assignment.goal.trim();
    let body = raw_output
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if success {
                assignment.completion_contract.expected_output.trim()
            } else {
                error.unwrap_or("Worker completed without an explicit result.")
            }
        });
    let verification = assignment
        .completion_contract
        .verification_hint
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let playbook_line = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|playbook_id| format!("Parent playbook: {}", playbook_id));
    let workflow = builtin_worker_workflow(
        assignment.template_id.as_deref(),
        assignment.workflow_id.as_deref(),
    );
    let workflow_line = workflow
        .as_ref()
        .map(|workflow| format!("Playbook: {} ({})", workflow.label, workflow.workflow_id));

    match assignment.completion_contract.merge_mode {
        WorkerMergeMode::AppendSummaryToParent => {
            let mut out = format!("{role} handoff\nGoal: {goal}");
            if let Some(playbook_line) = playbook_line.as_deref() {
                out.push_str(&format!("\n{playbook_line}"));
            }
            if let Some(workflow_line) = workflow_line.as_deref() {
                out.push_str(&format!("\n{workflow_line}"));
            }
            out.push_str(&format!("\n\n{body}"));
            if let Some(hint) = verification {
                out.push_str(&format!("\n\nVerification: {hint}"));
            }
            out
        }
        WorkerMergeMode::AppendAsEvidence => {
            let mut out = format!("Worker evidence\nRole: {role}\nGoal: {goal}",);
            if let Some(playbook_line) = playbook_line.as_deref() {
                out.push_str(&format!("\n{playbook_line}"));
            }
            if let Some(workflow_line) = workflow_line.as_deref() {
                out.push_str(&format!("\n{workflow_line}"));
            }
            out.push_str(&format!(
                "\nSuccess criteria: {}\n\n{body}",
                assignment.completion_contract.success_criteria
            ));
            if let Some(hint) = verification {
                out.push_str(&format!("\n\nVerification hint: {hint}"));
            }
            out
        }
        WorkerMergeMode::ReplaceParentDraft => body.to_string(),
        WorkerMergeMode::CompletionMessage => {
            if success {
                format!("{role} completed delegated work: {body}")
            } else {
                format!("{role} failed delegated work: {body}")
            }
        }
    }
}

pub(crate) fn materialize_worker_result(
    state: &mut dyn StateAccess,
    child_state: &AgentState,
) -> Result<WorkerSessionResult, String> {
    let child_session_id = child_state.session_id;
    let parent_session_id = child_state.parent_session_id.ok_or_else(|| {
        "ERROR_CLASS=UnexpectedState Child session is missing a parent session.".to_string()
    })?;

    let mut assignment =
        load_worker_assignment(state, child_session_id)?.unwrap_or_else(|| WorkerAssignment {
            step_key: format!("delegate:{}", hex::encode(&child_session_id[..4])),
            budget: child_state.budget,
            goal: child_state.goal.clone(),
            success_criteria: "Complete the delegated goal and return a deterministic handoff."
                .to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(child_session_id),
            status: "running".to_string(),
            playbook_id: None,
            template_id: None,
            workflow_id: None,
            role: Some("Sub-Worker".to_string()),
            allowed_tools: Vec::new(),
            completion_contract: WorkerCompletionContract {
                success_criteria: "Complete the delegated goal and return a deterministic handoff."
                    .to_string(),
                expected_output: "Delegated worker handoff summarizing the completed slice."
                    .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        });

    let (status, success, raw_output, error) = match &child_state.status {
        AgentStatus::Completed(result) => {
            let explicit_result = result
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let explicit_result = maybe_enrich_patch_build_verify_completion_result(
                child_state,
                &assignment,
                explicit_result,
            );
            let explicit_result = maybe_enrich_patch_synthesis_completion_result(
                state,
                parent_session_id,
                &assignment,
                explicit_result,
            );
            if explicit_result.is_none() {
                (
                    "Failed".to_string(),
                    false,
                    None,
                    Some(
                        "ERROR_CLASS=IncompleteWorkerResult Delegated worker completed without an explicit result."
                            .to_string(),
                    ),
                )
            } else {
                (
                    "Completed".to_string(),
                    true,
                    explicit_result,
                    None::<String>,
                )
            }
        }
        AgentStatus::Failed(reason) => ("Failed".to_string(), false, None, Some(reason.clone())),
        AgentStatus::Paused(reason) => (
            "Paused".to_string(),
            false,
            None,
            Some(materialize_paused_worker_error(reason)),
        ),
        AgentStatus::Terminated => (
            "Terminated".to_string(),
            false,
            None,
            Some("Child agent terminated.".to_string()),
        ),
        AgentStatus::Running | AgentStatus::Idle => {
            return Err(
                "ERROR_CLASS=UnexpectedState Child worker is not in a terminal state.".to_string(),
            );
        }
    };

    assignment.status = status.clone();
    persist_worker_assignment(state, child_session_id, &assignment).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist worker assignment update: {}",
            error
        )
    })?;

    Ok(WorkerSessionResult {
        child_session_id,
        parent_session_id,
        budget: assignment.budget,
        playbook_id: assignment.playbook_id.clone(),
        template_id: assignment.template_id.clone(),
        workflow_id: assignment.workflow_id.clone(),
        role: assignment
            .role
            .clone()
            .unwrap_or_else(|| "Sub-Worker".to_string()),
        goal: assignment.goal.clone(),
        status,
        success,
        error: error.clone(),
        raw_output: raw_output.clone(),
        merged_output: merged_worker_output(
            &assignment,
            success,
            raw_output.as_deref(),
            error.as_deref(),
        ),
        completion_contract: assignment.completion_contract.clone(),
        completed_at_ms: now_ms(),
        merged_at_ms: None,
        merged_step_index: None,
    })
}

pub(crate) fn load_or_materialize_worker_result(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    child_state: &AgentState,
    child_session_id: [u8; 32],
) -> Result<WorkerSessionResult, String> {
    match load_worker_session_result(state, child_session_id)? {
        Some(existing) => Ok(existing),
        None => {
            let materialized = materialize_worker_result(state, child_state)?;
            persist_worker_session_result(state, &materialized)?;
            emit_worker_completion_receipt(service, &materialized, child_state.step_count);
            Ok(materialized)
        }
    }
}

pub(crate) fn materialize_paused_worker_error(reason: &str) -> String {
    if extract_error_class_token(Some(reason)).is_some() {
        reason.to_string()
    } else {
        format!("ERROR_CLASS=UserInterventionNeeded {}", reason.trim())
    }
}

pub(crate) fn parent_playbook_terminal_status_for_block(
    reason: &str,
    worker_status: Option<&str>,
) -> AgentStatus {
    let reason = reason.trim();
    let reason = if reason.is_empty() {
        "Parent playbook blocked without an explicit reason."
    } else {
        reason
    };
    let needs_user_intervention = matches!(worker_status, Some("Paused"))
        || matches!(
            extract_error_class_token(Some(reason)),
            Some("UserInterventionNeeded")
        );
    if needs_user_intervention {
        AgentStatus::Paused(reason.to_string())
    } else {
        AgentStatus::Failed(reason.to_string())
    }
}
