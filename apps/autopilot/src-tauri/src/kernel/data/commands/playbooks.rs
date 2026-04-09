fn seed_parent_playbook_step_records(
    playbook: Option<&crate::models::LocalEngineAgentPlaybookRecord>,
) -> Vec<crate::models::LocalEngineParentPlaybookStepRunRecord> {
    playbook
        .map(|playbook| {
            playbook
                .steps
                .iter()
                .map(
                    |step| crate::models::LocalEngineParentPlaybookStepRunRecord {
                        step_id: step.step_id.clone(),
                        label: step.label.clone(),
                        summary: step.summary.clone(),
                        status: "pending".to_string(),
                        child_session_id: None,
                        template_id: Some(step.worker_template_id.clone()),
                        workflow_id: Some(step.worker_workflow_id.clone()),
                        updated_at_ms: None,
                        completed_at_ms: None,
                        error_class: None,
                        receipts: Vec::new(),
                    },
                )
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn ensure_parent_playbook_step_index(
    run: &mut crate::models::LocalEngineParentPlaybookRunRecord,
    playbook: Option<&crate::models::LocalEngineAgentPlaybookRecord>,
    step_id: &str,
    step_label: Option<&str>,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
) -> usize {
    if let Some(index) = run.steps.iter().position(|step| step.step_id == step_id) {
        return index;
    }

    if let Some(playbook) = playbook {
        if let Some(step) = playbook.steps.iter().find(|step| step.step_id == step_id) {
            run.steps
                .push(crate::models::LocalEngineParentPlaybookStepRunRecord {
                    step_id: step.step_id.clone(),
                    label: step.label.clone(),
                    summary: step.summary.clone(),
                    status: "pending".to_string(),
                    child_session_id: None,
                    template_id: Some(step.worker_template_id.clone()),
                    workflow_id: Some(step.worker_workflow_id.clone()),
                    updated_at_ms: None,
                    completed_at_ms: None,
                    error_class: None,
                    receipts: Vec::new(),
                });
            return run.steps.len().saturating_sub(1);
        }
    }

    run.steps
        .push(crate::models::LocalEngineParentPlaybookStepRunRecord {
            step_id: step_id.to_string(),
            label: step_label
                .map(str::to_string)
                .unwrap_or_else(|| humanize_token(step_id)),
            summary: "Observed runtime step".to_string(),
            status: "pending".to_string(),
            child_session_id: None,
            template_id: template_id.map(str::to_string),
            workflow_id: workflow_id.map(str::to_string),
            updated_at_ms: None,
            completed_at_ms: None,
            error_class: None,
            receipts: Vec::new(),
        });
    run.steps.len().saturating_sub(1)
}

fn ingest_parent_playbook_events(
    session_id: &str,
    events: &[crate::models::AgentEvent],
    playbook_specs: &BTreeMap<String, crate::models::LocalEngineAgentPlaybookRecord>,
    runs: &mut BTreeMap<String, crate::models::LocalEngineParentPlaybookRunRecord>,
) {
    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|left, right| {
        parse_event_timestamp_ms(left)
            .cmp(&parse_event_timestamp_ms(right))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    for event in sorted_events {
        let Some(digest) = event.digest.as_object() else {
            continue;
        };
        if digest.get("kind").and_then(Value::as_str).map(str::trim) != Some("parent_playbook") {
            continue;
        }

        let Some(playbook_id) = digest
            .get("playbook_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            continue;
        };

        let parent_session_id = json_string(&event.details, "parent_session_id")
            .unwrap_or_else(|| session_id.to_string());
        let playbook = playbook_specs.get(&playbook_id);
        let playbook_label = digest
            .get("playbook_label")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| playbook.map(|record| record.label.clone()))
            .unwrap_or_else(|| humanize_token(&playbook_id));
        let timestamp_ms = parse_event_timestamp_ms(&event);
        let run_id = format!("{}:{}", parent_session_id, playbook_id);
        let phase = digest
            .get("phase")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("observed");
        let status = digest
            .get("status")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| event_status_label(&event.status));
        let summary = json_string(&event.details, "summary").unwrap_or_else(|| event.title.clone());
        let step_id = json_string(&event.details, "step_id");
        let step_label = json_string(&event.details, "step_label");
        let child_session_id = json_string(&event.details, "child_session_id");
        let template_id = json_string(&event.details, "template_id");
        let workflow_id = json_string(&event.details, "workflow_id");
        let error_class = digest
            .get("error_class")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let success = digest
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(event.status, EventStatus::Success));

        let run = runs.entry(run_id.clone()).or_insert_with(|| {
            crate::models::LocalEngineParentPlaybookRunRecord {
                run_id: run_id.clone(),
                parent_session_id: parent_session_id.clone(),
                playbook_id: playbook_id.clone(),
                playbook_label: playbook_label.clone(),
                status: status.to_string(),
                latest_phase: phase.to_string(),
                summary: playbook
                    .map(|record| record.summary.clone())
                    .unwrap_or_else(|| format!("Observed parent playbook '{}'.", playbook_label)),
                current_step_id: None,
                current_step_label: None,
                active_child_session_id: None,
                started_at_ms: timestamp_ms,
                updated_at_ms: timestamp_ms,
                completed_at_ms: None,
                error_class: None,
                steps: seed_parent_playbook_step_records(playbook),
            }
        });

        run.playbook_label = playbook_label;
        run.status = status.to_string();
        run.latest_phase = phase.to_string();
        run.summary = summary.clone();
        run.updated_at_ms = run.updated_at_ms.max(timestamp_ms);
        run.started_at_ms = run.started_at_ms.min(timestamp_ms);
        if let Some(error_class) = error_class.clone() {
            run.error_class = Some(error_class);
        }

        if phase == "completed" || matches!(status, "completed" | "failed") {
            run.completed_at_ms = Some(timestamp_ms);
            run.active_child_session_id = None;
        }

        if let Some(step_id) = step_id.as_deref() {
            let step_index = ensure_parent_playbook_step_index(
                run,
                playbook,
                step_id,
                step_label.as_deref(),
                template_id.as_deref(),
                workflow_id.as_deref(),
            );
            let step = &mut run.steps[step_index];
            step.summary = summary.clone();
            step.updated_at_ms = Some(timestamp_ms);
            if let Some(child_session_id) = child_session_id.clone() {
                step.child_session_id = Some(child_session_id);
            }
            if let Some(template_id) = template_id.clone() {
                step.template_id = Some(template_id);
            }
            if let Some(workflow_id) = workflow_id.clone() {
                step.workflow_id = Some(workflow_id);
            }
            if let Some(error_class) = error_class.clone() {
                step.error_class = Some(error_class);
            }

            match phase {
                "step_spawned" => {
                    step.status = "running".to_string();
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    run.active_child_session_id = child_session_id.clone();
                }
                "operator_retry_requested" | "operator_resume_requested" => {
                    step.status = "running".to_string();
                    step.completed_at_ms = None;
                    step.error_class = None;
                    run.status = "running".to_string();
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    run.active_child_session_id = child_session_id.clone();
                    run.completed_at_ms = None;
                    run.error_class = None;
                }
                "step_completed" => {
                    step.status = "completed".to_string();
                    step.completed_at_ms = Some(timestamp_ms);
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    if run.active_child_session_id == child_session_id {
                        run.active_child_session_id = None;
                    }
                }
                "blocked" => {
                    step.status = "blocked".to_string();
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    run.active_child_session_id = child_session_id.clone();
                }
                _ => {
                    if !success {
                        step.status = "failed".to_string();
                    } else if status == "running" && step.status == "pending" {
                        step.status = "running".to_string();
                    } else if matches!(status, "completed" | "failed") {
                        step.status = status.to_string();
                    }
                }
            }

            step.receipts
                .push(crate::models::LocalEngineParentPlaybookReceiptRecord {
                    event_id: event.event_id.clone(),
                    timestamp_ms,
                    phase: phase.to_string(),
                    status: status.to_string(),
                    success,
                    summary: summary.clone(),
                    receipt_ref: event.receipt_ref.clone(),
                    child_session_id,
                    template_id,
                    workflow_id,
                    error_class,
                    artifact_ids: event
                        .artifact_refs
                        .iter()
                        .map(|artifact| artifact.artifact_id.clone())
                        .collect(),
                });
        }
    }
}

fn build_parent_playbook_runs(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    sessions: &[crate::models::SessionSummary],
    playbooks: &[crate::models::LocalEngineAgentPlaybookRecord],
) -> Vec<crate::models::LocalEngineParentPlaybookRunRecord> {
    let playbook_specs = playbooks
        .iter()
        .map(|playbook| (playbook.playbook_id.clone(), playbook.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut runs = BTreeMap::<String, crate::models::LocalEngineParentPlaybookRunRecord>::new();

    for session in sessions.iter().take(16) {
        let events = orchestrator::load_events(memory_runtime, &session.session_id, None, None);
        ingest_parent_playbook_events(&session.session_id, &events, &playbook_specs, &mut runs);
    }

    let mut projected = runs.into_values().collect::<Vec<_>>();
    for run in projected.iter_mut() {
        if run.current_step_id.is_none() {
            let selected_step = run
                .steps
                .iter()
                .find(|step| matches!(step.status.as_str(), "running" | "blocked" | "failed"))
                .or_else(|| run.steps.iter().find(|step| step.status == "pending"))
                .or_else(|| {
                    run.steps
                        .iter()
                        .rev()
                        .find(|step| step.status == "completed")
                });
            if let Some(step) = selected_step {
                run.current_step_id = Some(step.step_id.clone());
                run.current_step_label = Some(step.label.clone());
            }
        }
    }
    projected.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.playbook_label.cmp(&right.playbook_label))
    });
    projected
}

pub(crate) fn visible_parent_playbook_runs(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    sessions: &[crate::models::SessionSummary],
    playbooks: &[crate::models::LocalEngineAgentPlaybookRecord],
) -> Vec<crate::models::LocalEngineParentPlaybookRunRecord> {
    let dismissed = orchestrator::load_local_engine_parent_playbook_dismissals(memory_runtime)
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    build_parent_playbook_runs(memory_runtime, sessions, playbooks)
        .into_iter()
        .filter(|run| !dismissed.contains(&run.run_id))
        .collect()
}

fn resolve_parent_playbook_run(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    run_id: &str,
) -> Option<crate::models::LocalEngineParentPlaybookRunRecord> {
    let playbooks = default_agent_playbooks();
    let sessions = orchestrator::get_local_sessions(memory_runtime);
    build_parent_playbook_runs(memory_runtime, &sessions, &playbooks)
        .into_iter()
        .find(|run| run.run_id == run_id)
}

fn select_parent_playbook_step<'a>(
    run: &'a crate::models::LocalEngineParentPlaybookRunRecord,
    step_id: Option<&str>,
) -> Option<&'a crate::models::LocalEngineParentPlaybookStepRunRecord> {
    if let Some(step_id) = step_id {
        let trimmed = step_id.trim();
        if !trimmed.is_empty() {
            if let Some(step) = run.steps.iter().find(|step| step.step_id == trimmed) {
                return Some(step);
            }
        }
    }

    run.current_step_id
        .as_deref()
        .and_then(|current| run.steps.iter().find(|step| step.step_id == current))
        .or_else(|| {
            run.steps
                .iter()
                .find(|step| matches!(step.status.as_str(), "blocked" | "failed" | "running"))
        })
        .or_else(|| run.steps.iter().find(|step| step.status == "pending"))
        .or_else(|| run.steps.last())
}

fn persist_parent_playbook_dismissal(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    run_id: &str,
    dismissed: bool,
) {
    let mut run_ids = orchestrator::load_local_engine_parent_playbook_dismissals(memory_runtime);
    if dismissed {
        if !run_ids.iter().any(|entry| entry == run_id) {
            run_ids.push(run_id.to_string());
        }
    } else {
        run_ids.retain(|entry| entry != run_id);
    }
    orchestrator::save_local_engine_parent_playbook_dismissals(memory_runtime, &run_ids);
}

fn parent_playbook_thread_step_index(app: &tauri::AppHandle, parent_session_id: &str) -> u32 {
    let state = app.state::<Mutex<AppState>>();
    state
        .lock()
        .ok()
        .and_then(|guard| guard.current_task.clone())
        .and_then(|task| {
            let task_session_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
            if task_session_id == parent_session_id {
                Some(task.progress)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn register_parent_playbook_operator_event(
    app: &tauri::AppHandle,
    run: &crate::models::LocalEngineParentPlaybookRunRecord,
    phase: &str,
    status: &str,
    step: Option<&crate::models::LocalEngineParentPlaybookStepRunRecord>,
    summary: &str,
    target_session_id: Option<&str>,
) {
    let event = crate::kernel::events::build_event(
        &run.parent_session_id,
        parent_playbook_thread_step_index(app, &run.parent_session_id),
        crate::models::EventType::InfoNote,
        format!(
            "Operator {} {}",
            humanize_token(phase).to_lowercase(),
            run.playbook_label
        ),
        json!({
            "kind": "parent_playbook",
            "tool_name": "autopilot__parent_playbook_control",
            "phase": phase,
            "playbook_id": run.playbook_id,
            "playbook_label": run.playbook_label,
            "status": status,
            "success": true,
        }),
        json!({
            "timestamp_ms": Utc::now().timestamp_millis().max(0) as u64,
            "parent_session_id": run.parent_session_id,
            "step_id": step.map(|entry| entry.step_id.clone()),
            "step_label": step.map(|entry| entry.label.clone()),
            "child_session_id": step.and_then(|entry| entry.child_session_id.clone()),
            "template_id": step.and_then(|entry| entry.template_id.clone()),
            "workflow_id": step.and_then(|entry| entry.workflow_id.clone()),
            "operator_target_session_id": target_session_id,
            "summary": summary,
        }),
        EventStatus::Success,
        Vec::new(),
        None,
        Vec::new(),
        None,
    );
    crate::kernel::events::register_event(app, event);
}

fn mark_parent_playbook_operator_state(
    app: &tauri::AppHandle,
    run: &crate::models::LocalEngineParentPlaybookRunRecord,
    step: Option<&crate::models::LocalEngineParentPlaybookStepRunRecord>,
    summary: &str,
) {
    crate::kernel::state::update_task_state(app, |task| {
        let task_session_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
        if task_session_id == run.parent_session_id {
            task.phase = crate::models::AgentPhase::Running;
            task.current_step = summary.to_string();
        }

        if let Some(step) = step {
            if let Some(child_session_id) = step.child_session_id.as_deref() {
                if let Some(agent) = task
                    .swarm_tree
                    .iter_mut()
                    .find(|agent| agent.id == child_session_id)
                {
                    agent.status = "running".to_string();
                    agent.current_thought = Some(summary.to_string());
                }
            }
        }
    });
}
