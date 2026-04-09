pub(crate) fn build_local_engine_activity_record(
    session_id: &str,
    event: &crate::models::AgentEvent,
) -> Option<crate::models::LocalEngineActivityRecord> {
    let digest = event.digest.as_object()?;
    let family = digest.get("kind")?.as_str()?.to_string();
    let tool_name = digest.get("tool_name")?.as_str()?.to_string();

    if family == "model_lifecycle"
        || family == "parent_playbook"
        || tool_name.starts_with("model__")
        || tool_name.starts_with("media__")
        || tool_name.starts_with("model_registry__")
        || tool_name.starts_with("backend__")
        || tool_name.starts_with("gallery__")
    {
        let payload = event
            .details
            .get("payload")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let subject_kind = digest
            .get("subject_kind")
            .and_then(Value::as_str)
            .map(str::to_string);
        let subject_id = digest
            .get("subject_id")
            .or_else(|| digest.get("model_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let operation = digest
            .get("operation")
            .and_then(Value::as_str)
            .map(str::to_string);
        let error_class = digest
            .get("error_class")
            .and_then(Value::as_str)
            .map(str::to_string);
        let backend_id = payload
            .get("backend_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let success = digest
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(event.status, EventStatus::Success));

        let title = match family.as_str() {
            "model_lifecycle" => {
                let operation = operation
                    .clone()
                    .unwrap_or_else(|| "control".to_string())
                    .replace('_', " ");
                format!(
                    "{} {}",
                    operation,
                    subject_kind
                        .clone()
                        .unwrap_or_else(|| "subject".to_string())
                )
            }
            "inference" => "Run model workload".to_string(),
            "media" => "Run media workload".to_string(),
            "parent_playbook" => "Advance parent playbook".to_string(),
            _ => "Kernel-native workload".to_string(),
        };

        return Some(crate::models::LocalEngineActivityRecord {
            event_id: event.event_id.clone(),
            session_id: session_id.to_string(),
            family,
            title,
            tool_name,
            timestamp_ms: parse_event_timestamp_ms(event),
            success,
            operation,
            subject_kind,
            subject_id,
            backend_id,
            error_class,
        });
    }

    None
}

#[tauri::command]
pub async fn get_local_engine_snapshot(
    state: State<'_, Mutex<AppState>>,
) -> Result<crate::models::LocalEngineSnapshot, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let tools = collect_available_tools(&state).await?;
    let capabilities = build_local_engine_capabilities(&tools);
    let control_plane_state = load_or_initialize_local_engine_control_plane_state(&memory_runtime);
    let effective_control_plane_state =
        load_or_initialize_effective_local_engine_control_plane_state(&memory_runtime);
    let control_plane = effective_control_plane_state.control_plane.clone();
    let worker_templates = load_or_initialize_worker_templates(&memory_runtime);
    let agent_playbooks = default_agent_playbooks();
    let registry_state = crate::kernel::local_engine::load_or_sync_registry_state(
        &memory_runtime,
        Some(&control_plane),
    );
    let compatibility_routes = build_local_engine_compatibility_routes(&control_plane);
    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    staged_operations.sort_by(|left, right| {
        right
            .created_at_ms
            .cmp(&left.created_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    let mut jobs = orchestrator::load_local_engine_jobs(&memory_runtime);
    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });

    let interventions = orchestrator::load_interventions(&memory_runtime);
    let mut pending_controls = interventions
        .into_iter()
        .filter(is_local_engine_intervention)
        .filter(|record| unresolved_intervention_status(&record.status))
        .map(|record| crate::models::LocalEngineControlAction {
            item_id: record.item_id,
            title: record.title,
            summary: record.summary,
            status: intervention_status_label(&record.status).to_string(),
            severity: notification_severity_label(&record.severity).to_string(),
            requested_at_ms: record.created_at_ms,
            due_at_ms: record.due_at_ms,
            approval_scope: record.approval_scope,
            sensitive_action_type: record.sensitive_action_type,
            recommended_action: record.recommended_action,
            recovery_hint: record.recovery_hint,
            request_hash: record.request_hash,
        })
        .collect::<Vec<_>>();
    pending_controls.sort_by(|left, right| {
        right
            .requested_at_ms
            .cmp(&left.requested_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    pending_controls.extend(
        staged_operations
            .iter()
            .map(staged_operation_to_control_action)
            .collect::<Vec<_>>(),
    );
    pending_controls.sort_by(|left, right| {
        right
            .requested_at_ms
            .cmp(&left.requested_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });

    let sessions = orchestrator::get_local_sessions(&memory_runtime);
    let parent_playbook_runs =
        visible_parent_playbook_runs(&memory_runtime, &sessions, &agent_playbooks);
    let mut recent_activity = sessions
        .iter()
        .take(12)
        .flat_map(|session| {
            orchestrator::load_events(&memory_runtime, &session.session_id, None, None)
                .into_iter()
                .filter_map(|event| build_local_engine_activity_record(&session.session_id, &event))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    recent_activity =
        crate::kernel::local_engine::merge_recent_activity(recent_activity, &registry_state, 12);

    let pending_approval_count = pending_controls
        .iter()
        .filter(|record| {
            matches!(
                record.status.as_str(),
                "new" | "seen" | "pending" | "snoozed"
            )
        })
        .count();
    let active_issue_count = pending_controls
        .iter()
        .filter(|record| matches!(record.severity.as_str(), "critical" | "high"))
        .count()
        + jobs
            .iter()
            .filter(|job| matches!(job.status.as_str(), "failed"))
            .count()
        + registry_state
            .registry_models
            .iter()
            .filter(|record| matches!(record.status.as_str(), "failed"))
            .count()
        + registry_state
            .managed_backends
            .iter()
            .filter(|record| {
                matches!(record.status.as_str(), "failed") || record.health == "degraded"
            })
            .count()
        + registry_state
            .gallery_catalogs
            .iter()
            .filter(|record| matches!(record.sync_status.as_str(), "failed"))
            .count()
        + parent_playbook_runs
            .iter()
            .filter(|run| matches!(run.status.as_str(), "blocked" | "failed"))
            .count()
        + recent_activity
            .iter()
            .filter(|record| !record.success && record.family != "parent_playbook")
            .count();

    Ok(crate::models::LocalEngineSnapshot {
        generated_at_ms: Utc::now().timestamp_millis().max(0) as u64,
        total_native_tools: capabilities
            .iter()
            .flat_map(|family| family.tool_names.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        pending_control_count: pending_controls.len(),
        pending_approval_count,
        active_issue_count,
        capabilities,
        compatibility_routes,
        pending_controls,
        jobs,
        recent_activity,
        registry_models: registry_state.registry_models,
        managed_backends: registry_state.managed_backends,
        gallery_catalogs: registry_state.gallery_catalogs,
        worker_templates,
        agent_playbooks,
        parent_playbook_runs,
        control_plane_schema_version: control_plane_state.schema_version,
        control_plane_profile_id: control_plane_state.profile_id,
        control_plane_migrations: control_plane_state.migrations,
        control_plane,
        managed_settings: effective_control_plane_state.managed_settings,
        staged_operations,
    })
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineOperationDraftInput {
    pub subject_kind: String,
    pub operation: String,
    pub source_uri: Option<String>,
    pub subject_id: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineJobStatusUpdateInput {
    pub job_id: String,
    pub status: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentPlaybookResumeInput {
    pub run_id: String,
    pub step_id: Option<String>,
}

#[tauri::command]
pub async fn save_local_engine_control_plane(
    state: State<'_, Mutex<AppState>>,
    control_plane: crate::models::LocalEngineControlPlane,
) -> Result<crate::models::LocalEngineControlPlane, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let normalized =
        crate::kernel::local_engine::save_local_engine_control_plane_with_managed_settings(
            &memory_runtime,
            control_plane,
        )?;
    let _ = crate::kernel::local_engine::load_or_sync_registry_state(
        &memory_runtime,
        Some(&normalized),
    );
    Ok(normalized)
}

#[tauri::command]
pub async fn refresh_local_engine_managed_settings(
    state: State<'_, Mutex<AppState>>,
) -> Result<crate::models::LocalEngineManagedSettingsSnapshot, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let local_document = load_or_initialize_local_engine_control_plane_state(&memory_runtime);
    let snapshot = crate::kernel::local_engine::refresh_local_engine_managed_settings(
        &memory_runtime,
        &local_document,
    )?;
    let effective = load_or_initialize_effective_local_engine_control_plane_state(&memory_runtime);
    let _ = crate::kernel::local_engine::load_or_sync_registry_state(
        &memory_runtime,
        Some(&effective.control_plane),
    );
    Ok(snapshot)
}

#[tauri::command]
pub async fn clear_local_engine_managed_settings_overrides(
    state: State<'_, Mutex<AppState>>,
) -> Result<crate::models::LocalEngineManagedSettingsSnapshot, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let local_document = load_or_initialize_local_engine_control_plane_state(&memory_runtime);
    let snapshot = crate::kernel::local_engine::clear_local_engine_managed_settings_overrides(
        &memory_runtime,
        &local_document,
    )?;
    let effective = load_or_initialize_effective_local_engine_control_plane_state(&memory_runtime);
    let _ = crate::kernel::local_engine::load_or_sync_registry_state(
        &memory_runtime,
        Some(&effective.control_plane),
    );
    Ok(snapshot)
}

#[tauri::command]
pub async fn stage_local_engine_operation(
    state: State<'_, Mutex<AppState>>,
    draft: LocalEngineOperationDraftInput,
) -> Result<crate::models::LocalEngineStagedOperation, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;

    let subject_kind = trim_or_empty(draft.subject_kind).to_ascii_lowercase();
    let operation = trim_or_empty(draft.operation).to_ascii_lowercase();
    if subject_kind.is_empty() || operation.is_empty() {
        return Err("subject_kind and operation are required".to_string());
    }

    let subject_id = normalize_optional_text(draft.subject_id);
    let source_uri = normalize_optional_text(draft.source_uri);
    let notes = normalize_optional_text(draft.notes);
    let created_at_ms = Utc::now().timestamp_millis().max(0) as u64;
    let digest = sha256(
        format!(
            "{}|{}|{}|{}|{}",
            subject_kind,
            operation,
            source_uri.as_deref().unwrap_or_default(),
            subject_id.as_deref().unwrap_or_default(),
            created_at_ms
        )
        .as_bytes(),
    )
    .map_err(|error| format!("failed to stage local engine operation: {}", error))?;

    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    let staged = crate::models::LocalEngineStagedOperation {
        operation_id: hex::encode(digest),
        subject_kind: subject_kind.clone(),
        operation: operation.clone(),
        title: stage_operation_title(&subject_kind, &operation, subject_id.as_deref()),
        source_uri,
        subject_id,
        notes,
        created_at_ms,
        status: "staged".to_string(),
    };
    staged_operations.push(staged.clone());
    staged_operations.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    orchestrator::save_local_engine_staged_operations(&memory_runtime, &staged_operations);
    Ok(staged)
}

#[tauri::command]
pub async fn remove_local_engine_operation(
    state: State<'_, Mutex<AppState>>,
    operation_id: String,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    staged_operations.retain(|operation| operation.operation_id != operation_id);
    orchestrator::save_local_engine_staged_operations(&memory_runtime, &staged_operations);
    Ok(())
}

#[tauri::command]
pub async fn promote_local_engine_operation(
    state: State<'_, Mutex<AppState>>,
    operation_id: String,
) -> Result<crate::models::LocalEngineJobRecord, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    let Some(index) = staged_operations
        .iter()
        .position(|operation| operation.operation_id == operation_id)
    else {
        return Err("staged operation not found".to_string());
    };

    let operation = staged_operations.remove(index);
    orchestrator::save_local_engine_staged_operations(&memory_runtime, &staged_operations);

    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    let mut jobs = orchestrator::load_local_engine_jobs(&memory_runtime);
    let job = local_engine_job_from_staged_operation(&operation, now_ms);
    if let Some(existing_index) = jobs.iter().position(|entry| entry.job_id == job.job_id) {
        jobs[existing_index] = job.clone();
    } else {
        jobs.push(job.clone());
    }
    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    orchestrator::save_local_engine_jobs(&memory_runtime, &jobs);
    let control_plane = load_or_initialize_local_engine_control_plane(&memory_runtime);
    crate::kernel::local_engine::record_promoted_job(&memory_runtime, Some(&control_plane), &job);
    Ok(job)
}

#[tauri::command]
pub async fn update_local_engine_job_status(
    state: State<'_, Mutex<AppState>>,
    input: LocalEngineJobStatusUpdateInput,
) -> Result<crate::models::LocalEngineJobRecord, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let control_plane = load_or_initialize_local_engine_control_plane(&memory_runtime);
    crate::kernel::local_engine::update_job_status(
        &memory_runtime,
        Some(&control_plane),
        &input.job_id,
        &input.status,
    )
}

#[tauri::command]
pub async fn retry_local_engine_parent_playbook_run(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    run_id: String,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    persist_parent_playbook_dismissal(&memory_runtime, &run_id, false);
    let run = resolve_parent_playbook_run(&memory_runtime, &run_id)
        .ok_or_else(|| "parent playbook run not found".to_string())?;
    let step = select_parent_playbook_step(&run, None)
        .ok_or_else(|| "no current step is available to retry".to_string())?;
    let target_session_id = step
        .child_session_id
        .as_deref()
        .unwrap_or(run.parent_session_id.as_str());
    let summary = format!(
        "Operator requested retry for '{}' in parent playbook '{}'.",
        step.label, run.playbook_label
    );
    let message = format!(
        "Operator request: retry the '{}' step for parent playbook '{}'. Re-evaluate the last failure, revise your work instead of restarting blindly when possible, and continue toward the existing success criteria.",
        step.label, run.playbook_label
    );
    crate::kernel::task::send_message_to_session(&app, target_session_id, message).await?;
    mark_parent_playbook_operator_state(&app, &run, Some(step), &summary);
    register_parent_playbook_operator_event(
        &app,
        &run,
        "operator_retry_requested",
        "running",
        Some(step),
        &summary,
        Some(target_session_id),
    );
    crate::kernel::local_engine::emit_local_engine_update(&app, "parent_playbook_retry_requested");
    Ok(())
}

#[tauri::command]
pub async fn resume_local_engine_parent_playbook_run(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    input: ParentPlaybookResumeInput,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    persist_parent_playbook_dismissal(&memory_runtime, &input.run_id, false);
    let run = resolve_parent_playbook_run(&memory_runtime, &input.run_id)
        .ok_or_else(|| "parent playbook run not found".to_string())?;
    let step = select_parent_playbook_step(&run, input.step_id.as_deref())
        .ok_or_else(|| "no step is available to resume".to_string())?;
    let summary = format!(
        "Operator requested resume from '{}' in parent playbook '{}'.",
        step.label, run.playbook_label
    );
    let message = format!(
        "Operator request: resume the parent playbook '{}' from the '{}' step. Reopen that step, preserve prior evidence when it is still valid, redo dependent work when necessary, and continue the ordered sequence to completion.",
        run.playbook_label, step.label
    );
    crate::kernel::task::send_message_to_session(&app, &run.parent_session_id, message).await?;
    mark_parent_playbook_operator_state(&app, &run, Some(step), &summary);
    register_parent_playbook_operator_event(
        &app,
        &run,
        "operator_resume_requested",
        "running",
        Some(step),
        &summary,
        Some(run.parent_session_id.as_str()),
    );
    crate::kernel::local_engine::emit_local_engine_update(&app, "parent_playbook_resume_requested");
    Ok(())
}

#[tauri::command]
pub async fn dismiss_local_engine_parent_playbook_run(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    run_id: String,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let run = resolve_parent_playbook_run(&memory_runtime, &run_id)
        .ok_or_else(|| "parent playbook run not found".to_string())?;
    persist_parent_playbook_dismissal(&memory_runtime, &run_id, true);
    let summary = format!(
        "Operator dismissed parent playbook '{}' from the Runtime Deck.",
        run.playbook_label
    );
    register_parent_playbook_operator_event(
        &app,
        &run,
        "operator_dismissed",
        run.status.as_str(),
        select_parent_playbook_step(&run, run.current_step_id.as_deref()),
        &summary,
        Some(run.parent_session_id.as_str()),
    );
    crate::kernel::local_engine::emit_local_engine_update(&app, "parent_playbook_dismissed");
    Ok(())
}
