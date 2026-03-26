use super::*;

#[tauri::command]
pub fn notification_list_interventions(
    state: State<Mutex<AppState>>,
) -> Result<Vec<InterventionRecord>, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    Ok(load_interventions(&memory_runtime))
}

#[tauri::command]
pub fn notification_list_assistant(
    state: State<Mutex<AppState>>,
) -> Result<Vec<AssistantNotificationRecord>, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    Ok(load_assistant_notifications(&memory_runtime))
}

#[tauri::command]
pub fn notification_badge_count_get(state: State<Mutex<AppState>>) -> Result<usize, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    let interventions = load_interventions(&memory_runtime);
    let notifications = load_assistant_notifications(&memory_runtime);
    let policy = load_assistant_attention_policy(&memory_runtime);
    Ok(compute_badge_count(&interventions, &notifications, &policy))
}

#[tauri::command]
pub fn assistant_attention_policy_get(
    state: State<Mutex<AppState>>,
) -> Result<AssistantAttentionPolicy, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    Ok(load_assistant_attention_policy(&memory_runtime))
}

#[tauri::command]
pub fn assistant_attention_policy_set(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    policy: AssistantAttentionPolicy,
) -> Result<AssistantAttentionPolicy, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    save_assistant_attention_policy(&memory_runtime, &policy);
    let _ = app.emit("assistant-attention-policy-updated", &policy);
    emit_badge_count(&app);
    Ok(policy)
}

#[tauri::command]
pub fn assistant_attention_profile_get(
    state: State<Mutex<AppState>>,
) -> Result<AssistantAttentionProfile, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    Ok(load_assistant_attention_profile(&memory_runtime))
}

#[tauri::command]
pub fn assistant_user_profile_get(
    state: State<Mutex<AppState>>,
) -> Result<AssistantUserProfile, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    Ok(sanitize_assistant_user_profile(
        load_assistant_user_profile(&memory_runtime),
    ))
}

#[tauri::command]
pub fn assistant_user_profile_set(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    profile: AssistantUserProfile,
) -> Result<AssistantUserProfile, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    let sanitized = sanitize_assistant_user_profile(profile);
    save_assistant_user_profile(&memory_runtime, &sanitized);
    let _ = app.emit("assistant-user-profile-updated", &sanitized);
    Ok(sanitized)
}

#[tauri::command]
pub fn assistant_attention_policy_apply_query(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    instruction: String,
) -> Result<AssistantAttentionPolicy, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    let mut policy = load_assistant_attention_policy(&memory_runtime);
    let lower = instruction.to_ascii_lowercase();

    if lower.contains("build completion") && lower.contains("digest") {
        policy
            .detectors
            .entry("valuable_completion".to_string())
            .or_default()
            .toast_min_score = Some(0.99);
    }
    if lower.contains("only toast me for investor") || lower.contains("only notify me for investor")
    {
        policy
            .connectors
            .entry("gmail".to_string())
            .or_default()
            .scan_mode = Some("metadata_only".to_string());
    }
    if lower.contains("stop scanning gmail") {
        policy
            .connectors
            .entry("gmail".to_string())
            .or_default()
            .scan_mode = Some("disabled".to_string());
    }
    if lower.contains("scan gmail metadata") || lower.contains("gmail metadata only") {
        policy
            .connectors
            .entry("gmail".to_string())
            .or_default()
            .scan_mode = Some("metadata_only".to_string());
    }
    if lower.contains("stop reminding me about meetings") || lower.contains("disable meeting prep")
    {
        if let Some(detector) = policy.detectors.get_mut("meeting_prep") {
            detector.enabled = false;
        }
    }
    if lower.contains("enable meeting prep") || lower.contains("remind me about meetings") {
        policy
            .detectors
            .entry("meeting_prep".to_string())
            .or_default()
            .enabled = true;
    }
    if lower.contains("stop scanning calendar") {
        policy
            .connectors
            .entry("calendar".to_string())
            .or_default()
            .scan_mode = Some("disabled".to_string());
    }
    if lower.contains("calendar metadata only") || lower.contains("scan calendar metadata") {
        policy
            .connectors
            .entry("calendar".to_string())
            .or_default()
            .scan_mode = Some("metadata_only".to_string());
    }
    if lower.contains("disable follow up") || lower.contains("stop follow up reminders") {
        if let Some(detector) = policy.detectors.get_mut("follow_up_risk") {
            detector.enabled = false;
        }
    }
    if lower.contains("enable follow up") || lower.contains("email follow up reminders") {
        policy
            .detectors
            .entry("follow_up_risk".to_string())
            .or_default()
            .enabled = true;
    }
    if lower.contains("calendar focus") || lower.contains("during focus") {
        policy.global.toasts_enabled = false;
    }

    save_assistant_attention_policy(&memory_runtime, &policy);
    let _ = app.emit("assistant-attention-policy-updated", &policy);
    emit_badge_count(&app);
    Ok(policy)
}

#[tauri::command]
pub fn notification_update_intervention_status(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    item_id: String,
    status: InterventionStatus,
    snoozed_until_ms: Option<u64>,
) -> Result<(), String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    let mut items = load_interventions(&memory_runtime);
    if let Some(item) = items.iter_mut().find(|item| item.item_id == item_id) {
        item.status = status;
        item.snoozed_until_ms = snoozed_until_ms;
        item.updated_at_ms = now_ms();
        upsert_intervention(&memory_runtime, item.clone());
        let _ = app.emit("intervention-updated", item.clone());
        emit_badge_count(&app);
    }
    Ok(())
}

#[tauri::command]
pub fn notification_update_assistant_status(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    item_id: String,
    status: AssistantNotificationStatus,
    snoozed_until_ms: Option<u64>,
) -> Result<(), String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime not initialized".to_string())?;
    let mut items = load_assistant_notifications(&memory_runtime);
    if let Some(item) = items.iter_mut().find(|item| item.item_id == item_id) {
        item.status = status;
        item.snoozed_until_ms = snoozed_until_ms;
        item.updated_at_ms = now_ms();
        upsert_assistant_notification(&memory_runtime, item.clone());
        let _ = app.emit("assistant-notification-updated", item.clone());
        let profile =
            record_assistant_feedback(&memory_runtime, &item.notification_class, &item.status);
        let _ = app.emit("assistant-attention-profile-updated", profile);
        emit_badge_count(&app);
    }
    Ok(())
}

pub(crate) fn resolve_intervention_by_request_hash(app: &AppHandle, request_hash: &str) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let request_hash = normalize_request_hash(request_hash);
    let mut items = load_interventions(&memory_runtime);
    for item in items.iter_mut().filter(|item| {
        item.request_hash
            .as_deref()
            .map(normalize_request_hash)
            .as_deref()
            == Some(request_hash.as_str())
    }) {
        item.status = InterventionStatus::Resolved;
        item.updated_at_ms = now_ms();
        upsert_intervention(&memory_runtime, item.clone());
        let _ = app.emit("intervention-updated", item.clone());
    }
    emit_badge_count(app);
}

pub(crate) fn resolve_intervention_by_dedupe_prefix(app: &AppHandle, dedupe_prefix: &str) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let mut items = load_interventions(&memory_runtime);
    for item in items
        .iter_mut()
        .filter(|item| item.dedupe_key.starts_with(dedupe_prefix))
    {
        item.status = InterventionStatus::Resolved;
        item.updated_at_ms = now_ms();
        upsert_intervention(&memory_runtime, item.clone());
        let _ = app.emit("intervention-updated", item.clone());
    }
    emit_badge_count(app);
}
