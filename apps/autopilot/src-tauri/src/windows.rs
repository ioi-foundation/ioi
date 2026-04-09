// apps/autopilot/src-tauri/src/windows.rs

use crate::models::{AppState, StudioLaunchReceipt};
mod commands;
mod layout;
mod monitor;
mod state;
use serde_json::json;
use serde_json::Value;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Manager, State};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default)]
pub struct SpotlightLayout {
    pub sidebar_visible: bool,
    pub artifact_panel_visible: bool,
}

// Layout constants (logical pixels)
pub(super) const BASE_WIDTH: f64 = 450.0;
pub(super) const SIDEBAR_WIDTH: f64 = 280.0;
pub(super) const ARTIFACT_PANEL_WIDTH: f64 = 468.0;
pub(super) const COMPACT_SIDEBAR_WIDTH: f64 = 112.0;
pub(super) const COMPACT_ARTIFACT_PANEL_WIDTH: f64 = 336.0;
pub(super) const SPOTLIGHT_HEIGHT: f64 = 600.0;

// Linux taskbar margin - typical panel height
#[cfg(target_os = "linux")]
pub(super) const TASKBAR_MARGIN: f64 = 48.0;
#[cfg(not(target_os = "linux"))]
pub(super) const TASKBAR_MARGIN: f64 = 0.0;

#[cfg(target_os = "linux")]
pub(super) fn should_surface_overlay_windows_in_task_switcher() -> bool {
    for key in [
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
    ] {
        if let Ok(value) = std::env::var(key) {
            if value
                .split(':')
                .any(|entry| entry.trim().eq_ignore_ascii_case("cosmic"))
            {
                return true;
            }
        }
    }

    false
}

#[cfg(not(target_os = "linux"))]
pub(super) fn should_surface_overlay_windows_in_task_switcher() -> bool {
    false
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn push_studio_launch_receipt(state: &mut AppState, stage: impl Into<String>, detail: Value) {
    let receipt = StudioLaunchReceipt {
        timestamp_ms: now_ms(),
        stage: stage.into(),
        detail,
    };
    let detail_snapshot = receipt.detail.clone();
    eprintln!(
        "[Autopilot][StudioLaunch] stage={} detail={}",
        receipt.stage, detail_snapshot
    );
    state.studio_launch_receipts.push(receipt);
    let overflow = state.studio_launch_receipts.len().saturating_sub(128);
    if overflow > 0 {
        state.studio_launch_receipts.drain(0..overflow);
    }
}

fn summarize_assistant_workbench_session(session: Option<&Value>) -> Value {
    let Some(session) = session else {
        return Value::Null;
    };

    let kind = session
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let connector_id = session.get("connectorId").cloned().unwrap_or(Value::Null);
    let source_notification_id = session
        .get("sourceNotificationId")
        .cloned()
        .unwrap_or(Value::Null);

    match kind {
        "gmail_reply" => json!({
            "kind": kind,
            "connectorId": connector_id,
            "sourceNotificationId": source_notification_id,
            "threadId": session
                .get("thread")
                .and_then(|thread| thread.get("threadId"))
                .cloned()
                .unwrap_or(Value::Null),
        }),
        "meeting_prep" => json!({
            "kind": kind,
            "connectorId": connector_id,
            "sourceNotificationId": source_notification_id,
            "calendarId": session
                .get("event")
                .and_then(|event| event.get("calendarId"))
                .cloned()
                .unwrap_or(Value::Null),
            "eventId": session
                .get("event")
                .and_then(|event| event.get("eventId"))
                .cloned()
                .unwrap_or(Value::Null),
        }),
        _ => json!({
            "kind": kind,
            "connectorId": connector_id,
            "sourceNotificationId": source_notification_id,
        }),
    }
}

pub(super) fn summarize_studio_launch_request(request: &Value) -> Value {
    let kind = request
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    match kind {
        "view" => json!({
            "kind": kind,
            "view": request.get("view").cloned().unwrap_or(Value::Null),
        }),
        "session-target" => json!({
            "kind": kind,
            "sessionId": request.get("sessionId").cloned().unwrap_or(Value::Null),
        }),
        "capability" => json!({
            "kind": kind,
            "connectorId": request.get("connectorId").cloned().unwrap_or(Value::Null),
            "detailSection": request.get("detailSection").cloned().unwrap_or(Value::Null),
        }),
        "policy" => json!({
            "kind": kind,
            "connectorId": request.get("connectorId").cloned().unwrap_or(Value::Null),
        }),
        "autopilot-intent" => json!({
            "kind": kind,
            "intent": request.get("intent").cloned().unwrap_or(Value::Null),
        }),
        "assistant-workbench" => json!({
            "kind": kind,
            "session": summarize_assistant_workbench_session(request.get("session")),
        }),
        _ => json!({
            "kind": kind,
        }),
    }
}

fn studio_launch_envelope_request(envelope: &Value) -> &Value {
    envelope.get("request").unwrap_or(envelope)
}

fn studio_launch_envelope_id(envelope: &Value) -> Option<&str> {
    envelope.get("launchId").and_then(Value::as_str)
}

pub(super) fn summarize_studio_launch_envelope(envelope: &Value) -> Value {
    json!({
        "launchId": studio_launch_envelope_id(envelope),
        "request": summarize_studio_launch_request(studio_launch_envelope_request(envelope)),
    })
}

pub(super) fn record_studio_launch_receipt_for_app(
    app: &tauri::AppHandle,
    stage: impl Into<String>,
    detail: Value,
) {
    if let Ok(mut state) = app.state::<Mutex<AppState>>().lock() {
        push_studio_launch_receipt(&mut state, stage, detail);
    }
}

fn build_studio_launch_envelope(request: Value) -> Value {
    json!({
        "launchId": Uuid::new_v4().to_string(),
        "request": request,
    })
}

fn set_pending_studio_launch_request(state: &mut AppState, request: Value) -> Value {
    let envelope = build_studio_launch_envelope(request);
    let request_summary = summarize_studio_launch_envelope(&envelope);
    push_studio_launch_receipt(
        state,
        "queued",
        json!({
            "launch": request_summary,
        }),
    );
    state.pending_studio_launch_request = Some(envelope.clone());
    envelope
}

pub(super) fn queue_pending_studio_launch_for_app(
    app: &tauri::AppHandle,
    request: Value,
) -> Result<Value, String> {
    let state_handle = app.state::<Mutex<AppState>>();
    let mut state = state_handle
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    Ok(set_pending_studio_launch_request(&mut state, request))
}

#[tauri::command]
pub fn show_spotlight(app: tauri::AppHandle) {
    commands::show_spotlight(app);
}

#[tauri::command]
pub fn show_pill(app: tauri::AppHandle) {
    commands::show_pill(app);
}

#[tauri::command]
pub fn hide_pill(app: tauri::AppHandle) {
    commands::hide_pill(app);
}

#[tauri::command]
pub fn hide_spotlight(app: tauri::AppHandle) {
    commands::hide_spotlight(app);
}

#[tauri::command]
pub fn toggle_spotlight_sidebar(app: tauri::AppHandle, visible: bool) {
    commands::toggle_spotlight_sidebar(app, visible);
}

#[tauri::command]
pub fn toggle_spotlight_artifact_panel(app: tauri::AppHandle, visible: bool) {
    commands::toggle_spotlight_artifact_panel(app, visible);
}

#[tauri::command]
pub fn get_spotlight_layout() -> Result<(bool, bool), String> {
    commands::get_spotlight_layout()
}

#[tauri::command]
pub fn show_gate(app: tauri::AppHandle) {
    commands::show_gate(app);
}

#[tauri::command]
pub fn hide_gate(app: tauri::AppHandle) {
    commands::hide_gate(app);
}

#[tauri::command]
pub fn show_studio(app: tauri::AppHandle) {
    commands::show_studio(app);
}

#[tauri::command]
pub fn show_studio_with_target(app: tauri::AppHandle, request: Value) -> Result<(), String> {
    let envelope = queue_pending_studio_launch_for_app(&app, request)?;
    commands::show_studio_with_target(app, envelope);
    Ok(())
}

#[tauri::command]
pub fn hide_studio(app: tauri::AppHandle) {
    commands::hide_studio(app);
}

#[tauri::command]
pub fn set_pending_studio_launch(
    state: State<'_, Mutex<AppState>>,
    request: Value,
) -> Result<(), String> {
    let mut state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    set_pending_studio_launch_request(&mut state, request);
    Ok(())
}

#[tauri::command]
pub fn clear_pending_studio_launch(state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    let mut state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    let previous = state.pending_studio_launch_request.clone();
    push_studio_launch_receipt(
        &mut state,
        "cleared",
        json!({
            "hadPendingRequest": previous.is_some(),
            "launch": previous.as_ref().map(summarize_studio_launch_envelope),
        }),
    );
    state.pending_studio_launch_request = None;
    Ok(())
}

#[tauri::command]
pub fn peek_pending_studio_launch(
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<Value>, String> {
    let mut state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    let request = state.pending_studio_launch_request.clone();
    push_studio_launch_receipt(
        &mut state,
        "peeked",
        json!({
            "foundPendingRequest": request.is_some(),
            "launch": request.as_ref().map(summarize_studio_launch_envelope),
        }),
    );
    Ok(request)
}

#[tauri::command]
pub fn ack_pending_studio_launch(
    state: State<'_, Mutex<AppState>>,
    launch_id: String,
) -> Result<bool, String> {
    let mut state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    let pending_launch = state.pending_studio_launch_request.clone();
    let should_clear = pending_launch
        .as_ref()
        .and_then(studio_launch_envelope_id)
        .map(|pending_launch_id| pending_launch_id == launch_id)
        .unwrap_or(false);

    push_studio_launch_receipt(
        &mut state,
        if should_clear { "acked" } else { "ack_ignored" },
        json!({
            "launchId": launch_id,
            "hadPendingRequest": pending_launch.is_some(),
            "launch": pending_launch.as_ref().map(summarize_studio_launch_envelope),
        }),
    );

    if should_clear {
        state.pending_studio_launch_request = None;
    }

    Ok(should_clear)
}

#[tauri::command]
pub fn record_studio_launch_receipt(
    state: State<'_, Mutex<AppState>>,
    stage: String,
    detail: Option<Value>,
) -> Result<(), String> {
    let mut state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    push_studio_launch_receipt(&mut state, stage, detail.unwrap_or_else(|| json!({})));
    Ok(())
}

#[tauri::command]
pub fn get_studio_launch_receipts(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<StudioLaunchReceipt>, String> {
    let state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    Ok(state.studio_launch_receipts.clone())
}

#[cfg(test)]
mod tests {
    use super::summarize_studio_launch_request;
    use serde_json::json;

    #[test]
    fn summarizes_session_target_launch_requests() {
        let summary = summarize_studio_launch_request(&json!({
            "kind": "session-target",
            "sessionId": "session-123",
        }));

        assert_eq!(
            summary,
            json!({
                "kind": "session-target",
                "sessionId": "session-123",
            })
        );
    }
}
