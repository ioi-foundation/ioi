use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::support::thread_id_from_session;
use crate::kernel::state::update_task_state;
use crate::models::{EventStatus, EventType, GhostInputEvent};
use ioi_ipc::public::chain_event::GhostInput;
use serde_json::json;
use tauri::Emitter;

pub(super) async fn handle_ghost(app: &tauri::AppHandle, input: GhostInput) {
    let payload = GhostInputEvent {
        device: input.device.clone(),
        description: input.description.clone(),
    };
    let _ = app.emit("ghost-input", &payload);
    update_task_state(&app, |t| {
        if matches!(t.phase, crate::models::AgentPhase::Running) {
            t.current_step = format!("User Input: {}", input.description);
            t.history.push(crate::models::ChatMessage {
                role: "user".to_string(),
                text: format!("[Ghost] {}", input.description),
                timestamp: crate::kernel::state::now(),
            });
        }
    });

    let thread_id = thread_id_from_session(&app, "");
    let event = build_event(
        &thread_id,
        0,
        EventType::InfoNote,
        "Captured ghost input".to_string(),
        json!({
            "device": input.device,
            "description": input.description,
        }),
        json!({}),
        EventStatus::Success,
        Vec::new(),
        None,
        Vec::new(),
        None,
    );
    register_event(&app, event);
}
