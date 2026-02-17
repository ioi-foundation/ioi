use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::support::thread_id_from_session;
use crate::kernel::state::update_task_state;
use crate::models::{EventStatus, EventType};
use ioi_ipc::public::chain_event::SystemUpdate;
use serde_json::json;

pub(super) async fn handle_system(app: &tauri::AppHandle, update: SystemUpdate) {
    update_task_state(app, |t| {
        t.history.push(crate::models::ChatMessage {
            role: "system".to_string(),
            text: format!("⚙️ {}: {}", update.component, update.status),
            timestamp: crate::kernel::state::now(),
        });
    });

    let thread_id = thread_id_from_session(&app, "");
    let event = build_event(
        &thread_id,
        0,
        EventType::InfoNote,
        format!("System update: {}", update.component),
        json!({
            "component": update.component,
            "status": update.status,
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
