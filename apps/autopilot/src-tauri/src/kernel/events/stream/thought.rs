use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::support::thread_id_from_session;
use crate::kernel::state::update_task_state;
use crate::kernel::thresholds;
use crate::models::{AgentPhase, EventStatus, EventType};
use ioi_ipc::public::AgentThought;
use serde_json::json;

pub(super) async fn handle_thought(app: &tauri::AppHandle, thought: AgentThought) {
    update_task_state(&app, |t| {
        if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == thought.session_id) {
            if let Some(existing) = &agent.current_thought {
                agent.current_thought = Some(format!("{}{}", existing, thought.content));
            } else {
                agent.current_thought = Some(thought.content.clone());
            }
            if agent.status != "paused" && agent.status != "requisition" {
                agent.status = "running".to_string();
            }
        } else {
            if t.current_step == "Initializing..." || t.current_step.starts_with("Executed") {
                t.current_step = thought.content.clone();
            } else {
                t.current_step.push_str(&thought.content);
            }
        }

        if t.phase != AgentPhase::Complete
            && t.phase != AgentPhase::Failed
            && t.phase != AgentPhase::Gate
        {
            t.phase = AgentPhase::Running;
        }

        t.progress += 1;
        if !thought.visual_hash.is_empty() {
            t.visual_hash = Some(thought.visual_hash.clone());
        }
        if !thought.session_id.is_empty() {
            t.session_id = Some(thought.session_id.clone());
        }
    });

    if thought.is_final {
        let thread_id = thread_id_from_session(&app, &thought.session_id);
        let event = build_event(
            &thread_id,
            0,
            EventType::InfoNote,
            "Captured reasoning step".to_string(),
            json!({
                "session_id": thought.session_id,
                "visual_hash": thought.visual_hash,
                "token_count": thought.content.chars().count(),
            }),
            json!({
                "content": thresholds::trim_for_expanded_view(&thought.content),
            }),
            EventStatus::Success,
            Vec::new(),
            None,
            Vec::new(),
            None,
        );
        register_event(&app, event);
    }
}
