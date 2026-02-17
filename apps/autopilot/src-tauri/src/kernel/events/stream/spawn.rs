use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::support::thread_id_from_session;
use crate::kernel::state::update_task_state;
use crate::models::{EventStatus, EventType, SwarmAgent};
use ioi_ipc::public::chain_event::AgentSpawn;
use serde_json::json;

pub(super) async fn handle_spawn(app: &tauri::AppHandle, spawn: AgentSpawn) {
    update_task_state(app, |t| {
        let agent = SwarmAgent {
            id: spawn.new_session_id.clone(),
            parent_id: if spawn.parent_session_id.is_empty() {
                None
            } else {
                Some(spawn.parent_session_id.clone())
            },
            name: spawn.name.clone(),
            role: spawn.role.clone(),
            status: "running".to_string(),
            budget_used: 0.0,
            budget_cap: spawn.budget as f64,
            current_thought: Some(format!("Initialized goal: {}", spawn.goal)),
            artifacts_produced: 0,
            estimated_cost: 0.0,
            policy_hash: "".to_string(),
        };

        if let Some(pos) = t.swarm_tree.iter().position(|a| a.id == agent.id) {
            t.swarm_tree[pos] = agent;
        } else {
            t.swarm_tree.push(agent);
        }
    });

    let thread_id = thread_id_from_session(&app, &spawn.parent_session_id);
    let event = build_event(
        &thread_id,
        0,
        EventType::InfoNote,
        format!("Spawned agent {}", spawn.name),
        json!({
            "agent_id": spawn.new_session_id,
            "role": spawn.role,
            "budget": spawn.budget,
        }),
        json!({
            "goal": spawn.goal,
        }),
        EventStatus::Success,
        Vec::new(),
        None,
        Vec::new(),
        None,
    );
    register_event(&app, event);
}
