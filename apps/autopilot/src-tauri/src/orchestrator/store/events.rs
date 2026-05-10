use super::shared::thread_storage_key;
use crate::models::AgentEvent;
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

pub fn append_event(memory_runtime: &Arc<MemoryRuntime>, event: &AgentEvent) {
    let Some(key) = thread_storage_key(&event.thread_id) else {
        return;
    };
    let Ok(payload_json) = serde_json::to_string(event) else {
        return;
    };
    let _ = memory_runtime.append_event_json(key, &event.event_id, &payload_json);
}

pub fn load_events(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    limit: Option<usize>,
    cursor: Option<usize>,
) -> Vec<AgentEvent> {
    let Some(key) = thread_storage_key(thread_id) else {
        return Vec::new();
    };

    memory_runtime
        .load_event_jsons(key, limit, cursor)
        .ok()
        .into_iter()
        .flat_map(|events| events.into_iter())
        .filter_map(|event| serde_json::from_str::<AgentEvent>(&event.payload_json).ok())
        .collect()
}
