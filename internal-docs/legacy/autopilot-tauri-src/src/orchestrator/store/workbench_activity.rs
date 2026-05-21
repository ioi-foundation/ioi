use super::shared::{
    load_global_checkpoint_json, persist_global_checkpoint_json,
    ASSISTANT_WORKBENCH_ACTIVITY_INDEX_CHECKPOINT_NAME,
};
use crate::models::AssistantWorkbenchActivityRecord;
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

pub fn load_assistant_workbench_activities(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<AssistantWorkbenchActivityRecord> {
    load_global_checkpoint_json(
        memory_runtime,
        ASSISTANT_WORKBENCH_ACTIVITY_INDEX_CHECKPOINT_NAME,
    )
    .unwrap_or_default()
}

pub fn append_assistant_workbench_activity(
    memory_runtime: &Arc<MemoryRuntime>,
    activity: AssistantWorkbenchActivityRecord,
    limit: usize,
) {
    let mut activities = load_assistant_workbench_activities(memory_runtime);
    activities.retain(|entry| entry.activity_id != activity.activity_id);
    activities.insert(0, activity);
    if activities.len() > limit {
        activities.truncate(limit);
    }
    persist_global_checkpoint_json(
        memory_runtime,
        ASSISTANT_WORKBENCH_ACTIVITY_INDEX_CHECKPOINT_NAME,
        &activities,
    );
}
