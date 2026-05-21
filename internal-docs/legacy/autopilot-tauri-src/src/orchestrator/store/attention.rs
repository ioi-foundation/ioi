use super::shared::{
    load_global_checkpoint_json, persist_global_checkpoint_json,
    ASSISTANT_NOTIFICATION_INDEX_CHECKPOINT_NAME, ASSISTANT_USER_PROFILE_CHECKPOINT_NAME,
    ATTENTION_POLICY_CHECKPOINT_NAME, ATTENTION_PROFILE_CHECKPOINT_NAME,
    INTERVENTION_INDEX_CHECKPOINT_NAME,
};
use crate::models::{
    AssistantAttentionPolicy, AssistantAttentionProfile, AssistantNotificationRecord,
    AssistantUserProfile, InterventionRecord,
};
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

pub fn load_interventions(memory_runtime: &Arc<MemoryRuntime>) -> Vec<InterventionRecord> {
    load_global_checkpoint_json(memory_runtime, INTERVENTION_INDEX_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn load_assistant_notifications(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<AssistantNotificationRecord> {
    load_global_checkpoint_json(memory_runtime, ASSISTANT_NOTIFICATION_INDEX_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn upsert_intervention(memory_runtime: &Arc<MemoryRuntime>, record: InterventionRecord) {
    let mut records = load_interventions(memory_runtime);
    if let Some(index) = records
        .iter()
        .position(|item| item.item_id == record.item_id || item.dedupe_key == record.dedupe_key)
    {
        records[index] = record;
    } else {
        records.push(record);
    }
    records.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
    persist_global_checkpoint_json(memory_runtime, INTERVENTION_INDEX_CHECKPOINT_NAME, &records);
}

pub fn upsert_assistant_notification(
    memory_runtime: &Arc<MemoryRuntime>,
    record: AssistantNotificationRecord,
) {
    let mut records = load_assistant_notifications(memory_runtime);
    if let Some(index) = records
        .iter()
        .position(|item| item.item_id == record.item_id || item.dedupe_key == record.dedupe_key)
    {
        records[index] = record;
    } else {
        records.push(record);
    }
    records.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
    persist_global_checkpoint_json(
        memory_runtime,
        ASSISTANT_NOTIFICATION_INDEX_CHECKPOINT_NAME,
        &records,
    );
}

pub fn save_assistant_attention_policy(
    memory_runtime: &Arc<MemoryRuntime>,
    policy: &AssistantAttentionPolicy,
) {
    persist_global_checkpoint_json(memory_runtime, ATTENTION_POLICY_CHECKPOINT_NAME, policy);
}

pub fn load_assistant_attention_policy(
    memory_runtime: &Arc<MemoryRuntime>,
) -> AssistantAttentionPolicy {
    load_global_checkpoint_json(memory_runtime, ATTENTION_POLICY_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn save_assistant_attention_profile(
    memory_runtime: &Arc<MemoryRuntime>,
    profile: &AssistantAttentionProfile,
) {
    persist_global_checkpoint_json(memory_runtime, ATTENTION_PROFILE_CHECKPOINT_NAME, profile);
}

pub fn load_assistant_attention_profile(
    memory_runtime: &Arc<MemoryRuntime>,
) -> AssistantAttentionProfile {
    load_global_checkpoint_json(memory_runtime, ATTENTION_PROFILE_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn save_assistant_user_profile(
    memory_runtime: &Arc<MemoryRuntime>,
    profile: &AssistantUserProfile,
) {
    persist_global_checkpoint_json(
        memory_runtime,
        ASSISTANT_USER_PROFILE_CHECKPOINT_NAME,
        profile,
    );
}

pub fn load_assistant_user_profile(memory_runtime: &Arc<MemoryRuntime>) -> AssistantUserProfile {
    load_global_checkpoint_json(memory_runtime, ASSISTANT_USER_PROFILE_CHECKPOINT_NAME)
        .unwrap_or_default()
}
