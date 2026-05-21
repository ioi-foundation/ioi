use super::shared::{
    load_global_checkpoint_json, persist_global_checkpoint_json,
    KNOWLEDGE_COLLECTIONS_CHECKPOINT_NAME,
};
use crate::models::KnowledgeCollectionRecord;
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

pub fn save_knowledge_collections(
    memory_runtime: &Arc<MemoryRuntime>,
    collections: &[KnowledgeCollectionRecord],
) {
    let mut normalized = collections.to_vec();
    normalized.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.label.cmp(&right.label))
    });
    persist_global_checkpoint_json(
        memory_runtime,
        KNOWLEDGE_COLLECTIONS_CHECKPOINT_NAME,
        &normalized,
    );
}

pub fn load_knowledge_collections(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<KnowledgeCollectionRecord> {
    load_global_checkpoint_json(memory_runtime, KNOWLEDGE_COLLECTIONS_CHECKPOINT_NAME)
        .unwrap_or_default()
}
