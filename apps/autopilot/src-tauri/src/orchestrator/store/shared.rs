use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

pub(crate) const LOCAL_TASK_CHECKPOINT_NAME: &str = "autopilot.local_task.v1";
pub(crate) const SESSION_FILE_CONTEXT_CHECKPOINT_NAME: &str =
    "autopilot.session_file_context.v1";
pub(crate) const SESSION_COMPACTION_CHECKPOINT_NAME: &str = "autopilot.session_compaction.v1";
pub(crate) const TEAM_MEMORY_SYNC_CHECKPOINT_NAME: &str = "autopilot.team_memory_sync.v1";
pub(crate) const LOCAL_SESSION_INDEX_CHECKPOINT_NAME: &str = "autopilot.local_sessions.v1";
pub(crate) const INTERVENTION_INDEX_CHECKPOINT_NAME: &str = "autopilot.interventions.v1";
pub(crate) const ASSISTANT_NOTIFICATION_INDEX_CHECKPOINT_NAME: &str =
    "autopilot.assistant_notifications.v1";
pub(crate) const ATTENTION_POLICY_CHECKPOINT_NAME: &str =
    "autopilot.assistant_attention_policy.v1";
pub(crate) const ATTENTION_PROFILE_CHECKPOINT_NAME: &str =
    "autopilot.assistant_attention_profile.v1";
pub(crate) const ASSISTANT_USER_PROFILE_CHECKPOINT_NAME: &str =
    "autopilot.assistant_user_profile.v1";
pub(crate) const ASSISTANT_WORKBENCH_ACTIVITY_INDEX_CHECKPOINT_NAME: &str =
    "autopilot.assistant_workbench_activities.v1";
pub(crate) const LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_control_plane.v1";
pub(crate) const LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION: u32 = 1;
pub(crate) const LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID: &str = "local-engine.primary";
pub(crate) const LOCAL_ENGINE_STAGED_OPERATIONS_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_staged_operations.v1";
pub(crate) const LOCAL_ENGINE_JOBS_CHECKPOINT_NAME: &str = "autopilot.local_engine_jobs.v1";
pub(crate) const LOCAL_ENGINE_REGISTRY_STATE_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_registry_state.v1";
pub(crate) const LOCAL_ENGINE_PARENT_PLAYBOOK_DISMISSALS_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_parent_playbook_dismissals.v1";
pub(crate) const KNOWLEDGE_COLLECTIONS_CHECKPOINT_NAME: &str =
    "ioi.knowledge.collections.v1";
pub(crate) const SKILL_SOURCES_CHECKPOINT_NAME: &str = "ioi.skills.sources.v1";
pub(crate) const WORKER_TEMPLATES_CHECKPOINT_NAME: &str = "ioi.workers.templates.v1";

fn scoped_storage_key(scope: &str, id: &str) -> Option<[u8; 32]> {
    let preimage = format!("autopilot::{}::{}", scope, id);
    match sha256(preimage.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            Some(arr)
        }
        Err(_) => None,
    }
}

pub(crate) fn global_checkpoint_key(name: &str) -> Option<[u8; 32]> {
    scoped_storage_key("checkpoint", name)
}

pub(crate) fn thread_storage_key(thread_id: &str) -> Option<[u8; 32]> {
    scoped_storage_key("thread", thread_id)
}

pub(crate) fn load_global_checkpoint_json<T: DeserializeOwned>(
    memory_runtime: &Arc<MemoryRuntime>,
    checkpoint_name: &str,
) -> Option<T> {
    let bytes = load_global_checkpoint_blob(memory_runtime, checkpoint_name)?;
    serde_json::from_slice::<T>(&bytes).ok()
}

pub(crate) fn load_global_checkpoint_blob(
    memory_runtime: &Arc<MemoryRuntime>,
    checkpoint_name: &str,
) -> Option<Vec<u8>> {
    let key = global_checkpoint_key(checkpoint_name)?;
    match memory_runtime.load_checkpoint_blob(key, checkpoint_name) {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) => None,
        Err(error) => {
            eprintln!(
                "[Autopilot] Failed to load checkpoint '{}' from memory runtime: {}",
                checkpoint_name, error
            );
            None
        }
    }
}

pub(crate) fn persist_global_checkpoint_json<T: Serialize + ?Sized>(
    memory_runtime: &Arc<MemoryRuntime>,
    checkpoint_name: &str,
    value: &T,
) {
    let Some(key) = global_checkpoint_key(checkpoint_name) else {
        return;
    };

    let Ok(bytes) = serde_json::to_vec(value) else {
        eprintln!(
            "[Autopilot] Failed to serialize checkpoint '{}' for memory runtime persistence.",
            checkpoint_name
        );
        return;
    };

    if let Err(error) = memory_runtime.upsert_checkpoint_blob(key, checkpoint_name, &bytes) {
        eprintln!(
            "[Autopilot] Failed to persist checkpoint '{}' in memory runtime: {}",
            checkpoint_name, error
        );
    }
}

pub(crate) fn load_thread_checkpoint_json<T: DeserializeOwned>(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: [u8; 32],
    checkpoint_name: &str,
) -> Option<T> {
    match memory_runtime.load_checkpoint_blob(thread_id, checkpoint_name) {
        Ok(Some(bytes)) => serde_json::from_slice::<T>(&bytes).ok(),
        Ok(None) => None,
        Err(error) => {
            eprintln!(
                "[Autopilot] Failed to load thread checkpoint '{}' from memory runtime: {}",
                checkpoint_name, error
            );
            None
        }
    }
}

pub(crate) fn persist_thread_checkpoint_json<T: Serialize>(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: [u8; 32],
    checkpoint_name: &str,
    value: &T,
) {
    let Ok(bytes) = serde_json::to_vec(value) else {
        eprintln!(
            "[Autopilot] Failed to serialize thread checkpoint '{}' for memory runtime persistence.",
            checkpoint_name
        );
        return;
    };

    if let Err(error) = memory_runtime.upsert_checkpoint_blob(thread_id, checkpoint_name, &bytes) {
        eprintln!(
            "[Autopilot] Failed to persist thread checkpoint '{}' in memory runtime: {}",
            checkpoint_name, error
        );
    }
}

pub(crate) fn get_session_storage_key(session_id: &str) -> Option<[u8; 32]> {
    if session_id.len() == 64 {
        if let Ok(bytes) = hex::decode(session_id) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }
    }

    match sha256(session_id.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            Some(arr)
        }
        Err(_) => None,
    }
}
