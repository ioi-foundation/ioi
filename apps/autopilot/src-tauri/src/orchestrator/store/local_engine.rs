use super::shared::{
    load_global_checkpoint_blob, load_global_checkpoint_json, persist_global_checkpoint_json,
    LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME, LOCAL_ENGINE_JOBS_CHECKPOINT_NAME,
    LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID, LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
    LOCAL_ENGINE_PARENT_PLAYBOOK_DISMISSALS_CHECKPOINT_NAME,
    LOCAL_ENGINE_REGISTRY_STATE_CHECKPOINT_NAME, LOCAL_ENGINE_STAGED_OPERATIONS_CHECKPOINT_NAME,
};
use crate::models::{
    LocalEngineControlPlane, LocalEngineControlPlaneDocument, LocalEngineJobRecord,
    LocalEngineRegistryState, LocalEngineStagedOperation,
};
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

fn default_local_engine_control_plane_profile_id() -> String {
    LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID.to_string()
}

fn current_local_engine_control_plane_document(
    control_plane: LocalEngineControlPlane,
    existing: Option<LocalEngineControlPlaneDocument>,
) -> LocalEngineControlPlaneDocument {
    let existing = existing.unwrap_or(LocalEngineControlPlaneDocument {
        schema_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
        profile_id: default_local_engine_control_plane_profile_id(),
        migrations: Vec::new(),
        control_plane: control_plane.clone(),
    });

    LocalEngineControlPlaneDocument {
        schema_version: existing
            .schema_version
            .max(LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION),
        profile_id: if existing.profile_id.trim().is_empty() {
            default_local_engine_control_plane_profile_id()
        } else {
            existing.profile_id
        },
        migrations: existing.migrations,
        control_plane,
    }
}

pub fn save_local_engine_control_plane(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: &LocalEngineControlPlane,
) {
    let document = current_local_engine_control_plane_document(
        control_plane.clone(),
        load_local_engine_control_plane_document(memory_runtime),
    );
    save_local_engine_control_plane_document(memory_runtime, &document);
}

pub fn save_local_engine_control_plane_document(
    memory_runtime: &Arc<MemoryRuntime>,
    document: &LocalEngineControlPlaneDocument,
) {
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME,
        document,
    );
}

pub fn load_local_engine_control_plane(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Option<LocalEngineControlPlane> {
    load_local_engine_control_plane_document(memory_runtime).map(|document| document.control_plane)
}

pub fn load_local_engine_control_plane_document(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Option<LocalEngineControlPlaneDocument> {
    let bytes =
        load_global_checkpoint_blob(memory_runtime, LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME)?;
    if let Ok(mut document) = serde_json::from_slice::<LocalEngineControlPlaneDocument>(&bytes) {
        if document.schema_version == 0 {
            eprintln!(
                "[Autopilot] Rejected Local Engine control-plane checkpoint with legacy schema_version=0. Delete '{}' to regenerate a v1 config.",
                LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME
            );
            return None;
        }
        if document.profile_id.trim().is_empty() {
            document.profile_id = default_local_engine_control_plane_profile_id();
        }
        return Some(document);
    }

    eprintln!(
        "[Autopilot] Rejected unversioned Local Engine control-plane checkpoint. Delete '{}' to regenerate a v1 config.",
        LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME
    );
    None
}

pub fn save_local_engine_staged_operations(
    memory_runtime: &Arc<MemoryRuntime>,
    operations: &[LocalEngineStagedOperation],
) {
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_STAGED_OPERATIONS_CHECKPOINT_NAME,
        operations,
    );
}

pub fn load_local_engine_staged_operations(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<LocalEngineStagedOperation> {
    load_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_STAGED_OPERATIONS_CHECKPOINT_NAME,
    )
    .unwrap_or_default()
}

pub fn save_local_engine_jobs(memory_runtime: &Arc<MemoryRuntime>, jobs: &[LocalEngineJobRecord]) {
    persist_global_checkpoint_json(memory_runtime, LOCAL_ENGINE_JOBS_CHECKPOINT_NAME, jobs);
}

pub fn load_local_engine_jobs(memory_runtime: &Arc<MemoryRuntime>) -> Vec<LocalEngineJobRecord> {
    load_global_checkpoint_json(memory_runtime, LOCAL_ENGINE_JOBS_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn save_local_engine_registry_state(
    memory_runtime: &Arc<MemoryRuntime>,
    state: &LocalEngineRegistryState,
) {
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_REGISTRY_STATE_CHECKPOINT_NAME,
        state,
    );
}

pub fn load_local_engine_registry_state(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Option<LocalEngineRegistryState> {
    load_global_checkpoint_json(memory_runtime, LOCAL_ENGINE_REGISTRY_STATE_CHECKPOINT_NAME)
}

pub fn save_local_engine_parent_playbook_dismissals(
    memory_runtime: &Arc<MemoryRuntime>,
    run_ids: &[String],
) {
    let mut normalized = run_ids
        .iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_PARENT_PLAYBOOK_DISMISSALS_CHECKPOINT_NAME,
        &normalized,
    );
}

pub fn load_local_engine_parent_playbook_dismissals(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<String> {
    load_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_PARENT_PLAYBOOK_DISMISSALS_CHECKPOINT_NAME,
    )
    .unwrap_or_default()
}
