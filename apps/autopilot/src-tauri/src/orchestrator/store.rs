use crate::models::{
    AgentEvent, AgentPhase, AgentTask, Artifact, AssistantAttentionPolicy,
    AssistantAttentionProfile, AssistantNotificationRecord, AssistantUserProfile,
    AssistantWorkbenchActivityRecord, InterventionRecord, KnowledgeCollectionRecord,
    LocalEngineApiConfig, LocalEngineBackendPolicyConfig, LocalEngineConfigMigrationRecord,
    LocalEngineControlPlane, LocalEngineControlPlaneDocument, LocalEngineEnvironmentBinding,
    LocalEngineGallerySource, LocalEngineJobRecord, LocalEngineLauncherConfig,
    LocalEngineMemoryConfig, LocalEngineRegistryState, LocalEngineResponseConfig,
    LocalEngineRuntimeProfile, LocalEngineStagedOperation, LocalEngineStorageConfig,
    LocalEngineWatchdogConfig, LocalEngineWorkerTemplateRecord, SessionCompactionRecord,
    SessionFileContext, SessionSummary, SkillSourceRecord, TeamMemorySyncEntry,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

const LOCAL_TASK_CHECKPOINT_NAME: &str = "autopilot.local_task.v1";
const SESSION_FILE_CONTEXT_CHECKPOINT_NAME: &str = "autopilot.session_file_context.v1";
const SESSION_COMPACTION_CHECKPOINT_NAME: &str = "autopilot.session_compaction.v1";
const TEAM_MEMORY_SYNC_CHECKPOINT_NAME: &str = "autopilot.team_memory_sync.v1";
const LOCAL_SESSION_INDEX_CHECKPOINT_NAME: &str = "autopilot.local_sessions.v1";
const INTERVENTION_INDEX_CHECKPOINT_NAME: &str = "autopilot.interventions.v1";
const ASSISTANT_NOTIFICATION_INDEX_CHECKPOINT_NAME: &str = "autopilot.assistant_notifications.v1";
const ATTENTION_POLICY_CHECKPOINT_NAME: &str = "autopilot.assistant_attention_policy.v1";
const ATTENTION_PROFILE_CHECKPOINT_NAME: &str = "autopilot.assistant_attention_profile.v1";
const ASSISTANT_USER_PROFILE_CHECKPOINT_NAME: &str = "autopilot.assistant_user_profile.v1";
const ASSISTANT_WORKBENCH_ACTIVITY_INDEX_CHECKPOINT_NAME: &str =
    "autopilot.assistant_workbench_activities.v1";
const LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME: &str = "autopilot.local_engine_control_plane.v1";
const LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION: u32 = 1;
const LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID: &str = "local-engine.primary";
const LOCAL_ENGINE_CONTROL_PLANE_V0_TO_V1_MIGRATION_ID: &str =
    "local_engine_control_plane.v0_to_v1";
const LOCAL_ENGINE_STAGED_OPERATIONS_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_staged_operations.v1";
const LOCAL_ENGINE_JOBS_CHECKPOINT_NAME: &str = "autopilot.local_engine_jobs.v1";
const LOCAL_ENGINE_REGISTRY_STATE_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_registry_state.v1";
const LOCAL_ENGINE_PARENT_PLAYBOOK_DISMISSALS_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_parent_playbook_dismissals.v1";
const KNOWLEDGE_COLLECTIONS_CHECKPOINT_NAME: &str = "ioi.knowledge.collections.v1";
const SKILL_SOURCES_CHECKPOINT_NAME: &str = "ioi.skills.sources.v1";
const WORKER_TEMPLATES_CHECKPOINT_NAME: &str = "ioi.workers.templates.v1";

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

fn thread_storage_key(thread_id: &str) -> Option<[u8; 32]> {
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyLocalEngineControlPlaneV0 {
    runtime: LocalEngineRuntimeProfile,
    storage: LocalEngineStorageConfig,
    watchdog: LocalEngineWatchdogConfig,
    memory: LocalEngineMemoryConfig,
    backend_policy: LocalEngineBackendPolicyConfig,
    responses: LocalEngineResponseConfig,
    api: LocalEngineApiConfig,
    #[serde(default)]
    launcher: Option<LocalEngineLauncherConfig>,
    #[serde(default)]
    galleries: Vec<LocalEngineGallerySource>,
    #[serde(default)]
    environment: Vec<LocalEngineEnvironmentBinding>,
    #[serde(default)]
    notes: Vec<String>,
}

fn default_local_engine_control_plane_profile_id() -> String {
    LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID.to_string()
}

fn local_engine_v0_to_v1_migration(
    summary: &str,
    details: Vec<String>,
) -> LocalEngineConfigMigrationRecord {
    LocalEngineConfigMigrationRecord {
        migration_id: LOCAL_ENGINE_CONTROL_PLANE_V0_TO_V1_MIGRATION_ID.to_string(),
        from_version: 0,
        to_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
        applied_at_ms: crate::kernel::state::now(),
        summary: summary.to_string(),
        details,
    }
}

fn local_engine_control_plane_document_from_legacy(
    legacy: LegacyLocalEngineControlPlaneV0,
) -> LocalEngineControlPlaneDocument {
    let defaults = crate::kernel::data::default_local_engine_control_plane();
    let mut details = vec![
        "Wrapped legacy unversioned control-plane state in the canonical versioned config profile."
            .to_string(),
    ];

    if legacy.launcher.is_none() {
        details.push(
            "Backfilled launcher defaults so boot and update controls stay product-native."
                .to_string(),
        );
    }
    if legacy.galleries.is_empty() {
        details.push(
            "Restored default gallery sources because the legacy payload did not record them."
                .to_string(),
        );
    }
    if legacy.environment.is_empty() {
        details.push(
            "Restored authoritative environment bindings for runtime-side diffing.".to_string(),
        );
    }
    if legacy.notes.is_empty() {
        details.push(
            "Restored kernel guidance notes because the legacy payload did not retain them."
                .to_string(),
        );
    }

    LocalEngineControlPlaneDocument {
        schema_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
        profile_id: default_local_engine_control_plane_profile_id(),
        migrations: vec![local_engine_v0_to_v1_migration(
            "Upgraded Local Engine settings into the versioned config document.",
            details,
        )],
        control_plane: LocalEngineControlPlane {
            runtime: legacy.runtime,
            storage: legacy.storage,
            watchdog: legacy.watchdog,
            memory: legacy.memory,
            backend_policy: legacy.backend_policy,
            responses: legacy.responses,
            api: legacy.api,
            launcher: legacy.launcher.unwrap_or(defaults.launcher),
            galleries: if legacy.galleries.is_empty() {
                defaults.galleries
            } else {
                legacy.galleries
            },
            environment: if legacy.environment.is_empty() {
                defaults.environment
            } else {
                legacy.environment
            },
            notes: if legacy.notes.is_empty() {
                defaults.notes
            } else {
                legacy.notes
            },
        },
    }
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

fn load_thread_checkpoint_json<T: DeserializeOwned>(
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

fn persist_thread_checkpoint_json<T: Serialize>(
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

pub fn append_artifact(memory_runtime: &Arc<MemoryRuntime>, artifact: &Artifact, content: &[u8]) {
    let Some(thread_key) = thread_storage_key(&artifact.thread_id) else {
        return;
    };
    let Ok(payload_json) = serde_json::to_string(artifact) else {
        return;
    };
    let _ = memory_runtime.upsert_artifact_json(thread_key, &artifact.artifact_id, &payload_json);
    let _ = memory_runtime.put_artifact_blob(thread_key, &artifact.artifact_id, content);
}

pub fn load_artifacts(memory_runtime: &Arc<MemoryRuntime>, thread_id: &str) -> Vec<Artifact> {
    let Some(key) = thread_storage_key(thread_id) else {
        return Vec::new();
    };

    memory_runtime
        .load_artifact_jsons(key)
        .ok()
        .into_iter()
        .flat_map(|artifacts| artifacts.into_iter())
        .filter_map(|artifact| serde_json::from_str::<Artifact>(&artifact.payload_json).ok())
        .collect()
}

pub fn load_artifact_content(
    memory_runtime: &Arc<MemoryRuntime>,
    artifact_id: &str,
) -> Option<Vec<u8>> {
    memory_runtime
        .load_artifact_blob(artifact_id)
        .ok()
        .flatten()
}

pub fn get_local_sessions(memory_runtime: &Arc<MemoryRuntime>) -> Vec<SessionSummary> {
    load_global_checkpoint_json(memory_runtime, LOCAL_SESSION_INDEX_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn get_local_sessions_with_live_tasks(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<SessionSummary> {
    let mut sessions = get_local_sessions(memory_runtime);
    for checkpoint in memory_runtime
        .list_checkpoint_blobs(LOCAL_TASK_CHECKPOINT_NAME)
        .unwrap_or_default()
    {
        let Ok(task) = serde_json::from_slice::<AgentTask>(&checkpoint.payload) else {
            continue;
        };

        let session_id = task
            .session_id
            .as_deref()
            .unwrap_or(task.id.as_str())
            .to_string();
        let existing = sessions
            .iter()
            .find(|summary| summary.session_id == session_id)
            .cloned();
        let mut summary = session_summary_from_task(&task, existing.as_ref());
        summary.timestamp = summary.timestamp.max(checkpoint.updated_at_ms);
        if summary.workspace_root.is_none() {
            summary.workspace_root =
                persisted_workspace_root_for_session(memory_runtime, Some(session_id.as_str()));
        }

        if let Some(position) = sessions
            .iter()
            .position(|candidate| candidate.session_id == session_id)
        {
            sessions[position] = summary;
        } else {
            sessions.push(summary);
        }
    }

    sessions.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    sessions
}

pub fn save_local_session_summary(memory_runtime: &Arc<MemoryRuntime>, summary: SessionSummary) {
    let mut sessions = get_local_sessions(memory_runtime);
    if let Some(pos) = sessions
        .iter()
        .position(|s| s.session_id == summary.session_id)
    {
        sessions[pos] = summary;
    } else {
        sessions.push(summary);
    }
    sessions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_SESSION_INDEX_CHECKPOINT_NAME,
        &sessions,
    );
}

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

pub fn delete_local_session_summary(memory_runtime: &Arc<MemoryRuntime>, session_id: &str) {
    let mut sessions = get_local_sessions(memory_runtime);
    sessions.retain(|session| session.session_id != session_id);
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_SESSION_INDEX_CHECKPOINT_NAME,
        &sessions,
    );
}

fn get_session_storage_key(session_id: &str) -> Option<[u8; 32]> {
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

fn workspace_root_from_task(task: &AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.studio_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn normalize_workspace_root(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn session_summary_title_from_task_intent(intent: &str) -> String {
    truncate_session_summary_label(intent.trim(), 27)
}

fn truncate_session_summary_label(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    let mut chars = trimmed.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}...", shortened)
    } else {
        trimmed.to_string()
    }
}

fn session_resume_hint_from_task(task: &AgentTask) -> Option<String> {
    if let Some(clarification_request) = task.clarification_request.as_ref() {
        let question = clarification_request.question.trim();
        if !question.is_empty() {
            return Some(format!(
                "Clarify: {}",
                truncate_session_summary_label(question, 60)
            ));
        }
    }

    if let Some(credential_request) = task.credential_request.as_ref() {
        let prompt = credential_request.prompt.trim();
        if prompt.to_ascii_lowercase().contains("sudo") {
            return Some("Provide sudo password".to_string());
        }
        if !prompt.is_empty() {
            return Some(truncate_session_summary_label(prompt, 60));
        }
        if !credential_request.kind.trim().is_empty() {
            return Some("Provide credential".to_string());
        }
    }

    if task.phase == AgentPhase::Gate || task.pending_request_hash.is_some() {
        if let Some(gate_info) = task.gate_info.as_ref() {
            let gate_label = gate_info
                .operation_label
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    gate_info
                        .target_label
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
                .unwrap_or(gate_info.title.as_str());
            let trimmed = gate_label.trim();
            if !trimmed.is_empty() {
                return Some(format!(
                    "Review: {}",
                    truncate_session_summary_label(trimmed, 60)
                ));
            }
        }
        return Some("Review approval".to_string());
    }

    if task.phase == AgentPhase::Complete {
        if let Some(build_session) = task.build_session.as_ref() {
            if !build_session.workspace_root.trim().is_empty() {
                return Some("Open workspace".to_string());
            }
        }
    }

    None
}

pub const DRAFT_SESSION_FILE_CONTEXT_ID: &str = "__spotlight_draft_session__";

fn normalized_file_context_session_id(session_id: Option<&str>) -> &str {
    match session_id.map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => DRAFT_SESSION_FILE_CONTEXT_ID,
    }
}

fn default_workspace_root_for_file_context(provided_root: Option<&str>) -> String {
    let provided = provided_root
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(root) = provided {
        return root;
    }

    std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| ".".to_string())
}

fn default_session_file_context(
    session_id: Option<&str>,
    workspace_root: Option<&str>,
) -> SessionFileContext {
    SessionFileContext {
        session_id: session_id.map(ToOwned::to_owned),
        workspace_root: default_workspace_root_for_file_context(workspace_root),
        pinned_files: Vec::new(),
        recent_files: Vec::new(),
        explicit_includes: Vec::new(),
        explicit_excludes: Vec::new(),
        updated_at_ms: crate::kernel::state::now(),
    }
}

pub fn load_persisted_session_file_context(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
) -> Option<SessionFileContext> {
    let normalized_session_id = normalized_file_context_session_id(session_id);
    let session_key = get_session_storage_key(normalized_session_id)?;

    let normalize_loaded_context =
        |mut context: SessionFileContext, resolved_session_id: Option<&str>| {
            context.session_id = resolved_session_id.map(ToOwned::to_owned);
            context
        };

    if let Some(context) = load_thread_checkpoint_json(
        memory_runtime,
        session_key,
        SESSION_FILE_CONTEXT_CHECKPOINT_NAME,
    ) {
        return Some(normalize_loaded_context(context, session_id));
    }

    if session_id.is_some() {
        let draft_key = get_session_storage_key(DRAFT_SESSION_FILE_CONTEXT_ID)?;
        if let Some(mut promoted_context) = load_thread_checkpoint_json::<SessionFileContext>(
            memory_runtime,
            draft_key,
            SESSION_FILE_CONTEXT_CHECKPOINT_NAME,
        ) {
            promoted_context.session_id = session_id.map(ToOwned::to_owned);
            persist_thread_checkpoint_json(
                memory_runtime,
                session_key,
                SESSION_FILE_CONTEXT_CHECKPOINT_NAME,
                &promoted_context,
            );
            let _ = memory_runtime
                .delete_checkpoint_blob(draft_key, SESSION_FILE_CONTEXT_CHECKPOINT_NAME);
            return Some(promoted_context);
        }
    }

    None
}

pub fn load_session_compaction_records(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
) -> Vec<SessionCompactionRecord> {
    let normalized_session_id = normalized_file_context_session_id(session_id);
    let Some(session_key) = get_session_storage_key(normalized_session_id) else {
        return Vec::new();
    };

    load_thread_checkpoint_json(
        memory_runtime,
        session_key,
        SESSION_COMPACTION_CHECKPOINT_NAME,
    )
    .unwrap_or_default()
}

pub fn append_session_compaction_record(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
    record: SessionCompactionRecord,
) {
    let normalized_session_id = normalized_file_context_session_id(session_id);
    let Some(session_key) = get_session_storage_key(normalized_session_id) else {
        return;
    };

    let mut records = load_session_compaction_records(memory_runtime, session_id);
    records.retain(|existing| existing.compaction_id != record.compaction_id);
    records.insert(0, record);
    if records.len() > 8 {
        records.truncate(8);
    }
    persist_thread_checkpoint_json(
        memory_runtime,
        session_key,
        SESSION_COMPACTION_CHECKPOINT_NAME,
        &records,
    );
}

pub fn load_team_memory_sync_entries(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<TeamMemorySyncEntry> {
    load_global_checkpoint_json(memory_runtime, TEAM_MEMORY_SYNC_CHECKPOINT_NAME)
        .unwrap_or_default()
}

pub fn save_team_memory_sync_entries(
    memory_runtime: &Arc<MemoryRuntime>,
    entries: &[TeamMemorySyncEntry],
) {
    let mut normalized = entries.to_vec();
    normalized.sort_by(|left, right| {
        right
            .synced_at_ms
            .cmp(&left.synced_at_ms)
            .then_with(|| left.entry_id.cmp(&right.entry_id))
    });
    persist_global_checkpoint_json(
        memory_runtime,
        TEAM_MEMORY_SYNC_CHECKPOINT_NAME,
        &normalized,
    );
}

pub fn persisted_workspace_root_for_session(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
) -> Option<String> {
    load_persisted_session_file_context(memory_runtime, session_id)
        .and_then(|context| normalize_workspace_root(Some(context.workspace_root)))
}

pub fn session_summary_from_task(
    task: &AgentTask,
    existing: Option<&SessionSummary>,
) -> SessionSummary {
    let session_id = task.session_id.as_deref().unwrap_or(&task.id).to_string();
    let existing_workspace_root =
        existing.and_then(|summary| normalize_workspace_root(summary.workspace_root.clone()));

    SessionSummary {
        session_id,
        title: existing
            .map(|summary| summary.title.trim())
            .filter(|title| !title.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| session_summary_title_from_task_intent(&task.intent)),
        timestamp: existing
            .map(|summary| summary.timestamp)
            .unwrap_or_else(crate::kernel::state::now),
        phase: Some(task.phase.clone()),
        current_step: if task.current_step.trim().is_empty() {
            None
        } else {
            Some(task.current_step.clone())
        },
        resume_hint: session_resume_hint_from_task(task),
        workspace_root: normalize_workspace_root(workspace_root_from_task(task))
            .or(existing_workspace_root),
    }
}

pub fn save_local_task_state(memory_runtime: &Arc<MemoryRuntime>, task: &AgentTask) {
    let sid = task.session_id.as_deref().unwrap_or(&task.id);
    let Some(key) = get_session_storage_key(sid) else {
        return;
    };
    persist_thread_checkpoint_json(memory_runtime, key, LOCAL_TASK_CHECKPOINT_NAME, task);

    let existing_summary = get_local_sessions(memory_runtime)
        .into_iter()
        .find(|summary| summary.session_id == sid);
    let mut summary = session_summary_from_task(task, existing_summary.as_ref());
    if summary.workspace_root.is_none() {
        summary.workspace_root = persisted_workspace_root_for_session(memory_runtime, Some(sid));
    }
    save_local_session_summary(memory_runtime, summary);
}

pub fn clear_local_task_state(memory_runtime: &Arc<MemoryRuntime>, session_id: &str) {
    let Some(key) = get_session_storage_key(session_id) else {
        return;
    };
    if let Err(error) = memory_runtime.delete_checkpoint_blob(key, LOCAL_TASK_CHECKPOINT_NAME) {
        eprintln!(
            "[Autopilot] Failed to clear thread checkpoint '{}' in memory runtime: {}",
            LOCAL_TASK_CHECKPOINT_NAME, error
        );
    }

    let mut sessions = get_local_sessions(memory_runtime);
    if let Some(summary) = sessions
        .iter_mut()
        .find(|summary| summary.session_id == session_id)
    {
        summary.phase = Some(AgentPhase::Complete);
        summary.current_step = Some("Stopped by operator.".to_string());
        summary.resume_hint = None;
        save_local_session_summary(memory_runtime, summary.clone());
    }
}

pub fn load_local_task(memory_runtime: &Arc<MemoryRuntime>, session_id: &str) -> Option<AgentTask> {
    let key = get_session_storage_key(session_id)?;
    load_thread_checkpoint_json(memory_runtime, key, LOCAL_TASK_CHECKPOINT_NAME)
}

pub fn load_session_file_context(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
    workspace_root: Option<&str>,
) -> SessionFileContext {
    let normalized_session_id = normalized_file_context_session_id(session_id);
    if get_session_storage_key(normalized_session_id).is_none() {
        return default_session_file_context(session_id, workspace_root);
    }

    let normalize_loaded_context =
        |mut context: SessionFileContext, resolved_session_id: Option<&str>| {
            context.session_id = resolved_session_id.map(ToOwned::to_owned);
            if context.workspace_root.trim().is_empty() {
                context.workspace_root = default_workspace_root_for_file_context(workspace_root);
            }
            context
        };

    if let Some(context) = load_persisted_session_file_context(memory_runtime, session_id) {
        return normalize_loaded_context(context, session_id);
    }

    default_session_file_context(session_id, workspace_root)
}

pub fn save_session_file_context(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
    context: &SessionFileContext,
) {
    let normalized_session_id = normalized_file_context_session_id(session_id);
    let Some(key) = get_session_storage_key(normalized_session_id) else {
        return;
    };
    persist_thread_checkpoint_json(
        memory_runtime,
        key,
        SESSION_FILE_CONTEXT_CHECKPOINT_NAME,
        context,
    );

    let Some(session_id) = session_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    let Some(workspace_root) = normalize_workspace_root(Some(context.workspace_root.clone()))
    else {
        return;
    };
    let Some(mut summary) = get_local_sessions(memory_runtime)
        .into_iter()
        .find(|summary| summary.session_id == session_id)
    else {
        return;
    };
    if summary.workspace_root.as_deref() == Some(workspace_root.as_str()) {
        return;
    }
    summary.workspace_root = Some(workspace_root);
    save_local_session_summary(memory_runtime, summary);
}

pub fn clear_session_file_context(memory_runtime: &Arc<MemoryRuntime>, session_id: Option<&str>) {
    let normalized_session_id = normalized_file_context_session_id(session_id);
    let Some(key) = get_session_storage_key(normalized_session_id) else {
        return;
    };
    if let Err(error) =
        memory_runtime.delete_checkpoint_blob(key, SESSION_FILE_CONTEXT_CHECKPOINT_NAME)
    {
        eprintln!(
            "[Autopilot] Failed to clear thread checkpoint '{}' in memory runtime: {}",
            SESSION_FILE_CONTEXT_CHECKPOINT_NAME, error
        );
    }
}

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
            let already_recorded = document.migrations.iter().any(|record| {
                record.migration_id == LOCAL_ENGINE_CONTROL_PLANE_V0_TO_V1_MIGRATION_ID
            });
            document.schema_version = LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION;
            if !already_recorded {
                document.migrations.push(local_engine_v0_to_v1_migration(
                    "Stamped the Local Engine config document with the first canonical schema version.",
                    vec![
                        "The document already used the wrapped control-plane shape but did not record a schema version."
                            .to_string(),
                    ],
                ));
            }
        }
        if document.profile_id.trim().is_empty() {
            document.profile_id = default_local_engine_control_plane_profile_id();
        }
        return Some(document);
    }

    serde_json::from_slice::<LegacyLocalEngineControlPlaneV0>(&bytes)
        .ok()
        .map(local_engine_control_plane_document_from_legacy)
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

pub fn save_skill_sources(memory_runtime: &Arc<MemoryRuntime>, sources: &[SkillSourceRecord]) {
    let mut normalized = sources.to_vec();
    normalized.sort_by(|left, right| left.label.cmp(&right.label));
    persist_global_checkpoint_json(memory_runtime, SKILL_SOURCES_CHECKPOINT_NAME, &normalized);
}

pub fn load_skill_sources(memory_runtime: &Arc<MemoryRuntime>) -> Vec<SkillSourceRecord> {
    load_global_checkpoint_json(memory_runtime, SKILL_SOURCES_CHECKPOINT_NAME).unwrap_or_default()
}

pub fn save_worker_templates(
    memory_runtime: &Arc<MemoryRuntime>,
    templates: &[LocalEngineWorkerTemplateRecord],
) {
    persist_global_checkpoint_json(memory_runtime, WORKER_TEMPLATES_CHECKPOINT_NAME, templates);
}

pub fn load_worker_templates(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<LocalEngineWorkerTemplateRecord> {
    load_global_checkpoint_json(memory_runtime, WORKER_TEMPLATES_CHECKPOINT_NAME)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        get_local_sessions, get_local_sessions_with_live_tasks, load_global_checkpoint_blob,
        load_local_engine_control_plane_document, load_session_file_context,
        persisted_workspace_root_for_session, save_local_engine_control_plane,
        save_local_engine_control_plane_document, save_local_session_summary,
        save_local_task_state, save_session_file_context, session_summary_from_task,
        LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME, LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID,
        LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
    };
    use crate::kernel::file_context::{
        apply_exclude_file_context_path, apply_include_file_context_path,
    };
    use crate::models::{
        AgentPhase, AgentTask, BuildArtifactSession, LocalEngineConfigMigrationRecord,
        LocalEngineControlPlaneDocument, SessionFileContext, SessionSummary, StudioCodeWorkerLease,
    };
    use crate::open_or_create_memory_runtime;
    use ioi_memory::MemoryRuntime;
    use serde::Serialize;
    use serde_json::json;
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use uuid::Uuid;

    fn build_session(workspace_root: &str) -> BuildArtifactSession {
        BuildArtifactSession {
            session_id: "build-session".to_string(),
            studio_session_id: "studio-session".to_string(),
            workspace_root: workspace_root.to_string(),
            entry_document: "src/App.tsx".to_string(),
            preview_url: Some("http://127.0.0.1:4173".to_string()),
            preview_process_id: Some(41),
            scaffold_recipe_id: "workspace_surface".to_string(),
            presentation_variant_id: None,
            package_manager: "npm".to_string(),
            build_status: "ready".to_string(),
            verification_status: "ready".to_string(),
            receipts: Vec::new(),
            current_worker_execution: StudioCodeWorkerLease {
                backend: "local".to_string(),
                planner_authority: "runtime".to_string(),
                allowed_mutation_scope: vec!["workspace".to_string()],
                allowed_command_classes: vec!["build".to_string()],
                execution_state: "complete".to_string(),
                retry_classification: None,
                last_summary: Some("Preview verified.".to_string()),
            },
            current_lens: "render".to_string(),
            available_lenses: vec!["render".to_string()],
            ready_lenses: vec!["render".to_string()],
            retry_count: 0,
            last_failure_summary: None,
        }
    }

    fn task_with_workspace_root(workspace_root: &str) -> AgentTask {
        let mut task = AgentTask {
            id: "task-id".to_string(),
            intent: "Create a workspace artifact for billing settings".to_string(),
            agent: "Autopilot".to_string(),
            phase: AgentPhase::Complete,
            progress: 4,
            total_steps: 4,
            current_step: "Preview verified and ready".to_string(),
            gate_info: None,
            receipt: None,
            visual_hash: None,
            pending_request_hash: None,
            session_id: Some("session-123".to_string()),
            credential_request: None,
            clarification_request: None,
            session_checklist: Vec::new(),
            background_tasks: Vec::new(),
            history: Vec::new(),
            events: Vec::new(),
            artifacts: Vec::new(),
            studio_session: None,
            studio_outcome: None,
            renderer_session: None,
            build_session: Some(build_session(workspace_root)),
            run_bundle_id: None,
            processed_steps: HashSet::new(),
            swarm_tree: Vec::new(),
            generation: 0,
            lineage_id: "genesis".to_string(),
            fitness_score: 0.0,
        };
        task.sync_runtime_views();
        task
    }

    fn task_without_workspace_root() -> AgentTask {
        let mut task = task_with_workspace_root("/tmp/unused");
        task.build_session = None;
        task.sync_runtime_views();
        task
    }

    fn temp_runtime_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("autopilot-store-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp runtime dir");
        dir
    }

    fn save_local_engine_control_plane_value<T: Serialize>(
        memory_runtime: &Arc<MemoryRuntime>,
        value: &T,
    ) {
        let key = super::global_checkpoint_key(LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME)
            .expect("local engine checkpoint key");
        let bytes = serde_json::to_vec(value).expect("serialize local engine checkpoint value");
        memory_runtime
            .upsert_checkpoint_blob(key, LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME, &bytes)
            .expect("persist local engine checkpoint value");
    }

    #[test]
    fn session_summary_from_task_preserves_existing_title_and_timestamp() {
        let task = task_with_workspace_root("/tmp/workspace");
        let existing = SessionSummary {
            session_id: "session-123".to_string(),
            title: "Existing title".to_string(),
            timestamp: 42,
            phase: Some(AgentPhase::Running),
            current_step: Some("Initializing".to_string()),
            resume_hint: None,
            workspace_root: None,
        };

        let summary = session_summary_from_task(&task, Some(&existing));

        assert_eq!(summary.session_id, "session-123");
        assert_eq!(summary.title, "Existing title");
        assert_eq!(summary.timestamp, 42);
        assert_eq!(summary.phase, Some(AgentPhase::Complete));
        assert_eq!(
            summary.current_step.as_deref(),
            Some("Preview verified and ready")
        );
        assert_eq!(summary.resume_hint.as_deref(), Some("Open workspace"));
        assert_eq!(summary.workspace_root.as_deref(), Some("/tmp/workspace"));
    }

    #[test]
    fn session_summary_from_task_derives_title_when_no_summary_exists() {
        let mut task = task_with_workspace_root("/tmp/workspace");
        task.intent = "Create a React app for a property management dashboard".to_string();

        let summary = session_summary_from_task(&task, None);

        assert_eq!(summary.session_id, "session-123");
        assert_eq!(summary.title, "Create a React app for a pr...");
        assert_eq!(summary.phase, Some(AgentPhase::Complete));
        assert_eq!(summary.resume_hint.as_deref(), Some("Open workspace"));
        assert_eq!(summary.workspace_root.as_deref(), Some("/tmp/workspace"));
    }

    #[test]
    fn session_summary_from_task_preserves_existing_workspace_root() {
        let task = task_without_workspace_root();
        let existing = SessionSummary {
            session_id: "session-123".to_string(),
            title: "Existing title".to_string(),
            timestamp: 42,
            phase: Some(AgentPhase::Running),
            current_step: Some("Initializing".to_string()),
            resume_hint: None,
            workspace_root: Some("/tmp/preserved-root".to_string()),
        };

        let summary = session_summary_from_task(&task, Some(&existing));

        assert_eq!(
            summary.workspace_root.as_deref(),
            Some("/tmp/preserved-root")
        );
    }

    #[test]
    fn live_task_summary_appears_even_when_not_retained_in_session_index() {
        let dir = temp_runtime_dir();
        let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
        let mut task = task_with_workspace_root("/tmp/live-workspace");
        task.session_id =
            Some("e65b8f5b1a0f4dc9aa424d9d50a792f5378cda656a5a421fb8d154a2060faa54".to_string());
        task.phase = AgentPhase::Gate;
        task.current_step = "Waiting for clarification.".to_string();

        save_local_task_state(&memory_runtime, &task);
        let summaries = get_local_sessions_with_live_tasks(&memory_runtime);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].session_id, task.session_id.clone().unwrap());
        assert_eq!(summaries[0].phase, Some(AgentPhase::Gate));
        assert_eq!(
            summaries[0].workspace_root.as_deref(),
            Some("/tmp/live-workspace")
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn save_session_file_context_backfills_existing_session_summary_root() {
        let dir = temp_runtime_dir();
        let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
        save_local_session_summary(
            &memory_runtime,
            SessionSummary {
                session_id: "session-123".to_string(),
                title: "Existing title".to_string(),
                timestamp: 42,
                phase: Some(AgentPhase::Running),
                current_step: Some("Initializing".to_string()),
                resume_hint: None,
                workspace_root: None,
            },
        );

        save_session_file_context(
            &memory_runtime,
            Some("session-123"),
            &SessionFileContext {
                session_id: Some("session-123".to_string()),
                workspace_root: "/tmp/from-file-context".to_string(),
                pinned_files: Vec::new(),
                recent_files: Vec::new(),
                explicit_includes: Vec::new(),
                explicit_excludes: Vec::new(),
                updated_at_ms: 1,
            },
        );

        let saved = get_local_sessions(&memory_runtime);
        assert_eq!(saved.len(), 1);
        assert_eq!(
            saved[0].workspace_root.as_deref(),
            Some("/tmp/from-file-context")
        );
        assert_eq!(
            persisted_workspace_root_for_session(&memory_runtime, Some("session-123")).as_deref(),
            Some("/tmp/from-file-context")
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sequential_session_file_context_saves_preserve_existing_scope_entries() {
        let dir = temp_runtime_dir();
        let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
        let workspace_root = "/tmp/workspace";

        save_local_session_summary(
            &memory_runtime,
            SessionSummary {
                session_id: "session-123".to_string(),
                title: "Existing title".to_string(),
                timestamp: 42,
                phase: Some(AgentPhase::Running),
                current_step: Some("Initializing".to_string()),
                resume_hint: None,
                workspace_root: Some(workspace_root.to_string()),
            },
        );

        let mut initial =
            load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
        apply_include_file_context_path(&mut initial, "docs").expect("include docs");
        initial.updated_at_ms = 1;
        save_session_file_context(&memory_runtime, Some("session-123"), &initial);

        let mut reloaded =
            load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
        assert_eq!(reloaded.explicit_includes, vec!["docs"]);
        assert!(reloaded.explicit_excludes.is_empty());

        apply_exclude_file_context_path(&mut reloaded, "target").expect("exclude target");
        reloaded.updated_at_ms = 2;
        save_session_file_context(&memory_runtime, Some("session-123"), &reloaded);

        let final_context =
            load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
        assert_eq!(final_context.explicit_includes, vec!["docs"]);
        assert_eq!(final_context.explicit_excludes, vec!["target"]);
        assert_eq!(final_context.recent_files, vec!["target", "docs"]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_local_engine_control_plane_migrates_legacy_unversioned_payload() {
        let dir = temp_runtime_dir();
        let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
        let control_plane = crate::kernel::data::default_local_engine_control_plane();
        let legacy_value = json!({
            "runtime": control_plane.runtime.clone(),
            "storage": control_plane.storage.clone(),
            "watchdog": control_plane.watchdog.clone(),
            "memory": control_plane.memory.clone(),
            "backendPolicy": control_plane.backend_policy.clone(),
            "responses": control_plane.responses.clone(),
            "api": control_plane.api.clone(),
            "galleries": control_plane.galleries.clone(),
            "environment": control_plane.environment.clone()
        });
        save_local_engine_control_plane_value(&memory_runtime, &legacy_value);

        let document = load_local_engine_control_plane_document(&memory_runtime)
            .expect("migrated control plane document");

        assert_eq!(
            document.schema_version,
            LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION
        );
        assert_eq!(document.profile_id, LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID);
        assert_eq!(
            document.control_plane.runtime.default_model,
            control_plane.runtime.default_model
        );
        assert_eq!(
            document.control_plane.launcher.release_channel,
            control_plane.launcher.release_channel
        );
        assert_eq!(document.control_plane.notes, control_plane.notes);
        assert_eq!(document.migrations.len(), 1);
        assert_eq!(
            document.migrations[0].migration_id,
            "local_engine_control_plane.v0_to_v1"
        );
        assert!(document.migrations[0]
            .details
            .iter()
            .any(|detail| detail.contains("launcher defaults")));

        save_local_engine_control_plane_document(&memory_runtime, &document);
        let persisted = load_global_checkpoint_blob(
            &memory_runtime,
            LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME,
        )
        .expect("persisted control plane bytes");
        let stored: LocalEngineControlPlaneDocument =
            serde_json::from_slice(&persisted).expect("stored versioned control plane");
        assert_eq!(
            stored.schema_version,
            LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION
        );
        assert_eq!(stored.migrations.len(), 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn save_local_engine_control_plane_preserves_existing_profile_and_migrations() {
        let dir = temp_runtime_dir();
        let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
        let control_plane = crate::kernel::data::default_local_engine_control_plane();
        save_local_engine_control_plane_document(
            &memory_runtime,
            &LocalEngineControlPlaneDocument {
                schema_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
                profile_id: "custom.profile".to_string(),
                migrations: vec![LocalEngineConfigMigrationRecord {
                    migration_id: "legacy.seed".to_string(),
                    from_version: 0,
                    to_version: 1,
                    applied_at_ms: 7,
                    summary: "Imported legacy seed profile.".to_string(),
                    details: vec!["Preserve this history across later saves.".to_string()],
                }],
                control_plane: control_plane.clone(),
            },
        );

        let mut updated = control_plane;
        updated.runtime.default_model = "gpt-4.1-mini".to_string();
        save_local_engine_control_plane(&memory_runtime, &updated);

        let saved = load_local_engine_control_plane_document(&memory_runtime)
            .expect("saved control plane document");
        assert_eq!(saved.profile_id, "custom.profile");
        assert_eq!(
            saved.schema_version,
            LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION
        );
        assert_eq!(saved.migrations.len(), 1);
        assert_eq!(saved.migrations[0].migration_id, "legacy.seed");
        assert_eq!(saved.control_plane.runtime.default_model, "gpt-4.1-mini");

        let _ = fs::remove_dir_all(dir);
    }
}
