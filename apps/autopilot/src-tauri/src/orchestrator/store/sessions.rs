use super::core::{
    clean_chat_session_title_candidate, normalize_workspace_root, persist_runtime_evidence_projection,
    session_resume_hint_from_task, session_summary_title_from_task_intent, workspace_root_from_task,
};
use super::shared::{
    get_session_storage_key, load_global_checkpoint_json, load_thread_checkpoint_json,
    persist_global_checkpoint_json, persist_thread_checkpoint_json, LOCAL_SESSION_INDEX_CHECKPOINT_NAME,
    LOCAL_TASK_CHECKPOINT_NAME, SESSION_COMPACTION_CHECKPOINT_NAME, SESSION_FILE_CONTEXT_CHECKPOINT_NAME,
    TEAM_MEMORY_SYNC_CHECKPOINT_NAME,
};
use crate::models::{
    AgentPhase, AgentTask, SessionCompactionRecord, SessionFileContext, SessionSummary,
    TeamMemorySyncEntry,
};
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

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

pub fn delete_local_session_summary(memory_runtime: &Arc<MemoryRuntime>, session_id: &str) {
    let mut sessions = get_local_sessions(memory_runtime);
    sessions.retain(|session| session.session_id != session_id);
    persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_SESSION_INDEX_CHECKPOINT_NAME,
        &sessions,
    );
}

pub const DRAFT_SESSION_FILE_CONTEXT_ID: &str = "__chat_session_draft_session__";

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

    let existing_title =
        existing.and_then(|summary| clean_chat_session_title_candidate(summary.title.as_str()));
    let task_title = session_summary_title_from_task_intent(&task.intent);
    let title = existing_title.unwrap_or(task_title);

    SessionSummary {
        session_id,
        title,
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
    persist_runtime_evidence_projection(memory_runtime, task);
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
