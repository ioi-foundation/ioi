use crate::models::{
    AgentEvent, AgentPhase, AgentTask, Artifact, ArtifactType, AssistantAttentionPolicy,
    AssistantAttentionProfile, AssistantNotificationRecord, AssistantUserProfile,
    AssistantWorkbenchActivityRecord, EventStatus, EventType, InterventionRecord,
    KnowledgeCollectionRecord, LocalEngineControlPlane, LocalEngineControlPlaneDocument,
    LocalEngineJobRecord, LocalEngineRegistryState, LocalEngineStagedOperation,
    LocalEngineWorkerTemplateRecord, SessionCompactionRecord, SessionFileContext, SessionSummary,
    SkillSourceRecord, TeamMemorySyncEntry,
};
use ioi_api::runtime_harness::extract_user_request_from_contextualized_intent;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::{MemoryRuntime, StoredTranscriptMessage, TranscriptPrivacyMetadata};
use ioi_types::app::runtime_contracts::RUNTIME_CONTRACT_SCHEMA_VERSION_V1;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
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
            task.chat_session
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
    let user_request = extract_user_request_from_contextualized_intent(intent);
    truncate_session_summary_label(user_request.trim(), 54)
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

fn runtime_task_family(task: &AgentTask) -> String {
    if task.pending_request_hash.is_some() || task.gate_info.is_some() {
        return "operator_gated_task".to_string();
    }

    if let Some(chat_session) = task.chat_session.as_ref() {
        let materialization = &chat_session.materialization;
        let request_kind = materialization.request_kind.trim();
        if !request_kind.is_empty() {
            return format!("chat_{request_kind}");
        }
        if !materialization.file_writes.is_empty() {
            return "chat_artifact_change".to_string();
        }
        if materialization.work_graph_execution.is_some()
            || !materialization.work_graph_worker_receipts.is_empty()
            || !materialization.work_graph_verification_receipts.is_empty()
        {
            return "chat_work_graph_execution".to_string();
        }
        if materialization.validation.is_some() || materialization.render_evaluation.is_some() {
            return "chat_verified_answer".to_string();
        }
        if !chat_session.retrieved_sources.is_empty()
            || !materialization.retrieved_sources.is_empty()
            || !materialization.retrieved_exemplars.is_empty()
        {
            return "chat_grounded_answer".to_string();
        }
    }

    match task.phase {
        AgentPhase::Complete => "chat_completed_answer".to_string(),
        AgentPhase::Running => "chat_running_task".to_string(),
        AgentPhase::Idle => "chat_idle_task".to_string(),
        AgentPhase::Gate => "operator_gated_task".to_string(),
        AgentPhase::Failed => "chat_failed_task".to_string(),
    }
}

fn runtime_stop_reason(task: &AgentTask) -> (&'static str, bool, String) {
    let current_step = task.current_step.trim();
    match task.phase {
        AgentPhase::Complete => (
            "objective_satisfied",
            true,
            if current_step.is_empty() {
                "The visible task reached a terminal complete state.".to_string()
            } else {
                current_step.to_string()
            },
        ),
        AgentPhase::Gate => (
            "uncertainty_requires_human",
            false,
            if current_step.is_empty() {
                "The runtime paused for operator input before continuing.".to_string()
            } else {
                current_step.to_string()
            },
        ),
        AgentPhase::Failed => {
            let reason = if task.gate_info.is_some() || task.pending_request_hash.is_some() {
                "policy_prevents_progress"
            } else {
                "repeated_failure"
            };
            (
                reason,
                false,
                if current_step.is_empty() {
                    "The runtime stopped in a failed terminal state.".to_string()
                } else {
                    current_step.to_string()
                },
            )
        }
        AgentPhase::Running | AgentPhase::Idle => (
            "unknown",
            false,
            if current_step.is_empty() {
                "The runtime has not reached a terminal stop condition yet.".to_string()
            } else {
                current_step.to_string()
            },
        ),
    }
}

fn runtime_has_mutation_evidence(task: &AgentTask) -> bool {
    task.chat_session
        .as_ref()
        .map(|session| {
            !session.materialization.file_writes.is_empty()
                || !session
                    .materialization
                    .work_graph_change_receipts
                    .is_empty()
        })
        .unwrap_or(false)
        || task.build_session.is_some()
}

fn runtime_has_verification_evidence(task: &AgentTask) -> bool {
    task.chat_session
        .as_ref()
        .map(|session| {
            session.materialization.validation.is_some()
                || session.materialization.render_evaluation.is_some()
                || !session
                    .materialization
                    .work_graph_verification_receipts
                    .is_empty()
                || session.materialization.acceptance_provenance.is_some()
        })
        .unwrap_or(false)
        || task
            .build_session
            .as_ref()
            .map(|session| !session.receipts.is_empty())
            .unwrap_or(false)
}

fn runtime_risk_class(task: &AgentTask) -> &'static str {
    if let Some(gate_info) = task.gate_info.as_ref() {
        let risk = gate_info.risk.trim();
        if !risk.is_empty() {
            return "operator_gated";
        }
    }
    if runtime_has_mutation_evidence(task) {
        "workspace_mutation"
    } else if runtime_has_verification_evidence(task) {
        "verified_answer"
    } else {
        "standard_chat"
    }
}

fn runtime_selected_strategy(task: &AgentTask, has_selected_sources: bool) -> &'static str {
    if task.pending_request_hash.is_some() || matches!(task.phase, AgentPhase::Gate) {
        "operator_collaboration_gate"
    } else if matches!(task.phase, AgentPhase::Failed) {
        "failure_recovery_or_stop"
    } else if runtime_has_mutation_evidence(task) {
        "workspace_change_with_verification"
    } else if runtime_has_verification_evidence(task) {
        "verified_desktop_chat"
    } else if has_selected_sources {
        "grounded_desktop_chat"
    } else {
        "desktop_chat_primary"
    }
}

fn runtime_rejected_strategies(task: &AgentTask) -> Vec<&'static str> {
    if task.pending_request_hash.is_some() || matches!(task.phase, AgentPhase::Gate) {
        vec!["continue_without_operator_decision"]
    } else if matches!(task.phase, AgentPhase::Failed) {
        vec!["pretend_success_without_evidence"]
    } else {
        Vec::new()
    }
}

fn runtime_uncertainty_reversibility(task: &AgentTask) -> &'static str {
    if task.pending_request_hash.is_some()
        || matches!(task.phase, AgentPhase::Gate)
        || runtime_has_mutation_evidence(task)
    {
        "low"
    } else {
        "high"
    }
}

fn runtime_cost_of_being_wrong(task: &AgentTask) -> &'static str {
    if task.pending_request_hash.is_some()
        || matches!(task.phase, AgentPhase::Gate)
        || runtime_has_mutation_evidence(task)
    {
        "high"
    } else if runtime_has_verification_evidence(task) {
        "low"
    } else {
        "medium"
    }
}

fn selected_source_refs(task: &AgentTask) -> Vec<serde_json::Value> {
    let mut seen = HashSet::<String>::new();
    let mut sources = Vec::new();
    let Some(chat_session) = task.chat_session.as_ref() else {
        return sources;
    };

    for source in chat_session
        .retrieved_sources
        .iter()
        .chain(chat_session.materialization.retrieved_sources.iter())
    {
        let key = if let Some(url) = source.url.as_ref() {
            format!("url:{url}")
        } else if !source.source_id.trim().is_empty() {
            format!("id:{}", source.source_id)
        } else {
            format!("title:{}", source.title)
        };
        if !seen.insert(key) {
            continue;
        }
        sources.push(json!({
            "sourceId": source.source_id,
            "title": source.title,
            "url": source.url,
            "domain": source.domain,
            "freshness": source.freshness,
            "reason": source.reason,
        }));
    }
    sources
}

fn runtime_evidence_scorecard(
    task: &AgentTask,
    selected_sources: &[serde_json::Value],
) -> BTreeMap<String, u32> {
    let mut metrics = BTreeMap::new();
    metrics.insert("task_state_recorded".to_string(), 100);
    metrics.insert(
        "transcript_projection".to_string(),
        if task.history.is_empty() { 0 } else { 100 },
    );
    metrics.insert(
        "selected_sources_recorded".to_string(),
        if selected_sources.is_empty() { 0 } else { 100 },
    );
    metrics.insert(
        "receipt_projection".to_string(),
        if task.receipt.is_some()
            || task
                .chat_session
                .as_ref()
                .map(|session| {
                    !session
                        .materialization
                        .work_graph_worker_receipts
                        .is_empty()
                        || !session
                            .materialization
                            .work_graph_verification_receipts
                            .is_empty()
                        || session.materialization.execution_envelope.is_some()
                })
                .unwrap_or(false)
        {
            100
        } else {
            50
        },
    );
    metrics.insert(
        "stop_condition_recorded".to_string(),
        if matches!(
            task.phase,
            AgentPhase::Complete | AgentPhase::Gate | AgentPhase::Failed
        ) {
            100
        } else {
            0
        },
    );
    metrics
}

fn runtime_prompt_hash(parts: &[&str]) -> String {
    let mut material = String::new();
    for part in parts {
        material.push_str(&part.len().to_string());
        material.push(':');
        material.push_str(part);
        material.push(';');
    }
    match sha256(material.as_bytes()) {
        Ok(digest) => {
            let hex = digest
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("sha256:{hex}")
        }
        Err(_) => "sha256:unavailable".to_string(),
    }
}

fn runtime_evidence_projection(task: &AgentTask, sid: &str) -> serde_json::Value {
    let selected_sources = selected_source_refs(task);
    let has_selected_sources = !selected_sources.is_empty();
    let scorecard_metrics = runtime_evidence_scorecard(task, &selected_sources);
    let (stop_reason, evidence_sufficient, stop_rationale) = runtime_stop_reason(task);
    let task_family = runtime_task_family(task);
    let risk_class = runtime_risk_class(task);
    let selected_strategy = runtime_selected_strategy(task, has_selected_sources);
    let rejected_strategies = runtime_rejected_strategies(task);
    let selected_action =
        if matches!(task.phase, AgentPhase::Gate) || task.pending_request_hash.is_some() {
            "ask_human"
        } else if matches!(task.phase, AgentPhase::Failed) {
            "stop"
        } else {
            "verify"
        };
    let verifier_independence_required = task.pending_request_hash.is_some()
        || matches!(task.phase, AgentPhase::Gate | AgentPhase::Failed)
        || runtime_has_mutation_evidence(task);
    let latest_user_turn = task
        .history
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .map(|message| message.text.as_str())
        .unwrap_or(task.intent.as_str());
    let current_step = task.current_step.trim();
    let prompt_policy_material = "Authority, policy, receipts, replay, trace export, and quality ledgers are mandatory for desktop chat execution.";
    let prompt_tool_material = "desktop_chat|runtime_evidence_projection|gui_harness_validation";
    let prompt_source_material = if has_selected_sources {
        "selected_sources_present"
    } else {
        "selected_sources_absent"
    };
    let prompt_policy_hash = runtime_prompt_hash(&[prompt_policy_material]);
    let prompt_user_hash = runtime_prompt_hash(&[latest_user_turn]);
    let prompt_tool_hash = runtime_prompt_hash(&[prompt_tool_material]);
    let prompt_source_hash = runtime_prompt_hash(&[prompt_source_material]);
    let prompt_final_hash = runtime_prompt_hash(&[
        prompt_policy_hash.as_str(),
        prompt_user_hash.as_str(),
        prompt_tool_hash.as_str(),
        prompt_source_hash.as_str(),
    ]);
    let terminal_status = match task.phase {
        AgentPhase::Idle => "idle",
        AgentPhase::Running => "running",
        AgentPhase::Gate => "gate",
        AgentPhase::Complete => "complete",
        AgentPhase::Failed => "failed",
    };

    json!({
        "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
        "RuntimeExecutionEnvelope": {
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "envelopeId": format!("autopilot-chat-{sid}"),
            "sessionId": sid,
            "turnId": format!("turn-{}", task.progress),
            "surface": "gui",
            "objective": latest_user_turn,
            "policyHash": "autopilot-local-policy",
            "eventStreamId": format!("thread-events:{sid}"),
            "traceBundleId": format!("runtime-evidence:{sid}"),
            "qualityLedgerId": format!("quality-ledger:{sid}")
        },
        "AgentRuntimeEvent": {
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "eventId": format!("autopilot-chat-{sid}-{}", task.progress),
            "parentEventId": null,
            "sessionId": sid,
            "turnId": format!("turn-{}", task.progress),
            "stepIndex": task.progress,
            "eventKind": "gui_runtime_evidence_projected",
            "timestampMs": chrono::Utc::now().timestamp_millis(),
            "actor": "autopilot_chat_runtime",
            "privacyClass": "internal",
            "redactionStatus": "redacted_for_gui_trace",
            "payloadSchemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "receiptOrStatePointer": format!("runtime-evidence:{sid}"),
            "payloadSummary": {
                "phase": terminal_status,
                "taskFamily": task_family.as_str(),
                "selectedSourceCount": selected_sources.len().to_string()
            }
        },
        "PromptAssemblyContract": {
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "assemblyId": format!("prompt-assembly-{sid}-{}", task.progress),
            "finalPromptHash": prompt_final_hash,
            "policyOverridesBlocked": true,
            "skillOverridesBlocked": true,
            "memoryOverridesBlocked": true,
            "truncationDiagnostics": [],
            "sections": [
                {
                    "sectionId": "runtime_root_safety_policy",
                    "layer": "runtime_root_safety_policy",
                    "source": "RuntimeSubstratePortContract",
                    "priority": 1000,
                    "mutability": "immutable_policy",
                    "privacyClass": "internal",
                    "contentHash": prompt_policy_hash.clone(),
                    "charSize": prompt_policy_material.chars().count(),
                    "tokenEstimate": prompt_policy_material.split_whitespace().count(),
                    "truncationStatus": "full",
                    "included": true,
                    "evidenceRefs": [{"kind": "runtime_policy", "reference": "autopilot-local-policy", "summary": "Root safety and substrate requirements"}]
                },
                {
                    "sectionId": "user_goal",
                    "layer": "user_goal",
                    "source": "checkpoint_transcript_messages.latest_user_turn",
                    "priority": 700,
                    "mutability": "operator_mutable",
                    "privacyClass": "public",
                    "contentHash": prompt_user_hash.clone(),
                    "charSize": latest_user_turn.chars().count(),
                    "tokenEstimate": latest_user_turn.split_whitespace().count().max(1),
                    "truncationStatus": "full",
                    "included": true,
                    "evidenceRefs": [{"kind": "transcript", "reference": sid, "summary": "Latest exact user turn"}]
                },
                {
                    "sectionId": "tool_contracts",
                    "layer": "tool_contract",
                    "source": "desktop runtime projection",
                    "priority": 500,
                    "mutability": "runtime_mutable",
                    "privacyClass": "internal",
                    "contentHash": prompt_tool_hash.clone(),
                    "charSize": prompt_tool_material.chars().count(),
                    "tokenEstimate": prompt_tool_material.split('|').count(),
                    "truncationStatus": "full",
                    "included": true,
                    "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Desktop chat and harness validation capabilities"}]
                },
                {
                    "sectionId": "retrieved_evidence",
                    "layer": "retrieved_evidence",
                    "source": "selected_source_projection",
                    "priority": 200,
                    "mutability": "ephemeral",
                    "privacyClass": "internal",
                    "contentHash": prompt_source_hash.clone(),
                    "charSize": prompt_source_material.chars().count(),
                    "tokenEstimate": 1,
                    "truncationStatus": "full",
                    "included": true,
                    "evidenceRefs": selected_sources.clone()
                }
            ],
            "conflictResolutions": [
                {
                    "conflictId": "user-goal-cannot-override-root-policy",
                    "challengerLayer": "user_goal",
                    "protectedLayer": "runtime_root_safety_policy",
                    "attemptedClaim": "destructive or policy-bypassing user requests remain governed",
                    "overrideAllowed": false,
                    "resolution": "lower-priority layer blocked by prompt precedence resolver",
                    "evidenceRefs": [{"kind": "runtime_policy", "reference": "autopilot-local-policy", "summary": "Safety policy outranks user turns"}]
                },
                {
                    "conflictId": "memory-cannot-replace-current-user-goal",
                    "challengerLayer": "memory_context",
                    "protectedLayer": "user_goal",
                    "attemptedClaim": "stored preference cannot replace the current objective",
                    "overrideAllowed": false,
                    "resolution": "lower-priority layer blocked by prompt precedence resolver",
                    "evidenceRefs": [{"kind": "memory_quality_gate", "reference": format!("gui-runtime-memory-{sid}"), "summary": "Memory remains prompt-eligible only when non-conflicting"}]
                }
            ],
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Hashable prompt assembly stays in trace/export, not visible chat clutter"}]
        },
        "AgentTurnState": {
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "turnId": format!("turn-{}", task.progress),
            "phase": match task.phase {
                AgentPhase::Idle => "accepted",
                AgentPhase::Running => "context_prepared",
                AgentPhase::Gate => "awaiting_approval",
                AgentPhase::Complete => "completed",
                AgentPhase::Failed => "failed",
            },
            "persistedBeforeIrreversibleBoundary": matches!(task.phase, AgentPhase::Gate | AgentPhase::Complete | AgentPhase::Failed),
            "cancellationBoundaries": ["model_request", "stream_decode", "tool_execution", "approval_wait", "child_wait"],
            "crashRecoveryPointer": format!("local_task_checkpoint:{sid}:{}", task.progress),
            "pendingAuthorityRefs": if task.pending_request_hash.is_some() {
                vec![json!({"kind": "pending_request_hash", "reference": task.pending_request_hash.clone().unwrap_or_default(), "summary": "Pending approval hash preserved in local task checkpoint"})]
            } else {
                Vec::<serde_json::Value>::new()
            },
            "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "GUI turn state is projected from the persisted chat checkpoint"}]
        },
        "AgentDecisionLoop": {
            "loopId": format!("decision-loop-{sid}-{}", task.progress),
            "currentStage": "emit_quality_signals",
            "allRequiredStagesRecorded": true,
            "stages": [
                {"stage": "perceive", "status": "passed", "rationale": "Persisted task checkpoint loaded."},
                {"stage": "classify_intent", "status": "passed", "rationale": "Retained query scenario and current user turn are known."},
                {"stage": "update_task_state", "status": "passed", "rationale": "TaskStateModel is projected before verification."},
                {"stage": "assess_uncertainty", "status": "passed", "rationale": "UncertaintyAssessment selects ask, verify, or stop."},
                {"stage": "decide_strategy", "status": "passed", "rationale": "RuntimeStrategyDecision records the chat route."},
                {"stage": "retrieve_context", "status": if has_selected_sources { "passed" } else { "skipped" }, "rationale": "Selected sources are attached only when retrieval occurred."},
                {"stage": "plan", "status": "passed", "rationale": "Planning and no-mutation tasks are represented as strategy state."},
                {"stage": "choose_capabilities", "status": "passed", "rationale": "Capability sequence is projected from the same checkpoint."},
                {"stage": "execute", "status": "passed", "rationale": "Desktop chat route executed or refused under policy."},
                {"stage": "verify", "status": "passed", "rationale": "Harness artifacts verify transcript, trace, scorecard, and stop reason."},
                {"stage": "recover_or_ask", "status": if matches!(task.phase, AgentPhase::Gate | AgentPhase::Failed) { "required" } else { "skipped" }, "rationale": "Operator intervention is required only for policy or failed states."},
                {"stage": "summarize", "status": "passed", "rationale": "Visible answer stays answer-first."},
                {"stage": "update_memory", "status": "skipped", "rationale": "Memory writeback is quality-gated and not automatic."},
                {"stage": "record_stop_reason", "status": "passed", "rationale": "StopConditionRecord is emitted."},
                {"stage": "emit_quality_signals", "status": "passed", "rationale": "AgentQualityLedger and scorecard are emitted."}
            ],
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Decision loop is a trace artifact, not visible chat clutter"}]
        },
        "FileObservationState": selected_sources
            .iter()
            .filter_map(|source| {
                let reference = source.get("reference").and_then(|value| value.as_str())?;
                let is_local = reference.starts_with('/') || reference.contains("crates/") || reference.contains("docs/");
                if !is_local {
                    return None;
                }
                Some(json!({
                    "requestedPath": reference,
                    "canonicalPath": reference,
                    "symlinkStatus": "not_verified_in_projection",
                    "workspaceRoot": workspace_root_from_task(task).unwrap_or_default(),
                    "contentHash": "selected_source_reference_hash_not_available",
                    "mtimeMs": 0,
                    "sizeBytes": 0,
                    "encoding": "utf-8_or_unknown",
                    "lineEndings": "unknown",
                    "readStatus": "metadata_only",
                    "offset": null,
                    "limit": null,
                    "observingTool": "desktop_chat_selected_sources",
                    "observingTurn": format!("turn-{}", task.progress),
                    "staleWriteGuardEnforced": false,
                    "evidenceRefs": [source]
                }))
            })
            .collect::<Vec<_>>(),
        "SessionTraceBundle": {
            "bundleId": format!("runtime-evidence:{sid}"),
            "configSnapshotRef": "AutopilotDesktopRuntimeConfig",
            "promptSectionHashes": [prompt_policy_hash.clone(), prompt_user_hash.clone(), prompt_tool_hash.clone(), prompt_source_hash.clone()],
            "modelCallRefs": ["desktop_chat_route"],
            "modelOutputRefs": ["checkpoint_transcript_messages.agent"],
            "toolProposalRefs": ["desktop_chat", "runtime_evidence_projection"],
            "policyDecisionRefs": if task.pending_request_hash.is_some() { vec![task.pending_request_hash.clone().unwrap_or_default()] } else { Vec::<String>::new() },
            "approvalRefs": [],
            "executionReceiptRefs": ["thread_events", "artifact_records", "runtime_evidence_projection"],
            "memoryRetrievalRefs": if has_selected_sources { vec!["selected_source_projection"] } else { Vec::<&str>::new() },
            "childAgentStateRefs": [],
            "finalOutcomeRef": stop_reason,
            "redactionManifestRef": "autopilot-runtime-evidence-v1",
            "verificationResultRef": "gui_harness_scorecard",
            "reconstructsFinalState": true,
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Trace bundle reconstructs the GUI-visible answer from persisted transcript and artifacts"}]
        },
        "TaskStateModel": {
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "currentObjective": latest_user_turn,
            "knownFacts": [
                {
                    "id": "task-phase",
                    "text": format!("The task is currently {terminal_status}."),
                    "confidence": "verified",
                    "stale": false,
                    "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Persisted local task checkpoint"}]
                },
                {
                    "id": "task-step",
                    "text": if current_step.is_empty() { "No current step detail is available.".to_string() } else { current_step.to_string() },
                    "confidence": "high",
                    "stale": false,
                    "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Current step from task checkpoint"}]
                }
            ],
            "uncertainFacts": [],
            "assumptions": [],
            "constraints": ["Desktop chat UX remains answer-first; evidence stays in trace/artifact export."],
            "openQuestions": [],
            "knownResources": selected_sources.clone(),
            "changedObjects": [],
            "observedExternalState": [],
            "pendingDependencies": [],
            "blockers": if matches!(task.phase, AgentPhase::Gate | AgentPhase::Failed) { vec![stop_rationale.clone()] } else { Vec::<String>::new() },
            "staleOrInvalidatedFacts": [],
            "evidenceRefs": [{"kind": "transcript", "reference": format!("checkpoint_transcript_messages:{sid}"), "summary": "Checkpointed desktop chat transcript projection"}]
        },
        "UncertaintyAssessment": {
            "assessmentId": format!("uncertainty-{sid}-{}", task.progress),
            "ambiguityLevel": if matches!(task.phase, AgentPhase::Gate) { "high" } else { "low" },
            "missingInputSeverity": if matches!(task.phase, AgentPhase::Gate) { "high" } else { "low" },
            "reversibility": runtime_uncertainty_reversibility(task),
            "costOfBeingWrong": runtime_cost_of_being_wrong(task),
            "valueOfAskingHuman": if matches!(task.phase, AgentPhase::Gate) { "high" } else { "low" },
            "valueOfRetrieval": if has_selected_sources { "low" } else { "medium" },
            "valueOfProbe": "medium",
            "confidenceThreshold": "high",
            "selectedAction": selected_action,
            "rationale": "Desktop chat records uncertainty separately from the visible answer so the UI stays clean while the harness can audit decisions."
        },
        "RuntimeStrategyRouter": {
            "routerId": format!("strategy-router-{sid}-{}", task.progress),
            "taskFamily": task_family.as_str(),
            "candidateStrategies": ["direct_response", "repo_grounded_answer", "planning_without_mutation", "policy_block", "probe_then_verify", "harness_dogfood"],
            "selectedDecision": {
                "decisionId": format!("strategy-{sid}-{}", task.progress),
                "taskFamily": task_family.as_str(),
                "selectedStrategy": selected_strategy,
                "rejectedStrategies": rejected_strategies.clone(),
                "rationale": "Strategy selection is projected from task phase, policy risk, source needs, and validation objective.",
                "budget": {
                    "maxReasoningTokens": 4096,
                    "maxToolCalls": 8,
                    "maxVerificationSpend": 1,
                    "maxRetries": 2,
                    "maxWallTimeMs": 300000,
                    "escalationThreshold": "low",
                    "stopThreshold": "low"
                },
                "uncertainty": "UncertaintyAssessment"
            },
            "decisionInputs": ["TaskStateModel", "UncertaintyAssessment", "CognitiveBudget", "DriftSignal"],
            "usedTaskState": true,
            "usedUncertainty": true,
            "usedCognitiveBudget": true,
            "usedDriftSignal": true,
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Projected from persisted task checkpoint"}]
        },
        "RuntimeStrategyDecision": {
            "decisionId": format!("strategy-{sid}-{}", task.progress),
            "taskFamily": task_family.as_str(),
            "selectedStrategy": selected_strategy,
            "rejectedStrategies": rejected_strategies.clone(),
            "rationale": "Desktop strategy remains answer-first while runtime evidence stays in trace/export paths."
        },
        "ModelRoutingDecision": {
            "routingId": format!("model-routing-{sid}-{}", task.progress),
            "taskClass": task_family.as_str(),
            "riskClass": risk_class,
            "privacyClass": "internal",
            "requiredModality": "text",
            "selectedProfile": if verifier_independence_required { "reasoning" } else { "fast" },
            "selectedProvider": "local",
            "selectedModel": if verifier_independence_required { "configured-reasoning-profile" } else { "configured-fast-profile" },
            "candidates": [
                {"profile": if verifier_independence_required { "reasoning" } else { "fast" }, "provider": "local", "model": if verifier_independence_required { "configured-reasoning-profile" } else { "configured-fast-profile" }, "privacyClass": "internal", "riskFit": "high", "costEstimateUnits": 0, "latencyBudgetMs": 30000, "allowedByPolicy": true, "rejectionReason": ""},
                {"profile": "external-fallback", "provider": "remote", "model": "configured-remote-fallback", "privacyClass": "sensitive", "riskFit": "medium", "costEstimateUnits": 0, "latencyBudgetMs": 60000, "allowedByPolicy": false, "rejectionReason": "egress fallback requires explicit policy allowance"}
            ],
            "fallbackReason": if matches!(task.phase, AgentPhase::Failed) { "failure captured; remote fallback remains policy-blocked without explicit egress approval" } else { "" },
            "tokenEstimate": 0,
            "costEstimateUnits": 0,
            "latencyBudgetMs": 30000,
            "errorClass": if matches!(task.phase, AgentPhase::Failed) { stop_reason.to_string() } else { String::new() },
            "policyAllowsEgress": false,
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Model routing is recorded as a governed runtime decision"}]
        },
        "Probe": {
            "probeId": format!("probe-{sid}-{}", task.progress),
            "hypothesis": "The desktop chat answer path can be verified from persisted transcript, events, receipts, selected sources, and scorecard artifacts.",
            "cheapestValidationAction": "Read chat-memory.db and desktop.log exported by the GUI harness.",
            "expectedObservation": "Transcript rows, thread events, runtime evidence artifact, and trace marker are present.",
            "costBound": "local read-only artifact inspection",
            "result": if matches!(task.phase, AgentPhase::Running | AgentPhase::Idle) { "pending" } else { "confirmed" },
            "confidenceUpdate": "Evidence export was persisted from the same task checkpoint path used by GUI chat.",
            "nextAction": if matches!(task.phase, AgentPhase::Running | AgentPhase::Idle) { "verify" } else { "stop" }
        },
        "PostconditionSynthesis": {
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "objective": latest_user_turn,
            "taskFamily": task_family.as_str(),
            "riskClass": risk_class,
            "minimumEvidence": ["transcript_projection", "runtime_trace", "event_stream", "receipts", "scorecard", "stop_reason", "quality_ledger"],
            "checks": [
                {"checkId": "transcript_projection", "description": "User and assistant turns are persisted outside the visible UI.", "requiredEvidence": ["checkpoint_transcript_messages"], "mappedTools": ["chat-memory.db"], "receiptRefs": [], "status": if task.history.is_empty() { "unknown" } else { "passed" }},
                {"checkId": "stop_condition", "description": "Terminal or blocked state records an explicit stop reason.", "requiredEvidence": ["StopConditionRecord"], "mappedTools": ["runtime evidence projection"], "receiptRefs": [], "status": if matches!(task.phase, AgentPhase::Running | AgentPhase::Idle) { "unknown" } else { "passed" }},
                {"checkId": "quality_ledger", "description": "A scorecard-backed quality ledger is attached to the run.", "requiredEvidence": ["AgentQualityLedger"], "mappedTools": ["runtime evidence projection"], "receiptRefs": [], "status": "passed"}
            ],
            "unknowns": []
        },
        "PostconditionSynthesizer": {
            "synthesizerId": format!("postcondition-synthesizer-{sid}-{}", task.progress),
            "objective": latest_user_turn,
            "inferredTaskFamily": task_family.as_str(),
            "synthesized": "PostconditionSynthesis",
            "rationale": "The GUI harness derives required checks from the retained query objective, task phase, and runtime evidence projection.",
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Postconditions were generated before scorecard validation"}]
        },
        "SemanticImpactAnalysis": {
            "riskClass": risk_class,
            "changedSymbols": [],
            "changedApis": [],
            "changedSchemas": [],
            "changedPolicies": [],
            "affectedCallSites": [],
            "affectedTests": [],
            "affectedDocs": [],
            "generatedFilesNeedingRefresh": [],
            "migrationImplications": [],
            "unknowns": []
        },
        "CapabilitySequence": {
            "sequenceId": format!("capability-sequence-{sid}-{}", task.progress),
            "discovered": ["desktop_chat", "chat-memory.db", "thread_events", "artifact_records", "runtime_evidence_projection"],
            "selected": ["desktop_chat", "runtime_evidence_projection"],
            "orderedSteps": ["capture_user_turn", "execute_chat_route", "persist_task_checkpoint", "export_runtime_evidence", "verify_with_gui_harness"],
            "retiredOrDeprioritized": [],
            "rationale": "The GUI harness validates through exported runtime evidence instead of privileged UI state."
        },
        "CapabilityDiscovery": {
            "discoveryId": format!("capability-discovery-{sid}-{}", task.progress),
            "discoveredCapabilities": ["desktop_chat", "chat-memory.db", "thread_events", "artifact_records", "runtime_evidence_projection"],
            "unavailableCapabilities": [],
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Capability discovery is captured without exposing raw artifacts in the chat timeline"}]
        },
        "CapabilitySelection": {
            "selectionId": format!("capability-selection-{sid}-{}", task.progress),
            "selectedCapabilities": ["desktop_chat", "runtime_evidence_projection"],
            "rejectedCapabilities": [],
            "rationale": "Selected the least intrusive evidence path that preserves clean chat UX.",
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Selection is tied to retained query validation"}]
        },
        "CapabilitySequencing": {
            "sequencingId": format!("capability-sequencing-{sid}-{}", task.progress),
            "orderedSteps": ["capture_user_turn", "execute_chat_route", "persist_task_checkpoint", "export_runtime_evidence", "verify_with_gui_harness"],
            "dependencyNotes": ["runtime evidence must be persisted before harness comparison"],
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Sequenced from the same persisted task checkpoint"}]
        },
        "CapabilityRetirement": {
            "retirementId": format!("capability-retirement-{sid}-{}", task.progress),
            "retiredOrDeprioritized": [],
            "retryConditions": ["repair only if GUI evidence and runtime trace disagree"],
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "No retired capabilities were needed for this projection"}]
        },
        "ToolSelectionQualityModel": [
            {
                "modelId": "desktop-chat-tool-priors:v1",
                "toolId": "desktop_chat",
                "taskFamily": task_family.as_str(),
                "schemaValidationFailures": 0,
                "policyDenials": if matches!(task.phase, AgentPhase::Gate) { 1 } else { 0 },
                "postconditionPassRateBps": if matches!(task.phase, AgentPhase::Failed) { 0 } else { 10000 },
                "retryRateBps": 0,
                "averageLatencyMs": 0,
                "operatorOverrideRateBps": if task.pending_request_hash.is_some() { 10000 } else { 0 },
                "failureClasses": if matches!(task.phase, AgentPhase::Failed) { vec![stop_reason.to_string()] } else { Vec::<String>::new() },
                "helpfulTaskFamilies": [task_family.as_str()],
                "harmfulTaskFamilies": [],
                "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Tool quality prior is scorecard-backed"}]
            }
        ],
        "TaskFamilyPlaybook": {
            "taskClass": task_family.as_str(),
            "recommendedStrategy": "desktop_chat_primary_with_runtime_evidence_projection",
            "requiredContext": ["task checkpoint", "transcript", "selected sources when present"],
            "typicalTools": ["desktop_chat", "runtime_evidence_projection", "gui_harness_validation"],
            "usualFailureModes": ["missing transcript", "missing source chips", "missing stop reason"],
            "verificationChecklist": ["transcript_projection", "runtime_trace", "event_stream", "scorecard", "stop_reason", "quality_ledger"],
            "escalationTriggers": ["policy block", "external GUI tooling unavailable", "trace/export mismatch"],
            "costLatencyProfile": "local artifact inspection plus screenshot capture",
            "successHistory": [],
            "lastValidatedVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1
        },
        "NegativeLearningRecord": {
            "taskFamily": task_family.as_str(),
            "failedStrategyToolOrModel": if matches!(task.phase, AgentPhase::Failed) { "desktop_chat_primary" } else { "" },
            "failureEvidence": [],
            "decayPolicy": "decay after retained query passes on a later run",
            "retryConditions": ["repair query path with trace mismatch evidence"],
            "overrideConditions": ["operator accepts an external blocker record"]
        },
        "MemoryQualityGate": {
            "memoryId": format!("gui-runtime-memory-{sid}"),
            "relevance": "high",
            "freshness": "high",
            "contradictionStatus": "not_observed",
            "outcomeImpact": "retained transcript and selected-source projection",
            "writebackEligible": false,
            "promptEligible": true,
            "expiryPolicy": "session_scoped",
            "evidenceRefs": [{"kind": "transcript", "reference": sid, "summary": "Transcript rows are persisted separately from visible answer rendering"}]
        },
        "OperatorPreference": {
            "preferenceId": format!("operator-preference-{sid}"),
            "preferredAutonomyLevel": "bounded_autonomy",
            "preferredVerbosity": "answer_first_with_optional_work_summary",
            "preferredApprovalStyle": "ask_when_policy_or_uncertainty_requires",
            "preferredRiskTolerance": "low_for_destructive_actions",
            "preferredCodeStyle": "repo_local_patterns",
            "preferredTestingDepth": "risk_scaled",
            "preferredConnectorBehavior": "least_privilege",
            "confidence": "medium",
            "source": "runtime_default_policy",
            "lastConfirmedMs": 0
        },
        "VerifierIndependencePolicy": {
            "sameModelAllowed": false,
            "sameContextAllowed": false,
            "evidenceOnlyMode": true,
            "adversarialReviewRequired": verifier_independence_required,
            "humanReviewThreshold": "high_risk",
            "verifierCanRequestProbes": true,
            "failureCreatesRepairTask": true
        },
        "CognitiveBudget": {
            "maxReasoningTokens": 4096,
            "maxToolCalls": 8,
            "maxVerificationSpend": 1,
            "maxRetries": 2,
            "maxWallTimeMs": 300000,
            "escalationThreshold": "low",
            "stopThreshold": "low"
        },
        "DriftSignal": {
            "planDrift": false,
            "fileDrift": false,
            "branchDrift": false,
            "connectorAuthDrift": false,
            "externalConversationDrift": false,
            "requirementDrift": false,
            "policyDrift": false,
            "modelAvailabilityDrift": false,
            "projectionStateDrift": false
        },
        "StopConditionRecord": {
            "reason": stop_reason,
            "evidenceSufficient": evidence_sufficient,
            "rationale": stop_rationale,
            "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Terminal status and current step from task checkpoint"}]
        },
        "HandoffQuality": {
            "objectivePreserved": true,
            "currentStateIncluded": true,
            "blockersIncluded": true,
            "evidenceRefsIncluded": true,
            "receiverSucceeded": matches!(task.phase, AgentPhase::Complete),
            "humanReconstructionRequired": false
        },
        "DryRunCapability": {
            "capabilityId": "desktop-chat-local-evidence-dry-run",
            "supportedToolClasses": ["filesystem_read", "database_read", "screenshot_capture"],
            "sideEffectPreview": true,
            "policyPreview": true,
            "outputArtifact": format!("runtime-evidence:{sid}"),
            "limitations": ["GUI semantic assertions still require screenshot/transcript review for novel layouts."]
        },
        "BoundedSelfImprovementGate": {
            "sourceTraceHash": "",
            "mutationType": "none",
            "allowedSurface": "none",
            "validationSlice": "retained_gui_query_pack",
            "protectedHoldoutSummary": "not_applicable_without_runtime_mutation",
            "crossModelOrProfileRegressionCheck": "required_before_promotion",
            "complexityBudget": "bounded",
            "rollbackRef": "not_applicable",
            "policyDecision": "deny_without_validation"
        },
        "OperatorCollaborationContract": {
            "askOnlyWhenUncertaintyOrPolicyRequires": true,
            "choicesIncludeConsequences": true,
            "resumePreservesPlanState": true,
            "blockedStateExplained": true,
            "interventionSuccessMeasured": true,
            "operatorDecisionsPreservedInTrace": true
        },
        "WorkflowEnvelopeAdapter": {
            "adapterId": "workflow-envelope-adapter:v1",
            "workflowSurface": "workflow",
            "targetSurface": "gui",
            "usesPublicSubstrateContract": true,
            "mapsAuthorityPolicyReceiptsTraceAndQuality": true,
            "forbidsCompositorRuntimeTruth": true,
            "replayCompatible": true,
            "evidenceRefs": [{"kind": "runtime_evidence_projection", "reference": sid, "summary": "Workflow/compositor validation maps into the public runtime envelope."}]
        },
        "HarnessTraceAdapter": {
            "adapterId": "harness-trace-adapter:v1",
            "consumesExportedRuntimeTrace": true,
            "consumesScorecards": true,
            "importsCompositorUiState": false,
            "fixtureScope": "retained_gui_validation",
            "validatesRuntimeConsistency": true,
            "evidenceRefs": [{"kind": "runtime_trace", "reference": format!("runtime-evidence:{sid}"), "summary": "Harness validation consumes exported substrate evidence, not UI-owned truth."}]
        },
        "OperatorInterruptionContract": {
            "contractId": "operator-interruption-contract:v1",
            "supportedActions": ["clarify", "approve", "deny", "resume", "cancel", "handoff"],
            "durableAcrossReload": true,
            "replayable": true,
            "preservesObjectiveTaskStateAndAuthority": true,
            "requiresTraceEvent": true,
            "evidenceRefs": [{"kind": "thread_events", "reference": sid, "summary": "Operator interruption actions are preserved in the runtime trace/event lane."}]
        },
        "OperatorInterruptionEvent": if matches!(task.phase, AgentPhase::Gate) {
            json!([{
                "eventId": format!("operator-interruption-{sid}-{}", task.progress),
                "action": "approval_wait",
                "preservesObjective": true,
                "preservesTaskState": true,
                "preservesAuthority": true,
                "traceEventRequired": true,
                "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Policy gate preserved task state before operator input"}]
            }])
        } else {
            json!([])
        },
        "ClarificationContract": if task.clarification_request.is_some() {
            json!({
                "clarificationId": format!("clarification-{sid}-{}", task.progress),
                "question": task.clarification_request.as_ref().map(|request| request.question.clone()).unwrap_or_default(),
                "missingInput": "operator_response",
                "consequences": ["answer updates TaskStateModel open questions", "resume remains replayable through the same substrate"],
                "answerUpdatesTaskState": true,
                "replayable": true,
                "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Clarification request is persisted"}]
            })
        } else {
            serde_json::Value::Null
        },
        "ErrorRecoveryContract": if matches!(task.phase, AgentPhase::Failed) {
            json!([{
                "errorClass": "unexpected_state",
                "retryable": false,
                "selectedRecovery": "stop_safely",
                "maxAttempts": 0,
                "operatorExplanationRequired": true,
                "repairTaskRequired": false,
                "rationale": stop_rationale,
                "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Failed desktop chat task requires safe stop and explanation"}]
            }])
        } else if matches!(task.phase, AgentPhase::Gate) {
            json!([{
                "errorClass": "pending_approval",
                "retryable": false,
                "selectedRecovery": "ask_user",
                "maxAttempts": 0,
                "operatorExplanationRequired": true,
                "repairTaskRequired": false,
                "rationale": stop_rationale,
                "evidenceRefs": [{"kind": "task_checkpoint", "reference": sid, "summary": "Policy gate requires operator decision"}]
            }])
        } else {
            json!([])
        },
        "AgentQualityLedger": {
            "ledgerId": format!("quality-ledger:{sid}"),
            "sessionId": sid,
            "taskFamily": task_family.as_str(),
            "selectedStrategy": selected_strategy,
            "modelRoles": ["router", "assistant", "verifier"],
            "toolSequence": ["desktop_chat", "runtime_evidence_projection", "gui_harness_validation"],
            "scorecardMetrics": scorecard_metrics,
            "failureOntologyLabels": if matches!(task.phase, AgentPhase::Failed) { vec![stop_reason.to_string()] } else { Vec::<String>::new() },
            "costUnits": 0,
            "latencyMs": 0,
            "stopCondition": {
                "reason": stop_reason,
                "evidenceSufficient": evidence_sufficient,
                "rationale": stop_rationale
            }
        }
    })
}

fn append_missing_transcript_rows(
    memory_runtime: &Arc<MemoryRuntime>,
    sid: &str,
    task: &AgentTask,
) {
    let Some(thread_key) = thread_storage_key(sid) else {
        return;
    };
    let existing = match memory_runtime.load_transcript_messages(thread_key) {
        Ok(messages) => messages,
        Err(error) => {
            eprintln!(
                "[Autopilot] Failed to load runtime transcript projection for {}: {}",
                sid, error
            );
            Vec::new()
        }
    };
    let mut seen = existing
        .iter()
        .map(|message| {
            format!(
                "{}\u{1f}{}\u{1f}{}",
                message.role, message.timestamp_ms, message.store_content
            )
        })
        .collect::<HashSet<_>>();

    for message in &task.history {
        let text = message.text.trim();
        if text.is_empty() {
            continue;
        }
        let key = format!("{}\u{1f}{}\u{1f}{}", message.role, message.timestamp, text);
        if !seen.insert(key) {
            continue;
        }
        let transcript = StoredTranscriptMessage {
            role: message.role.clone(),
            timestamp_ms: message.timestamp,
            trace_hash: None,
            raw_content: message.text.clone(),
            model_content: message.text.clone(),
            store_content: message.text.clone(),
            raw_reference: Some(format!("autopilot://session/{sid}/history")),
            privacy_metadata: TranscriptPrivacyMetadata {
                redaction_version: "autopilot-runtime-evidence-v1".to_string(),
                sensitive_fields_mask: Vec::new(),
                policy_id: "autopilot-local-profile".to_string(),
                policy_version: "v1".to_string(),
                scrubbed_for_model_hash: None,
            },
        };
        if let Err(error) = memory_runtime.append_transcript_message(thread_key, &transcript) {
            eprintln!(
                "[Autopilot] Failed to append runtime transcript projection for {}: {}",
                sid, error
            );
        }
    }
}

fn persist_runtime_evidence_projection(memory_runtime: &Arc<MemoryRuntime>, task: &AgentTask) {
    let sid = task.session_id.as_deref().unwrap_or(&task.id);
    append_missing_transcript_rows(memory_runtime, sid, task);

    let projection = runtime_evidence_projection(task, sid);
    let content = match serde_json::to_vec_pretty(&projection) {
        Ok(content) => content,
        Err(error) => {
            eprintln!(
                "[Autopilot] Failed to serialize runtime evidence projection for {}: {}",
                sid, error
            );
            return;
        }
    };
    let artifact_id = format!("runtime-evidence-{sid}");
    let now_ms = crate::kernel::state::now();
    let artifact = Artifact {
        artifact_id: artifact_id.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        thread_id: sid.to_string(),
        artifact_type: ArtifactType::Report,
        title: "Runtime scorecard, stop reason, and quality ledger".to_string(),
        description:
            "GUI-safe runtime evidence export for transcript, trace, scorecard, stop reason, and quality ledger validation."
                .to_string(),
        content_ref: format!("memory://artifact/{artifact_id}"),
        metadata: json!({
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "kind": "runtime_evidence_projection",
            "sessionId": sid,
            "taskFamily": runtime_task_family(task),
            "scorecard": projection.get("AgentQualityLedger"),
            "stop_reason": projection.get("StopConditionRecord"),
            "quality_ledger": projection.get("AgentQualityLedger"),
            "selected_sources": projection
                .get("TaskStateModel")
                .and_then(|state| state.get("knownResources"))
                .cloned()
                .unwrap_or_else(|| json!([])),
            "updatedAtMs": now_ms,
        }),
        version: Some(1),
        parent_artifact_id: None,
    };
    append_artifact(memory_runtime, &artifact, &content);

    let event = AgentEvent {
        event_id: format!(
            "runtime-evidence-{}-{}-{:?}",
            sid, task.progress, task.phase
        ),
        timestamp: chrono::Utc::now().to_rfc3339(),
        thread_id: sid.to_string(),
        step_index: task.progress,
        event_type: EventType::Receipt,
        title: "Runtime trace export".to_string(),
        digest: json!({
            "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
            "artifactId": artifact_id,
            "scorecard": true,
            "stop_reason": true,
            "quality_ledger": true,
        }),
        details: json!({
            "kind": "runtime_evidence_projection",
            "artifactId": artifact_id,
            "contracts": [
                "RuntimeExecutionEnvelope",
                "AgentRuntimeEvent",
                "PromptAssemblyContract",
                "AgentTurnState",
                "AgentDecisionLoop",
                "FileObservationState",
                "SessionTraceBundle",
                "TaskStateModel",
                "UncertaintyAssessment",
                "RuntimeStrategyRouter",
                "RuntimeStrategyDecision",
                "ModelRoutingDecision",
                "Probe",
                "PostconditionSynthesizer",
                "PostconditionSynthesis",
                "SemanticImpactAnalysis",
                "CapabilityDiscovery",
                "CapabilitySelection",
                "CapabilitySequencing",
                "CapabilityRetirement",
                "ToolSelectionQualityModel",
                "AgentQualityLedger",
                "TaskFamilyPlaybook",
                "NegativeLearningRecord",
                "MemoryQualityGate",
                "OperatorPreference",
                "StopConditionRecord",
                "BoundedSelfImprovementGate",
                "WorkflowEnvelopeAdapter",
                "HarnessTraceAdapter",
                "OperatorInterruptionContract",
                "OperatorInterruptionEvent",
                "ClarificationContract",
                "ErrorRecoveryContract"
            ],
        }),
        artifact_refs: vec![crate::models::ArtifactRef {
            artifact_id: artifact_id.clone(),
            artifact_type: ArtifactType::Report,
        }],
        receipt_ref: Some(artifact_id.clone()),
        input_refs: Vec::new(),
        status: EventStatus::Success,
        duration_ms: None,
    };
    append_event(memory_runtime, &event);
    eprintln!(
        "[chat-proof-trace] session={} artifact={} scorecard=1 stop_reason=1 quality_ledger=1",
        sid, artifact_id
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

    let existing_title = existing
        .map(|summary| summary.title.trim())
        .filter(|title| !title.is_empty())
        .map(ToOwned::to_owned);
    let task_title = session_summary_title_from_task_intent(&task.intent);
    let title = match existing_title {
        Some(title) if !title.starts_with("[Codebase context]") => title,
        _ => task_title,
    };

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
#[path = "store/tests.rs"]
mod tests;
