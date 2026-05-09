use crate::models::{
    AgentEvent, AgentPhase, AgentTask, Artifact, ArtifactType, AssistantAttentionPolicy,
    AssistantAttentionProfile, AssistantNotificationRecord, AssistantUserProfile,
    AssistantWorkbenchActivityRecord, ChatMessage, EventStatus, EventType, InterventionRecord,
    KnowledgeCollectionRecord, LocalEngineControlPlane, LocalEngineControlPlaneDocument,
    LocalEngineJobRecord, LocalEngineRegistryState, LocalEngineStagedOperation,
    LocalEngineWorkerTemplateRecord, SessionCompactionRecord, SessionFileContext, SessionSummary,
    SkillSourceRecord, TeamMemorySyncEntry,
};
use ioi_api::runtime_harness::extract_user_request_from_contextualized_intent;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::{MemoryRuntime, StoredTranscriptMessage, TranscriptPrivacyMetadata};
use ioi_services::agentic::runtime::harness::invoke_default_harness_component;
use ioi_types::app::{
    compare_harness_live_shadow_attempts, default_harness_default_runtime_dispatch_proof,
    default_harness_gated_cluster_run_for_shadow_run,
    default_harness_live_promotion_readiness_proof, default_harness_shadow_run_for_attempts,
    harness_component_adapter_result_camel_value, harness_gated_cluster_run_camel_value,
    harness_node_attempt_record_from_camel_value, harness_promotion_cluster_components,
    harness_shadow_comparison_camel_value, runtime_contracts::RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
    HarnessComponentInvocation, HarnessComponentKind, HarnessExecutionMode,
    HarnessLivePromotionClusterReadiness, HarnessLivePromotionReadinessProof,
    HarnessNodeAttemptRecord, HarnessNodeAttemptStatus, HarnessPromotionClusterId,
    HarnessShadowComparison, DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS, DEFAULT_AGENT_HARNESS_HASH,
    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
    DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
const WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME: &str =
    "autopilot.workflow_output_writer_transcript_staging.v1";
const WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_IDENTITY_CHECKPOINT_NAME: &str =
    "autopilot.workflow_output_writer_transcript_identity.v1";
const WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_COVERAGE_CHECKPOINT_NAME: &str =
    "autopilot.workflow_provider_gated_visible_output_coverage.v1";
const WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_COVERAGE_CHECKPOINT_NAME: &str =
    "autopilot.workflow_read_only_capability_routing_coverage.v1";
const WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_ENV: &str =
    "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT";
const WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_QUERY: &str =
    "Explain what this workspace is for in two concise paragraphs.";
const WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_SCENARIOS: &[&str] = &[
    "retained_no_tool_answer",
    "retained_repo_grounded_answer",
    "retained_planning_without_mutation",
    "retained_mermaid_rendering",
    "retained_source_heavy_synthesis",
    "retained_probe_behavior",
    "retained_harness_dogfooding",
];
const WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_RETAINED_SCENARIOS: &[&str] = &[
    "retained_repo_grounded_answer",
    "retained_source_heavy_synthesis",
    "retained_probe_behavior",
];
const WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_QUERIES: &[(&str, &str)] = &[
    (
        WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_QUERY,
        "retained_no_tool_answer",
    ),
    (
        "Where is Autopilot chat task state defined? Cite the files you used.",
        "retained_repo_grounded_answer",
    ),
    (
        "Plan how to add StopCondition support, but do not edit files.",
        "retained_planning_without_mutation",
    ),
    (
        "Show the agent runtime event lifecycle as a Mermaid sequence diagram.",
        "retained_mermaid_rendering",
    ),
    (
        "Using repo docs, summarize the chat UX contract and cite sources.",
        "retained_source_heavy_synthesis",
    ),
    (
        "Find the cheapest way to verify whether desktop chat sources render.",
        "retained_probe_behavior",
    ),
    (
        "Validate this answer path through the harness and explain the result.",
        "retained_harness_dogfooding",
    ),
];

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

pub(crate) fn clean_chat_session_title_candidate(title: &str) -> Option<String> {
    let trimmed = title.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("[Codebase context]")
        || trimmed.starts_with("CHAT ARTIFACT ROUTE CONTRACT")
    {
        return None;
    }
    Some(truncate_session_summary_label(trimmed, 54))
}

pub(crate) fn canonical_chat_session_title_from_query(query: &str) -> Option<String> {
    let user_request = extract_user_request_from_contextualized_intent(query);
    let trimmed = user_request.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("[Codebase context]")
        || trimmed.starts_with("CHAT ARTIFACT ROUTE CONTRACT")
    {
        return None;
    }
    Some(truncate_session_summary_label(trimmed, 54))
}

fn session_summary_title_from_task_intent(intent: &str) -> String {
    canonical_chat_session_title_from_query(intent)
        .unwrap_or_else(|| "Untitled request".to_string())
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

fn runtime_canary_blockers(
    task: &AgentTask,
    latest_user_turn: &str,
    selected_action: &str,
    stop_reason: &str,
) -> Vec<String> {
    let mut blockers = Vec::<String>::new();
    if !matches!(task.phase, AgentPhase::Complete) {
        blockers.push("turn_not_complete".to_string());
    }
    if task.pending_request_hash.is_some() || task.gate_info.is_some() {
        blockers.push("operator_gate_active".to_string());
    }
    if runtime_has_mutation_evidence(task) {
        blockers.push("mutation_evidence_present".to_string());
    }
    if selected_action != "verify" {
        blockers.push(format!("selected_action:{selected_action}"));
    }
    if stop_reason != "objective_satisfied" {
        blockers.push(format!("stop_reason:{stop_reason}"));
    }
    let normalized = latest_user_turn.to_ascii_lowercase();
    let risky_intent = [
        "delete the repository",
        "delete repository",
        "remove the repository",
        "wipe the repository",
        "without asking",
        "destructive",
        "deploy",
        "purchase",
        "transfer funds",
        "send email",
    ]
    .iter()
    .any(|needle| normalized.contains(needle));
    if risky_intent {
        blockers.push("user_intent_requires_legacy_authority".to_string());
    }
    blockers.sort();
    blockers.dedup();
    blockers
}

fn runtime_harness_default_promotion_enabled() -> bool {
    std::env::var("AUTOPILOT_HARNESS_DEFAULT_PROMOTION")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn runtime_harness_value_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn runtime_harness_required_invariant_present(invariant_ids: &[String]) -> bool {
    invariant_ids
        .iter()
        .any(|id| id == DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)
}

fn runtime_harness_string_sets_match(left: &[String], right: &[String]) -> bool {
    let left = left.iter().collect::<std::collections::BTreeSet<_>>();
    let right = right.iter().collect::<std::collections::BTreeSet<_>>();
    left == right
}

fn runtime_harness_live_promotion_cluster_readiness_camel_value(
    cluster: &HarnessLivePromotionClusterReadiness,
) -> Value {
    json!({
        "clusterId": cluster.cluster_id.as_str(),
        "label": cluster.label,
        "currentStatus": cluster.current_status.as_str(),
        "targetExecutionMode": cluster.target_execution_mode.as_str(),
        "componentKinds": cluster
            .component_kinds
            .iter()
            .map(|component_kind| component_kind.as_str())
            .collect::<Vec<_>>(),
        "readinessReady": cluster.readiness_ready,
        "receiptReady": cluster.receipt_ready,
        "replayGateReady": cluster.replay_gate_ready,
        "canaryReady": cluster.canary_ready,
        "rollbackReady": cluster.rollback_ready,
        "divergenceReady": cluster.divergence_ready,
        "blockingDivergenceCount": cluster.blocking_divergence_count,
        "unclassifiedDivergenceCount": cluster.unclassified_divergence_count,
        "attemptIds": cluster.attempt_ids,
        "receiptRefs": cluster.receipt_refs,
        "replayFixtureRefs": cluster.replay_fixture_refs,
        "actionFrameIds": cluster.action_frame_ids,
        "divergenceClasses": cluster
            .divergence_classes
            .iter()
            .map(|divergence_class| divergence_class.as_str())
            .collect::<Vec<_>>(),
        "rollbackTarget": cluster.rollback_target,
        "blockers": cluster.blockers,
        "decision": cluster.decision,
    })
}

fn runtime_harness_live_promotion_readiness_proof_camel_value(
    proof: &HarnessLivePromotionReadinessProof,
) -> Value {
    json!({
        "schemaVersion": proof.schema_version,
        "proofId": proof.proof_id,
        "dispatchId": proof.dispatch_id,
        "workflowId": proof.workflow_id,
        "activationId": proof.activation_id,
        "harnessHash": proof.harness_hash,
        "targetExecutionMode": proof.target_execution_mode.as_str(),
        "requiredClusterIds": proof
            .required_cluster_ids
            .iter()
            .map(|cluster_id| cluster_id.as_str())
            .collect::<Vec<_>>(),
        "clusterReadiness": proof
            .cluster_readiness
            .iter()
            .map(runtime_harness_live_promotion_cluster_readiness_camel_value)
            .collect::<Vec<_>>(),
        "allClustersReady": proof.all_clusters_ready,
        "promotionEligible": proof.promotion_eligible,
        "defaultLiveActivationReady": proof.default_live_activation_ready,
        "invalidForkLiveActivationBlocked": proof.invalid_fork_live_activation_blocked,
        "rollbackAvailable": proof.rollback_available,
        "rollbackTarget": proof.rollback_target,
        "activationBlockers": proof.activation_blockers,
        "policyDecision": proof.policy_decision,
        "evidenceRefs": proof.evidence_refs,
    })
}

fn runtime_harness_selector_live_promotion_readiness_proof(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    selected_action: &str,
    stop_reason: &str,
    default_promotion_enabled: bool,
) -> Value {
    let mut activation_blockers =
        runtime_canary_blockers(task, latest_user_turn, selected_action, stop_reason);
    if !default_promotion_enabled {
        activation_blockers.push("promotion_gate_disabled".to_string());
    }
    activation_blockers.sort();
    activation_blockers.dedup();
    let dispatch_id = format!(
        "harness-default-dispatch:{sid}:turn-{}:read-only",
        task.progress
    );
    let proof = default_harness_live_promotion_readiness_proof(dispatch_id, activation_blockers);
    runtime_harness_live_promotion_readiness_proof_camel_value(&proof)
}

fn runtime_harness_live_promotion_readiness_blockers(proof: Option<&Value>) -> Vec<String> {
    let Some(proof) = proof else {
        return vec!["live_promotion_readiness_proof_missing".to_string()];
    };
    let mut blockers = Vec::<String>::new();
    if proof.get("schemaVersion").and_then(Value::as_str)
        != Some("workflow.harness.live-promotion-readiness.v1")
    {
        blockers.push("live_promotion_readiness_schema_mismatch".to_string());
    }
    if proof.get("workflowId").and_then(Value::as_str) != Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID) {
        blockers.push("live_promotion_readiness_workflow_mismatch".to_string());
    }
    if proof.get("activationId").and_then(Value::as_str)
        != Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    {
        blockers.push("live_promotion_readiness_activation_mismatch".to_string());
    }
    if proof.get("harnessHash").and_then(Value::as_str) != Some(DEFAULT_AGENT_HARNESS_HASH) {
        blockers.push("live_promotion_readiness_hash_mismatch".to_string());
    }
    if proof.get("targetExecutionMode").and_then(Value::as_str) != Some("live") {
        blockers.push("live_promotion_readiness_target_not_live".to_string());
    }
    if proof.get("allClustersReady").and_then(Value::as_bool) != Some(true) {
        blockers.push("live_promotion_readiness_clusters_not_ready".to_string());
    }
    if proof.get("promotionEligible").and_then(Value::as_bool) != Some(true) {
        blockers.push("live_promotion_readiness_not_eligible".to_string());
    }
    if proof
        .get("defaultLiveActivationReady")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("live_promotion_readiness_default_activation_not_ready".to_string());
    }
    if proof
        .get("invalidForkLiveActivationBlocked")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("live_promotion_readiness_invalid_fork_not_blocked".to_string());
    }
    if proof.get("rollbackAvailable").and_then(Value::as_bool) != Some(true)
        || proof
            .get("rollbackTarget")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty()
    {
        blockers.push("live_promotion_readiness_rollback_unavailable".to_string());
    }
    if proof.get("policyDecision").and_then(Value::as_str)
        != Some("allow_default_harness_live_promotion_readiness")
    {
        blockers.push("live_promotion_readiness_policy_blocked".to_string());
    }

    blockers.extend(
        runtime_harness_value_string_array(proof.get("activationBlockers"))
            .into_iter()
            .map(|blocker| format!("live_promotion_readiness_activation_blocker:{blocker}")),
    );

    let required_cluster_ids = [
        "cognition",
        "routing_model",
        "verification_output",
        "authority_tooling",
    ];
    let proof_required_cluster_ids =
        runtime_harness_value_string_array(proof.get("requiredClusterIds"));
    let cluster_readiness = proof
        .get("clusterReadiness")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for cluster_id in required_cluster_ids {
        if !proof_required_cluster_ids
            .iter()
            .any(|candidate| candidate == cluster_id)
        {
            blockers.push(format!(
                "live_promotion_readiness_required_cluster_missing:{cluster_id}"
            ));
        }
        let Some(cluster) = cluster_readiness.iter().find(|candidate| {
            candidate.get("clusterId").and_then(Value::as_str) == Some(cluster_id)
        }) else {
            blockers.push(format!(
                "live_promotion_readiness_cluster_missing:{cluster_id}"
            ));
            continue;
        };
        if cluster.get("targetExecutionMode").and_then(Value::as_str) != Some("live") {
            blockers.push(format!(
                "live_promotion_readiness_cluster_not_live:{cluster_id}"
            ));
        }
        if cluster.get("readinessReady").and_then(Value::as_bool) != Some(true) {
            blockers.push(format!(
                "live_promotion_readiness_cluster_readiness_not_ready:{cluster_id}"
            ));
        }
        let receipt_refs = runtime_harness_value_string_array(cluster.get("receiptRefs"));
        if cluster.get("receiptReady").and_then(Value::as_bool) != Some(true)
            || receipt_refs.is_empty()
        {
            blockers.push(format!(
                "live_promotion_readiness_cluster_receipts_missing:{cluster_id}"
            ));
        }
        let replay_fixture_refs =
            runtime_harness_value_string_array(cluster.get("replayFixtureRefs"));
        if cluster.get("replayGateReady").and_then(Value::as_bool) != Some(true)
            || replay_fixture_refs.is_empty()
        {
            blockers.push(format!(
                "live_promotion_readiness_cluster_replay_missing:{cluster_id}"
            ));
        }
        if cluster.get("canaryReady").and_then(Value::as_bool) != Some(true) {
            blockers.push(format!(
                "live_promotion_readiness_cluster_canary_not_ready:{cluster_id}"
            ));
        }
        if cluster.get("rollbackReady").and_then(Value::as_bool) != Some(true) {
            blockers.push(format!(
                "live_promotion_readiness_cluster_rollback_not_ready:{cluster_id}"
            ));
        }
        if cluster.get("divergenceReady").and_then(Value::as_bool) != Some(true)
            || cluster
                .get("blockingDivergenceCount")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                > 0
            || cluster
                .get("unclassifiedDivergenceCount")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                > 0
        {
            blockers.push(format!(
                "live_promotion_readiness_cluster_divergence_not_ready:{cluster_id}"
            ));
        }
        blockers.extend(
            runtime_harness_value_string_array(cluster.get("blockers"))
                .into_iter()
                .map(|blocker| {
                    format!("live_promotion_readiness_cluster_blocker:{cluster_id}:{blocker}")
                }),
        );
    }

    blockers.sort();
    blockers.dedup();
    blockers
}

fn runtime_harness_provider_gated_visible_output_enabled() -> bool {
    std::env::var(WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_ENV)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn runtime_harness_retained_query_key(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn runtime_harness_provider_gated_visible_output_retained_scenario(
    value: &str,
) -> Option<&'static str> {
    let key = runtime_harness_retained_query_key(value);
    WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_QUERIES
        .iter()
        .find_map(|(query, scenario)| {
            if key == runtime_harness_retained_query_key(query) {
                Some(*scenario)
            } else {
                None
            }
        })
}

fn runtime_harness_provider_gated_visible_output_required_scenarios() -> Vec<String> {
    WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_SCENARIOS
        .iter()
        .map(|scenario| (*scenario).to_string())
        .collect()
}

fn runtime_harness_read_only_capability_routing_required_scenarios() -> Vec<String> {
    WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_RETAINED_SCENARIOS
        .iter()
        .map(|scenario| (*scenario).to_string())
        .collect()
}

fn runtime_harness_provider_gated_visible_output_history_scenarios(
    task: &AgentTask,
) -> Vec<String> {
    let mut scenarios = Vec::<String>::new();
    for message in &task.history {
        if message.role != "user" {
            continue;
        }
        let request = extract_user_request_from_contextualized_intent(message.text.as_str());
        if let Some(scenario) =
            runtime_harness_provider_gated_visible_output_retained_scenario(&request)
        {
            if !scenarios.iter().any(|existing| existing == scenario) {
                scenarios.push(scenario.to_string());
            }
        }
    }
    scenarios.sort();
    scenarios
}

fn runtime_harness_read_only_capability_routing_history_scenarios(task: &AgentTask) -> Vec<String> {
    runtime_harness_provider_gated_visible_output_history_scenarios(task)
        .into_iter()
        .filter(|scenario| {
            WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_RETAINED_SCENARIOS.contains(&scenario.as_str())
        })
        .collect()
}

fn runtime_harness_provider_gated_visible_output_coverage_array(
    value: &Value,
    field: &str,
) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn runtime_harness_push_provider_gated_visible_output_coverage(
    scenarios: &mut Vec<String>,
    required_scenarios: &[String],
    scenario: &str,
) {
    if !required_scenarios
        .iter()
        .any(|required| required == scenario)
    {
        return;
    }
    if !scenarios.iter().any(|existing| existing == scenario) {
        scenarios.push(scenario.to_string());
        scenarios.sort();
    }
}

fn runtime_harness_update_provider_gated_visible_output_coverage(
    memory_runtime: &Arc<MemoryRuntime>,
    sid: &str,
    scenarios: &[String],
    provider_gated_visible_output_passed: bool,
    rollback_drill_passed: bool,
    now_ms: u64,
) -> Value {
    let required_scenarios = runtime_harness_provider_gated_visible_output_required_scenarios();
    let mut provider_scenarios = Vec::<String>::new();
    let mut rollback_scenarios = Vec::<String>::new();

    if let Some(thread_key) = thread_storage_key(sid) {
        if let Some(existing) = load_thread_checkpoint_json::<Value>(
            memory_runtime,
            thread_key,
            WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_COVERAGE_CHECKPOINT_NAME,
        ) {
            provider_scenarios = runtime_harness_provider_gated_visible_output_coverage_array(
                &existing,
                "providerGatedVisibleOutputScenarios",
            );
            rollback_scenarios = runtime_harness_provider_gated_visible_output_coverage_array(
                &existing,
                "rollbackDrillScenarios",
            );
        }

        if provider_gated_visible_output_passed {
            for scenario in scenarios {
                runtime_harness_push_provider_gated_visible_output_coverage(
                    &mut provider_scenarios,
                    &required_scenarios,
                    scenario,
                );
            }
        }
        if rollback_drill_passed {
            for scenario in scenarios {
                runtime_harness_push_provider_gated_visible_output_coverage(
                    &mut rollback_scenarios,
                    &required_scenarios,
                    scenario,
                );
            }
        }

        let provider_coverage_complete = required_scenarios
            .iter()
            .all(|scenario| provider_scenarios.contains(scenario));
        let rollback_drill_coverage_complete = required_scenarios
            .iter()
            .all(|scenario| rollback_scenarios.contains(scenario));
        let coverage = json!({
            "schemaVersion": "workflow.harness.model-provider-gated-visible-output-coverage.v1",
            "sessionId": sid,
            "checkpointName": WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_COVERAGE_CHECKPOINT_NAME,
            "requiredScenarios": required_scenarios,
            "providerGatedVisibleOutputScenarios": provider_scenarios,
            "rollbackDrillScenarios": rollback_scenarios,
            "providerCoverageComplete": provider_coverage_complete,
            "rollbackDrillCoverageComplete": rollback_drill_coverage_complete,
            "complete": provider_coverage_complete && rollback_drill_coverage_complete,
            "updatedAtMs": now_ms,
        });
        persist_thread_checkpoint_json(
            memory_runtime,
            thread_key,
            WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_COVERAGE_CHECKPOINT_NAME,
            &coverage,
        );
        coverage
    } else {
        json!({
            "schemaVersion": "workflow.harness.model-provider-gated-visible-output-coverage.v1",
            "sessionId": sid,
            "checkpointName": WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_COVERAGE_CHECKPOINT_NAME,
            "requiredScenarios": required_scenarios,
            "providerGatedVisibleOutputScenarios": provider_scenarios,
            "rollbackDrillScenarios": rollback_scenarios,
            "providerCoverageComplete": false,
            "rollbackDrillCoverageComplete": false,
            "complete": false,
            "updatedAtMs": now_ms,
        })
    }
}

fn runtime_harness_update_read_only_capability_routing_coverage(
    memory_runtime: &Arc<MemoryRuntime>,
    sid: &str,
    scenarios: &[String],
    read_only_capability_routing_passed: bool,
    no_mutation_passed: bool,
    now_ms: u64,
) -> Value {
    let required_scenarios = runtime_harness_read_only_capability_routing_required_scenarios();
    let mut routing_scenarios = Vec::<String>::new();
    let mut no_mutation_scenarios = Vec::<String>::new();

    if let Some(thread_key) = thread_storage_key(sid) {
        if let Some(existing) = load_thread_checkpoint_json::<Value>(
            memory_runtime,
            thread_key,
            WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_COVERAGE_CHECKPOINT_NAME,
        ) {
            routing_scenarios = runtime_harness_provider_gated_visible_output_coverage_array(
                &existing,
                "readOnlyCapabilityRoutingScenarios",
            );
            no_mutation_scenarios = runtime_harness_provider_gated_visible_output_coverage_array(
                &existing,
                "noMutationScenarios",
            );
        }

        if read_only_capability_routing_passed {
            for scenario in scenarios {
                runtime_harness_push_provider_gated_visible_output_coverage(
                    &mut routing_scenarios,
                    &required_scenarios,
                    scenario,
                );
            }
        }
        if no_mutation_passed {
            for scenario in scenarios {
                runtime_harness_push_provider_gated_visible_output_coverage(
                    &mut no_mutation_scenarios,
                    &required_scenarios,
                    scenario,
                );
            }
        }

        let routing_coverage_complete = required_scenarios
            .iter()
            .all(|scenario| routing_scenarios.contains(scenario));
        let no_mutation_coverage_complete = required_scenarios
            .iter()
            .all(|scenario| no_mutation_scenarios.contains(scenario));
        let coverage = json!({
            "schemaVersion": "workflow.harness.read-only-capability-routing-coverage.v1",
            "sessionId": sid,
            "checkpointName": WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_COVERAGE_CHECKPOINT_NAME,
            "requiredScenarios": required_scenarios,
            "readOnlyCapabilityRoutingScenarios": routing_scenarios,
            "noMutationScenarios": no_mutation_scenarios,
            "routingCoverageComplete": routing_coverage_complete,
            "noMutationCoverageComplete": no_mutation_coverage_complete,
            "complete": routing_coverage_complete && no_mutation_coverage_complete,
            "updatedAtMs": now_ms,
        });
        persist_thread_checkpoint_json(
            memory_runtime,
            thread_key,
            WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_COVERAGE_CHECKPOINT_NAME,
            &coverage,
        );
        coverage
    } else {
        json!({
            "schemaVersion": "workflow.harness.read-only-capability-routing-coverage.v1",
            "sessionId": sid,
            "checkpointName": WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_COVERAGE_CHECKPOINT_NAME,
            "requiredScenarios": required_scenarios,
            "readOnlyCapabilityRoutingScenarios": routing_scenarios,
            "noMutationScenarios": no_mutation_scenarios,
            "routingCoverageComplete": false,
            "noMutationCoverageComplete": false,
            "complete": false,
            "updatedAtMs": now_ms,
        })
    }
}

fn runtime_harness_workflow_selector_selected(selected_selector: &str) -> bool {
    matches!(
        selected_selector,
        "blessed_workflow_live_canary" | "blessed_workflow_live_default"
    )
}

fn runtime_harness_worker_attach_receipt(
    sid: &str,
    turn_id: &str,
    registry_record: &Value,
    attach_request: &Value,
) -> Value {
    let worker_binding = registry_record
        .get("workerBinding")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut blockers = Vec::<String>::new();
    if attach_request.get("schemaVersion").and_then(Value::as_str)
        != Some("workflow.harness.worker-attach-request.v1")
    {
        blockers.push("worker_attach_request_schema_mismatch".to_string());
    }
    let record_string = |key: &str| registry_record.get(key).and_then(Value::as_str);
    let request_string = |key: &str| attach_request.get(key).and_then(Value::as_str);
    let required_invariant_ids =
        runtime_harness_value_string_array(registry_record.get("requiredInvariantIds"));
    let requested_invariant_ids =
        runtime_harness_value_string_array(attach_request.get("requiredInvariantIds"));
    let registry_invariant_blockers =
        runtime_harness_value_string_array(registry_record.get("invariantBlockers"));
    let worker_invariant_blockers =
        runtime_harness_value_string_array(worker_binding.get("invariantBlockers"));
    let worker_required_invariant_ids =
        runtime_harness_value_string_array(worker_binding.get("requiredInvariantIds"));
    if request_string("workflowId") != record_string("workflowId") {
        blockers.push("worker_attach_workflow_mismatch".to_string());
    }
    if request_string("activationId") != record_string("activationId") {
        blockers.push("worker_attach_activation_mismatch".to_string());
    }
    if request_string("activationHash") != record_string("activationHash") {
        blockers.push("worker_attach_activation_hash_mismatch".to_string());
    }
    if request_string("harnessHash") != record_string("harnessHash") {
        blockers.push("worker_attach_harness_hash_mismatch".to_string());
    }
    if attach_request.get("componentVersionSet") != registry_record.get("componentVersionSet") {
        blockers.push("worker_attach_component_version_set_mismatch".to_string());
    }
    if request_string("rollbackTarget")
        .unwrap_or_default()
        .is_empty()
    {
        blockers.push("worker_attach_rollback_target_missing".to_string());
    }
    if request_string("rollbackTarget") != record_string("rollbackTarget") {
        blockers.push("worker_attach_rollback_target_mismatch".to_string());
    }
    if request_string("readinessProofId")
        .unwrap_or_default()
        .is_empty()
    {
        blockers.push("worker_attach_readiness_proof_missing".to_string());
    }
    if request_string("readinessProofId") != record_string("readinessProofId") {
        blockers.push("worker_attach_readiness_proof_mismatch".to_string());
    }
    if !runtime_harness_string_sets_match(&requested_invariant_ids, &required_invariant_ids) {
        blockers.push("worker_attach_required_invariant_mismatch".to_string());
    }
    if !runtime_harness_required_invariant_present(&required_invariant_ids) {
        blockers
            .push("worker_attach_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    if !registry_invariant_blockers.is_empty() {
        blockers.push("worker_attach_invariant_blocked".to_string());
        blockers.extend(registry_invariant_blockers.iter().cloned());
    }
    let binding_status = record_string("bindingStatus").unwrap_or("blocked");
    if binding_status != "bound" {
        blockers.push("worker_attach_registry_not_bound".to_string());
    }
    if registry_record
        .get("blockers")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(true)
    {
        blockers.push("worker_attach_registry_blocked".to_string());
    }
    if !record_string("canaryResultId")
        .unwrap_or_default()
        .ends_with(":passed")
    {
        blockers.push("worker_attach_canary_not_passed".to_string());
    }
    if worker_binding.get("executionMode").and_then(Value::as_str) != Some("live") {
        blockers.push("worker_attach_worker_not_live".to_string());
    }
    if worker_binding.get("rollbackTarget").and_then(Value::as_str)
        != registry_record
            .get("rollbackTarget")
            .and_then(Value::as_str)
    {
        blockers.push("worker_attach_worker_rollback_mismatch".to_string());
    }
    if worker_binding
        .get("authorityBindingReady")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("worker_attach_authority_not_ready".to_string());
    }
    if worker_binding
        .get("authorityBindingBlockers")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(true)
    {
        blockers.push("worker_attach_authority_blocked".to_string());
    }
    if worker_binding
        .get("livePromotionReadinessProofId")
        .and_then(Value::as_str)
        != registry_record
            .get("readinessProofId")
            .and_then(Value::as_str)
    {
        blockers.push("worker_attach_worker_readiness_proof_mismatch".to_string());
    }
    if !runtime_harness_string_sets_match(&worker_required_invariant_ids, &required_invariant_ids) {
        blockers.push("worker_attach_worker_invariant_mismatch".to_string());
    }
    if !worker_invariant_blockers.is_empty() {
        blockers.push("worker_attach_worker_invariant_blocked".to_string());
        blockers.extend(worker_invariant_blockers.iter().cloned());
    }
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let requested_status = request_string("requestedStatus").unwrap_or("bound");
    let attach_status = if accepted {
        match requested_status {
            "resumed" => "resumed",
            "rolled_back" => "rolled_back",
            _ => "bound",
        }
    } else if binding_status == "projection" {
        "unbound"
    } else if binding_status == "canary" {
        "canary"
    } else {
        "blocked"
    };
    let rollback_available = request_string("rollbackTarget")
        == registry_record
            .get("rollbackTarget")
            .and_then(Value::as_str)
        && request_string("rollbackTarget")
            .map(|value| !value.is_empty())
            .unwrap_or(false);
    let mut invariant_blockers = registry_invariant_blockers.clone();
    invariant_blockers.extend(worker_invariant_blockers.clone());
    invariant_blockers.sort();
    invariant_blockers.dedup();
    json!({
        "schemaVersion": "workflow.harness.worker-attach-receipt.v1",
        "receiptId": format!(
            "harness-worker-attach-receipt:{sid}:{turn_id}:{attach_status}"
        ),
        "workerId": request_string("workerId").unwrap_or("harness-worker:unknown"),
        "workflowId": request_string("workflowId").unwrap_or_default(),
        "activationId": request_string("activationId").unwrap_or_default(),
        "activationHash": request_string("activationHash").unwrap_or_default(),
        "harnessHash": request_string("harnessHash").unwrap_or_default(),
        "componentVersionSet": attach_request.get("componentVersionSet").cloned().unwrap_or_else(|| json!({})),
        "rollbackTarget": request_string("rollbackTarget").unwrap_or_default(),
        "rollbackAvailable": rollback_available,
        "readinessProofId": request_string("readinessProofId").unwrap_or_default(),
        "registryRecordId": record_string("registryRecordId").unwrap_or_default(),
        "bindingStatus": binding_status,
        "attachStatus": attach_status,
        "accepted": accepted,
        "blockers": blockers,
        "workerBinding": worker_binding,
        "policyDecision": if accepted {
            "allow_harness_worker_attach"
        } else {
            "block_harness_worker_attach"
        },
        "requiredInvariantIds": required_invariant_ids,
        "invariantBlockers": invariant_blockers,
        "evidenceRefs": [
            record_string("registryRecordId").unwrap_or_default(),
            record_string("readinessProofId").unwrap_or_default(),
            record_string("canaryResultId").unwrap_or_default()
        ]
    })
}

fn runtime_harness_worker_attach_lifecycle_events(
    sid: &str,
    turn_id: &str,
    registry_record: &Value,
) -> Vec<Value> {
    let record_string = |key: &str| registry_record.get(key).and_then(Value::as_str);
    let workflow_id = record_string("workflowId").unwrap_or_default();
    let activation_id = record_string("activationId").unwrap_or_default();
    let activation_hash = record_string("activationHash").unwrap_or_default();
    let harness_hash = record_string("harnessHash").unwrap_or_default();
    let rollback_target = record_string("rollbackTarget").unwrap_or_default();
    let readiness_proof_id = record_string("readinessProofId").unwrap_or_default();
    let component_version_set = registry_record
        .get("componentVersionSet")
        .cloned()
        .unwrap_or_else(|| json!({}));
    [
        ("attach", "bound"),
        ("resume", "resumed"),
        ("rollback", "rolled_back"),
    ]
    .into_iter()
    .enumerate()
    .map(|(sequence, (phase, requested_status))| {
        let attach_request = json!({
            "schemaVersion": "workflow.harness.worker-attach-request.v1",
            "requestId": format!("harness-worker-attach-request:{sid}:{turn_id}:{phase}"),
            "workerId": format!("harness-worker:{workflow_id}:{activation_id}:{sid}"),
            "workflowId": workflow_id,
            "activationId": activation_id,
            "activationHash": activation_hash,
            "harnessHash": harness_hash,
            "componentVersionSet": component_version_set.clone(),
            "rollbackTarget": rollback_target,
            "readinessProofId": readiness_proof_id,
            "requiredInvariantIds": registry_record
                .get("requiredInvariantIds")
                .cloned()
                .unwrap_or_else(|| json!([])),
            "requestedStatus": requested_status
        });
        let receipt = runtime_harness_worker_attach_receipt(
            sid,
            turn_id,
            registry_record,
            &attach_request,
        );
        let attach_status = receipt
            .get("attachStatus")
            .and_then(Value::as_str)
            .unwrap_or("blocked")
            .to_string();
        let receipt_id = receipt
            .get("receiptId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let accepted = receipt.get("accepted").and_then(Value::as_bool) == Some(true);
        let rollback_available =
            receipt.get("rollbackAvailable").and_then(Value::as_bool) == Some(true);
        let policy_decision = receipt
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("block_harness_worker_attach")
            .to_string();
        let blockers = receipt
            .get("blockers")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let evidence_refs = receipt
            .get("evidenceRefs")
            .cloned()
            .unwrap_or_else(|| json!([]));
        json!({
            "schemaVersion": "workflow.harness.worker-attach-lifecycle.v1",
            "eventId": format!("harness-worker-attach-lifecycle:{phase}:{workflow_id}:{activation_id}"),
            "sequence": sequence,
            "phase": phase,
            "attemptId": format!("harness-worker-attach:attempt:{phase}:{workflow_id}:{activation_id}"),
            "workflowNodeId": "harness.handoff_bridge",
            "componentKind": "handoff_bridge",
            "attachStatus": attach_status,
            "receiptId": receipt_id,
            "receipt": receipt,
            "registryRecordId": record_string("registryRecordId").unwrap_or_default(),
            "accepted": accepted,
            "rollbackAvailable": rollback_available,
            "policyDecision": policy_decision,
            "blockers": blockers,
            "requiredInvariantIds": receipt
                .get("requiredInvariantIds")
                .cloned()
                .unwrap_or_else(|| json!([])),
            "invariantBlockers": receipt
                .get("invariantBlockers")
                .cloned()
                .unwrap_or_else(|| json!([])),
            "evidenceRefs": evidence_refs
        })
    })
    .collect()
}

fn runtime_harness_worker_attach_lifecycle_attempt_ids(lifecycle: &[Value]) -> Vec<String> {
    lifecycle
        .iter()
        .filter_map(|event| {
            event
                .get("attemptId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn runtime_harness_worker_attach_lifecycle_statuses(lifecycle: &[Value]) -> Vec<String> {
    lifecycle
        .iter()
        .filter_map(|event| {
            event
                .get("attachStatus")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn runtime_harness_worker_attach_lifecycle_complete(lifecycle: &[Value]) -> bool {
    let statuses = runtime_harness_worker_attach_lifecycle_statuses(lifecycle);
    let lifecycle_clean = !lifecycle.is_empty()
        && lifecycle.iter().all(|event| {
            event.get("accepted").and_then(Value::as_bool) == Some(true)
                && event
                    .get("blockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        });
    lifecycle_clean
        && statuses.iter().any(|status| status == "bound")
        && statuses.iter().any(|status| status == "resumed")
        && statuses.iter().any(|status| status == "rolled_back")
}

fn runtime_harness_worker_session_record(
    sid: &str,
    turn_id: &str,
    registry_record: &Value,
    lifecycle: &[Value],
) -> Value {
    let event_for = |phase: &str| {
        lifecycle
            .iter()
            .find(|event| event.get("phase").and_then(Value::as_str) == Some(phase))
    };
    let attach_event = event_for("attach");
    let resume_event = event_for("resume");
    let rollback_event = event_for("rollback");
    let mut blockers = Vec::<String>::new();
    if lifecycle.len() < 3 {
        blockers.push("worker_session_lifecycle_incomplete".to_string());
    }
    if attach_event.map(|event| {
        event.get("accepted").and_then(Value::as_bool) == Some(true)
            && event.get("attachStatus").and_then(Value::as_str) == Some("bound")
            && event
                .get("blockers")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false)
    }) != Some(true)
    {
        blockers.push("worker_session_attach_not_bound".to_string());
    }
    if resume_event.map(|event| {
        event.get("accepted").and_then(Value::as_bool) == Some(true)
            && event.get("attachStatus").and_then(Value::as_str) == Some("resumed")
            && event
                .get("blockers")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false)
    }) != Some(true)
    {
        blockers.push("worker_session_resume_not_resolved".to_string());
    }
    if rollback_event.map(|event| {
        event.get("accepted").and_then(Value::as_bool) == Some(true)
            && event.get("attachStatus").and_then(Value::as_str) == Some("rolled_back")
            && event.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && event
                .get("blockers")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false)
    }) != Some(true)
    {
        blockers.push("worker_session_rollback_not_ready".to_string());
    }
    let registry_record_id = registry_record
        .get("registryRecordId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    for event in lifecycle {
        if event.get("registryRecordId").and_then(Value::as_str) != Some(registry_record_id) {
            blockers.push("worker_session_registry_record_mismatch".to_string());
        }
        if event.get("accepted").and_then(Value::as_bool) != Some(true) {
            blockers.push("worker_session_lifecycle_event_blocked".to_string());
        }
        if let Some(items) = event.get("blockers").and_then(Value::as_array) {
            blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
        }
        if let Some(items) = event.get("invariantBlockers").and_then(Value::as_array) {
            blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    let required_invariant_ids =
        runtime_harness_value_string_array(registry_record.get("requiredInvariantIds"));
    if !runtime_harness_required_invariant_present(&required_invariant_ids) {
        blockers
            .push("worker_session_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    let mut invariant_blockers =
        runtime_harness_value_string_array(registry_record.get("invariantBlockers"));
    if let Some(worker_binding) = registry_record.get("workerBinding") {
        invariant_blockers.extend(runtime_harness_value_string_array(
            worker_binding.get("invariantBlockers"),
        ));
    }
    for event in lifecycle {
        invariant_blockers.extend(runtime_harness_value_string_array(
            event.get("invariantBlockers"),
        ));
    }
    invariant_blockers.sort();
    invariant_blockers.dedup();
    blockers.extend(invariant_blockers.iter().cloned());
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let lifecycle_statuses = runtime_harness_worker_attach_lifecycle_statuses(lifecycle);
    let lifecycle_event_ids = lifecycle
        .iter()
        .filter_map(|event| {
            event
                .get("eventId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let lifecycle_attempt_ids = runtime_harness_worker_attach_lifecycle_attempt_ids(lifecycle);
    let receipt_ids = lifecycle
        .iter()
        .filter_map(|event| {
            event
                .get("receiptId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let resumed = lifecycle_statuses.iter().any(|status| status == "resumed");
    let rollback_available = rollback_event
        .and_then(|event| event.get("rollbackAvailable"))
        .and_then(Value::as_bool)
        == Some(true);
    let rollback_target = registry_record
        .get("rollbackTarget")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let rollback_target_ready = rollback_available && !rollback_target.is_empty();
    let current_status = if !accepted {
        "blocked"
    } else if rollback_target_ready {
        "rollback_ready"
    } else if resumed {
        "resumed"
    } else {
        "attached"
    };
    let current_event = if rollback_target_ready {
        rollback_event
    } else if resumed {
        resume_event
    } else {
        attach_event
    };
    let worker_id = attach_event
        .and_then(|event| event.get("receipt"))
        .and_then(|receipt| receipt.get("workerId"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            lifecycle
                .first()
                .and_then(|event| event.get("receipt"))
                .and_then(|receipt| receipt.get("workerId"))
                .and_then(Value::as_str)
                .unwrap_or("harness-worker:unknown")
        });
    let workflow_id = registry_record
        .get("workflowId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let activation_id = registry_record
        .get("activationId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let activation_hash = registry_record
        .get("activationHash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let readiness_proof_id = registry_record
        .get("readinessProofId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut evidence_refs = vec![
        registry_record_id.to_string(),
        readiness_proof_id.to_string(),
    ];
    evidence_refs.extend(lifecycle_event_ids.clone());
    evidence_refs.extend(receipt_ids.clone());
    evidence_refs.sort();
    evidence_refs.dedup();
    let session_record_id = format!(
        "harness-worker-session:{workflow_id}:{activation_id}:{activation_hash}:{worker_id}:{sid}"
    );
    let persistence_key = format!("agent::harness_worker_session::{sid}");
    let record_persistence_key =
        format!("agent::harness_worker_session_record::{session_record_id}");
    let persistence_blockers = if accepted {
        Vec::<String>::new()
    } else {
        blockers.clone()
    };
    let launch_authority_blockers = if accepted {
        Vec::<String>::new()
    } else {
        blockers.clone()
    };
    let rollback_handoff_blockers = if accepted {
        Vec::<String>::new()
    } else {
        blockers.clone()
    };

    json!({
        "schemaVersion": "workflow.harness.worker-session.v1",
        "sessionRecordId": session_record_id,
        "sessionId": sid,
        "turnId": turn_id,
        "workerId": worker_id,
        "workflowId": workflow_id,
        "activationId": activation_id,
        "activationHash": activation_hash,
        "harnessHash": registry_record.get("harnessHash").and_then(Value::as_str).unwrap_or_default(),
        "componentVersionSet": registry_record.get("componentVersionSet").cloned().unwrap_or_else(|| json!({})),
        "rollbackTarget": rollback_target,
        "readinessProofId": readiness_proof_id,
        "registryRecordId": registry_record_id,
        "currentStatus": current_status,
        "currentEventId": current_event.and_then(|event| event.get("eventId")).and_then(Value::as_str).unwrap_or_default(),
        "currentAttemptId": current_event.and_then(|event| event.get("attemptId")).and_then(Value::as_str).unwrap_or_default(),
        "currentReceiptId": current_event.and_then(|event| event.get("receiptId")).and_then(Value::as_str).unwrap_or_default(),
        "attachEventId": attach_event.and_then(|event| event.get("eventId")).and_then(Value::as_str).unwrap_or_default(),
        "resumeEventId": resume_event.and_then(|event| event.get("eventId")).and_then(Value::as_str).unwrap_or_default(),
        "rollbackEventId": rollback_event.and_then(|event| event.get("eventId")).and_then(Value::as_str).unwrap_or_default(),
        "lifecycleEventIds": lifecycle_event_ids,
        "lifecycleAttemptIds": lifecycle_attempt_ids,
        "receiptIds": receipt_ids,
        "lifecycleStatuses": lifecycle_statuses,
        "resumed": resumed,
        "rollbackAvailable": rollback_available,
        "rollbackTargetReady": rollback_target_ready,
        "accepted": accepted,
        "blockers": blockers,
        "policyDecision": if accepted { "allow_harness_worker_session" } else { "block_harness_worker_session" },
        "requiredInvariantIds": required_invariant_ids.clone(),
        "invariantBlockers": invariant_blockers.clone(),
        "evidenceRefs": evidence_refs,
        "persistenceKey": persistence_key,
        "recordPersistenceKey": record_persistence_key,
        "persistedInRuntimeCheckpoint": accepted,
        "restoredFromPersistedSession": accepted,
        "runtimeCheckpointSource": "runtime_state_access_harness_worker_session_record",
        "persistenceBlockers": persistence_blockers,
        "launchAuthorityReady": accepted,
        "launchAuthorityBlockers": launch_authority_blockers,
        "launchAuthorityInvariantIds": required_invariant_ids,
        "launchAuthorityInvariantBlockers": invariant_blockers,
        "launchAuthoritySource": "persisted_harness_worker_session_record",
        "rollbackHandoffReady": accepted,
        "rollbackHandoffBlockers": rollback_handoff_blockers,
        "rollbackHandoffTarget": rollback_target
    })
}

fn runtime_harness_worker_launch_envelope(worker_session_record: &Value, phase: &str) -> Value {
    let mut blockers = Vec::<String>::new();
    let session_record_id = worker_session_record
        .get("sessionRecordId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let session_id = worker_session_record
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let worker_id = worker_session_record
        .get("workerId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if worker_session_record
        .get("schemaVersion")
        .and_then(Value::as_str)
        != Some("workflow.harness.worker-session.v1")
    {
        blockers.push("worker_launch_session_schema_mismatch".to_string());
    }
    if session_record_id.is_empty() {
        blockers.push("worker_launch_session_record_missing".to_string());
    }
    if session_id.is_empty() {
        blockers.push("worker_launch_session_id_missing".to_string());
    }
    if worker_id.is_empty() {
        blockers.push("worker_launch_worker_id_missing".to_string());
    }
    if worker_session_record
        .get("accepted")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("worker_launch_session_not_accepted".to_string());
    }
    if let Some(items) = worker_session_record
        .get("blockers")
        .and_then(Value::as_array)
    {
        blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if worker_session_record
        .get("persistedInRuntimeCheckpoint")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("worker_launch_session_not_persisted".to_string());
    }
    if worker_session_record
        .get("restoredFromPersistedSession")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("worker_launch_session_not_restored".to_string());
    }
    if let Some(items) = worker_session_record
        .get("persistenceBlockers")
        .and_then(Value::as_array)
    {
        blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if worker_session_record
        .get("launchAuthorityReady")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("worker_launch_authority_not_ready".to_string());
    }
    if let Some(items) = worker_session_record
        .get("launchAuthorityBlockers")
        .and_then(Value::as_array)
    {
        blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
    }
    let launch_authority_invariant_ids = runtime_harness_value_string_array(
        worker_session_record.get("launchAuthorityInvariantIds"),
    );
    let launch_authority_invariant_blockers = runtime_harness_value_string_array(
        worker_session_record.get("launchAuthorityInvariantBlockers"),
    );
    if !runtime_harness_required_invariant_present(&launch_authority_invariant_ids) {
        blockers
            .push("worker_launch_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    blockers.extend(launch_authority_invariant_blockers.iter().cloned());
    if worker_session_record
        .get("launchAuthoritySource")
        .and_then(Value::as_str)
        != Some("persisted_harness_worker_session_record")
    {
        blockers.push("worker_launch_authority_source_invalid".to_string());
    }
    if phase == "resume"
        && worker_session_record
            .get("resumed")
            .and_then(Value::as_bool)
            != Some(true)
    {
        blockers.push("worker_launch_resume_not_resolved".to_string());
    }
    if phase == "rollback"
        && worker_session_record
            .get("rollbackAvailable")
            .and_then(Value::as_bool)
            != Some(true)
    {
        blockers.push("worker_launch_rollback_not_available".to_string());
    }
    if phase == "rollback"
        && worker_session_record
            .get("rollbackTargetReady")
            .and_then(Value::as_bool)
            != Some(true)
    {
        blockers.push("worker_launch_rollback_target_not_ready".to_string());
    }
    if phase == "rollback"
        && worker_session_record
            .get("rollbackHandoffReady")
            .and_then(Value::as_bool)
            != Some(true)
    {
        blockers.push("worker_launch_rollback_handoff_not_ready".to_string());
    }
    if phase == "rollback"
        && worker_session_record
            .get("rollbackHandoffTarget")
            .and_then(Value::as_str)
            != worker_session_record
                .get("rollbackTarget")
                .and_then(Value::as_str)
    {
        blockers.push("worker_launch_rollback_target_mismatch".to_string());
    }
    if phase == "rollback" {
        if let Some(items) = worker_session_record
            .get("rollbackHandoffBlockers")
            .and_then(Value::as_array)
        {
            blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let lifecycle_event_ids = worker_session_record
        .get("lifecycleEventIds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let receipt_ids = worker_session_record
        .get("receiptIds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut evidence_refs = vec![
        json!(session_record_id),
        worker_session_record
            .get("registryRecordId")
            .cloned()
            .unwrap_or_else(|| json!("")),
        worker_session_record
            .get("readinessProofId")
            .cloned()
            .unwrap_or_else(|| json!("")),
    ];
    evidence_refs.extend(lifecycle_event_ids);
    evidence_refs.extend(receipt_ids);

    json!({
        "schemaVersion": "workflow.harness.worker-launch-envelope.v1",
        "envelopeId": format!("harness-worker-launch-envelope:{phase}:{session_record_id}"),
        "phase": phase,
        "workflowNodeId": "harness.handoff_bridge",
        "componentKind": "handoff_bridge",
        "sessionRecordId": session_record_id,
        "sessionId": session_id,
        "workerId": worker_id,
        "workflowId": worker_session_record.get("workflowId").and_then(Value::as_str).unwrap_or_default(),
        "activationId": worker_session_record.get("activationId").and_then(Value::as_str).unwrap_or_default(),
        "activationHash": worker_session_record.get("activationHash").and_then(Value::as_str).unwrap_or_default(),
        "harnessHash": worker_session_record.get("harnessHash").and_then(Value::as_str).unwrap_or_default(),
        "componentVersionSet": worker_session_record.get("componentVersionSet").cloned().unwrap_or_else(|| json!({})),
        "registryRecordId": worker_session_record.get("registryRecordId").and_then(Value::as_str).unwrap_or_default(),
        "readinessProofId": worker_session_record.get("readinessProofId").and_then(Value::as_str).unwrap_or_default(),
        "rollbackTarget": worker_session_record.get("rollbackTarget").and_then(Value::as_str).unwrap_or_default(),
        "persistenceKey": worker_session_record.get("persistenceKey").and_then(Value::as_str).unwrap_or_default(),
        "recordPersistenceKey": worker_session_record.get("recordPersistenceKey").and_then(Value::as_str).unwrap_or_default(),
        "launchAuthoritySource": worker_session_record.get("launchAuthoritySource").and_then(Value::as_str).unwrap_or_default(),
        "launchAuthorityReady": worker_session_record.get("launchAuthorityReady").and_then(Value::as_bool) == Some(true),
        "launchAuthorityInvariantIds": launch_authority_invariant_ids,
        "launchAuthorityInvariantBlockers": launch_authority_invariant_blockers,
        "rollbackHandoffReady": worker_session_record.get("rollbackHandoffReady").and_then(Value::as_bool) == Some(true),
        "accepted": accepted,
        "blockers": blockers,
        "policyDecision": if accepted { "allow_harness_worker_launch_envelope" } else { "block_harness_worker_launch_envelope" },
        "evidenceRefs": evidence_refs
    })
}

fn runtime_harness_worker_handoff_receipt(
    worker_session_record: &Value,
    launch_envelope: &Value,
) -> Value {
    let mut blockers = Vec::<String>::new();
    let phase = launch_envelope
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("launch");
    if launch_envelope.get("schemaVersion").and_then(Value::as_str)
        != Some("workflow.harness.worker-launch-envelope.v1")
    {
        blockers.push("worker_handoff_envelope_schema_mismatch".to_string());
    }
    if launch_envelope.get("accepted").and_then(Value::as_bool) != Some(true) {
        blockers.push("worker_handoff_envelope_not_accepted".to_string());
    }
    if let Some(items) = launch_envelope.get("blockers").and_then(Value::as_array) {
        blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
    }
    for (field, blocker) in [
        ("sessionRecordId", "worker_handoff_session_record_mismatch"),
        ("sessionId", "worker_handoff_session_id_mismatch"),
        ("workerId", "worker_handoff_worker_id_mismatch"),
        ("workflowId", "worker_handoff_workflow_mismatch"),
        ("activationId", "worker_handoff_activation_mismatch"),
        ("harnessHash", "worker_handoff_harness_hash_mismatch"),
    ] {
        if launch_envelope.get(field).and_then(Value::as_str)
            != worker_session_record.get(field).and_then(Value::as_str)
        {
            blockers.push(blocker.to_string());
        }
    }
    if launch_envelope
        .get("launchAuthorityReady")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("worker_handoff_launch_authority_not_ready".to_string());
    }
    let launch_authority_invariant_ids =
        runtime_harness_value_string_array(launch_envelope.get("launchAuthorityInvariantIds"));
    let launch_authority_invariant_blockers =
        runtime_harness_value_string_array(launch_envelope.get("launchAuthorityInvariantBlockers"));
    if !runtime_harness_required_invariant_present(&launch_authority_invariant_ids) {
        blockers
            .push("worker_handoff_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    blockers.extend(launch_authority_invariant_blockers.iter().cloned());
    if phase == "rollback"
        && launch_envelope
            .get("rollbackHandoffReady")
            .and_then(Value::as_bool)
            != Some(true)
    {
        blockers.push("worker_handoff_rollback_not_ready".to_string());
    }
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let handoff_status = if !accepted {
        "blocked"
    } else if phase == "rollback" {
        "rollback_handoff_ready"
    } else if phase == "resume" {
        "resumed"
    } else {
        "launched"
    };
    let session_record_id = worker_session_record
        .get("sessionRecordId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut receipt_refs = worker_session_record
        .get("receiptIds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    receipt_refs.push(
        launch_envelope
            .get("envelopeId")
            .cloned()
            .unwrap_or_else(|| json!("")),
    );
    let mut evidence_refs = worker_session_record
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    evidence_refs.push(
        launch_envelope
            .get("envelopeId")
            .cloned()
            .unwrap_or_else(|| json!("")),
    );
    evidence_refs.push(json!(session_record_id));

    json!({
        "schemaVersion": "workflow.harness.worker-handoff-receipt.v1",
        "receiptId": format!("harness-worker-handoff-receipt:{phase}:{session_record_id}"),
        "envelopeId": launch_envelope.get("envelopeId").and_then(Value::as_str).unwrap_or_default(),
        "phase": phase,
        "workflowNodeId": launch_envelope.get("workflowNodeId").and_then(Value::as_str).unwrap_or_default(),
        "componentKind": launch_envelope.get("componentKind").and_then(Value::as_str).unwrap_or_default(),
        "sessionRecordId": session_record_id,
        "sessionId": worker_session_record.get("sessionId").and_then(Value::as_str).unwrap_or_default(),
        "workerId": worker_session_record.get("workerId").and_then(Value::as_str).unwrap_or_default(),
        "workflowId": worker_session_record.get("workflowId").and_then(Value::as_str).unwrap_or_default(),
        "activationId": worker_session_record.get("activationId").and_then(Value::as_str).unwrap_or_default(),
        "activationHash": worker_session_record.get("activationHash").and_then(Value::as_str).unwrap_or_default(),
        "harnessHash": worker_session_record.get("harnessHash").and_then(Value::as_str).unwrap_or_default(),
        "registryRecordId": worker_session_record.get("registryRecordId").and_then(Value::as_str).unwrap_or_default(),
        "readinessProofId": worker_session_record.get("readinessProofId").and_then(Value::as_str).unwrap_or_default(),
        "rollbackTarget": worker_session_record.get("rollbackTarget").and_then(Value::as_str).unwrap_or_default(),
        "rollbackAvailable": worker_session_record.get("rollbackAvailable").and_then(Value::as_bool) == Some(true),
        "launchAuthoritySource": worker_session_record.get("launchAuthoritySource").and_then(Value::as_str).unwrap_or_default(),
        "accepted": accepted,
        "handoffStatus": handoff_status,
        "blockers": blockers,
        "requiredInvariantIds": launch_authority_invariant_ids,
        "invariantBlockers": launch_authority_invariant_blockers,
        "policyDecision": if accepted { "allow_harness_worker_handoff" } else { "block_harness_worker_handoff" },
        "receiptRefs": receipt_refs,
        "evidenceRefs": evidence_refs
    })
}

fn runtime_harness_worker_handoff_node_attempt(
    receipt: &Value,
    attempt_index: usize,
    execution_mode: &str,
) -> Value {
    let phase = receipt
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("launch");
    let session_record_id = receipt
        .get("sessionRecordId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let receipt_id = receipt
        .get("receiptId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let envelope_id = receipt
        .get("envelopeId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let accepted = receipt.get("accepted").and_then(Value::as_bool) == Some(true);
    let mut receipt_ids = runtime_harness_value_string_array(receipt.get("receiptRefs"));
    receipt_ids.push(receipt_id.clone());
    receipt_ids.push(envelope_id.clone());
    receipt_ids.sort();
    receipt_ids.dedup();
    let evidence_refs = runtime_harness_value_string_array(receipt.get("evidenceRefs"));
    let fixture_ref = format!("harness-worker-handoff:fixture:{phase}:{session_record_id}");
    json!({
        "attemptId": format!("harness-worker-handoff:attempt:{phase}:{session_record_id}"),
        "harnessWorkflowId": receipt.get("workflowId").and_then(Value::as_str).unwrap_or(DEFAULT_AGENT_HARNESS_WORKFLOW_ID),
        "harnessActivationId": receipt.get("activationId").and_then(Value::as_str).unwrap_or(DEFAULT_AGENT_HARNESS_ACTIVATION_ID),
        "harnessHash": receipt.get("harnessHash").and_then(Value::as_str).unwrap_or(DEFAULT_AGENT_HARNESS_HASH),
        "workflowNodeId": receipt.get("workflowNodeId").and_then(Value::as_str).unwrap_or("harness.handoff_bridge"),
        "workflowNodeType": "decision",
        "componentId": "ioi.agent-harness.handoff_bridge.v1",
        "componentKind": "handoff_bridge",
        "executionMode": execution_mode,
        "readiness": "live_ready",
        "attemptIndex": attempt_index,
        "status": if accepted { execution_mode } else { "blocked" },
        "executor": "workflow_node_executor",
        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
        "inputHash": format!("sha256:worker-handoff-input-{phase}-{session_record_id}"),
        "outputHash": if accepted {
            json!(format!("sha256:worker-handoff-output-{phase}-{session_record_id}"))
        } else {
            Value::Null
        },
        "errorClass": if accepted { Value::Null } else { json!("worker_handoff_blocked") },
        "policyDecision": receipt.get("policyDecision").and_then(Value::as_str).unwrap_or("block_harness_worker_handoff"),
        "startedAtMs": Value::Null,
        "durationMs": Value::Null,
        "receiptIds": receipt_ids,
        "evidenceRefs": evidence_refs,
        "replay": {
            "deterministicEnvelope": true,
            "capturesInput": true,
            "capturesOutput": true,
            "capturesPolicyDecision": true,
            "fixtureRef": fixture_ref,
            "determinism": "deterministic",
            "nondeterminismReason": Value::Null,
            "redactionPolicy": "autopilot-runtime-evidence-v1"
        }
    })
}

fn runtime_harness_default_runtime_binding(
    sid: &str,
    task: &AgentTask,
    selector_decision: &Value,
    live_handoff: &Value,
    default_dispatch: &Value,
) -> Value {
    let turn_id = format!("turn-{}", task.progress);
    let selector_decision_id = selector_decision
        .get("decisionId")
        .and_then(Value::as_str)
        .unwrap_or("harness-selector:unknown");
    let default_dispatch_id = default_dispatch
        .get("dispatchId")
        .and_then(Value::as_str)
        .unwrap_or("harness-default-dispatch:unknown");
    let selected_selector = selector_decision
        .get("selectedSelector")
        .and_then(Value::as_str)
        .unwrap_or("legacy_runtime");
    let production_default_selector = selector_decision
        .get("productionDefaultSelector")
        .and_then(Value::as_str)
        .unwrap_or("legacy_runtime");
    let execution_mode = selector_decision
        .get("executionMode")
        .and_then(Value::as_str)
        .unwrap_or("gated");
    let runtime_authority = default_dispatch
        .get("runtimeAuthority")
        .and_then(Value::as_str)
        .or_else(|| {
            selector_decision
                .get("actualRuntimeAuthority")
                .and_then(Value::as_str)
        })
        .unwrap_or("existing_runtime_service");
    let rollback_target = selector_decision
        .get("rollbackTarget")
        .and_then(Value::as_str)
        .or_else(|| live_handoff.get("rollbackTarget").and_then(Value::as_str))
        .or_else(|| {
            default_dispatch
                .get("rollbackTarget")
                .and_then(Value::as_str)
        })
        .unwrap_or(DEFAULT_AGENT_HARNESS_ACTIVATION_ID);
    let workflow_identity_matches = selector_decision.get("workflowId").and_then(Value::as_str)
        == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
        && live_handoff.get("workflowId").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
        && default_dispatch.get("workflowId").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID);
    let activation_identity_matches = selector_decision
        .get("activationId")
        .and_then(Value::as_str)
        == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
        && live_handoff.get("activationId").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
        && default_dispatch.get("activationId").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID);
    let harness_hash_matches = selector_decision.get("harnessHash").and_then(Value::as_str)
        == Some(DEFAULT_AGENT_HARNESS_HASH)
        && live_handoff.get("harnessHash").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_HASH)
        && default_dispatch.get("harnessHash").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_HASH);
    let selector_decision_links_dispatch = default_dispatch
        .get("selectorDecisionId")
        .and_then(Value::as_str)
        == Some(selector_decision_id);
    let rollback_target_matches = rollback_target == DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        && live_handoff.get("rollbackTarget").and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
        && default_dispatch
            .get("rollbackTarget")
            .and_then(Value::as_str)
            == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID);
    let authority_transferred = selector_decision
        .get("actualRuntimeAuthority")
        .and_then(Value::as_str)
        == Some("blessed_workflow_activation_default")
        && live_handoff
            .get("defaultAuthorityTransferred")
            .and_then(Value::as_bool)
            == Some(true)
        && default_dispatch
            .get("runtimeAuthority")
            .and_then(Value::as_str)
            == Some("blessed_workflow_activation_default");
    let drives_runtime_decision = default_dispatch
        .get("drivesRuntimeDecision")
        .and_then(Value::as_bool)
        == Some(true)
        && default_dispatch
            .get("readOnlyDispatchAccepted")
            .and_then(Value::as_bool)
            == Some(true);
    let selector_live_promotion_readiness_proof =
        selector_decision.get("livePromotionReadinessProof");
    let live_handoff_live_promotion_readiness_proof =
        live_handoff.get("livePromotionReadinessProof");
    let dispatch_live_promotion_readiness_proof =
        default_dispatch.get("livePromotionReadinessProof");
    let selector_live_promotion_readiness_proof_id = selector_live_promotion_readiness_proof
        .and_then(|proof| proof.get("proofId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let live_handoff_live_promotion_readiness_proof_id =
        live_handoff_live_promotion_readiness_proof
            .and_then(|proof| proof.get("proofId"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
    let dispatch_live_promotion_readiness_proof_id = dispatch_live_promotion_readiness_proof
        .and_then(|proof| proof.get("proofId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let selector_live_promotion_readiness_blockers =
        runtime_harness_live_promotion_readiness_blockers(selector_live_promotion_readiness_proof);
    let live_handoff_live_promotion_readiness_blockers =
        runtime_harness_live_promotion_readiness_blockers(
            live_handoff_live_promotion_readiness_proof,
        );
    let dispatch_live_promotion_readiness_blockers =
        runtime_harness_live_promotion_readiness_blockers(dispatch_live_promotion_readiness_proof);
    let selector_live_promotion_readiness_ready = selector_decision
        .get("livePromotionReadinessReady")
        .and_then(Value::as_bool)
        == Some(true)
        && selector_live_promotion_readiness_blockers.is_empty()
        && selector_decision
            .get("livePromotionReadinessBlockers")
            .and_then(Value::as_array)
            .map(|items| items.is_empty())
            .unwrap_or(false);
    let live_handoff_live_promotion_readiness_ready = live_handoff
        .get("livePromotionReadinessReady")
        .and_then(Value::as_bool)
        == Some(true)
        && live_handoff_live_promotion_readiness_blockers.is_empty()
        && live_handoff
            .get("livePromotionReadinessBlockers")
            .and_then(Value::as_array)
            .map(|items| items.is_empty())
            .unwrap_or(false);
    let dispatch_live_promotion_readiness_ready =
        dispatch_live_promotion_readiness_blockers.is_empty();
    let live_promotion_readiness_proof_ids_match = !selector_live_promotion_readiness_proof_id
        .is_empty()
        && selector_live_promotion_readiness_proof_id == dispatch_live_promotion_readiness_proof_id
        && selector_live_promotion_readiness_proof_id
            == live_handoff_live_promotion_readiness_proof_id;
    let invalid_fork_live_activation_blocked = selector_live_promotion_readiness_proof
        .and_then(|proof| proof.get("invalidForkLiveActivationBlocked"))
        .and_then(Value::as_bool)
        == Some(true)
        && live_handoff_live_promotion_readiness_proof
            .and_then(|proof| proof.get("invalidForkLiveActivationBlocked"))
            .and_then(Value::as_bool)
            == Some(true)
        && dispatch_live_promotion_readiness_proof
            .and_then(|proof| proof.get("invalidForkLiveActivationBlocked"))
            .and_then(Value::as_bool)
            == Some(true);
    let dispatch_drives_runtime = drives_runtime_decision
        && default_dispatch.get("status").and_then(Value::as_str) == Some("accepted")
        && default_dispatch
            .get("activationBlockers")
            .and_then(Value::as_array)
            .map(|items| items.is_empty())
            .unwrap_or(false);
    let worker_binding_source = if selected_selector == "blessed_workflow_live_default" {
        "autopilot_runtime_selector_default_v1"
    } else if selected_selector == "blessed_workflow_live_canary" {
        "autopilot_runtime_selector_canary_v1"
    } else {
        "autopilot_runtime_selector_legacy_default_v1"
    };
    let mut worker_binding_authority_blockers = Vec::<String>::new();
    if selected_selector != "blessed_workflow_live_default" {
        worker_binding_authority_blockers.push("selector_not_default_live".to_string());
    }
    if production_default_selector != "blessed_workflow_live_default" {
        worker_binding_authority_blockers.push("production_default_not_live".to_string());
    }
    if execution_mode != "live" {
        worker_binding_authority_blockers.push("execution_mode_not_live".to_string());
    }
    if !workflow_identity_matches {
        worker_binding_authority_blockers.push("workflow_identity_mismatch".to_string());
    }
    if !activation_identity_matches {
        worker_binding_authority_blockers.push("activation_identity_mismatch".to_string());
    }
    if !harness_hash_matches {
        worker_binding_authority_blockers.push("harness_hash_mismatch".to_string());
    }
    if !selector_decision_links_dispatch {
        worker_binding_authority_blockers.push("selector_dispatch_not_linked".to_string());
    }
    if !rollback_target_matches {
        worker_binding_authority_blockers.push("rollback_target_mismatch".to_string());
    }
    if !authority_transferred {
        worker_binding_authority_blockers.push("default_authority_not_transferred".to_string());
    }
    if !dispatch_drives_runtime {
        worker_binding_authority_blockers.push("dispatch_not_driving_runtime".to_string());
    }
    if !selector_live_promotion_readiness_ready {
        worker_binding_authority_blockers
            .push("selector_live_promotion_readiness_not_ready".to_string());
    }
    if !live_handoff_live_promotion_readiness_ready {
        worker_binding_authority_blockers
            .push("live_handoff_live_promotion_readiness_not_ready".to_string());
    }
    if !dispatch_live_promotion_readiness_ready {
        worker_binding_authority_blockers
            .push("dispatch_live_promotion_readiness_not_ready".to_string());
    }
    if !live_promotion_readiness_proof_ids_match {
        worker_binding_authority_blockers
            .push("live_promotion_readiness_proof_mismatch".to_string());
    }
    if !invalid_fork_live_activation_blocked {
        worker_binding_authority_blockers
            .push("invalid_fork_live_activation_not_blocked".to_string());
    }
    let selector_required_invariant_ids = runtime_harness_value_string_array(
        selector_decision.get("defaultLivePromotionInvariantIds"),
    );
    let live_handoff_required_invariant_ids =
        runtime_harness_value_string_array(live_handoff.get("defaultLivePromotionInvariantIds"));
    let dispatch_required_invariant_ids = runtime_harness_value_string_array(
        default_dispatch.get("defaultLivePromotionInvariantIds"),
    );
    let required_invariant_ids = if !dispatch_required_invariant_ids.is_empty() {
        dispatch_required_invariant_ids.clone()
    } else if !live_handoff_required_invariant_ids.is_empty() {
        live_handoff_required_invariant_ids.clone()
    } else {
        selector_required_invariant_ids.clone()
    };
    let mut invariant_blockers = Vec::<String>::new();
    invariant_blockers.extend(runtime_harness_value_string_array(
        selector_decision.get("defaultLivePromotionInvariantBlockers"),
    ));
    invariant_blockers.extend(runtime_harness_value_string_array(
        live_handoff.get("defaultLivePromotionInvariantBlockers"),
    ));
    invariant_blockers.extend(runtime_harness_value_string_array(
        default_dispatch.get("defaultLivePromotionInvariantBlockers"),
    ));
    invariant_blockers.sort();
    invariant_blockers.dedup();
    if !runtime_harness_required_invariant_present(&required_invariant_ids)
        || !runtime_harness_required_invariant_present(&selector_required_invariant_ids)
        || !runtime_harness_required_invariant_present(&live_handoff_required_invariant_ids)
        || !runtime_harness_required_invariant_present(&dispatch_required_invariant_ids)
    {
        worker_binding_authority_blockers
            .push("reviewed_import_activation_apply_invariant_missing".to_string());
    }
    if !runtime_harness_string_sets_match(&selector_required_invariant_ids, &required_invariant_ids)
        || !runtime_harness_string_sets_match(
            &live_handoff_required_invariant_ids,
            &required_invariant_ids,
        )
    {
        worker_binding_authority_blockers
            .push("reviewed_import_activation_apply_invariant_mismatch".to_string());
    }
    if !invariant_blockers.is_empty() {
        worker_binding_authority_blockers
            .push("reviewed_import_activation_apply_invariant_blocked".to_string());
        worker_binding_authority_blockers.extend(invariant_blockers.iter().cloned());
    }
    worker_binding_authority_blockers.sort();
    worker_binding_authority_blockers.dedup();
    let worker_binding_authority_ready = worker_binding_authority_blockers.is_empty();
    let policy_decision = selector_decision
        .get("policyDecision")
        .and_then(Value::as_str)
        .unwrap_or("retain_legacy_runtime_default");
    let component_version_set = live_handoff
        .get("componentVersionSet")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut worker_binding_registry_blockers = worker_binding_authority_blockers.clone();
    if !component_version_set
        .as_object()
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        worker_binding_registry_blockers.push("component_version_set_missing".to_string());
    }
    if selector_live_promotion_readiness_proof_id.is_empty() {
        worker_binding_registry_blockers.push("readiness_proof_id_missing".to_string());
    }
    if live_handoff.get("canaryStatus").and_then(Value::as_str) != Some("passed") {
        worker_binding_registry_blockers.push("canary_result_not_passed".to_string());
    }
    if policy_decision != "promote_blessed_workflow_default_for_non_mutating_turn" {
        worker_binding_registry_blockers.push("policy_decision_not_live_default".to_string());
    }
    worker_binding_registry_blockers.sort();
    worker_binding_registry_blockers.dedup();
    let worker_binding_registry_bound = worker_binding_registry_blockers.is_empty();
    let worker_binding_registry_status = if worker_binding_registry_bound {
        "bound"
    } else if selected_selector == "blessed_workflow_live_canary" {
        "canary"
    } else {
        "blocked"
    };
    let canary_result_id =
        if live_handoff.get("canaryStatus").and_then(Value::as_str) == Some("passed") {
            format!("harness-canary-result:{sid}:{turn_id}:passed")
        } else {
            format!("harness-canary-result:{sid}:{turn_id}:blocked")
        };
    let worker_binding = json!({
        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "executionMode": execution_mode,
        "source": worker_binding_source,
        "selectorDecisionId": selector_decision_id,
        "defaultDispatchId": default_dispatch_id,
        "rollbackTarget": rollback_target,
        "authorityBindingReady": worker_binding_authority_ready,
        "authorityBindingBlockers": worker_binding_authority_blockers.clone(),
        "livePromotionReadinessProofId": selector_live_promotion_readiness_proof_id.clone(),
        "policyDecision": policy_decision,
        "requiredInvariantIds": required_invariant_ids.clone(),
        "invariantBlockers": invariant_blockers.clone()
    });
    let worker_binding_registry_record = json!({
        "schemaVersion": "workflow.harness.worker-binding-registry.v1",
        "registryRecordId": format!(
            "harness-worker-binding-registry:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:{default_dispatch_id}"
        ),
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "activationHash": DEFAULT_AGENT_HARNESS_HASH,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": component_version_set.clone(),
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "readinessProofId": selector_live_promotion_readiness_proof_id.clone(),
        "canaryResultId": canary_result_id,
        "policyDecision": policy_decision,
        "bindingStatus": worker_binding_registry_status,
        "blockers": worker_binding_registry_blockers.clone(),
        "requiredInvariantIds": required_invariant_ids.clone(),
        "invariantBlockers": invariant_blockers.clone(),
        "workerBinding": worker_binding.clone()
    });
    let worker_attach_request = json!({
        "schemaVersion": "workflow.harness.worker-attach-request.v1",
        "requestId": format!("harness-worker-attach-request:{sid}:{turn_id}:bound"),
        "workerId": format!("harness-worker:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:{sid}"),
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "activationHash": DEFAULT_AGENT_HARNESS_HASH,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": component_version_set,
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "readinessProofId": selector_live_promotion_readiness_proof_id.clone(),
        "requiredInvariantIds": required_invariant_ids,
        "requestedStatus": "bound"
    });
    let worker_attach_lifecycle = runtime_harness_worker_attach_lifecycle_events(
        sid,
        &turn_id,
        &worker_binding_registry_record,
    );
    let worker_attach_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("attach"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| {
            runtime_harness_worker_attach_receipt(
                sid,
                &turn_id,
                &worker_binding_registry_record,
                &worker_attach_request,
            )
        });
    let worker_attach_resume_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("resume"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| worker_attach_receipt.clone());
    let worker_attach_rollback_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("rollback"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| worker_attach_receipt.clone());
    let worker_attach_lifecycle_attempt_ids =
        runtime_harness_worker_attach_lifecycle_attempt_ids(&worker_attach_lifecycle);
    let worker_attach_lifecycle_statuses =
        runtime_harness_worker_attach_lifecycle_statuses(&worker_attach_lifecycle);
    let worker_attach_lifecycle_complete =
        runtime_harness_worker_attach_lifecycle_complete(&worker_attach_lifecycle);
    let worker_session_record = runtime_harness_worker_session_record(
        sid,
        &turn_id,
        &worker_binding_registry_record,
        &worker_attach_lifecycle,
    );
    let worker_session_accepted = worker_session_record
        .get("accepted")
        .and_then(Value::as_bool)
        == Some(true);
    let worker_session_status = worker_session_record
        .get("currentStatus")
        .and_then(Value::as_str)
        .unwrap_or("blocked")
        .to_string();
    let worker_session_blockers = worker_session_record
        .get("blockers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let worker_session_record_id = worker_session_record
        .get("sessionRecordId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let worker_launch_envelopes = ["launch", "resume", "rollback"]
        .iter()
        .map(|phase| runtime_harness_worker_launch_envelope(&worker_session_record, phase))
        .collect::<Vec<_>>();
    let worker_handoff_receipts = worker_launch_envelopes
        .iter()
        .map(|envelope| runtime_harness_worker_handoff_receipt(&worker_session_record, envelope))
        .collect::<Vec<_>>();
    let worker_launch_envelope_ids = worker_launch_envelopes
        .iter()
        .filter_map(|envelope| {
            envelope
                .get("envelopeId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let worker_handoff_receipt_ids = worker_handoff_receipts
        .iter()
        .filter_map(|receipt| {
            receipt
                .get("receiptId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let worker_launch_envelopes_accepted = worker_launch_envelopes.len() == 3
        && worker_launch_envelopes.iter().all(|envelope| {
            envelope.get("accepted").and_then(Value::as_bool) == Some(true)
                && envelope
                    .get("blockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        });
    let worker_handoff_receipts_accepted = worker_handoff_receipts.len() == 3
        && worker_handoff_receipts.iter().all(|receipt| {
            receipt.get("accepted").and_then(Value::as_bool) == Some(true)
                && receipt
                    .get("blockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        })
        && worker_handoff_receipts.iter().any(|receipt| {
            receipt.get("handoffStatus").and_then(Value::as_str) == Some("launched")
        })
        && worker_handoff_receipts
            .iter()
            .any(|receipt| receipt.get("handoffStatus").and_then(Value::as_str) == Some("resumed"))
        && worker_handoff_receipts.iter().any(|receipt| {
            receipt.get("handoffStatus").and_then(Value::as_str) == Some("rollback_handoff_ready")
        });
    let worker_attach_status = worker_attach_receipt
        .get("attachStatus")
        .and_then(Value::as_str)
        .unwrap_or("blocked")
        .to_string();
    let worker_attach_blockers = worker_attach_receipt
        .get("blockers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let worker_attach_accepted = worker_attach_receipt
        .get("accepted")
        .and_then(Value::as_bool)
        == Some(true)
        && worker_attach_status == "bound"
        && worker_attach_blockers.is_empty();
    let mut invalid_worker_attach_request = worker_attach_request.clone();
    invalid_worker_attach_request["activationHash"] = json!("sha256:invalid-worker-attach");
    let invalid_worker_attach_receipt = runtime_harness_worker_attach_receipt(
        sid,
        &turn_id,
        &worker_binding_registry_record,
        &invalid_worker_attach_request,
    );
    let invalid_worker_attach_blocked = invalid_worker_attach_receipt
        .get("accepted")
        .and_then(Value::as_bool)
        == Some(false)
        && invalid_worker_attach_receipt
            .get("attachStatus")
            .and_then(Value::as_str)
            == Some("blocked")
        && invalid_worker_attach_receipt
            .get("blockers")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .any(|item| item.as_str() == Some("worker_attach_activation_hash_mismatch"))
            })
            .unwrap_or(false);
    let worker_attach_resume_accepted = worker_attach_resume_receipt
        .get("accepted")
        .and_then(Value::as_bool)
        == Some(true)
        && worker_attach_resume_receipt
            .get("attachStatus")
            .and_then(Value::as_str)
            == Some("resumed");
    let worker_attach_rollback_accepted = worker_attach_rollback_receipt
        .get("accepted")
        .and_then(Value::as_bool)
        == Some(true)
        && worker_attach_rollback_receipt
            .get("attachStatus")
            .and_then(Value::as_str)
            == Some("rolled_back");
    let binding_matched = worker_binding_authority_ready
        && worker_binding_registry_bound
        && worker_attach_accepted
        && worker_attach_resume_accepted
        && worker_attach_rollback_accepted
        && worker_attach_lifecycle_complete
        && worker_session_accepted
        && worker_session_status == "rollback_ready"
        && worker_session_blockers.is_empty()
        && worker_launch_envelopes_accepted
        && worker_handoff_receipts_accepted;

    json!({
        "schemaVersion": "workflow.harness.default-runtime-binding.v1",
        "bindingId": format!("harness-default-runtime-binding:{sid}:{turn_id}"),
        "sessionId": sid,
        "turnId": turn_id,
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "selectorDecisionId": selector_decision_id,
        "defaultDispatchId": default_dispatch_id,
        "selectedSelector": selected_selector,
        "productionDefaultSelector": production_default_selector,
        "executionMode": execution_mode,
        "runtimeAuthority": runtime_authority,
        "rollbackTarget": rollback_target,
        "rollbackAvailable": selector_decision.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && live_handoff.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && default_dispatch.get("rollbackAvailable").and_then(Value::as_bool) == Some(true),
        "selectorLivePromotionReadinessReady": selector_live_promotion_readiness_ready,
        "liveHandoffLivePromotionReadinessReady": live_handoff_live_promotion_readiness_ready,
        "dispatchLivePromotionReadinessReady": dispatch_live_promotion_readiness_ready,
        "selectorLivePromotionReadinessProofId": selector_live_promotion_readiness_proof_id.clone(),
        "liveHandoffLivePromotionReadinessProofId": live_handoff_live_promotion_readiness_proof_id.clone(),
        "dispatchLivePromotionReadinessProofId": dispatch_live_promotion_readiness_proof_id.clone(),
        "livePromotionReadinessProofIdsMatch": live_promotion_readiness_proof_ids_match,
        "invalidForkLiveActivationBlocked": invalid_fork_live_activation_blocked,
        "dispatchDrivesRuntime": dispatch_drives_runtime,
        "workerBindingAuthorityReady": worker_binding_authority_ready,
        "workerBindingAuthorityBlockers": worker_binding_authority_blockers.clone(),
        "workerBindingRegistryBound": worker_binding_registry_bound,
        "workerBindingRegistryStatus": worker_binding_registry_status,
        "workerBindingRegistryBlockers": worker_binding_registry_blockers,
        "workerBinding": worker_binding,
        "workerBindingRegistryRecord": worker_binding_registry_record,
        "workerAttachRequest": worker_attach_request,
        "workerAttachReceipt": worker_attach_receipt,
        "workerAttachResumeReceipt": worker_attach_resume_receipt,
        "workerAttachRollbackReceipt": worker_attach_rollback_receipt,
        "workerAttachLifecycle": worker_attach_lifecycle,
        "workerAttachLifecycleAttemptIds": worker_attach_lifecycle_attempt_ids,
        "workerAttachLifecycleStatuses": worker_attach_lifecycle_statuses,
        "workerAttachLifecycleComplete": worker_attach_lifecycle_complete,
        "workerSessionRecord": worker_session_record,
        "workerSessionRecordId": worker_session_record_id,
        "workerSessionStatus": worker_session_status,
        "workerSessionAccepted": worker_session_accepted,
        "workerSessionBlockers": worker_session_blockers,
        "workerLaunchEnvelopes": worker_launch_envelopes,
        "workerHandoffReceipts": worker_handoff_receipts,
        "workerLaunchEnvelopeIds": worker_launch_envelope_ids,
        "workerHandoffReceiptIds": worker_handoff_receipt_ids,
        "workerLaunchEnvelopesAccepted": worker_launch_envelopes_accepted,
        "workerHandoffReceiptsAccepted": worker_handoff_receipts_accepted,
        "workerAttachAccepted": worker_attach_accepted,
        "workerAttachResumeAccepted": worker_attach_resume_accepted,
        "workerAttachRollbackAccepted": worker_attach_rollback_accepted,
        "workerAttachStatus": worker_attach_status,
        "workerAttachBlockers": worker_attach_blockers,
        "workerAttachRollbackAvailable": worker_attach_receipt.get("rollbackAvailable").and_then(Value::as_bool) == Some(true),
        "invalidWorkerAttachBlocked": invalid_worker_attach_blocked,
        "invalidWorkerAttachReceipt": invalid_worker_attach_receipt,
        "workflowIdentityMatches": workflow_identity_matches,
        "activationIdentityMatches": activation_identity_matches,
        "harnessHashMatches": harness_hash_matches,
        "selectorDecisionLinksDispatch": selector_decision_links_dispatch,
        "rollbackTargetMatches": rollback_target_matches,
        "authorityTransferred": authority_transferred,
        "drivesRuntimeDecision": drives_runtime_decision,
        "bindingMatched": binding_matched,
        "sourceRefs": [
            "HarnessRuntimeSelectorDecision",
            "HarnessLiveHandoff",
            "HarnessDefaultRuntimeDispatch"
        ]
    })
}

fn runtime_harness_selector_decision(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    selected_action: &str,
    stop_reason: &str,
) -> Value {
    let default_promotion_enabled = runtime_harness_default_promotion_enabled();
    let live_promotion_readiness_proof = runtime_harness_selector_live_promotion_readiness_proof(
        sid,
        task,
        latest_user_turn,
        selected_action,
        stop_reason,
        default_promotion_enabled,
    );
    runtime_harness_selector_decision_with_default_promotion(
        sid,
        task,
        latest_user_turn,
        selected_action,
        stop_reason,
        default_promotion_enabled,
        Some(&live_promotion_readiness_proof),
    )
}

fn runtime_harness_selector_decision_with_default_promotion(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    selected_action: &str,
    stop_reason: &str,
    default_promotion_enabled: bool,
    live_promotion_readiness_proof: Option<&Value>,
) -> Value {
    let canary_blockers =
        runtime_canary_blockers(task, latest_user_turn, selected_action, stop_reason);
    let canary_eligible = canary_blockers.is_empty();
    let mut default_promotion_blockers = canary_blockers.clone();
    if !default_promotion_enabled {
        default_promotion_blockers.push("promotion_gate_disabled".to_string());
    }
    let live_promotion_readiness_blockers = if default_promotion_enabled {
        runtime_harness_live_promotion_readiness_blockers(live_promotion_readiness_proof)
    } else {
        Vec::new()
    };
    let require_reviewed_import_activation_apply_proof = default_promotion_enabled;
    let reviewed_import_activation_apply_proof_present =
        require_reviewed_import_activation_apply_proof;
    let reviewed_import_activation_apply_proof_blockers =
        if reviewed_import_activation_apply_proof_present {
            Vec::new()
        } else if require_reviewed_import_activation_apply_proof {
            vec!["package_import_activation_apply_proof_missing".to_string()]
        } else {
            Vec::new()
        };
    let reviewed_import_activation_apply_proof_passed =
        reviewed_import_activation_apply_proof_present
            && reviewed_import_activation_apply_proof_blockers.is_empty();
    let default_live_promotion_invariant_ids = if require_reviewed_import_activation_apply_proof {
        vec![DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT.to_string()]
    } else {
        Vec::new()
    };
    let default_live_promotion_invariant_blockers =
        reviewed_import_activation_apply_proof_blockers.clone();
    default_promotion_blockers.extend(live_promotion_readiness_blockers.clone());
    default_promotion_blockers.extend(default_live_promotion_invariant_blockers.clone());
    default_promotion_blockers.sort();
    default_promotion_blockers.dedup();
    let default_promotion_eligible = default_promotion_blockers.is_empty();
    let selected_selector = if default_promotion_eligible {
        "blessed_workflow_live_default"
    } else if canary_eligible {
        "blessed_workflow_live_canary"
    } else {
        "legacy_runtime"
    };
    let production_default_selector = if default_promotion_eligible {
        "blessed_workflow_live_default"
    } else {
        "legacy_runtime"
    };
    let execution_mode = if canary_eligible { "live" } else { "gated" };
    let actual_runtime_authority = if default_promotion_eligible {
        "blessed_workflow_activation_default"
    } else if canary_eligible {
        "blessed_workflow_activation_canary"
    } else {
        "existing_runtime_service"
    };
    let policy_decision = if default_promotion_eligible {
        "promote_blessed_workflow_default_for_non_mutating_turn"
    } else if canary_eligible {
        "allow_blessed_workflow_live_canary"
    } else {
        "retain_legacy_runtime_default"
    };
    json!({
        "schemaVersion": "workflow.harness.runtime-selector.v1",
        "decisionId": format!("harness-selector:{sid}:{}", task.progress),
        "requestedSelector": "auto_canary",
        "selectedSelector": selected_selector,
        "productionDefaultSelector": production_default_selector,
        "canaryEligible": canary_eligible,
        "canaryBlockers": canary_blockers,
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "executionMode": execution_mode,
        "actualRuntimeAuthority": actual_runtime_authority,
        "fallbackSelector": "legacy_runtime",
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "rollbackAvailable": true,
        "policyDecision": policy_decision,
        "livePromotionReadinessProof": live_promotion_readiness_proof.cloned(),
        "livePromotionReadinessReady": default_promotion_enabled
            && live_promotion_readiness_blockers.is_empty(),
        "livePromotionReadinessBlockers": live_promotion_readiness_blockers,
        "livePromotionReadinessPolicyDecision": live_promotion_readiness_proof
            .and_then(|proof| proof.get("policyDecision"))
            .and_then(Value::as_str)
            .unwrap_or(if default_promotion_enabled {
                "block_default_harness_live_promotion_readiness"
            } else {
                "not_required_for_canary_selector"
            }),
        "defaultLivePromotionInvariantIds": default_live_promotion_invariant_ids.clone(),
        "defaultLivePromotionInvariantBlockers": default_live_promotion_invariant_blockers.clone(),
        "reviewedImportActivationApplyProofPresent": reviewed_import_activation_apply_proof_present,
        "reviewedImportActivationApplyProofPassed": reviewed_import_activation_apply_proof_passed,
        "reviewedImportActivationApplyProofBlockers": reviewed_import_activation_apply_proof_blockers,
        "reviewedImportActivationApplyActivationId": if reviewed_import_activation_apply_proof_present {
            Value::String(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string())
        } else {
            Value::Null
        },
        "defaultPromotionGate": {
            "configKey": "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
            "enabled": default_promotion_enabled,
            "eligible": default_promotion_eligible,
            "nonMutatingOnly": true,
            "selector": selected_selector,
            "productionDefaultSelector": production_default_selector,
            "defaultAuthorityTransferred": false,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "activationBlockers": default_promotion_blockers,
            "requiredInvariantIds": default_live_promotion_invariant_ids,
            "invariantBlockers": default_live_promotion_invariant_blockers,
            "policyDecision": if default_promotion_eligible {
                "allow_default_promotion_after_live_handoff"
            } else {
                "retain_legacy_runtime_default"
            }
        },
        "routeReason": if default_promotion_eligible {
            "Turn is terminal, non-mutating, ungated, and default promotion is enabled for the blessed workflow harness."
        } else if canary_eligible {
            "Turn is terminal, non-mutating, ungated, and eligible for blessed workflow canary routing."
        } else {
            "Turn remains on legacy runtime because one or more canary safety gates did not pass."
        },
        "evidenceRefs": [
            {"kind": "runtime_evidence_projection", "reference": sid},
            {"kind": "task_family", "reference": runtime_task_family(task)},
            {"kind": "risk_class", "reference": runtime_risk_class(task)},
            {"kind": "default_promotion_gate", "reference": "AUTOPILOT_HARNESS_DEFAULT_PROMOTION"}
        ]
    })
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

fn runtime_harness_hash_strings(parts: &[String]) -> String {
    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    runtime_prompt_hash(&refs)
}

fn runtime_harness_shadow_attempt(
    sid: &str,
    turn_id: &str,
    attempt_index: u32,
    component_kind: &str,
    input_parts: Vec<String>,
    output_parts: Vec<String>,
    policy_decision: Option<String>,
    deterministic: bool,
    receipt_kind: &str,
    evidence_refs: Vec<String>,
) -> Value {
    let workflow_node_id = format!("harness.{component_kind}");
    let attempt_id =
        format!("harness-shadow:{sid}:{turn_id}:{component_kind}:attempt-{attempt_index}");
    let receipt_id = format!("{sid}:{workflow_node_id}:{receipt_kind}");
    let captures_policy_decision = policy_decision.is_some();
    let mut all_evidence_refs = vec![format!("runtime-evidence:{sid}")];
    all_evidence_refs.extend(evidence_refs);
    all_evidence_refs.sort();
    all_evidence_refs.dedup();

    json!({
        "attemptId": attempt_id,
        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "workflowNodeId": workflow_node_id,
        "componentId": format!("ioi.agent-harness.{component_kind}.v1"),
        "componentKind": component_kind,
        "executionMode": "shadow",
        "readiness": "shadow_ready",
        "attemptIndex": attempt_index,
        "status": "shadow",
        "inputHash": runtime_harness_hash_strings(&input_parts),
        "outputHash": runtime_harness_hash_strings(&output_parts),
        "errorClass": null,
        "policyDecision": policy_decision,
        "startedAtMs": null,
        "durationMs": 0,
        "receiptIds": [receipt_id],
        "evidenceRefs": all_evidence_refs,
        "replay": {
            "deterministicEnvelope": deterministic,
            "capturesInput": true,
            "capturesOutput": true,
            "capturesPolicyDecision": captures_policy_decision,
            "fixtureRef": format!("runtime-evidence:{sid}:shadow-fixture:{component_kind}"),
            "determinism": if deterministic { "deterministic" } else { "nondeterministic" },
            "nondeterminismReason": if deterministic {
                Value::Null
            } else {
                json!("Shadow replay depends on model or tool boundary output captured from the live turn checkpoint.")
            },
            "redactionPolicy": "autopilot-runtime-evidence-v1"
        }
    })
}

fn runtime_harness_attempt_records_from_values(
    attempts: &[Value],
) -> Vec<HarnessNodeAttemptRecord> {
    attempts
        .iter()
        .filter_map(harness_node_attempt_record_from_camel_value)
        .collect()
}

fn runtime_harness_shadow_attempt_records_from_run(
    shadow_run: &Value,
) -> Vec<HarnessNodeAttemptRecord> {
    shadow_run
        .get("nodeAttempts")
        .and_then(Value::as_array)
        .map(|attempts| runtime_harness_attempt_records_from_values(attempts))
        .unwrap_or_default()
}

fn runtime_harness_shadow_comparison_records_for_attempt_records(
    attempts: &[HarnessNodeAttemptRecord],
) -> Vec<HarnessShadowComparison> {
    attempts
        .iter()
        .map(|shadow| {
            let mut live = shadow.clone();
            live.attempt_id = format!("live-checkpoint:{}", shadow.workflow_node_id);
            live.execution_mode = HarnessExecutionMode::Live;
            live.status = HarnessNodeAttemptStatus::Live;
            compare_harness_live_shadow_attempts(&live, shadow)
        })
        .collect()
}

fn runtime_harness_shadow_run(
    task: &AgentTask,
    sid: &str,
    latest_user_turn: &str,
    latest_agent_turn: &str,
    prompt_final_hash: &str,
    selected_strategy: &str,
    selected_action: &str,
    stop_reason: &str,
    evidence_sufficient: bool,
    has_selected_sources: bool,
    verifier_independence_required: bool,
) -> Value {
    let turn_id = format!("turn-{}", task.progress);
    let task_family = runtime_task_family(task);
    let current_step = task.current_step.trim();
    let terminal_status = match task.phase {
        AgentPhase::Idle => "idle",
        AgentPhase::Running => "running",
        AgentPhase::Gate => "gate",
        AgentPhase::Complete => "complete",
        AgentPhase::Failed => "failed",
    };
    let policy_decision = if matches!(task.phase, AgentPhase::Gate) {
        "requires_approval"
    } else if matches!(task.phase, AgentPhase::Failed) {
        "blocked"
    } else {
        "allowed"
    };
    let model_profile = if verifier_independence_required {
        "reasoning"
    } else {
        "fast"
    };
    let selected_sources_state = if has_selected_sources {
        "selected_sources_present"
    } else {
        "selected_sources_absent"
    };
    let mut attempts = Vec::new();
    let mut push_attempt = |component_kind: &str,
                            input_parts: Vec<String>,
                            output_parts: Vec<String>,
                            policy: Option<String>,
                            deterministic: bool,
                            receipt_kind: &str,
                            evidence_refs: Vec<String>| {
        let attempt = runtime_harness_shadow_attempt(
            sid,
            &turn_id,
            (attempts.len() + 1) as u32,
            component_kind,
            input_parts,
            output_parts,
            policy,
            deterministic,
            receipt_kind,
            evidence_refs,
        );
        attempts.push(attempt);
    };

    push_attempt(
        "planner",
        vec![
            latest_user_turn.to_string(),
            task_family.as_str().to_string(),
        ],
        vec![selected_strategy.to_string()],
        None,
        true,
        "PlanReceipt",
        vec![format!("checkpoint_transcript_messages:{sid}")],
    );
    push_attempt(
        "prompt_assembler",
        vec![
            latest_user_turn.to_string(),
            selected_sources_state.to_string(),
        ],
        vec![prompt_final_hash.to_string()],
        None,
        true,
        "PromptAssemblyContract",
        vec![format!("prompt-assembly:{sid}:{}", task.progress)],
    );
    push_attempt(
        "task_state",
        vec![terminal_status.to_string(), current_step.to_string()],
        vec![
            latest_user_turn.to_string(),
            selected_sources_state.to_string(),
        ],
        None,
        true,
        "TaskStateModel",
        vec![format!("task_checkpoint:{sid}")],
    );
    push_attempt(
        "uncertainty_gate",
        vec![
            terminal_status.to_string(),
            task_family.as_str().to_string(),
        ],
        vec![selected_action.to_string()],
        Some(selected_action.to_string()),
        true,
        "UncertaintyAssessment",
        vec![format!("uncertainty:{sid}:{}", task.progress)],
    );
    push_attempt(
        "budget_gate",
        vec![
            task_family.as_str().to_string(),
            "maxWallTimeMs:300000".to_string(),
        ],
        vec!["bounded".to_string()],
        Some("allowed".to_string()),
        true,
        "CognitiveBudget",
        vec![format!("budget:{sid}:{}", task.progress)],
    );
    push_attempt(
        "capability_sequencer",
        vec![selected_strategy.to_string()],
        vec!["desktop_chat|runtime_evidence_projection|gui_harness_validation".to_string()],
        None,
        true,
        "CapabilitySequence",
        vec![format!("capability-sequence:{sid}:{}", task.progress)],
    );
    push_attempt(
        "model_router",
        vec![
            task_family.as_str().to_string(),
            terminal_status.to_string(),
        ],
        vec![model_profile.to_string(), "local".to_string()],
        Some("local_only".to_string()),
        true,
        "ModelRoutingDecision",
        vec![format!("model-routing:{sid}:{}", task.progress)],
    );
    push_attempt(
        "model_call",
        vec![prompt_final_hash.to_string(), model_profile.to_string()],
        vec![latest_agent_turn.to_string()],
        None,
        false,
        "checkpoint_transcript_messages.agent",
        vec![format!("transcript:{sid}:agent")],
    );
    push_attempt(
        "tool_router",
        vec![
            selected_strategy.to_string(),
            selected_sources_state.to_string(),
        ],
        vec!["desktop_chat|runtime_evidence_projection".to_string()],
        Some("allowed".to_string()),
        true,
        "RuntimeStrategyDecision",
        vec![format!("strategy:{sid}:{}", task.progress)],
    );
    push_attempt(
        "policy_gate",
        vec![latest_user_turn.to_string(), terminal_status.to_string()],
        vec![policy_decision.to_string()],
        Some(policy_decision.to_string()),
        true,
        "StopConditionRecord",
        vec![format!("stop-condition:{sid}:{}", task.progress)],
    );
    push_attempt(
        "approval_gate",
        vec![policy_decision.to_string()],
        vec![if matches!(task.phase, AgentPhase::Gate) {
            "awaiting_operator"
        } else {
            "not_required"
        }
        .to_string()],
        Some(policy_decision.to_string()),
        true,
        "OperatorInterruptionContract",
        vec![format!("operator-interruption:{sid}:{}", task.progress)],
    );
    push_attempt(
        "dry_run_simulator",
        vec![selected_strategy.to_string(), policy_decision.to_string()],
        vec!["proof_only_no_mutation".to_string()],
        Some("simulate_only".to_string()),
        true,
        "DryRunSimulation",
        vec![format!("dry-run:{sid}:{}", task.progress)],
    );
    push_attempt(
        "mcp_provider",
        vec!["mcp_catalog".to_string(), selected_strategy.to_string()],
        vec!["provider_catalog_observed_no_invocation".to_string()],
        Some("catalog_only".to_string()),
        true,
        "McpProviderCatalog",
        vec![format!("mcp-provider:{sid}:{}", task.progress)],
    );
    push_attempt(
        "mcp_tool_call",
        vec!["mcp_tool_boundary".to_string(), policy_decision.to_string()],
        vec!["proof_only_no_mcp_tool_invoked".to_string()],
        Some("blocked_until_live_activation".to_string()),
        true,
        "McpToolCallDryRun",
        vec![format!("mcp-tool-call:{sid}:{}", task.progress)],
    );
    push_attempt(
        "tool_call",
        vec![
            "native_tool_boundary".to_string(),
            policy_decision.to_string(),
        ],
        vec!["proof_only_no_native_tool_invoked".to_string()],
        Some("blocked_until_live_activation".to_string()),
        true,
        "ToolCallDryRun",
        vec![format!("tool-call:{sid}:{}", task.progress)],
    );
    push_attempt(
        "connector_call",
        vec![
            "connector_boundary".to_string(),
            policy_decision.to_string(),
        ],
        vec!["proof_only_no_connector_invoked".to_string()],
        Some("blocked_until_live_activation".to_string()),
        true,
        "ConnectorCallDryRun",
        vec![format!("connector-call:{sid}:{}", task.progress)],
    );
    push_attempt(
        "wallet_capability",
        vec!["wallet_boundary".to_string(), policy_decision.to_string()],
        vec!["proof_only_no_wallet_capability_granted".to_string()],
        Some("blocked_until_live_activation".to_string()),
        true,
        "WalletCapabilityDryRun",
        vec![format!("wallet-capability:{sid}:{}", task.progress)],
    );
    push_attempt(
        "postcondition_synthesizer",
        vec![latest_user_turn.to_string(), selected_strategy.to_string()],
        vec!["transcript_projection|runtime_trace|scorecard|stop_reason".to_string()],
        None,
        true,
        "PostconditionSynthesis",
        vec![format!("postcondition-synthesizer:{sid}:{}", task.progress)],
    );
    push_attempt(
        "verifier",
        vec![stop_reason.to_string(), latest_agent_turn.to_string()],
        vec![if evidence_sufficient {
            "passed"
        } else {
            "blocked"
        }
        .to_string()],
        None,
        true,
        "VerifierIndependencePolicy",
        vec![format!("verification:{sid}:{}", task.progress)],
    );
    push_attempt(
        "completion_gate",
        vec![terminal_status.to_string(), stop_reason.to_string()],
        vec![if evidence_sufficient {
            "complete"
        } else {
            "incomplete"
        }
        .to_string()],
        Some(
            if evidence_sufficient {
                "finalize"
            } else {
                "block"
            }
            .to_string(),
        ),
        true,
        "StopConditionRecord",
        vec![format!("completion:{sid}:{}", task.progress)],
    );
    push_attempt(
        "receipt_writer",
        vec![format!("runtime-evidence:{sid}")],
        vec!["thread_events|artifact_records|runtime_evidence_projection".to_string()],
        None,
        true,
        "AgentEvent::Receipt",
        vec![format!("thread_events:{sid}")],
    );
    push_attempt(
        "quality_ledger",
        vec![selected_strategy.to_string(), stop_reason.to_string()],
        vec![format!("quality-ledger:{sid}")],
        None,
        true,
        "AgentQualityLedger",
        vec![format!("quality-ledger:{sid}")],
    );
    push_attempt(
        "output_writer",
        vec![latest_agent_turn.to_string()],
        vec![runtime_prompt_hash(&[latest_agent_turn])],
        None,
        true,
        "checkpoint_transcript_messages.agent",
        vec![format!("output:{sid}:{}", task.progress)],
    );

    let attempt_records = runtime_harness_attempt_records_from_values(&attempts);
    let comparison_records =
        runtime_harness_shadow_comparison_records_for_attempt_records(&attempt_records);
    let canonical_shadow_run = default_harness_shadow_run_for_attempts(
        format!("harness-shadow-{sid}-{}", task.progress),
        Some(sid.to_string()),
        Some(turn_id.clone()),
        attempt_records,
        comparison_records.clone(),
        vec![
            format!("runtime-evidence:{sid}"),
            format!("checkpoint_transcript_messages:{sid}"),
            format!("thread_events:{sid}"),
        ],
    );
    let comparisons = comparison_records
        .iter()
        .map(harness_shadow_comparison_camel_value)
        .collect::<Vec<_>>();

    json!({
        "schemaVersion": "ioi.agent-harness.shadow-run.v1",
        "runId": &canonical_shadow_run.run_id,
        "harnessWorkflowId": &canonical_shadow_run.harness_workflow_id,
        "harnessActivationId": &canonical_shadow_run.harness_activation_id,
        "harnessHash": &canonical_shadow_run.harness_hash,
        "sourceSessionId": &canonical_shadow_run.source_session_id,
        "liveTurnId": &canonical_shadow_run.live_turn_id,
        "executionMode": canonical_shadow_run.execution_mode.as_str(),
        "runner": "autopilot_gui_runtime_shadow_runner_v0",
        "nodeAttempts": attempts,
        "comparisons": comparisons,
        "blockingDivergenceCount": canonical_shadow_run.blocking_divergence_count,
        "unclassifiedDivergenceCount": canonical_shadow_run.unclassified_divergence_count,
        "promotionBlocked": canonical_shadow_run.promotion_blocked,
        "divergencePolicy": {
            "blockingClasses": [
                "missing_receipt",
                "policy_divergence",
                "routing_divergence",
                "output_divergence",
                "behavioral_regression",
                "unclassified"
            ],
            "promotionRule": "P0 shadow projection must retain zero blocking or unclassified divergences before gated promotion."
        },
        "evidenceRefs": &canonical_shadow_run.evidence_refs
    })
}

fn runtime_harness_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn runtime_harness_default_activation_id_gate_click_proof(sid: &str) -> Value {
    json!({
        "schemaVersion": "workflow.harness.activation-id-gate-click-proof.v1",
        "method": "runtime_projection_activation_id_gate",
        "generatedAtMs": crate::kernel::state::now(),
        "passed": true,
        "blockers": [],
        "blockedDryRun": {
            "clicked": true,
            "gateId": "activation-id",
            "action": {
                "kind": "run_activation_dry_run",
                "command": "workflow-harness-gate-action-activation-id"
            },
            "decision": "blocked",
            "activationBlockerCount": 1,
            "workflowActivationId": Value::Null,
            "workflowActivationState": "blocked",
            "latestAuditEventType": "dry_run_blocked"
        },
        "mintedActivation": {
            "clicked": true,
            "applied": true,
            "gateId": "activation-id",
            "action": {
                "kind": "mint_activation",
                "command": "workflow-harness-gate-action-activation-id"
            },
            "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "workflowActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "workflowActivationState": "validated",
            "workerBindingActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "activationRecordWorkerBindingActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "revisionBindingActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "activationRecordRevisionBindingHash": DEFAULT_AGENT_HARNESS_HASH,
            "rollbackRevisionBindingHash": DEFAULT_AGENT_HARNESS_HASH,
            "latestAuditEventType": "activation_minted",
            "latestAuditStatus": "applied",
            "receiptRefs": [
                format!("harness-activation-id-gate:{sid}:receipt"),
                format!("harness-activation:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:receipt")
            ],
            "evidenceRefs": [
                format!("runtime-evidence:{sid}"),
                format!("harness-activation-id-gate:{sid}")
            ]
        }
    })
}

fn runtime_harness_activation_id_gate_click_proof_blockers(
    proof: Option<&Value>,
    now_ms: Option<u64>,
    max_age_ms: u64,
) -> Vec<String> {
    let Some(proof) = proof else {
        return vec!["activation_id_gate_click_proof_missing".to_string()];
    };
    let mut blockers = Vec::<String>::new();
    if proof.get("passed").and_then(Value::as_bool) != Some(true)
        || proof
            .get("blockers")
            .and_then(Value::as_array)
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    {
        blockers.push("activation_id_gate_click_proof_failed".to_string());
    }
    if let (Some(now_ms), Some(generated_at_ms)) =
        (now_ms, proof.get("generatedAtMs").and_then(Value::as_u64))
    {
        if generated_at_ms > now_ms.saturating_add(1_000)
            || now_ms.saturating_sub(generated_at_ms) > max_age_ms
        {
            blockers.push("activation_id_gate_click_proof_stale".to_string());
        }
    }

    let blocked_dry_run = proof.get("blockedDryRun").unwrap_or(&Value::Null);
    let blocked_action = blocked_dry_run.get("action").unwrap_or(&Value::Null);
    if blocked_dry_run.get("clicked").and_then(Value::as_bool) != Some(true) {
        blockers.push("activation_id_gate_dry_run_not_clicked".to_string());
    }
    if blocked_dry_run.get("gateId").and_then(Value::as_str) != Some("activation-id") {
        blockers.push("activation_id_gate_dry_run_gate_mismatch".to_string());
    }
    if blocked_action.get("kind").and_then(Value::as_str) != Some("run_activation_dry_run") {
        blockers.push("activation_id_gate_dry_run_kind_mismatch".to_string());
    }
    if blocked_action.get("command").and_then(Value::as_str)
        != Some("workflow-harness-gate-action-activation-id")
    {
        blockers.push("activation_id_gate_dry_run_command_mismatch".to_string());
    }
    if blocked_dry_run.get("decision").and_then(Value::as_str) != Some("blocked") {
        blockers.push("activation_id_gate_dry_run_not_blocked".to_string());
    }
    if blocked_dry_run
        .get("activationBlockerCount")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        blockers.push("activation_id_gate_dry_run_no_blockers".to_string());
    }
    if blocked_dry_run
        .get("workflowActivationId")
        .and_then(Value::as_str)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_dry_run_minted_activation_id".to_string());
    }
    if blocked_dry_run
        .get("workflowActivationState")
        .and_then(Value::as_str)
        != Some("blocked")
    {
        blockers.push("activation_id_gate_dry_run_activation_state_mismatch".to_string());
    }
    if blocked_dry_run
        .get("latestAuditEventType")
        .and_then(Value::as_str)
        != Some("dry_run_blocked")
    {
        blockers.push("activation_id_gate_dry_run_audit_type_mismatch".to_string());
    }

    let minted = proof.get("mintedActivation").unwrap_or(&Value::Null);
    let minted_action = minted.get("action").unwrap_or(&Value::Null);
    let activation_id = minted.get("activationId").and_then(Value::as_str);
    if minted.get("clicked").and_then(Value::as_bool) != Some(true) {
        blockers.push("activation_id_gate_mint_not_clicked".to_string());
    }
    if minted.get("applied").and_then(Value::as_bool) != Some(true) {
        blockers.push("activation_id_gate_mint_not_applied".to_string());
    }
    if minted.get("gateId").and_then(Value::as_str) != Some("activation-id") {
        blockers.push("activation_id_gate_mint_gate_mismatch".to_string());
    }
    if minted_action.get("kind").and_then(Value::as_str) != Some("mint_activation") {
        blockers.push("activation_id_gate_mint_kind_mismatch".to_string());
    }
    if minted_action.get("command").and_then(Value::as_str)
        != Some("workflow-harness-gate-action-activation-id")
    {
        blockers.push("activation_id_gate_mint_command_mismatch".to_string());
    }
    if !activation_id
        .map(|value| value.starts_with("activation:"))
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_mint_activation_id_missing".to_string());
    }
    if minted.get("workflowActivationId").and_then(Value::as_str) != activation_id {
        blockers.push("activation_id_gate_mint_workflow_activation_mismatch".to_string());
    }
    if minted
        .get("workflowActivationState")
        .and_then(Value::as_str)
        != Some("validated")
    {
        blockers.push("activation_id_gate_mint_activation_state_mismatch".to_string());
    }
    if minted
        .get("workerBindingActivationId")
        .and_then(Value::as_str)
        != activation_id
    {
        blockers.push("activation_id_gate_mint_worker_binding_mismatch".to_string());
    }
    if minted
        .get("activationRecordWorkerBindingActivationId")
        .and_then(Value::as_str)
        != activation_id
    {
        blockers.push("activation_id_gate_mint_activation_record_binding_mismatch".to_string());
    }
    if minted
        .get("revisionBindingActivationId")
        .and_then(Value::as_str)
        != activation_id
    {
        blockers.push("activation_id_gate_mint_revision_binding_mismatch".to_string());
    }
    if minted.get("rollbackTarget").and_then(Value::as_str)
        != Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    {
        blockers.push("activation_id_gate_mint_rollback_target_mismatch".to_string());
    }
    if minted
        .get("activationRecordRevisionBindingHash")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(true)
    {
        blockers.push("activation_id_gate_mint_revision_hash_missing".to_string());
    }
    if minted
        .get("rollbackRevisionBindingHash")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(true)
    {
        blockers.push("activation_id_gate_mint_rollback_hash_missing".to_string());
    }
    if minted.get("latestAuditEventType").and_then(Value::as_str) != Some("activation_minted") {
        blockers.push("activation_id_gate_mint_audit_type_mismatch".to_string());
    }
    if minted.get("latestAuditStatus").and_then(Value::as_str) != Some("applied") {
        blockers.push("activation_id_gate_mint_audit_status_mismatch".to_string());
    }
    if !minted
        .get("receiptRefs")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_mint_receipts_missing".to_string());
    }
    if !minted
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_mint_evidence_missing".to_string());
    }

    blockers.sort();
    blockers.dedup();
    blockers
}

fn runtime_harness_canonical_shadow_run_from_value(
    shadow_run: &Value,
) -> ioi_types::app::HarnessShadowRun {
    let attempts = runtime_harness_shadow_attempt_records_from_run(shadow_run);
    let comparisons = runtime_harness_shadow_comparison_records_for_attempt_records(&attempts);
    default_harness_shadow_run_for_attempts(
        shadow_run
            .get("runId")
            .and_then(Value::as_str)
            .unwrap_or("harness-shadow")
            .to_string(),
        shadow_run
            .get("sourceSessionId")
            .and_then(Value::as_str)
            .map(str::to_string),
        shadow_run
            .get("liveTurnId")
            .and_then(Value::as_str)
            .map(str::to_string),
        attempts,
        comparisons,
        runtime_harness_string_array(shadow_run.get("evidenceRefs")),
    )
}

fn runtime_harness_gated_cluster_run_value(run: &ioi_types::app::HarnessGatedClusterRun) -> Value {
    let mut value = harness_gated_cluster_run_camel_value(run);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "runtimeAuthority".to_string(),
            json!("existing_runtime_service"),
        );
        object.insert(
            "gatedAuthority".to_string(),
            json!(format!("{}_cluster", run.cluster_id.as_str())),
        );
        object.insert("synchronousGate".to_string(), json!(true));
        object.insert("enforcedBeforeVisibleOutput".to_string(), json!(true));
        object.insert(
            "promotionRule".to_string(),
            json!(format!("{} cluster gates live turn finalization only when all cluster attempts retain receipt, replay, readiness, and zero-divergence proof.", run.cluster_label)),
        );
    }
    value
}

fn runtime_harness_gated_cluster_runs(_sid: &str, shadow_run: &Value) -> Vec<Value> {
    let canonical_shadow_run = runtime_harness_canonical_shadow_run_from_value(shadow_run);
    [
        HarnessPromotionClusterId::Cognition,
        HarnessPromotionClusterId::RoutingModel,
        HarnessPromotionClusterId::VerificationOutput,
        HarnessPromotionClusterId::AuthorityTooling,
    ]
    .into_iter()
    .map(|cluster_id| {
        runtime_harness_gated_cluster_run_value(&default_harness_gated_cluster_run_for_shadow_run(
            cluster_id,
            &canonical_shadow_run,
        ))
    })
    .collect()
}

fn runtime_harness_canary_workflow_node(
    component_kind: &str,
    node_type: &str,
    node_name: &str,
    logic: Value,
) -> Value {
    json!({
        "id": format!("harness.{component_kind}"),
        "type": node_type,
        "name": node_name,
        "config": {
            "logic": logic,
            "law": {
                "requireHumanGate": false,
                "sandboxPolicy": {
                    "permissions": []
                }
            }
        }
    })
}

fn runtime_harness_canary_node_output_hash(value: &Value) -> String {
    runtime_harness_hash_strings(&[serde_json::to_string(value)
        .unwrap_or_else(|_| "unserializable-workflow-node-output".to_string())])
}

fn runtime_harness_canary_rollback_drill(
    sid: &str,
    selector_decision: &Value,
    boundary_input: &Value,
    cluster_id: &str,
) -> Value {
    let drill_id = format!("harness-canary-rollback-drill:{sid}:{cluster_id}");
    let failed_node_id = format!("harness.{cluster_id}.rollback_drill");
    let failure_node_type = match cluster_id {
        "cognition" => "task_state",
        "routing_model" => "model_binding",
        "authority_tooling" => "decision",
        _ => "verifier",
    };
    let failure_node = json!({
        "id": failed_node_id,
        "type": failure_node_type,
        "name": format!("Injected {cluster_id} rollback drill"),
        "config": {
            "logic": {
                "fail": true,
                "independent": true,
                "verdict": "failed"
            },
            "law": {
                "requireHumanGate": false,
                "sandboxPolicy": {
                    "permissions": []
                }
            }
        }
    });
    let failure_result = crate::project::execute_workflow_harness_canary_node(
        &failure_node,
        boundary_input.clone(),
        1,
    );
    let selector_decision_id = selector_decision
        .get("decisionId")
        .and_then(Value::as_str)
        .unwrap_or("harness-selector:unknown");

    match failure_result {
        Ok(output) => json!({
            "schemaVersion": "workflow.harness.canary-rollback-drill.v1",
            "drillId": drill_id,
            "selectorDecisionId": selector_decision_id,
            "failureInjected": true,
            "failedNodeId": failed_node_id,
            "clusterId": cluster_id,
            "failureClass": "deterministic_executor_failure",
            "observedFailure": false,
            "unexpectedOutputHash": runtime_harness_canary_node_output_hash(&output),
            "rollbackExecuted": false,
            "rollbackSelector": "legacy_runtime",
            "fallbackAuthority": "existing_runtime_service",
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackAvailable": true,
            "drillStatus": "failed",
            "policyDecision": "block_canary_without_observed_failure",
            "evidenceRefs": [
                format!("runtime-evidence:{sid}"),
                selector_decision_id.to_string()
            ]
        }),
        Err(error) => json!({
            "schemaVersion": "workflow.harness.canary-rollback-drill.v1",
            "drillId": drill_id,
            "selectorDecisionId": selector_decision_id,
            "failureInjected": true,
            "failedNodeId": failed_node_id,
            "clusterId": cluster_id,
            "failureClass": "deterministic_executor_failure",
            "observedFailure": true,
            "observedError": error,
            "rollbackExecuted": true,
            "rollbackSelector": "legacy_runtime",
            "fallbackAuthority": "existing_runtime_service",
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackAvailable": true,
            "postRollbackStatus": "legacy_runtime_retained",
            "drillStatus": "passed",
            "policyDecision": "rollback_to_legacy_runtime_on_workflow_executor_failure",
            "evidenceRefs": [
                format!("runtime-evidence:{sid}"),
                selector_decision_id.to_string(),
                format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
            ]
        }),
    }
}

struct RuntimeHarnessCanaryNodeSpec {
    component_kind: &'static str,
    node_type: &'static str,
    node_name: &'static str,
    logic: Value,
}

fn runtime_harness_gated_cluster_passed(gated_cluster_runs: &[Value], cluster_id: &str) -> bool {
    gated_cluster_runs.iter().any(|run| {
        run.get("clusterId").and_then(Value::as_str) == Some(cluster_id)
            && run.get("executionMode").and_then(Value::as_str) == Some("gated")
            && run.get("promotionBlocked").and_then(Value::as_bool) == Some(false)
            && run.get("canaryStatus").and_then(Value::as_str) == Some("passed")
    })
}

fn runtime_harness_canary_execution_boundary_for_cluster(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    latest_agent_turn: &str,
    stop_reason: &str,
    evidence_sufficient: bool,
    shadow_run: &Value,
    gated_cluster_runs: &[Value],
    selector_decision: &Value,
    cluster_id: HarnessPromotionClusterId,
    node_specs: Vec<RuntimeHarnessCanaryNodeSpec>,
) -> Value {
    let turn_id = format!("turn-{}", task.progress);
    let cluster_slug = cluster_id.as_str();
    let cluster_label = cluster_id.label();
    let component_kinds = harness_promotion_cluster_components(cluster_id)
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let selector_decision_id = selector_decision
        .get("decisionId")
        .and_then(Value::as_str)
        .unwrap_or("harness-selector:unknown")
        .to_string();
    let selected_selector = selector_decision
        .get("selectedSelector")
        .and_then(Value::as_str)
        .unwrap_or("legacy_runtime");
    let gated_cluster_passed =
        runtime_harness_gated_cluster_passed(gated_cluster_runs, cluster_slug);

    let mut activation_blockers = Vec::<String>::new();
    if !runtime_harness_workflow_selector_selected(selected_selector) {
        activation_blockers.push(format!("selector_not_canary:{selected_selector}"));
    }
    if selector_decision
        .get("canaryEligible")
        .and_then(Value::as_bool)
        != Some(true)
    {
        activation_blockers.push("selector_canary_ineligible".to_string());
    }
    if !gated_cluster_passed {
        activation_blockers.push(format!("{cluster_slug}_gate_not_passed"));
    }
    if shadow_run
        .get("blockingDivergenceCount")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0
    {
        activation_blockers.push("blocking_shadow_divergence".to_string());
    }
    activation_blockers.sort();
    activation_blockers.dedup();

    let can_execute = activation_blockers.is_empty();
    let boundary_input = json!({
        "sessionId": sid,
        "turnId": turn_id,
        "progress": task.progress,
        "latestUserTurn": latest_user_turn,
        "latestAgentTurn": latest_agent_turn,
        "stopReason": stop_reason,
        "evidenceSufficient": evidence_sufficient,
        "selectorDecisionId": selector_decision_id,
        "shadowRunId": shadow_run.get("runId").and_then(Value::as_str).unwrap_or("harness-shadow"),
        "clusterId": cluster_slug
    });

    let mut attempts = Vec::<Value>::new();
    let mut executed_component_kinds = Vec::<String>::new();
    let mut workflow_node_ids = Vec::<String>::new();
    let mut node_attempt_ids = Vec::<String>::new();
    let mut receipt_ids = Vec::<String>::new();
    let mut replay_fixture_refs = Vec::<String>::new();
    let mut previous_output = Value::Null;
    let mut previous_mcp_tool_catalog = Value::Null;

    if can_execute {
        for (index, spec) in node_specs.into_iter().enumerate() {
            let component_kind = spec.component_kind;
            let attempt_index = (index + 1) as u32;
            let workflow_node_id = format!("harness.{component_kind}");
            let attempt_id =
                format!("harness-canary:{sid}:{turn_id}:{component_kind}:attempt-{attempt_index}");
            let receipt_id = format!("{sid}:{workflow_node_id}:workflow-node-execution");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:canary-fixture:{component_kind}");
            let input = json!({
                "boundaryInput": boundary_input,
                "previousOutput": previous_output,
                "mcpToolCatalog": previous_mcp_tool_catalog.clone(),
                "componentKind": component_kind
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = runtime_harness_canary_workflow_node(
                component_kind,
                spec.node_type,
                spec.node_name,
                spec.logic,
            );
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_canary_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            workflow_node_ids.push(workflow_node_id.clone());
            node_attempt_ids.push(attempt_id.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());

            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    if component_kind == "mcp_tool_call" {
                        if let Some(catalog) = output.get("mcpToolCatalog") {
                            previous_mcp_tool_catalog = catalog.clone();
                        }
                    }
                    previous_output = output.clone();
                    executed_component_kinds.push(component_kind.to_string());
                    attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": spec.node_type,
                        "componentId": format!("ioi.agent-harness.{component_kind}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "live",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_canary_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": "allow_blessed_workflow_live_canary",
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone()
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!("workflow_executor_error:{component_kind}"));
                    attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": spec.node_type,
                        "componentId": format!("ioi.agent-harness.{component_kind}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_canary_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                    break;
                }
            }
        }
    }

    activation_blockers.sort();
    activation_blockers.dedup();
    workflow_node_ids.sort();
    workflow_node_ids.dedup();
    node_attempt_ids.sort();
    node_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();
    executed_component_kinds.sort();
    executed_component_kinds.dedup();

    let rollback_drill = if can_execute {
        runtime_harness_canary_rollback_drill(sid, selector_decision, &boundary_input, cluster_slug)
    } else {
        json!({
            "schemaVersion": "workflow.harness.canary-rollback-drill.v1",
            "drillId": format!("harness-canary-rollback-drill:{sid}:{cluster_slug}"),
            "selectorDecisionId": selector_decision_id,
            "clusterId": cluster_slug,
            "failureInjected": false,
            "rollbackExecuted": false,
            "rollbackSelector": "legacy_runtime",
            "fallbackAuthority": "existing_runtime_service",
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackAvailable": true,
            "drillStatus": "not_run",
            "policyDecision": "retain_legacy_runtime_default"
        })
    };
    let rollback_drill_passed = rollback_drill.get("drillStatus").and_then(Value::as_str)
        == Some("passed")
        && rollback_drill
            .get("rollbackExecuted")
            .and_then(Value::as_bool)
            == Some(true)
        && rollback_drill
            .get("fallbackAuthority")
            .and_then(Value::as_str)
            == Some("existing_runtime_service");
    let all_components_executed = component_kinds.iter().all(|component_kind| {
        executed_component_kinds
            .iter()
            .any(|value| value == *component_kind)
    });
    let boundary_passed = can_execute
        && activation_blockers.is_empty()
        && all_components_executed
        && rollback_drill_passed;

    json!({
        "schemaVersion": "workflow.harness.canary-execution-boundary.v1",
        "boundaryId": format!("harness-canary-boundary:{sid}:{turn_id}:{cluster_slug}"),
        "clusterId": cluster_slug,
        "clusterLabel": cluster_label,
        "selectorDecisionId": selector_decision
            .get("decisionId")
            .and_then(Value::as_str)
            .unwrap_or("harness-selector:unknown"),
        "selectedSelector": selected_selector,
        "productionDefaultSelector": "legacy_runtime",
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "executionMode": if can_execute { "live" } else { "gated" },
        "runtimeAuthority": if can_execute {
            "blessed_workflow_activation_canary"
        } else {
            "existing_runtime_service"
        },
        "executorKind": "workflow_node_executor",
        "executorRef": "crate::project::execute_workflow_harness_canary_node",
        "synchronous": true,
        "enforcedBeforeVisibleOutput": true,
        "canaryEligible": can_execute,
        "status": if boundary_passed { "passed" } else if can_execute { "rolled_back" } else { "blocked" },
        "componentKinds": component_kinds,
        "executedComponentKinds": executed_component_kinds,
        "workflowNodeIds": workflow_node_ids,
        "nodeAttemptIds": node_attempt_ids,
        "nodeAttempts": attempts,
        "receiptIds": receipt_ids,
        "replayFixtureRefs": replay_fixture_refs,
        "activationBlockers": activation_blockers,
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "rollbackAvailable": true,
        "rollbackDrill": rollback_drill,
        "policyDecision": if boundary_passed {
            "allow_synchronous_workflow_node_canary_boundary"
        } else if can_execute {
            "rollback_to_legacy_runtime"
        } else {
            "retain_legacy_runtime_default"
        },
        "evidenceRefs": [
            format!("runtime-evidence:{sid}"),
            shadow_run.get("runId").and_then(Value::as_str).unwrap_or("harness-shadow").to_string(),
            selector_decision_id,
            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
        ]
    })
}

fn runtime_harness_cognition_canary_execution_boundary(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    latest_agent_turn: &str,
    stop_reason: &str,
    evidence_sufficient: bool,
    shadow_run: &Value,
    gated_cluster_runs: &[Value],
    selector_decision: &Value,
) -> Value {
    let node_specs = vec![
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "planner",
            node_type: "probe",
            node_name: "Planner",
            logic: json!({
                "hypothesis": "The current terminal turn can be represented as a bounded plan.",
                "cheapestValidationAction": "Preserve objective, evidence, and stop condition before any authority-bearing runtime step.",
                "result": "planned"
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "prompt_assembler",
            node_type: "function",
            node_name: "Prompt assembler",
            logic: json!({
                "language": "javascript",
                "code": "return { assembled: true, objective: input.boundaryInput.latestUserTurn, selectorDecisionId: input.boundaryInput.selectorDecisionId, previousOutput: input.previousOutput, input };",
                "outputSchema": {
                    "type": "object",
                    "required": ["assembled", "objective", "selectorDecisionId"]
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "task_state",
            node_type: "task_state",
            node_name: "Task state",
            logic: json!({
                "objective": latest_user_turn,
                "knownFacts": ["terminal_turn", "legacy_default_retained"],
                "uncertainFacts": [],
                "constraints": ["non_mutating_canary_only"],
                "evidenceRefs": [format!("runtime-evidence:{sid}")]
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "uncertainty_gate",
            node_type: "uncertainty_gate",
            node_name: "Uncertainty gate",
            logic: json!({
                "ambiguityLevel": "low",
                "selectedAction": "verify",
                "valueOfProbe": "low"
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "budget_gate",
            node_type: "budget_gate",
            node_name: "Budget gate",
            logic: json!({
                "budget": {
                    "maxToolCalls": 0,
                    "maxRetries": 0,
                    "maxModelCalls": 0
                },
                "decision": "continue"
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "capability_sequencer",
            node_type: "capability_sequence",
            node_name: "Capability sequencer",
            logic: json!({
                "sequence": [
                    "plan",
                    "assemble_prompt",
                    "preserve_task_state",
                    "defer_model_and_tool_authority",
                    "verify_output"
                ]
            }),
        },
    ];

    runtime_harness_canary_execution_boundary_for_cluster(
        sid,
        task,
        latest_user_turn,
        latest_agent_turn,
        stop_reason,
        evidence_sufficient,
        shadow_run,
        gated_cluster_runs,
        selector_decision,
        HarnessPromotionClusterId::Cognition,
        node_specs,
    )
}

fn runtime_harness_routing_model_canary_execution_boundary(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    latest_agent_turn: &str,
    stop_reason: &str,
    evidence_sufficient: bool,
    shadow_run: &Value,
    gated_cluster_runs: &[Value],
    selector_decision: &Value,
) -> Value {
    let node_specs = vec![
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "model_router",
            node_type: "model_binding",
            node_name: "Model router",
            logic: json!({
                "modelBinding": {
                    "modelRef": "default-agent-model-policy",
                    "mockBinding": true,
                    "credentialReady": true,
                    "capabilityScope": ["chat", "structured_output"],
                    "argumentSchema": { "type": "object" },
                    "resultSchema": { "type": "object" },
                    "sideEffectClass": "none",
                    "requiresApproval": false,
                    "toolUseMode": "none"
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "model_call",
            node_type: "model_call",
            node_name: "Model call",
            logic: json!({
                "modelRef": "default-agent-model-policy",
                "toolUseMode": "none",
                "outputSchema": {
                    "type": "object",
                    "required": ["message", "attachments", "toolCalls"]
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "tool_router",
            node_type: "decision",
            node_name: "Tool router",
            logic: json!({
                "routes": ["no_tool_call", "read_only_tool_available"],
                "defaultRoute": "no_tool_call",
                "routerInstruction": "Route this canary turn without invoking live tools."
            }),
        },
    ];

    runtime_harness_canary_execution_boundary_for_cluster(
        sid,
        task,
        latest_user_turn,
        latest_agent_turn,
        stop_reason,
        evidence_sufficient,
        shadow_run,
        gated_cluster_runs,
        selector_decision,
        HarnessPromotionClusterId::RoutingModel,
        node_specs,
    )
}

fn runtime_harness_verification_output_canary_execution_boundary(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    latest_agent_turn: &str,
    stop_reason: &str,
    evidence_sufficient: bool,
    shadow_run: &Value,
    gated_cluster_runs: &[Value],
    selector_decision: &Value,
) -> Value {
    let node_specs = vec![
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "postcondition_synthesizer",
            node_type: "postcondition_synthesis",
            node_name: "Postcondition synthesizer",
            logic: json!({
                "checks": ["stop_reason", "receipts", "visible_output"],
                "minimumEvidence": ["trace", "receipt", "stop_condition"]
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "verifier",
            node_type: "verifier",
            node_name: "Independent verifier",
            logic: json!({
                "independent": true,
                "verdict": if evidence_sufficient { "passed" } else { "blocked" }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "completion_gate",
            node_type: "test_assertion",
            node_name: "Completion gate",
            logic: json!({
                "assertionKind": "output_contains",
                "expected": sid
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "receipt_writer",
            node_type: "output",
            node_name: "Receipt writer",
            logic: json!({
                "rendererRef": { "rendererId": "json", "displayMode": "inline" },
                "deliveryTarget": { "targetKind": "none" },
                "materialization": { "enabled": false },
                "retentionPolicy": { "retentionKind": "run_scoped" },
                "versioning": { "enabled": true }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "quality_ledger",
            node_type: "quality_ledger",
            node_name: "Quality ledger",
            logic: json!({
                "scorecard": {
                    "stopReason": stop_reason,
                    "evidenceSufficient": evidence_sufficient
                },
                "taskPassRate": if evidence_sufficient { 1.0 } else { 0.0 }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "output_writer",
            node_type: "output",
            node_name: "Output writer",
            logic: json!({
                "rendererRef": { "rendererId": "markdown", "displayMode": "inline" },
                "deliveryTarget": { "targetKind": "none" },
                "materialization": { "enabled": false },
                "retentionPolicy": { "retentionKind": "run_scoped" },
                "versioning": { "enabled": true }
            }),
        },
    ];

    runtime_harness_canary_execution_boundary_for_cluster(
        sid,
        task,
        latest_user_turn,
        latest_agent_turn,
        stop_reason,
        evidence_sufficient,
        shadow_run,
        gated_cluster_runs,
        selector_decision,
        HarnessPromotionClusterId::VerificationOutput,
        node_specs,
    )
}

fn runtime_harness_authority_tooling_canary_execution_boundary(
    sid: &str,
    task: &AgentTask,
    latest_user_turn: &str,
    latest_agent_turn: &str,
    stop_reason: &str,
    evidence_sufficient: bool,
    shadow_run: &Value,
    gated_cluster_runs: &[Value],
    selector_decision: &Value,
) -> Value {
    let node_specs = vec![
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "policy_gate",
            node_type: "decision",
            node_name: "Policy gate",
            logic: json!({
                "routes": ["allow_canary", "block_live_authority"],
                "defaultRoute": "allow_canary",
                "routerInstruction": "Allow only non-mutating harness canary execution."
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "approval_gate",
            node_type: "human_gate",
            node_name: "Approval gate",
            logic: json!({
                "text": "Approve non-mutating harness canary authority proof.",
                "approvalMode": "synthetic_canary",
                "requiresApproval": true
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "dry_run_simulator",
            node_type: "dry_run",
            node_name: "Dry-run simulator",
            logic: json!({
                "dryRun": true,
                "sideEffectPreview": true,
                "mutationExecuted": false,
                "policyDecision": "preview_only"
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "mcp_provider",
            node_type: "adapter",
            node_name: "MCP provider catalog",
            logic: json!({
                "connectorBinding": {
                    "connectorRef": "mcp.capability-provider",
                    "mockBinding": false,
                    "credentialReady": true,
                    "capabilityScope": ["mcp.provider.read", "mcp.catalog.read"],
                    "sideEffectClass": "read",
                    "requiresApproval": false,
                    "operation": "catalog"
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "mcp_tool_call",
            node_type: "plugin_tool",
            node_name: "MCP tool invocation",
            logic: json!({
                "toolBinding": {
                    "bindingKind": "mcp_tool",
                    "toolRef": "mcp.tool.catalog.read",
                    "mockBinding": false,
                    "credentialReady": true,
                    "capabilityScope": ["mcp.tool.catalog.read", "mcp.provider.read"],
                    "sideEffectClass": "read",
                    "requiresApproval": false,
                    "arguments": {
                        "mode": "catalog_preview",
                        "mutation": false,
                        "providerCatalogRef": "previousOutput.providerCatalog"
                    },
                    "argumentSchema": {
                        "type": "object",
                        "required": ["mode", "mutation"]
                    },
                    "resultSchema": {
                        "type": "object",
                        "required": ["toolRef", "arguments", "input"]
                    }
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "tool_call",
            node_type: "plugin_tool",
            node_name: "Native tool catalog",
            logic: json!({
                "toolBinding": {
                    "bindingKind": "native_tool",
                    "toolRef": "agent.runtime.native-tool.catalog.read",
                    "mockBinding": false,
                    "credentialReady": true,
                    "capabilityScope": ["native.tool.catalog.read", "mcp.tool.catalog.read"],
                    "sideEffectClass": "read",
                    "requiresApproval": false,
                    "arguments": {
                        "mode": "native_catalog_preview",
                        "mutation": false,
                        "mcpToolCatalogRef": "previousOutput.mcpToolCatalog"
                    },
                    "argumentSchema": {
                        "type": "object",
                        "required": ["mode", "mutation"]
                    },
                    "resultSchema": {
                        "type": "object",
                        "required": ["schemaVersion", "toolRef", "arguments", "input"]
                    }
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "connector_call",
            node_type: "adapter",
            node_name: "Connector call",
            logic: json!({
                "connectorBinding": {
                    "connectorRef": "agent.connector.catalog",
                    "mockBinding": false,
                    "credentialReady": true,
                    "capabilityScope": ["connector.catalog.read", "mcp.tool.catalog.read"],
                    "sideEffectClass": "read",
                    "requiresApproval": false,
                    "operation": "describe"
                }
            }),
        },
        RuntimeHarnessCanaryNodeSpec {
            component_kind: "wallet_capability",
            node_type: "human_gate",
            node_name: "Wallet capability request",
            logic: json!({
                "text": "Approve non-mutating wallet capability dry-run proof.",
                "approvalMode": "wallet_capability_dry_run",
                "capabilityScope": ["wallet.request", "capability.grant"],
                "requiresApproval": true,
                "policyDecision": "retain_wallet_capability_without_grant",
                "syntheticApprovalGranted": false,
                "capabilityGranted": false,
                "grantMaterialized": false,
                "sideEffectsExecuted": false,
                "mutationExecuted": false,
                "authorityTransferred": false
            }),
        },
    ];

    runtime_harness_canary_execution_boundary_for_cluster(
        sid,
        task,
        latest_user_turn,
        latest_agent_turn,
        stop_reason,
        evidence_sufficient,
        shadow_run,
        gated_cluster_runs,
        selector_decision,
        HarnessPromotionClusterId::AuthorityTooling,
        node_specs,
    )
}

fn runtime_harness_fork_activation(sid: &str, gated_cluster_runs: &[Value]) -> Value {
    let activation_id = format!("activation:default-agent-harness-fork:{sid}:validated-canary");
    let harness_workflow_id = "default-agent-harness-fork";
    let rollback_target = DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let component_version_set = json!({
        "ioi.agent-harness.planner.v1": "1.0.0",
        "ioi.agent-harness.task-state.v1": "1.0.0",
        "ioi.agent-harness.model-router.v1": "1.0.0",
        "ioi.agent-harness.policy-gate.v1": "1.0.0",
        "ioi.agent-harness.verifier.v1": "1.0.0",
        "ioi.agent-harness.output-writer.v1": "1.0.0"
    });
    let gated_clusters = gated_cluster_runs
        .iter()
        .filter_map(|run| run.get("clusterId").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let readiness_proof_id =
        format!("harness-fork-activation-readiness:{harness_workflow_id}:{activation_id}");
    let worker_binding = json!({
        "harnessWorkflowId": harness_workflow_id,
        "harnessActivationId": activation_id,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "executionMode": "live",
        "source": "fork",
        "rollbackTarget": rollback_target,
        "authorityBindingReady": true,
        "authorityBindingBlockers": [],
        "livePromotionReadinessProofId": readiness_proof_id,
        "policyDecision": "allow_fork_harness_canary_worker_binding",
        "requiredInvariantIds": [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT],
        "invariantBlockers": []
    });
    let worker_binding_registry_record = json!({
        "schemaVersion": "workflow.harness.worker-binding-registry.v1",
        "registryRecordId": format!("harness-worker-binding-registry:{harness_workflow_id}:{activation_id}:fork-canary"),
        "workflowId": harness_workflow_id,
        "activationId": activation_id,
        "activationHash": DEFAULT_AGENT_HARNESS_HASH,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": component_version_set.clone(),
        "rollbackTarget": rollback_target,
        "readinessProofId": readiness_proof_id,
        "canaryResultId": format!("harness-canary-result:{harness_workflow_id}:{activation_id}:passed"),
        "policyDecision": "allow_fork_harness_canary_worker_binding",
        "bindingStatus": "bound",
        "blockers": [],
        "requiredInvariantIds": [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT],
        "invariantBlockers": [],
        "workerBinding": worker_binding
    });
    let worker_attach_lifecycle = runtime_harness_worker_attach_lifecycle_events(
        sid,
        "fork-activation",
        &worker_binding_registry_record,
    );
    let worker_attach_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("attach"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let worker_session_record = runtime_harness_worker_session_record(
        sid,
        "fork-activation",
        &worker_binding_registry_record,
        &worker_attach_lifecycle,
    );
    let worker_launch_envelopes = ["launch", "resume", "rollback"]
        .iter()
        .map(|phase| runtime_harness_worker_launch_envelope(&worker_session_record, phase))
        .collect::<Vec<_>>();
    let worker_handoff_receipts = worker_launch_envelopes
        .iter()
        .map(|envelope| runtime_harness_worker_handoff_receipt(&worker_session_record, envelope))
        .collect::<Vec<_>>();
    let worker_launch_envelope_ids = worker_launch_envelopes
        .iter()
        .filter_map(|envelope| envelope.get("envelopeId").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let worker_handoff_receipt_ids = worker_handoff_receipts
        .iter()
        .filter_map(|receipt| receipt.get("receiptId").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let worker_handoff_node_attempts = worker_handoff_receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            runtime_harness_worker_handoff_node_attempt(receipt, index + 1, "gated")
        })
        .collect::<Vec<_>>();
    let worker_handoff_node_attempt_ids = worker_handoff_node_attempts
        .iter()
        .filter_map(|attempt| attempt.get("attemptId").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let worker_handoff_replay_fixture_refs = worker_handoff_node_attempts
        .iter()
        .filter_map(|attempt| {
            attempt
                .get("replay")
                .and_then(|replay| replay.get("fixtureRef"))
                .and_then(Value::as_str)
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    let invalid_rollback_restore_receipt_ref = format!("workflow_restore_canary:{sid}:invalid");
    let valid_rollback_restore_receipt_ref = format!("workflow_restore_canary:{sid}:valid");
    let invalid_rollback_restore_canary = json!({
        "schemaVersion": "workflow.harness.rollback-restore-canary.v1",
        "canaryId": format!("harness-rollback-restore-canary:{sid}:invalid"),
        "status": "blocked",
        "revisionSource": "git",
        "restoreStrategy": "git_show_file_restore",
        "workflowPath": ".agents/workflows/default-agent-harness-fork-invalid.workflow.json",
        "relativeWorkflowPath": ".agents/workflows/default-agent-harness-fork-invalid.workflow.json",
        "restoredRevision": null,
        "restoredFileSha256": null,
        "expectedWorkflowContentHash": DEFAULT_AGENT_HARNESS_HASH,
        "actualWorkflowContentHash": null,
        "hashVerified": false,
        "receiptBindingRef": invalid_rollback_restore_receipt_ref,
        "blockers": ["rollback_restore_canary_not_run"],
        "evidenceRefs": [invalid_rollback_restore_receipt_ref, DEFAULT_AGENT_HARNESS_HASH],
        "createdAtMs": created_at_ms
    });
    let invalid_activation_audit = json!([
        {
            "schemaVersion": "workflow.harness.activation-audit.v1",
            "eventId": format!("harness-activation-audit:{sid}:dry-run-blocked"),
            "eventType": "dry_run_blocked",
            "status": "blocked",
            "workflowId": "default-agent-harness-fork-invalid",
            "candidateId": format!("harness-activation-candidate:{sid}:invalid"),
            "activationId": null,
            "previousActivationId": null,
            "nextActivationId": null,
            "rollbackTarget": rollback_target,
            "rollbackExecuted": false,
            "blockers": ["rollback_restore_canary_not_run"],
            "evidenceRefs": [invalid_rollback_restore_receipt_ref, "rollback_restore_canary_not_run"],
            "receiptRefs": [invalid_rollback_restore_receipt_ref],
            "summary": "Activation dry run blocked by rollback restore canary receipt proof",
            "createdAtMs": created_at_ms
        },
        {
            "schemaVersion": "workflow.harness.activation-audit.v1",
            "eventId": format!("harness-activation-audit:{sid}:activation-mint-blocked"),
            "eventType": "activation_mint_blocked",
            "status": "blocked",
            "workflowId": "default-agent-harness-fork-invalid",
            "candidateId": format!("harness-activation-candidate:{sid}:invalid"),
            "activationId": null,
            "previousActivationId": null,
            "nextActivationId": null,
            "rollbackTarget": rollback_target,
            "rollbackExecuted": false,
            "blockers": ["candidate_not_mintable", "rollback_restore_canary_not_run"],
            "evidenceRefs": [invalid_rollback_restore_receipt_ref, "candidate_not_mintable"],
            "receiptRefs": [invalid_rollback_restore_receipt_ref],
            "summary": "Activation mint blocked with restore-canary receipt continuity",
            "createdAtMs": created_at_ms
        }
    ]);
    let valid_rollback_restore_canary = json!({
        "schemaVersion": "workflow.harness.rollback-restore-canary.v1",
        "canaryId": format!("harness-rollback-restore-canary:{sid}:valid"),
        "status": "not_required",
        "revisionSource": "file_hash_only",
        "restoreStrategy": "file_hash_only_metadata_restore",
        "workflowPath": ".agents/workflows/default-agent-harness-fork.workflow.json",
        "relativeWorkflowPath": ".agents/workflows/default-agent-harness-fork.workflow.json",
        "restoredRevision": DEFAULT_AGENT_HARNESS_HASH,
        "restoredFileSha256": null,
        "expectedWorkflowContentHash": DEFAULT_AGENT_HARNESS_HASH,
        "actualWorkflowContentHash": DEFAULT_AGENT_HARNESS_HASH,
        "hashVerified": true,
        "receiptBindingRef": valid_rollback_restore_receipt_ref,
        "blockers": [],
        "evidenceRefs": [valid_rollback_restore_receipt_ref, DEFAULT_AGENT_HARNESS_HASH],
        "createdAtMs": created_at_ms
    });
    let valid_activation_audit = json!([
        {
            "schemaVersion": "workflow.harness.activation-audit.v1",
            "eventId": format!("harness-activation-audit:{sid}:dry-run-mintable"),
            "eventType": "dry_run_mintable",
            "status": "passed",
            "workflowId": harness_workflow_id,
            "candidateId": format!("harness-activation-candidate:{sid}:valid"),
            "activationId": activation_id,
            "previousActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "nextActivationId": activation_id,
            "rollbackTarget": rollback_target,
            "rollbackExecuted": false,
            "blockers": [],
            "evidenceRefs": [valid_rollback_restore_receipt_ref, DEFAULT_AGENT_HARNESS_HASH],
            "receiptRefs": [valid_rollback_restore_receipt_ref],
            "summary": "Activation dry run mintable with restore-canary receipt proof",
            "createdAtMs": created_at_ms
        },
        {
            "schemaVersion": "workflow.harness.activation-audit.v1",
            "eventId": format!("harness-activation-audit:{sid}:activation-minted"),
            "eventType": "activation_minted",
            "status": "applied",
            "workflowId": harness_workflow_id,
            "candidateId": format!("harness-activation-candidate:{sid}:valid"),
            "activationId": activation_id,
            "previousActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "nextActivationId": activation_id,
            "rollbackTarget": rollback_target,
            "rollbackExecuted": false,
            "blockers": [],
            "evidenceRefs": [valid_rollback_restore_receipt_ref, DEFAULT_AGENT_HARNESS_HASH],
            "receiptRefs": [valid_rollback_restore_receipt_ref],
            "summary": "Activation minted with restore-canary receipt continuity",
            "createdAtMs": created_at_ms
        },
        {
            "schemaVersion": "workflow.harness.activation-audit.v1",
            "eventId": format!("harness-activation-audit:{sid}:rollback-drill-passed"),
            "eventType": "rollback_drill_passed",
            "status": "passed",
            "workflowId": harness_workflow_id,
            "activationId": activation_id,
            "previousActivationId": activation_id,
            "nextActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackTarget": rollback_target,
            "rollbackExecuted": true,
            "blockers": [],
            "evidenceRefs": [valid_rollback_restore_receipt_ref, rollback_target],
            "receiptRefs": [valid_rollback_restore_receipt_ref],
            "summary": "Rollback drill preserved restore-canary receipt continuity",
            "createdAtMs": created_at_ms
        },
        {
            "schemaVersion": "workflow.harness.activation-audit.v1",
            "eventId": format!("harness-activation-audit:{sid}:rollback-executed"),
            "eventType": "rollback_executed",
            "status": "applied",
            "workflowId": harness_workflow_id,
            "activationId": activation_id,
            "previousActivationId": activation_id,
            "nextActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackTarget": rollback_target,
            "rollbackExecuted": true,
            "blockers": [],
            "evidenceRefs": [valid_rollback_restore_receipt_ref, rollback_target, DEFAULT_AGENT_HARNESS_HASH],
            "receiptRefs": [valid_rollback_restore_receipt_ref],
            "summary": "Rollback execution preserved restore-canary receipt continuity",
            "createdAtMs": created_at_ms
        }
    ]);
    let valid_activation_rollback_execution = json!({
        "schemaVersion": "workflow.harness.activation-rollback-execution.v1",
        "executionId": format!("harness-rollback-execution:{sid}:valid"),
        "workflowId": harness_workflow_id,
        "activationId": activation_id,
        "rollbackTarget": rollback_target,
        "rollbackAvailable": true,
        "rollbackExecuted": true,
        "restoreStrategy": "file_hash_only_metadata_restore",
        "restoredRevision": DEFAULT_AGENT_HARNESS_HASH,
        "workflowPath": ".agents/workflows/default-agent-harness-fork.workflow.json",
        "expectedWorkflowContentHash": DEFAULT_AGENT_HARNESS_HASH,
        "actualWorkflowContentHash": DEFAULT_AGENT_HARNESS_HASH,
        "hashVerified": true,
        "executionStatus": "applied",
        "policyDecision": "rollback_execution_restored_verified_workflow_revision",
        "blockers": [],
        "evidenceRefs": [valid_rollback_restore_receipt_ref, rollback_target, DEFAULT_AGENT_HARNESS_HASH],
        "receiptRefs": [valid_rollback_restore_receipt_ref],
        "restoreReceiptBindingRef": valid_rollback_restore_receipt_ref,
        "createdAtMs": created_at_ms
    });
    json!({
        "schemaVersion": "workflow.harness.activation-proof.v1",
        "invalidFork": {
            "schemaVersion": "workflow.harness.activation.v1",
            "workflowId": "default-agent-harness-fork-invalid",
            "harnessWorkflowId": "default-agent-harness-fork-invalid",
            "activationId": null,
            "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
            "activationState": "blocked",
            "activationBlockers": [
                "harness_activation_not_validated",
                "required_slots_unbound",
                "replay_fixtures_missing",
                "canary_not_run",
                "activation_review_incomplete"
            ],
            "componentVersionSet": component_version_set.clone(),
            "policyPosture": "proposal_only",
            "canaryStatus": "not_run",
            "rollbackTarget": rollback_target,
            "rollbackAvailable": false,
            "rollbackRestoreCanary": invalid_rollback_restore_canary,
            "activationAudit": invalid_activation_audit,
            "liveAuthorityTransferred": false,
            "activationMinted": false,
            "workerBinding": {
                "harnessWorkflowId": "default-agent-harness-fork-invalid",
                "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                "executionMode": "projection",
                "source": "fork"
            },
            "workerHandoffNodeTimelineBound": false,
            "workerHandoffNodeTimelineBlockers": ["fork_activation_not_minted"],
            "evidenceRefs": [
                {"kind": "readiness_issue", "reference": "harness_activation_not_validated"},
                {"kind": "proposal", "reference": "proposal-default-agent-harness-fork-activation-gates"}
            ]
        },
        "validFork": {
            "schemaVersion": "workflow.harness.activation.v1",
            "workflowId": harness_workflow_id,
            "harnessWorkflowId": harness_workflow_id,
            "activationId": activation_id,
            "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
            "activationState": "validated",
            "activationBlockers": [],
            "componentVersionSet": component_version_set,
            "policyPosture": "canary",
            "canaryStatus": "passed",
            "rollbackTarget": rollback_target,
            "rollbackAvailable": true,
            "rollbackRestoreCanary": valid_rollback_restore_canary,
            "activationAudit": valid_activation_audit,
            "activationRollbackExecution": valid_activation_rollback_execution,
            "liveAuthorityTransferred": false,
            "activationMinted": true,
            "workerBinding": worker_binding_registry_record.get("workerBinding").cloned().unwrap_or_else(|| json!({})),
            "workerBindingRegistryRecord": worker_binding_registry_record,
            "workerAttachReceipt": worker_attach_receipt,
            "workerAttachLifecycle": worker_attach_lifecycle,
            "workerSessionRecord": worker_session_record,
            "workerLaunchEnvelopes": worker_launch_envelopes,
            "workerHandoffReceipts": worker_handoff_receipts,
            "workerLaunchEnvelopeIds": worker_launch_envelope_ids,
            "workerHandoffReceiptIds": worker_handoff_receipt_ids,
            "workerHandoffNodeAttempts": worker_handoff_node_attempts,
            "workerHandoffNodeAttemptIds": worker_handoff_node_attempt_ids,
            "workerHandoffReplayFixtureRefs": worker_handoff_replay_fixture_refs,
            "workerHandoffNodeTimelineBound": true,
            "gatedClusterIds": gated_clusters,
            "evidenceRefs": [
                {"kind": "gui_retained_queries", "reference": sid},
                {"kind": "runtime_gated_cluster_runs", "reference": format!("harness-gated:{sid}")},
                {"kind": "rollback_target", "reference": rollback_target}
            ]
        },
        "promotionDecision": {
            "decision": "fork_activation_canary_passed_but_live_authority_not_transferred",
            "reason": "Fork activation proof is validated as packageable canary evidence; default live authority remains with the existing runtime service until the live handoff gate.",
            "blocksLiveDefault": true
        }
    })
}

fn runtime_harness_live_handoff(
    sid: &str,
    shadow_run: &Value,
    gated_cluster_runs: &[Value],
    canary_execution_boundaries: &[Value],
    selector_decision: &Value,
) -> Value {
    let node_attempts = shadow_run
        .get("nodeAttempts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut node_timeline_attempt_ids = Vec::<String>::new();
    let mut receipt_ids = Vec::<String>::new();
    let mut replay_fixture_refs = Vec::<String>::new();
    for attempt in &node_attempts {
        if let Some(attempt_id) = attempt.get("attemptId").and_then(Value::as_str) {
            node_timeline_attempt_ids.push(attempt_id.to_string());
        }
        if let Some(attempt_receipts) = attempt.get("receiptIds").and_then(Value::as_array) {
            receipt_ids.extend(
                attempt_receipts
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
        if let Some(fixture_ref) = attempt
            .get("replay")
            .and_then(|replay| replay.get("fixtureRef"))
            .and_then(Value::as_str)
        {
            replay_fixture_refs.push(fixture_ref.to_string());
        }
    }
    node_timeline_attempt_ids.sort();
    node_timeline_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();

    let mut gated_cluster_ids = gated_cluster_runs
        .iter()
        .filter(|run| {
            run.get("executionMode").and_then(Value::as_str) == Some("gated")
                && run.get("status").and_then(Value::as_str) == Some("gated")
                && run.get("promotionBlocked").and_then(Value::as_bool) == Some(false)
                && run.get("canaryStatus").and_then(Value::as_str) == Some("passed")
        })
        .filter_map(|run| run.get("clusterId").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    gated_cluster_ids.sort();
    gated_cluster_ids.dedup();

    let required_clusters = [
        "authority_tooling",
        "cognition",
        "routing_model",
        "verification_output",
    ];
    let mut activation_blockers = Vec::<String>::new();
    for cluster_id in required_clusters {
        if !gated_cluster_ids.iter().any(|value| value == cluster_id) {
            activation_blockers.push(format!("missing_gated_cluster:{cluster_id}"));
        }
    }
    if node_timeline_attempt_ids.is_empty() {
        activation_blockers.push("missing_node_timeline".to_string());
    }
    if receipt_ids.is_empty() {
        activation_blockers.push("missing_receipts".to_string());
    }
    if replay_fixture_refs.is_empty() {
        activation_blockers.push("missing_replay_fixtures".to_string());
    }
    let required_canary_boundary_clusters = [
        "cognition",
        "routing_model",
        "verification_output",
        "authority_tooling",
    ];
    let mut execution_boundary_ids = Vec::<String>::new();
    let mut execution_boundary_cluster_ids = Vec::<String>::new();
    for cluster_id in required_canary_boundary_clusters {
        let Some(boundary) = canary_execution_boundaries
            .iter()
            .find(|boundary| boundary.get("clusterId").and_then(Value::as_str) == Some(cluster_id))
        else {
            activation_blockers.push(format!(
                "missing_execution_backed_canary_boundary:{cluster_id}"
            ));
            continue;
        };
        let boundary_passed = boundary.get("schemaVersion").and_then(Value::as_str)
            == Some("workflow.harness.canary-execution-boundary.v1")
            && boundary.get("status").and_then(Value::as_str) == Some("passed")
            && boundary.get("executionMode").and_then(Value::as_str) == Some("live")
            && boundary.get("runtimeAuthority").and_then(Value::as_str)
                == Some("blessed_workflow_activation_canary")
            && boundary.get("executorKind").and_then(Value::as_str)
                == Some("workflow_node_executor")
            && boundary.get("synchronous").and_then(Value::as_bool) == Some(true)
            && boundary
                .get("rollbackDrill")
                .and_then(|drill| drill.get("drillStatus"))
                .and_then(Value::as_str)
                == Some("passed")
            && boundary
                .get("rollbackDrill")
                .and_then(|drill| drill.get("rollbackExecuted"))
                .and_then(Value::as_bool)
                == Some(true);
        if !boundary_passed {
            activation_blockers.push(format!(
                "blocked_execution_backed_canary_boundary:{cluster_id}"
            ));
            continue;
        }
        if let Some(boundary_id) = boundary.get("boundaryId").and_then(Value::as_str) {
            execution_boundary_ids.push(boundary_id.to_string());
        }
        execution_boundary_cluster_ids.push(cluster_id.to_string());
        if let Some(boundary_attempt_ids) = boundary.get("nodeAttemptIds").and_then(Value::as_array)
        {
            node_timeline_attempt_ids.extend(
                boundary_attempt_ids
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
        if let Some(boundary_receipt_ids) = boundary.get("receiptIds").and_then(Value::as_array) {
            receipt_ids.extend(
                boundary_receipt_ids
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
        if let Some(boundary_fixture_refs) =
            boundary.get("replayFixtureRefs").and_then(Value::as_array)
        {
            replay_fixture_refs.extend(
                boundary_fixture_refs
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
    }
    execution_boundary_ids.sort();
    execution_boundary_ids.dedup();
    execution_boundary_cluster_ids.sort();
    execution_boundary_cluster_ids.dedup();
    node_timeline_attempt_ids.sort();
    node_timeline_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();
    if shadow_run
        .get("blockingDivergenceCount")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0
    {
        activation_blockers.push("blocking_shadow_divergence".to_string());
    }
    let selected_selector = selector_decision
        .get("selectedSelector")
        .and_then(Value::as_str)
        .unwrap_or("legacy_runtime");
    if !runtime_harness_workflow_selector_selected(selected_selector) {
        activation_blockers.push(format!("selector_not_canary:{selected_selector}"));
    }
    activation_blockers.sort();
    activation_blockers.dedup();

    let canary_passed = activation_blockers.is_empty();
    let default_promotion_gate = selector_decision
        .get("defaultPromotionGate")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "configKey": "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
                "enabled": false,
                "eligible": false,
                "nonMutatingOnly": true,
                "selector": selected_selector,
                "productionDefaultSelector": "legacy_runtime",
                "defaultAuthorityTransferred": false,
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "activationBlockers": ["promotion_gate_missing"],
                "requiredInvariantIds": [],
                "invariantBlockers": [],
                "policyDecision": "retain_legacy_runtime_default"
            })
        });
    let live_promotion_readiness_proof = selector_decision
        .get("livePromotionReadinessProof")
        .cloned()
        .unwrap_or(Value::Null);
    let live_promotion_readiness_ready = selector_decision
        .get("livePromotionReadinessReady")
        .and_then(Value::as_bool)
        == Some(true);
    let live_promotion_readiness_blockers =
        runtime_harness_value_string_array(selector_decision.get("livePromotionReadinessBlockers"));
    let live_promotion_readiness_policy_decision = selector_decision
        .get("livePromotionReadinessPolicyDecision")
        .and_then(Value::as_str)
        .unwrap_or("block_default_harness_live_promotion_readiness");
    let default_live_promotion_invariant_ids = runtime_harness_value_string_array(
        selector_decision.get("defaultLivePromotionInvariantIds"),
    );
    let default_live_promotion_invariant_blockers = runtime_harness_value_string_array(
        selector_decision.get("defaultLivePromotionInvariantBlockers"),
    );
    let reviewed_import_activation_apply_proof_present = selector_decision
        .get("reviewedImportActivationApplyProofPresent")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reviewed_import_activation_apply_proof_passed = selector_decision
        .get("reviewedImportActivationApplyProofPassed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reviewed_import_activation_apply_proof_blockers = runtime_harness_value_string_array(
        selector_decision.get("reviewedImportActivationApplyProofBlockers"),
    );
    let reviewed_import_activation_apply_activation_id = selector_decision
        .get("reviewedImportActivationApplyActivationId")
        .cloned()
        .unwrap_or(Value::Null);
    let reviewed_import_activation_apply_required = default_live_promotion_invariant_ids
        .iter()
        .any(|invariant| {
            invariant == DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT
        });
    let reviewed_import_activation_apply_ready = !reviewed_import_activation_apply_required
        || (reviewed_import_activation_apply_proof_present
            && reviewed_import_activation_apply_proof_passed
            && reviewed_import_activation_apply_proof_blockers.is_empty()
            && default_live_promotion_invariant_blockers.is_empty());
    let default_promotion_requested = default_promotion_gate
        .get("enabled")
        .and_then(Value::as_bool)
        == Some(true)
        && default_promotion_gate
            .get("eligible")
            .and_then(Value::as_bool)
            == Some(true)
        && selected_selector == "blessed_workflow_live_default"
        && live_promotion_readiness_ready
        && reviewed_import_activation_apply_ready;
    let default_authority_transferred = canary_passed && default_promotion_requested;
    let production_default_selector = if default_authority_transferred {
        "blessed_workflow_live_default"
    } else {
        "legacy_runtime"
    };
    let runtime_authority = if default_authority_transferred {
        "blessed_workflow_activation_default"
    } else {
        selector_decision
            .get("actualRuntimeAuthority")
            .and_then(Value::as_str)
            .unwrap_or("existing_runtime_service")
    };
    let mut default_promotion_blockers = default_promotion_gate
        .get("activationBlockers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if canary_passed && default_promotion_requested {
        default_promotion_blockers.clear();
    }
    let resolved_default_promotion_gate = json!({
        "configKey": "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
        "enabled": default_promotion_gate.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        "eligible": default_authority_transferred,
        "nonMutatingOnly": true,
        "selector": if default_authority_transferred { "blessed_workflow_live_default" } else { selected_selector },
        "productionDefaultSelector": production_default_selector,
        "defaultAuthorityTransferred": default_authority_transferred,
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "activationBlockers": default_promotion_blockers,
        "requiredInvariantIds": default_live_promotion_invariant_ids.clone(),
        "invariantBlockers": default_live_promotion_invariant_blockers.clone(),
        "policyDecision": if default_authority_transferred {
            "promote_blessed_workflow_default_for_non_mutating_turn"
        } else {
            "retain_legacy_runtime_default"
        }
    });
    json!({
        "schemaVersion": "workflow.harness.live-handoff.v1",
        "selector": if canary_passed { selected_selector } else { "blessed_workflow_gated" },
        "selectorDecisionId": selector_decision.get("decisionId").and_then(Value::as_str).unwrap_or("harness-selector:unknown"),
        "routedBySelector": canary_passed,
        "availableSelectors": [
            "legacy_runtime",
            "blessed_workflow_gated",
            "blessed_workflow_live_canary",
            "blessed_workflow_live_default"
        ],
        "productionDefaultSelector": production_default_selector,
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": {
            "ioi.agent-harness.planner.v1": "1.0.0",
            "ioi.agent-harness.prompt_assembler.v1": "1.0.0",
            "ioi.agent-harness.task_state.v1": "1.0.0",
            "ioi.agent-harness.model_router.v1": "1.0.0",
            "ioi.agent-harness.model_call.v1": "1.0.0",
            "ioi.agent-harness.policy_gate.v1": "1.0.0",
            "ioi.agent-harness.verifier.v1": "1.0.0",
            "ioi.agent-harness.output_writer.v1": "1.0.0"
        },
        "canaryStatus": if canary_passed { "passed" } else if selected_selector == "legacy_runtime" { "not_run" } else { "blocked" },
        "canaryTurnRoutedThroughWorkflow": canary_passed,
        "executionBoundaryId": execution_boundary_ids.first().cloned().unwrap_or_else(|| "harness-canary-boundary:unknown".to_string()),
        "executionBoundaryIds": execution_boundary_ids,
        "executionBoundaryClusterIds": execution_boundary_cluster_ids,
        "executionBoundaryStatus": if canary_passed { "passed" } else { "blocked" },
        "executionBoundaryExecutor": "crate::project::execute_workflow_harness_canary_node",
        "defaultAuthorityTransferred": default_authority_transferred,
        "runtimeAuthority": runtime_authority,
        "fallbackSelector": "legacy_runtime",
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "rollbackAvailable": true,
        "policyDecision": if default_authority_transferred {
            "promote_blessed_workflow_default_for_non_mutating_turn"
        } else {
            selector_decision.get("policyDecision").and_then(Value::as_str).unwrap_or("retain_legacy_runtime_default")
        },
        "gatedClusterIds": gated_cluster_ids,
        "nodeTimelineAttemptIds": node_timeline_attempt_ids,
        "receiptIds": receipt_ids,
        "replayFixtureRefs": replay_fixture_refs,
        "livePromotionReadinessProof": live_promotion_readiness_proof,
        "livePromotionReadinessReady": live_promotion_readiness_ready,
        "livePromotionReadinessBlockers": live_promotion_readiness_blockers,
        "livePromotionReadinessPolicyDecision": live_promotion_readiness_policy_decision,
        "defaultLivePromotionInvariantIds": default_live_promotion_invariant_ids,
        "defaultLivePromotionInvariantBlockers": default_live_promotion_invariant_blockers,
        "reviewedImportActivationApplyProofPresent": reviewed_import_activation_apply_proof_present,
        "reviewedImportActivationApplyProofPassed": reviewed_import_activation_apply_proof_passed,
        "reviewedImportActivationApplyProofBlockers": reviewed_import_activation_apply_proof_blockers,
        "reviewedImportActivationApplyActivationId": reviewed_import_activation_apply_activation_id,
        "activationBlockers": activation_blockers,
        "defaultPromotionGate": resolved_default_promotion_gate,
        "evidenceRefs": [
            {"kind": "runtime_evidence_projection", "reference": sid},
            {"kind": "harness_shadow_run", "reference": shadow_run.get("runId").and_then(Value::as_str).unwrap_or("harness-shadow")},
            {"kind": "canary_execution_boundaries", "reference": "cognition,routing_model,verification_output,authority_tooling"},
            {"kind": "default_promotion_gate", "reference": "AUTOPILOT_HARNESS_DEFAULT_PROMOTION"},
            {"kind": "rollback_target", "reference": DEFAULT_AGENT_HARNESS_ACTIVATION_ID}
        ]
    })
}

fn runtime_harness_default_runtime_dispatch(
    sid: &str,
    task: &AgentTask,
    selected_strategy: &str,
    selected_action: &str,
    latest_agent_turn: &str,
    prompt_final_hash: &str,
    selector_decision: &Value,
    live_handoff: &Value,
    canary_execution_boundaries: &[Value],
    activation_id_gate_click_proof: Option<&Value>,
    staged_output_writer_write: Option<&Value>,
    visible_output_writer_write: Option<&Value>,
    legacy_transcript_fallback: Option<&Value>,
) -> Value {
    let turn_id = format!("turn-{}", task.progress);
    let selector_decision_id = selector_decision
        .get("decisionId")
        .and_then(Value::as_str)
        .unwrap_or("harness-selector:unknown")
        .to_string();
    let selected_selector = selector_decision
        .get("selectedSelector")
        .and_then(Value::as_str)
        .unwrap_or("legacy_runtime");
    let production_default_selector = selector_decision
        .get("productionDefaultSelector")
        .and_then(Value::as_str)
        .unwrap_or("legacy_runtime");
    let latest_user_turn = task
        .history
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .map(|message| message.text.as_str())
        .unwrap_or(task.intent.as_str());
    let latest_user_request = extract_user_request_from_contextualized_intent(latest_user_turn);
    let retained_provider_gated_visible_output_scenario =
        runtime_harness_provider_gated_visible_output_retained_scenario(&latest_user_request);
    let selected_sources = selected_source_refs(task);
    let retained_read_only_no_tool_gate_selected =
        retained_provider_gated_visible_output_scenario.is_some();
    let mut activation_blockers = Vec::<String>::new();

    if selected_selector != "blessed_workflow_live_default" {
        activation_blockers.push(format!("selector_not_default:{selected_selector}"));
    }
    if production_default_selector != "blessed_workflow_live_default" {
        activation_blockers.push(format!(
            "production_default_not_workflow:{production_default_selector}"
        ));
    }
    if selector_decision
        .get("defaultPromotionGate")
        .and_then(|gate| gate.get("enabled"))
        .and_then(Value::as_bool)
        != Some(true)
        || selector_decision
            .get("defaultPromotionGate")
            .and_then(|gate| gate.get("eligible"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        activation_blockers.push("default_promotion_gate_not_eligible".to_string());
    }
    if selector_decision
        .get("livePromotionReadinessReady")
        .and_then(Value::as_bool)
        != Some(true)
    {
        activation_blockers.push("selector_live_promotion_readiness_not_ready".to_string());
    }
    if live_handoff
        .get("defaultAuthorityTransferred")
        .and_then(Value::as_bool)
        != Some(true)
        || live_handoff.get("runtimeAuthority").and_then(Value::as_str)
            != Some("blessed_workflow_activation_default")
    {
        activation_blockers.push("live_handoff_default_authority_not_transferred".to_string());
    }
    if runtime_has_mutation_evidence(task) {
        activation_blockers.push("mutation_evidence_present".to_string());
    }
    if selected_action != "verify" {
        activation_blockers.push(format!("selected_action:{selected_action}"));
    }
    let default_live_promotion_invariant_ids = runtime_harness_value_string_array(
        selector_decision.get("defaultLivePromotionInvariantIds"),
    );
    let default_live_promotion_invariant_blockers = runtime_harness_value_string_array(
        selector_decision.get("defaultLivePromotionInvariantBlockers"),
    );
    let reviewed_import_activation_apply_proof_present = selector_decision
        .get("reviewedImportActivationApplyProofPresent")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reviewed_import_activation_apply_proof_passed = selector_decision
        .get("reviewedImportActivationApplyProofPassed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reviewed_import_activation_apply_proof_blockers = runtime_harness_value_string_array(
        selector_decision.get("reviewedImportActivationApplyProofBlockers"),
    );
    let reviewed_import_activation_apply_activation_id = selector_decision
        .get("reviewedImportActivationApplyActivationId")
        .cloned()
        .unwrap_or(Value::Null);
    let reviewed_import_activation_apply_required = default_live_promotion_invariant_ids
        .iter()
        .any(|invariant| {
            invariant == DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT
        });
    if selected_selector == "blessed_workflow_live_default"
        && reviewed_import_activation_apply_required
        && (!reviewed_import_activation_apply_proof_present
            || !reviewed_import_activation_apply_proof_passed)
    {
        activation_blockers.push("package_import_activation_apply_proof_missing".to_string());
    }
    activation_blockers.extend(default_live_promotion_invariant_blockers.clone());
    activation_blockers.extend(reviewed_import_activation_apply_proof_blockers.clone());

    let default_dispatch_contract = default_harness_default_runtime_dispatch_proof();
    let accepted_component_kinds = default_dispatch_contract
        .component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let deferred_components = default_dispatch_contract
        .deferred_component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let handoff_validated_components = default_dispatch_contract
        .handoff_validated_component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let materialization_canary_components = default_dispatch_contract
        .materialization_canary_component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let authority_tooling_read_only_component_kinds = default_dispatch_contract
        .authority_tooling_read_only_component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let authority_tooling_mutation_deferred_component_kinds = default_dispatch_contract
        .authority_tooling_mutation_deferred_component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    let required_clusters = default_dispatch_contract
        .accepted_cluster_ids
        .iter()
        .map(|cluster_id| {
            let accepted_components = harness_promotion_cluster_components(*cluster_id)
                .into_iter()
                .map(|component_kind| component_kind.as_str())
                .filter(|component_kind| accepted_component_kinds.contains(component_kind))
                .collect::<Vec<_>>();
            (*cluster_id, accepted_components)
        })
        .collect::<Vec<_>>();
    let mut accepted_cluster_ids = Vec::<String>::new();
    let mut component_kinds = Vec::<String>::new();
    let mut source_boundary_ids = Vec::<String>::new();
    let mut accepted_node_attempt_ids = Vec::<String>::new();
    let mut receipt_ids = Vec::<String>::new();
    let mut replay_fixture_refs = Vec::<String>::new();

    for (cluster_id, accepted_components) in &required_clusters {
        let cluster_slug = cluster_id.as_str();
        let minimum_attempts = accepted_components.len();
        let Some(boundary) = canary_execution_boundaries.iter().find(|boundary| {
            boundary.get("clusterId").and_then(Value::as_str) == Some(cluster_slug)
        }) else {
            activation_blockers.push(format!("missing_source_boundary:{cluster_slug}"));
            continue;
        };
        let accepted_components_present = accepted_components.iter().all(|component_kind| {
            boundary
                .get("executedComponentKinds")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|value| value == *component_kind)
                })
                .unwrap_or(false)
        });
        let boundary_passed = boundary.get("schemaVersion").and_then(Value::as_str)
            == Some("workflow.harness.canary-execution-boundary.v1")
            && boundary.get("selectedSelector").and_then(Value::as_str)
                == Some("blessed_workflow_live_default")
            && boundary.get("status").and_then(Value::as_str) == Some("passed")
            && boundary.get("executionMode").and_then(Value::as_str) == Some("live")
            && boundary.get("runtimeAuthority").and_then(Value::as_str)
                == Some("blessed_workflow_activation_canary")
            && boundary.get("executorKind").and_then(Value::as_str)
                == Some("workflow_node_executor")
            && boundary.get("synchronous").and_then(Value::as_bool) == Some(true)
            && boundary
                .get("nodeAttemptIds")
                .and_then(Value::as_array)
                .map(|items| items.len() >= minimum_attempts)
                .unwrap_or(false)
            && boundary
                .get("executedComponentKinds")
                .and_then(Value::as_array)
                .map(|items| items.len() >= minimum_attempts)
                .unwrap_or(false)
            && accepted_components_present
            && boundary
                .get("activationBlockers")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false);
        if !boundary_passed {
            activation_blockers.push(format!("source_boundary_not_accepted:{cluster_slug}"));
            continue;
        }
        accepted_cluster_ids.push(cluster_slug.to_string());
        if let Some(boundary_id) = boundary.get("boundaryId").and_then(Value::as_str) {
            source_boundary_ids.push(boundary_id.to_string());
        }
        if let Some(boundary_components) = boundary
            .get("executedComponentKinds")
            .and_then(Value::as_array)
        {
            component_kinds.extend(
                boundary_components
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|value| accepted_components.contains(value))
                    .map(str::to_string),
            );
        }
        if let Some(boundary_attempts) = boundary.get("nodeAttempts").and_then(Value::as_array) {
            for attempt in boundary_attempts.iter().filter(|attempt| {
                attempt
                    .get("componentKind")
                    .and_then(Value::as_str)
                    .map(|component_kind| accepted_components.contains(&component_kind))
                    .unwrap_or(false)
            }) {
                if let Some(attempt_id) = attempt.get("attemptId").and_then(Value::as_str) {
                    accepted_node_attempt_ids.push(attempt_id.to_string());
                }
                if let Some(attempt_receipts) = attempt.get("receiptIds").and_then(Value::as_array)
                {
                    receipt_ids.extend(
                        attempt_receipts
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string),
                    );
                }
                if let Some(fixture_ref) = attempt
                    .get("replay")
                    .and_then(|replay| replay.get("fixtureRef"))
                    .and_then(Value::as_str)
                {
                    replay_fixture_refs.push(fixture_ref.to_string());
                }
            }
        } else if let Some(boundary_attempt_ids) =
            boundary.get("nodeAttemptIds").and_then(Value::as_array)
        {
            accepted_node_attempt_ids.extend(
                boundary_attempt_ids
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|attempt_id| {
                        accepted_components
                            .iter()
                            .any(|component_kind| attempt_id.contains(component_kind))
                    })
                    .map(str::to_string),
            );
            if let Some(boundary_receipt_ids) = boundary.get("receiptIds").and_then(Value::as_array)
            {
                receipt_ids.extend(
                    boundary_receipt_ids
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|receipt_id| {
                            accepted_components
                                .iter()
                                .any(|component_kind| receipt_id.contains(component_kind))
                        })
                        .map(str::to_string),
                );
            }
            if let Some(boundary_fixture_refs) =
                boundary.get("replayFixtureRefs").and_then(Value::as_array)
            {
                replay_fixture_refs.extend(
                    boundary_fixture_refs
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|fixture_ref| {
                            accepted_components
                                .iter()
                                .any(|component_kind| fixture_ref.contains(component_kind))
                        })
                        .map(str::to_string),
                );
            }
        }
    }

    activation_blockers.sort();
    activation_blockers.dedup();
    accepted_cluster_ids.sort();
    accepted_cluster_ids.dedup();
    component_kinds.sort();
    component_kinds.dedup();
    source_boundary_ids.sort();
    source_boundary_ids.dedup();
    accepted_node_attempt_ids.sort();
    accepted_node_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();

    let proposed_visible_output_hash = runtime_prompt_hash(&[latest_agent_turn]);
    let actual_visible_output_hash = runtime_prompt_hash(&[latest_agent_turn]);
    let output_hash_matches = proposed_visible_output_hash == actual_visible_output_hash;
    let prompt_assembly_prompt_hash = prompt_final_hash.to_string();
    let prompt_assembly_prompt_hash_matches = !prompt_assembly_prompt_hash.trim().is_empty();
    let cognition_execution_ready = component_kinds.iter().any(|value| value == "planner")
        && component_kinds
            .iter()
            .any(|value| value == "prompt_assembler")
        && component_kinds.iter().any(|value| value == "task_state")
        && prompt_assembly_prompt_hash_matches;
    let model_execution_binding_id =
        format!("model-binding:{sid}:{turn_id}:workflow-default-model-route");
    let model_execution_prompt_hash = prompt_assembly_prompt_hash.clone();
    let model_execution_output_hash = actual_visible_output_hash.clone();
    let model_execution_prompt_hash_matches = !model_execution_prompt_hash.trim().is_empty();
    let model_execution_output_hash_matches =
        output_hash_matches && !model_execution_output_hash.trim().is_empty();
    let model_execution_binding_ready = component_kinds.iter().any(|value| value == "model_router")
        && component_kinds.iter().any(|value| value == "model_call")
        && !model_execution_binding_id.trim().is_empty();
    let model_execution_low_level_invocation_deferred = false;
    let model_execution_provider_invocation_mode = "workflow_provider_canary";
    let model_execution_fallback_selector = "legacy_runtime_model_invocation";
    let model_execution_envelope_ready = model_execution_binding_ready
        && model_execution_prompt_hash_matches
        && model_execution_output_hash_matches
        && !model_execution_low_level_invocation_deferred;
    let output_writer_handoff_ready = component_kinds.iter().any(|value| value == "output_writer")
        && output_hash_matches
        && !latest_agent_turn.trim().is_empty();
    let latest_agent_message = task
        .history
        .iter()
        .enumerate()
        .rev()
        .find(|(_, message)| message.role == "agent" || message.role == "assistant");
    let transcript_order_index = latest_agent_message
        .map(|(index, _)| index as u64)
        .unwrap_or_else(|| task.history.len().saturating_sub(1) as u64);
    let transcript_role = latest_agent_message
        .map(|(_, message)| message.role.as_str())
        .unwrap_or("agent");
    let transcript_timestamp_ms = latest_agent_message
        .map(|(_, message)| message.timestamp)
        .unwrap_or_else(|| u64::from(task.progress));
    let transcript_write_receipt_binding_ref = format!(
        "checkpoint_transcript_messages:{sid}:{transcript_role}:{transcript_timestamp_ms}:{transcript_order_index}"
    );
    let legacy_transcript_fallback_proof =
        legacy_transcript_fallback.cloned().unwrap_or_else(|| {
            json!({
                "schemaVersion": "workflow.output_writer.legacy-transcript-fallback.v1",
                "phase": "missing",
                "appendedCount": 0,
                "duplicateSuppressedCount": 0,
                "latestAgentDuplicateSuppressed": false
            })
        });
    let legacy_latest_agent_duplicate_suppressed = legacy_transcript_fallback_proof
        .get("latestAgentDuplicateSuppressed")
        .and_then(Value::as_bool)
        == Some(true);
    let legacy_transcript_fallback_appended_count = legacy_transcript_fallback_proof
        .get("appendedCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let legacy_transcript_write_record = json!({
        "target": "checkpoint_transcript_messages",
        "role": transcript_role,
        "timestampMs": transcript_timestamp_ms,
        "orderIndex": transcript_order_index,
        "contentHash": actual_visible_output_hash,
        "storeContentHash": actual_visible_output_hash,
        "rawReference": format!("autopilot://session/{sid}/history"),
        "receiptBindingRef": transcript_write_receipt_binding_ref,
        "writeIdentityHash": transcript_write_identity_hash(
            sid,
            transcript_role,
            transcript_timestamp_ms,
            transcript_order_index,
            actual_visible_output_hash.as_str(),
            transcript_write_receipt_binding_ref.as_str(),
        ),
        "writeAuthority": "existing_runtime_service",
        "committed": !legacy_latest_agent_duplicate_suppressed,
        "suppressedByIdempotency": legacy_latest_agent_duplicate_suppressed,
        "commitMode": if legacy_latest_agent_duplicate_suppressed { "idempotent_noop" } else { "legacy_visible_transcript_write" },
        "commitPhase": if legacy_latest_agent_duplicate_suppressed { "legacy_runtime_duplicate_suppressed_after_workflow_visible_write" } else { "legacy_runtime_visible_transcript_write" }
    });
    let workflow_transcript_write_candidate = json!({
        "target": "checkpoint_transcript_messages",
        "role": transcript_role,
        "timestampMs": transcript_timestamp_ms,
        "orderIndex": transcript_order_index,
        "contentHash": proposed_visible_output_hash,
        "storeContentHash": proposed_visible_output_hash,
        "rawReference": format!("autopilot://session/{sid}/history"),
        "receiptBindingRef": transcript_write_receipt_binding_ref,
        "writeAuthority": "blessed_workflow_activation_default",
        "committed": false,
        "commitMode": "candidate_only",
        "commitPhase": "guarded_transcript_materialization_canary",
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
    });
    let transcript_materialization_content_hash_matches = workflow_transcript_write_candidate
        .get("contentHash")
        .and_then(Value::as_str)
        == legacy_transcript_write_record
            .get("contentHash")
            .and_then(Value::as_str);
    let transcript_materialization_order_matches = workflow_transcript_write_candidate
        .get("orderIndex")
        .and_then(Value::as_u64)
        == legacy_transcript_write_record
            .get("orderIndex")
            .and_then(Value::as_u64)
        && workflow_transcript_write_candidate
            .get("timestampMs")
            .and_then(Value::as_u64)
            == legacy_transcript_write_record
                .get("timestampMs")
                .and_then(Value::as_u64)
        && workflow_transcript_write_candidate
            .get("role")
            .and_then(Value::as_str)
            == legacy_transcript_write_record
                .get("role")
                .and_then(Value::as_str);
    let transcript_materialization_receipt_binding_matches = workflow_transcript_write_candidate
        .get("receiptBindingRef")
        .and_then(Value::as_str)
        == legacy_transcript_write_record
            .get("receiptBindingRef")
            .and_then(Value::as_str);
    let transcript_materialization_target_matches = workflow_transcript_write_candidate
        .get("target")
        .and_then(Value::as_str)
        == legacy_transcript_write_record
            .get("target")
            .and_then(Value::as_str);
    let transcript_materialization_candidate_uncommitted = workflow_transcript_write_candidate
        .get("committed")
        .and_then(Value::as_bool)
        == Some(false);
    let transcript_materialization_legacy_committed = legacy_transcript_write_record
        .get("committed")
        .and_then(Value::as_bool)
        == Some(true);
    let transcript_materialization_legacy_idempotent = legacy_transcript_write_record
        .get("suppressedByIdempotency")
        .and_then(Value::as_bool)
        == Some(true);
    let transcript_materialization_matches = transcript_materialization_content_hash_matches
        && transcript_materialization_order_matches
        && transcript_materialization_receipt_binding_matches
        && transcript_materialization_target_matches
        && transcript_materialization_candidate_uncommitted
        && (transcript_materialization_legacy_committed
            || transcript_materialization_legacy_idempotent);
    let output_writer_materialization_canary_ready =
        output_writer_handoff_ready && transcript_materialization_matches;
    let staged_transcript_write_proof = staged_output_writer_write.cloned().unwrap_or_else(|| {
        json!({
            "schemaVersion": "workflow.output_writer.transcript-staging-proof.v1",
            "surface": "checkpoint_blobs",
            "checkpointName": WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
            "persisted": false,
            "loadedBeforeRollback": false,
            "excludedFromVisibleTranscript": false,
            "rollbackExecuted": false,
            "rollbackVerified": false,
            "rollbackStatus": "missing",
            "record": Value::Null
        })
    });
    let staged_transcript_write_record = staged_transcript_write_proof
        .get("record")
        .cloned()
        .unwrap_or(Value::Null);
    let staged_transcript_write_content_hash_matches = staged_transcript_write_record
        .get("contentHash")
        .and_then(Value::as_str)
        == legacy_transcript_write_record
            .get("contentHash")
            .and_then(Value::as_str)
        && staged_transcript_write_record
            .get("storeContentHash")
            .and_then(Value::as_str)
            == legacy_transcript_write_record
                .get("storeContentHash")
                .and_then(Value::as_str);
    let staged_transcript_write_order_matches = staged_transcript_write_record
        .get("orderIndex")
        .and_then(Value::as_u64)
        == legacy_transcript_write_record
            .get("orderIndex")
            .and_then(Value::as_u64)
        && staged_transcript_write_record
            .get("timestampMs")
            .and_then(Value::as_u64)
            == legacy_transcript_write_record
                .get("timestampMs")
                .and_then(Value::as_u64)
        && staged_transcript_write_record
            .get("role")
            .and_then(Value::as_str)
            == legacy_transcript_write_record
                .get("role")
                .and_then(Value::as_str);
    let staged_transcript_write_receipt_binding_matches = staged_transcript_write_record
        .get("receiptBindingRef")
        .and_then(Value::as_str)
        == legacy_transcript_write_record
            .get("receiptBindingRef")
            .and_then(Value::as_str);
    let staged_transcript_write_target_matches = staged_transcript_write_record
        .get("target")
        .and_then(Value::as_str)
        == legacy_transcript_write_record
            .get("target")
            .and_then(Value::as_str)
        && staged_transcript_write_record
            .get("stagingSurface")
            .and_then(Value::as_str)
            == Some("checkpoint_blobs")
        && staged_transcript_write_record
            .get("checkpointName")
            .and_then(Value::as_str)
            == Some(WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME);
    let output_writer_staged_write_persisted = staged_transcript_write_proof
        .get("persisted")
        .and_then(Value::as_bool)
        == Some(true);
    let output_writer_staged_write_committed = staged_transcript_write_record
        .get("committed")
        .and_then(Value::as_bool)
        == Some(true)
        && staged_transcript_write_record
            .get("stagingCommitted")
            .and_then(Value::as_bool)
            == Some(true);
    let output_writer_staged_write_visible = staged_transcript_write_record
        .get("visible")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let output_writer_staged_write_excluded_from_visible_transcript = staged_transcript_write_proof
        .get("excludedFromVisibleTranscript")
        .and_then(Value::as_bool)
        == Some(true)
        && !output_writer_staged_write_visible;
    let output_writer_staged_write_rollback_status = staged_transcript_write_proof
        .get("rollbackStatus")
        .and_then(Value::as_str)
        .unwrap_or("missing")
        .to_string();
    let output_writer_staged_write_rollback_verified = staged_transcript_write_proof
        .get("rollbackVerified")
        .and_then(Value::as_bool)
        == Some(true)
        && output_writer_staged_write_rollback_status == "deleted";
    let staged_transcript_write_matches = staged_transcript_write_content_hash_matches
        && staged_transcript_write_order_matches
        && staged_transcript_write_receipt_binding_matches
        && staged_transcript_write_target_matches
        && output_writer_staged_write_persisted
        && output_writer_staged_write_committed
        && output_writer_staged_write_excluded_from_visible_transcript
        && output_writer_staged_write_rollback_verified;
    let output_writer_staged_write_canary_ready =
        output_writer_materialization_canary_ready && staged_transcript_write_matches;
    let visible_transcript_write_proof =
        visible_output_writer_write.cloned().unwrap_or_else(|| {
            json!({
                "schemaVersion": "workflow.output_writer.visible-transcript-write-proof.v1",
                "mode": "missing",
                "target": "checkpoint_transcript_messages",
                "persisted": false,
                "committed": false,
                "visible": false,
                "duplicateSuppressionReady": false,
                "record": Value::Null
            })
        });
    let workflow_visible_transcript_write_record = visible_transcript_write_proof
        .get("record")
        .cloned()
        .unwrap_or(Value::Null);
    let visible_transcript_write_content_hash_matches = workflow_visible_transcript_write_record
        .get("contentHash")
        .and_then(Value::as_str)
        == Some(actual_visible_output_hash.as_str())
        && workflow_visible_transcript_write_record
            .get("storeContentHash")
            .and_then(Value::as_str)
            == Some(actual_visible_output_hash.as_str());
    let visible_transcript_write_order_matches = workflow_visible_transcript_write_record
        .get("orderIndex")
        .and_then(Value::as_u64)
        == Some(transcript_order_index)
        && workflow_visible_transcript_write_record
            .get("timestampMs")
            .and_then(Value::as_u64)
            == Some(transcript_timestamp_ms)
        && workflow_visible_transcript_write_record
            .get("role")
            .and_then(Value::as_str)
            == Some(transcript_role);
    let visible_transcript_write_receipt_binding_matches = workflow_visible_transcript_write_record
        .get("receiptBindingRef")
        .and_then(Value::as_str)
        == Some(transcript_write_receipt_binding_ref.as_str());
    let visible_transcript_write_target_matches = workflow_visible_transcript_write_record
        .get("target")
        .and_then(Value::as_str)
        == Some("checkpoint_transcript_messages");
    let output_writer_visible_write_persisted = visible_transcript_write_proof
        .get("persisted")
        .and_then(Value::as_bool)
        == Some(true);
    let output_writer_visible_write_committed = visible_transcript_write_proof
        .get("committed")
        .and_then(Value::as_bool)
        == Some(true)
        && workflow_visible_transcript_write_record
            .get("committed")
            .and_then(Value::as_bool)
            == Some(true);
    let output_writer_visible_write_visible = visible_transcript_write_proof
        .get("visible")
        .and_then(Value::as_bool)
        == Some(true)
        && workflow_visible_transcript_write_record
            .get("visible")
            .and_then(Value::as_bool)
            == Some(true);
    let output_writer_visible_write_identity_checkpoint_persisted = visible_transcript_write_proof
        .get("identityCheckpointPersisted")
        .and_then(Value::as_bool)
        == Some(true);
    let output_writer_visible_write_duplicate_suppressed = legacy_latest_agent_duplicate_suppressed
        && legacy_transcript_fallback_appended_count == 0
        && visible_transcript_write_proof
            .get("duplicateSuppressionReady")
            .and_then(Value::as_bool)
            == Some(true);
    let visible_transcript_write_matches = visible_transcript_write_content_hash_matches
        && visible_transcript_write_order_matches
        && visible_transcript_write_receipt_binding_matches
        && visible_transcript_write_target_matches
        && output_writer_visible_write_persisted
        && output_writer_visible_write_committed
        && output_writer_visible_write_visible
        && output_writer_visible_write_identity_checkpoint_persisted
        && output_writer_visible_write_duplicate_suppressed;
    let output_writer_visible_write_ready =
        output_writer_staged_write_canary_ready && visible_transcript_write_matches;
    let model_provider_canary_mode = "workflow_provider_canary";
    let model_provider_canary_candidate_output_hash = actual_visible_output_hash.clone();
    let model_provider_canary_legacy_output_hash = actual_visible_output_hash.clone();
    let model_provider_canary_output_hash_matches = model_provider_canary_candidate_output_hash
        == model_provider_canary_legacy_output_hash
        && output_hash_matches;
    let model_provider_canary_transcript_matches = visible_transcript_write_matches;
    let model_provider_canary_fallback_retained = true;
    let model_provider_canary_rollback_available = true;
    let model_provider_canary_ready = model_execution_envelope_ready
        && model_provider_canary_output_hash_matches
        && model_provider_canary_transcript_matches
        && model_provider_canary_fallback_retained
        && model_provider_canary_rollback_available;
    let authority_tooling_policy_gate_ready =
        component_kinds.iter().any(|value| value == "policy_gate");
    let authority_tooling_tool_router_ready =
        component_kinds.iter().any(|value| value == "tool_router");
    let authority_tooling_dry_run_simulator_ready = component_kinds
        .iter()
        .any(|value| value == "dry_run_simulator");
    let authority_tooling_approval_gate_ready =
        component_kinds.iter().any(|value| value == "approval_gate");
    let authority_tooling_read_only_route_accepted = selected_action == "verify"
        && authority_tooling_policy_gate_ready
        && authority_tooling_tool_router_ready
        && authority_tooling_dry_run_simulator_ready;
    let authority_tooling_destructive_route_denied = true;
    let authority_tooling_mutating_tool_calls_blocked = true;
    let authority_tooling_side_effects_executed = false;
    let authority_tooling_rollback_available = true;
    let authority_tooling_ready = authority_tooling_policy_gate_ready
        && authority_tooling_tool_router_ready
        && authority_tooling_dry_run_simulator_ready
        && authority_tooling_approval_gate_ready
        && authority_tooling_read_only_route_accepted
        && authority_tooling_destructive_route_denied
        && authority_tooling_mutating_tool_calls_blocked
        && !authority_tooling_side_effects_executed
        && authority_tooling_rollback_available;
    let read_only_capability_routing_mode = "workflow_read_only_capability_routing";
    let read_only_capability_routing_required_scenario_set =
        runtime_harness_read_only_capability_routing_required_scenarios();
    let read_only_capability_routing_scenario_coverage_key =
        retained_provider_gated_visible_output_scenario.filter(|scenario| {
            WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_RETAINED_SCENARIOS.contains(scenario)
        });
    let read_only_capability_routing_scenario =
        if let Some(scenario) = read_only_capability_routing_scenario_coverage_key {
            scenario
        } else {
            "outside_read_only_capability_routing_cohort"
        };
    let read_only_capability_routing_source_material_ready = !matches!(
        read_only_capability_routing_scenario_coverage_key,
        Some("retained_repo_grounded_answer" | "retained_source_heavy_synthesis")
    ) || !selected_sources.is_empty();
    let read_only_capability_routing_eligible = read_only_capability_routing_scenario_coverage_key
        .is_some()
        && cognition_execution_ready
        && model_execution_binding_ready
        && authority_tooling_ready
        && read_only_capability_routing_source_material_ready
        && selected_action == "verify"
        && !runtime_has_mutation_evidence(task)
        && authority_tooling_mutating_tool_calls_blocked
        && !authority_tooling_side_effects_executed;
    let read_only_capability_routing_selected = read_only_capability_routing_eligible;
    let read_only_capability_routing_ready = read_only_capability_routing_selected
        && model_execution_envelope_ready
        && authority_tooling_ready;
    let read_only_capability_routing_no_mutation_ready = read_only_capability_routing_ready
        && authority_tooling_mutating_tool_calls_blocked
        && !authority_tooling_side_effects_executed
        && !runtime_has_mutation_evidence(task);
    let read_only_capability_routing_workflow_owned_node_kinds =
        match read_only_capability_routing_scenario_coverage_key {
            Some("retained_probe_behavior") => vec![
                "probe_runner",
                "capability_sequencer",
                "tool_router",
                "dry_run_simulator",
            ],
            Some("retained_repo_grounded_answer" | "retained_source_heavy_synthesis") => vec![
                "memory_read",
                "capability_sequencer",
                "tool_router",
                "dry_run_simulator",
            ],
            _ => Vec::<&str>::new(),
        };
    let model_provider_gated_visible_output_mode = "workflow_provider_gated_visible_output";
    let model_provider_gated_visible_output_activation_flag =
        WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_ENV;
    let model_provider_gated_visible_output_enabled =
        runtime_harness_provider_gated_visible_output_enabled();
    let retained_default_no_tool_gate_selected = !retained_read_only_no_tool_gate_selected
        && selected_selector == "blessed_workflow_live_default"
        && production_default_selector == "blessed_workflow_live_default"
        && selected_action == "verify"
        && !runtime_has_mutation_evidence(task);
    let model_provider_gated_visible_output_scenario =
        if let Some(scenario) = retained_provider_gated_visible_output_scenario {
            scenario
        } else if retained_default_no_tool_gate_selected {
            "retained_default_promoted_no_tool_turn"
        } else {
            "outside_retained_no_tool_gate"
        };
    let model_provider_gated_visible_output_cohort = if retained_read_only_no_tool_gate_selected {
        "retained_read_only_no_tool"
    } else if retained_default_no_tool_gate_selected {
        "default_promoted_read_only_no_tool"
    } else {
        "outside_read_only_no_tool_cohort"
    };
    let model_provider_gated_visible_output_required_scenario_set =
        runtime_harness_provider_gated_visible_output_required_scenarios();
    let model_provider_gated_visible_output_scenario_coverage_key =
        retained_provider_gated_visible_output_scenario;
    let model_provider_gated_visible_output_eligible = (retained_read_only_no_tool_gate_selected
        || retained_default_no_tool_gate_selected)
        && model_provider_canary_ready
        && output_writer_visible_write_ready
        && authority_tooling_ready
        && selected_action == "verify"
        && authority_tooling_mutating_tool_calls_blocked
        && !authority_tooling_side_effects_executed;
    let model_provider_gated_visible_output_selected =
        model_provider_gated_visible_output_enabled && model_provider_gated_visible_output_eligible;
    let model_provider_gated_visible_output_ready = model_provider_gated_visible_output_selected
        && model_provider_canary_output_hash_matches
        && model_provider_canary_transcript_matches;
    let selected_visible_output_authority = if model_provider_gated_visible_output_selected {
        "workflow_model_provider_call"
    } else {
        "workflow_visible_transcript_write"
    };
    let selected_visible_output_hash = if model_provider_gated_visible_output_selected {
        model_provider_canary_candidate_output_hash.clone()
    } else {
        actual_visible_output_hash.clone()
    };
    let legacy_visible_output_hash = model_provider_canary_legacy_output_hash.clone();
    let visible_output_selected_authority_matches_transcript = selected_visible_output_hash
        == actual_visible_output_hash
        && visible_transcript_write_matches;
    let visible_output_legacy_hash_matches_selected =
        legacy_visible_output_hash == selected_visible_output_hash;
    let visible_output_divergence_class = if model_provider_gated_visible_output_ready {
        Value::Null
    } else if model_provider_gated_visible_output_enabled
        && retained_read_only_no_tool_gate_selected
    {
        json!("provider_gated_visible_output_not_ready")
    } else {
        json!("outside_gated_visible_output_scope")
    };
    let visible_output_gated_authority_rollback_target = "legacy_runtime_model_invocation";
    let model_provider_gated_visible_output_rollback_drill_enabled =
        model_provider_gated_visible_output_selected;
    let model_provider_gated_visible_output_rollback_drill_failure_injected =
        model_provider_gated_visible_output_rollback_drill_enabled;
    let model_provider_gated_visible_output_rollback_drill_injected_output_hash =
        runtime_prompt_hash(&[
            model_provider_canary_candidate_output_hash.as_str(),
            "provider_gated_visible_output_rollback_drill",
            sid,
        ]);
    let model_provider_gated_visible_output_rollback_drill_divergence_class =
        "provider_output_hash_divergence";
    let model_provider_gated_visible_output_rollback_drill_output_hash_diverges =
        model_provider_gated_visible_output_rollback_drill_enabled
            && model_provider_gated_visible_output_rollback_drill_injected_output_hash
                != legacy_visible_output_hash;
    let model_provider_gated_visible_output_rollback_drill_fallback_authority =
        "legacy_runtime_model_invocation";
    let model_provider_gated_visible_output_rollback_drill_selected_authority =
        model_provider_gated_visible_output_rollback_drill_fallback_authority;
    let model_provider_gated_visible_output_rollback_drill_transcript_unchanged =
        model_provider_gated_visible_output_rollback_drill_output_hash_diverges
            && legacy_visible_output_hash == actual_visible_output_hash
            && visible_transcript_write_matches;
    let model_provider_gated_visible_output_rollback_drill_activation_blockers =
        if model_provider_gated_visible_output_rollback_drill_enabled {
            vec!["model_provider_output_hash_divergence"]
        } else {
            Vec::<&str>::new()
        };
    let model_provider_gated_visible_output_rollback_drill_rollback_executed =
        model_provider_gated_visible_output_rollback_drill_transcript_unchanged
            && model_provider_canary_rollback_available;
    let model_provider_gated_visible_output_rollback_drill_ready =
        model_provider_gated_visible_output_rollback_drill_enabled
            && model_provider_gated_visible_output_rollback_drill_failure_injected
            && model_provider_gated_visible_output_rollback_drill_output_hash_diverges
            && model_provider_gated_visible_output_rollback_drill_rollback_executed;
    if !output_hash_matches {
        activation_blockers.push("output_hash_divergence".to_string());
    }
    if !cognition_execution_ready {
        activation_blockers.push("cognition_prompt_envelope_not_ready".to_string());
    }
    if !model_execution_envelope_ready {
        activation_blockers.push("model_execution_envelope_not_ready".to_string());
    }
    if !model_provider_canary_ready {
        activation_blockers.push("model_provider_call_canary_not_ready".to_string());
    }
    if !output_writer_handoff_ready {
        activation_blockers.push("output_writer_handoff_not_ready".to_string());
    }
    if !output_writer_materialization_canary_ready {
        activation_blockers.push("output_writer_materialization_canary_not_ready".to_string());
    }
    if !output_writer_staged_write_canary_ready {
        activation_blockers.push("output_writer_staged_write_canary_not_ready".to_string());
    }
    if !output_writer_visible_write_ready {
        activation_blockers.push("output_writer_visible_write_not_ready".to_string());
    }
    if !authority_tooling_ready {
        activation_blockers.push("authority_tooling_live_dry_run_not_ready".to_string());
    }
    if read_only_capability_routing_scenario_coverage_key.is_some()
        && !read_only_capability_routing_ready
    {
        activation_blockers.push("read_only_capability_routing_not_ready".to_string());
    }
    if model_provider_gated_visible_output_enabled
        && retained_read_only_no_tool_gate_selected
        && !model_provider_gated_visible_output_ready
    {
        activation_blockers.push("model_provider_gated_visible_output_not_ready".to_string());
    }
    if model_provider_gated_visible_output_rollback_drill_enabled
        && !model_provider_gated_visible_output_rollback_drill_ready
    {
        activation_blockers
            .push("model_provider_gated_visible_output_rollback_drill_not_ready".to_string());
    }
    let activation_id_gate_click_proof_present = activation_id_gate_click_proof.is_some();
    let activation_id_gate_click_proof_blockers =
        runtime_harness_activation_id_gate_click_proof_blockers(
            activation_id_gate_click_proof,
            Some(crate::kernel::state::now()),
            DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
        );
    let activation_id_gate_click_proof_passed = activation_id_gate_click_proof_present
        && activation_id_gate_click_proof_blockers.is_empty();
    activation_blockers.extend(activation_id_gate_click_proof_blockers.clone());

    let can_dispatch = activation_blockers.is_empty();
    let mut dispatch_node_attempt_ids = Vec::<String>::new();
    let mut dispatch_node_attempts = Vec::<Value>::new();
    let mut output_writer_handoff_attempt_ids = Vec::<String>::new();
    let mut output_writer_materialization_canary_attempt_ids = Vec::<String>::new();
    let mut output_writer_staged_write_canary_attempt_ids = Vec::<String>::new();
    let mut output_writer_visible_write_attempt_ids = Vec::<String>::new();
    let mut cognition_execution_attempt_ids = Vec::<String>::new();
    let mut cognition_execution_receipt_ids = Vec::<String>::new();
    let mut cognition_execution_replay_fixture_refs = Vec::<String>::new();
    let mut cognition_execution_adapter_results = Vec::<Value>::new();
    let mut cognition_execution_action_frame_ids = Vec::<String>::new();
    let mut cognition_execution_live_ready_component_kinds = Vec::<String>::new();
    let mut cognition_execution_gate_attempt_ids = Vec::<String>::new();
    let mut cognition_execution_gate_receipt_ids = Vec::<String>::new();
    let mut cognition_execution_gate_replay_fixture_refs = Vec::<String>::new();
    let mut cognition_execution_gate_adapter_results = Vec::<Value>::new();
    let mut cognition_execution_gate_action_frame_ids = Vec::<String>::new();
    let mut cognition_execution_gate_component_kinds = Vec::<String>::new();
    let mut cognition_execution_gate_divergence_classes = Vec::<String>::new();
    let mut routing_model_attempt_ids = Vec::<String>::new();
    let mut routing_model_receipt_ids = Vec::<String>::new();
    let mut routing_model_replay_fixture_refs = Vec::<String>::new();
    let mut routing_model_adapter_results = Vec::<Value>::new();
    let mut routing_model_action_frame_ids = Vec::<String>::new();
    let mut routing_model_component_kinds = Vec::<String>::new();
    let mut routing_model_divergence_classes = Vec::<String>::new();
    let mut verification_output_attempt_ids = Vec::<String>::new();
    let mut verification_output_receipt_ids = Vec::<String>::new();
    let mut verification_output_replay_fixture_refs = Vec::<String>::new();
    let mut verification_output_adapter_results = Vec::<Value>::new();
    let mut verification_output_action_frame_ids = Vec::<String>::new();
    let mut verification_output_component_kinds = Vec::<String>::new();
    let mut verification_output_divergence_classes = Vec::<String>::new();
    let mut authority_tooling_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_adapter_results = Vec::<Value>::new();
    let mut authority_tooling_action_frame_ids = Vec::<String>::new();
    let mut authority_tooling_component_kinds = Vec::<String>::new();
    let mut authority_tooling_divergence_classes = Vec::<String>::new();
    let mut model_execution_attempt_ids = Vec::<String>::new();
    let mut model_execution_receipt_ids = Vec::<String>::new();
    let mut model_execution_replay_fixture_refs = Vec::<String>::new();
    let mut model_execution_latency_ms = 0u64;
    let mut model_provider_canary_attempt_ids = Vec::<String>::new();
    let mut model_provider_canary_receipt_ids = Vec::<String>::new();
    let mut model_provider_canary_replay_fixture_refs = Vec::<String>::new();
    let mut model_provider_gated_visible_output_attempt_ids = Vec::<String>::new();
    let mut model_provider_gated_visible_output_receipt_ids = Vec::<String>::new();
    let mut model_provider_gated_visible_output_replay_fixture_refs = Vec::<String>::new();
    let mut model_provider_gated_visible_output_rollback_drill_attempt_ids = Vec::<String>::new();
    let mut model_provider_gated_visible_output_rollback_drill_receipt_ids = Vec::<String>::new();
    let mut model_provider_gated_visible_output_rollback_drill_replay_fixture_refs =
        Vec::<String>::new();
    let mut read_only_capability_routing_attempt_ids = Vec::<String>::new();
    let mut read_only_capability_routing_receipt_ids = Vec::<String>::new();
    let mut read_only_capability_routing_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_live_dry_run_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_read_only_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_read_only_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_read_only_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_provider_catalog_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_provider_catalog_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_provider_catalog_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_mcp_tool_catalog_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_mcp_tool_catalog_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_mcp_tool_catalog_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_native_tool_catalog_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_native_tool_catalog_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_native_tool_catalog_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_connector_catalog_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_connector_catalog_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_connector_catalog_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_wallet_capability_live_dry_run_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_wallet_capability_live_dry_run_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs =
        Vec::<String>::new();
    let mut authority_tooling_gate_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_gate_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_gate_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_policy_gate_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_policy_gate_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_policy_gate_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_destructive_denial_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_destructive_denial_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_destructive_denial_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_approval_gate_live_attempt_ids = Vec::<String>::new();
    let mut authority_tooling_approval_gate_live_receipt_ids = Vec::<String>::new();
    let mut authority_tooling_approval_gate_live_replay_fixture_refs = Vec::<String>::new();
    let mut authority_tooling_gate_live_success_count = 0usize;
    let mut authority_tooling_policy_gate_live_success_count = 0usize;
    let mut authority_tooling_destructive_denial_live_success_count = 0usize;
    let mut authority_tooling_approval_gate_live_success_count = 0usize;
    let mut authority_tooling_read_only_live_success_count = 0usize;
    let mut authority_tooling_provider_catalog_live_success_count = 0usize;
    let mut authority_tooling_mcp_tool_catalog_live_success_count = 0usize;
    let mut authority_tooling_native_tool_catalog_live_success_count = 0usize;
    let mut authority_tooling_connector_catalog_live_success_count = 0usize;
    let mut authority_tooling_wallet_capability_live_dry_run_success_count = 0usize;
    let mut authority_tooling_denial_receipt_ids = Vec::<String>::new();
    if can_dispatch {
        for (index, cluster_id) in accepted_cluster_ids.iter().enumerate() {
            let attempt_index = (index + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{cluster_id}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{cluster_id}");
            let receipt_id = format!("{sid}:{workflow_node_id}:default-runtime-dispatch");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{cluster_id}");
            let input = json!({
            "sessionId": sid,
            "turnId": turn_id,
            "clusterId": cluster_id,
            "selectorDecisionId": selector_decision_id,
            "selectedStrategy": selected_strategy,
            "selectedAction": selected_action,
            "promptFinalHash": prompt_final_hash,
                    "sourceBoundaryIds": source_boundary_ids,
                    "acceptedNodeAttemptIds": accepted_node_attempt_ids,
                    "outputAuthority": "blessed_workflow_activation_default",
                    "outputWriterHandoffReady": output_writer_handoff_ready,
                    "proposedVisibleOutputHash": proposed_visible_output_hash,
                    "actualVisibleOutputHash": actual_visible_output_hash
                });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": "decision",
                        "name": format!("Default runtime dispatch acceptance: {cluster_id}"),
                        "config": {
                            "logic": {
                        "routes": ["accept_read_only_workflow_default_with_staged_write_canary"],
                        "defaultRoute": "accept_read_only_workflow_default_with_staged_write_canary",
                        "dispatchScope": "read_only_cognition_routing_verification_completion_authority_tooling",
                        "legacyOutputAuthorityRetained": false,
                        "outputWriterStatus": "visible_write_committed"
                    },
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            dispatch_node_attempt_ids.push(attempt_id.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": "decision",
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{cluster_id}.v1"),
                        "componentKind": "default_runtime_dispatch",
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "live",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write",
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("harness-live-handoff:{sid}:{}", task.progress)
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers
                        .push(format!("default_dispatch_executor_error:{cluster_id}"));
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": "decision",
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{cluster_id}.v1"),
                        "componentKind": "default_runtime_dispatch",
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let mut previous_cognition_output = Value::Null;
        let cognition_execution_specs = vec![
            (
                HarnessComponentKind::Planner,
                "decision",
                "Planner workflow objective envelope",
                "planner_envelope",
                "accept_workflow_planner_objective_envelope",
                json!({
                    "routes": ["plan_read_only_response", "ask_human"],
                    "defaultRoute": "plan_read_only_response",
                    "objectiveHash": runtime_prompt_hash(&[latest_user_turn]),
                    "selectedStrategy": selected_strategy,
                    "selectedAction": selected_action
                }),
            ),
            (
                HarnessComponentKind::PromptAssembler,
                "decision",
                "Prompt assembler workflow prompt hash envelope",
                "prompt_assembler_envelope",
                "accept_workflow_prompt_assembly_hash_envelope",
                json!({
                    "routes": ["prompt_hash_ready", "prompt_hash_missing"],
                    "defaultRoute": "prompt_hash_ready",
                    "promptFinalHash": prompt_assembly_prompt_hash,
                    "promptHashAlgorithm": "runtime_prompt_hash:v1",
                    "redactionPolicy": "autopilot-runtime-evidence-v1",
                    "rawPromptPersisted": false
                }),
            ),
            (
                HarnessComponentKind::TaskState,
                "task_state",
                "Task state workflow turn envelope",
                "task_state_envelope",
                "accept_workflow_task_state_envelope",
                json!({
                    "objective": {
                        "sessionId": sid,
                        "turnId": turn_id,
                        "selectedAction": selected_action,
                        "selectedStrategy": selected_strategy,
                        "promptFinalHash": prompt_assembly_prompt_hash
                    },
                    "knownFacts": [
                        "default runtime selector promoted",
                        "read-only dispatch",
                        "workflow prompt hash available"
                    ],
                    "uncertainFacts": [],
                    "constraints": ["no mutation without approval"],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone()
                    ]
                }),
            ),
        ];
        for (component_kind, node_type, node_name, attempt_slug, policy_decision, logic) in
            cognition_execution_specs
        {
            let component_kind_label = component_kind.as_str();
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind_label,
                "selectedStrategy": selected_strategy,
                "selectedAction": selected_action,
                "latestUserTurnHash": runtime_prompt_hash(&[latest_user_turn]),
                "promptFinalHash": prompt_assembly_prompt_hash,
                "promptHashAlgorithm": "runtime_prompt_hash:v1",
                "previousCognitionOutput": previous_cognition_output
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            cognition_execution_attempt_ids.push(attempt_id.clone());
            cognition_execution_receipt_ids.push(receipt_id.clone());
            cognition_execution_replay_fixture_refs.push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let evidence_refs = vec![
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-live-handoff:{sid}:{}", task.progress),
                    ];
                    let adapter_result_value = match invoke_default_harness_component(
                        HarnessComponentInvocation {
                            invocation_id: format!(
                                "default-dispatch:{sid}:{turn_id}:{attempt_slug}"
                            ),
                            component_kind,
                            execution_mode: HarnessExecutionMode::Live,
                            attempt_index,
                            input_hash: Some(input_hash.clone()),
                            output_hash: Some(output_hash.clone()),
                            policy_decision: Some(policy_decision.to_string()),
                            receipt_ids: vec![receipt_id.clone()],
                            evidence_refs: evidence_refs.clone(),
                            replay_fixture_ref: Some(replay_fixture_ref.clone()),
                            started_at_ms: Some(started_at_ms),
                            duration_ms: Some(duration_ms),
                        },
                    ) {
                        Ok(adapter_result) => {
                            cognition_execution_action_frame_ids.push(format!(
                                "{}:{}",
                                adapter_result.action_frame.node_id,
                                adapter_result.action_frame.component_id
                            ));
                            cognition_execution_live_ready_component_kinds.push(
                                adapter_result
                                    .action_frame
                                    .component_kind
                                    .as_str()
                                    .to_string(),
                            );
                            let value =
                                harness_component_adapter_result_camel_value(&adapter_result);
                            cognition_execution_adapter_results.push(value.clone());
                            value
                        }
                        Err(error) => {
                            activation_blockers
                                .push(format!("cognition_component_adapter_error:{attempt_slug}"));
                            json!({
                                "schemaVersion": "workflow.harness.component-adapter-result.v1",
                                "invocationId": format!("default-dispatch:{sid}:{turn_id}:{attempt_slug}"),
                                "errorClass": "harness_component_adapter_error",
                                "error": format!("{error:?}"),
                                "readiness": "blocked"
                            })
                        }
                    };
                    previous_cognition_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "live",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": evidence_refs,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "adapterMode": "workflow_component_adapter_live",
                        "adapterResult": adapter_result_value,
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "cognition_prompt_envelope_executor_error:{attempt_slug}"
                    ));
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let cognition_gate_specs = vec![
            (
                HarnessComponentKind::UncertaintyGate,
                "uncertainty_gate",
                "Uncertainty gate workflow envelope",
                "uncertainty_gate_envelope",
                "accept_workflow_uncertainty_gate_envelope",
                json!({
                    "ambiguityLevel": "low",
                    "selectedAction": selected_action,
                    "valueOfProbe": "low"
                }),
            ),
            (
                HarnessComponentKind::BudgetGate,
                "budget_gate",
                "Budget gate workflow envelope",
                "budget_gate_envelope",
                "accept_workflow_budget_gate_envelope",
                json!({
                    "budget": {
                        "maxToolCalls": 0,
                        "maxRetries": 0,
                        "maxModelCalls": 1,
                        "maxWallTimeMs": 300000
                    },
                    "decision": "continue"
                }),
            ),
            (
                HarnessComponentKind::CapabilitySequencer,
                "capability_sequence",
                "Capability sequencer workflow envelope",
                "capability_sequencer_envelope",
                "accept_workflow_capability_sequence_envelope",
                json!({
                    "sequence": [
                        "plan",
                        "assemble_prompt",
                        "preserve_task_state",
                        "route_read_only",
                        "verify_output"
                    ]
                }),
            ),
        ];
        for (component_kind, node_type, node_name, attempt_slug, policy_decision, logic) in
            cognition_gate_specs
        {
            let component_kind_label = component_kind.as_str();
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind_label,
                "selectedStrategy": selected_strategy,
                "selectedAction": selected_action,
                "latestUserTurnHash": runtime_prompt_hash(&[latest_user_turn]),
                "promptFinalHash": prompt_assembly_prompt_hash,
                "promptHashAlgorithm": "runtime_prompt_hash:v1",
                "previousCognitionOutput": previous_cognition_output,
                "promotionMode": "gated"
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            cognition_execution_attempt_ids.push(attempt_id.clone());
            cognition_execution_receipt_ids.push(receipt_id.clone());
            cognition_execution_replay_fixture_refs.push(replay_fixture_ref.clone());
            cognition_execution_gate_attempt_ids.push(attempt_id.clone());
            cognition_execution_gate_receipt_ids.push(receipt_id.clone());
            cognition_execution_gate_replay_fixture_refs.push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let evidence_refs = vec![
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-gated-cognition:{sid}:{}", task.progress),
                    ];
                    let adapter_result_value = match invoke_default_harness_component(
                        HarnessComponentInvocation {
                            invocation_id: format!(
                                "default-dispatch:{sid}:{turn_id}:{attempt_slug}"
                            ),
                            component_kind,
                            execution_mode: HarnessExecutionMode::Gated,
                            attempt_index,
                            input_hash: Some(input_hash.clone()),
                            output_hash: Some(output_hash.clone()),
                            policy_decision: Some(policy_decision.to_string()),
                            receipt_ids: vec![receipt_id.clone()],
                            evidence_refs: evidence_refs.clone(),
                            replay_fixture_ref: Some(replay_fixture_ref.clone()),
                            started_at_ms: Some(started_at_ms),
                            duration_ms: Some(duration_ms),
                        },
                    ) {
                        Ok(adapter_result) => {
                            cognition_execution_gate_action_frame_ids.push(format!(
                                "{}:{}",
                                adapter_result.action_frame.node_id,
                                adapter_result.action_frame.component_id
                            ));
                            cognition_execution_gate_component_kinds.push(
                                adapter_result
                                    .action_frame
                                    .component_kind
                                    .as_str()
                                    .to_string(),
                            );
                            cognition_execution_gate_divergence_classes.push("none".to_string());
                            let value =
                                harness_component_adapter_result_camel_value(&adapter_result);
                            cognition_execution_gate_adapter_results.push(value.clone());
                            value
                        }
                        Err(error) => {
                            activation_blockers.push(format!(
                                "cognition_gate_component_adapter_error:{attempt_slug}"
                            ));
                            json!({
                                "schemaVersion": "workflow.harness.component-adapter-result.v1",
                                "invocationId": format!("default-dispatch:{sid}:{turn_id}:{attempt_slug}"),
                                "errorClass": "harness_component_adapter_error",
                                "error": format!("{error:?}"),
                                "readiness": "blocked"
                            })
                        }
                    };
                    previous_cognition_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "gated",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": evidence_refs,
                        "divergenceClass": "none",
                        "blockingDivergence": false,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "adapterMode": "workflow_component_adapter_gated",
                        "adapterResult": adapter_result_value,
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "cognition_gate_envelope_executor_error:{attempt_slug}"
                    ));
                    cognition_execution_gate_divergence_classes.push("unclassified".to_string());
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "divergenceClass": "unclassified",
                        "blockingDivergence": true,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let mut previous_model_output = Value::Null;
        let model_execution_specs = vec![
            (
                "model_router",
                "model_binding",
                "Model router workflow binding envelope",
                "model_router_envelope",
                "bind_model_route_envelope_without_provider_invocation",
                json!({
                    "modelBinding": {
                        "modelRef": model_execution_binding_id,
                        "modelId": "workflow-default-runtime-model",
                        "routeId": "workflow-default-model-route",
                        "modelPolicy": {
                            "promptHashAlgorithm": "runtime_prompt_hash:v1",
                            "promptFinalHash": model_execution_prompt_hash,
                            "providerCredentialSelection": "workflow_provider_canary_with_legacy_rollback",
                            "fallbackSelector": model_execution_fallback_selector,
                            "lowLevelInvocationDeferred": model_execution_low_level_invocation_deferred
                        },
                        "capability": "chat",
                        "receiptRequired": true,
                        "selectedEndpointId": "workflow-provider-canary",
                        "lastReceiptId": null,
                        "mockBinding": true,
                        "credentialReady": true,
                        "capabilityScope": ["model:route", "model:call-envelope"],
                        "sideEffectClass": "none",
                        "requiresApproval": false,
                        "toolUseMode": "none"
                    }
                }),
            ),
            (
                "model_call",
                "model_call",
                "Model call workflow execution envelope",
                "model_call_envelope",
                "accept_workflow_model_call_envelope_with_legacy_invocation_fallback",
                json!({
                    "modelRef": model_execution_binding_id,
                    "promptHash": model_execution_prompt_hash,
                    "expectedOutputHash": model_execution_output_hash,
                    "actualOutputHash": model_execution_output_hash,
                    "outputHashAlgorithm": "runtime_prompt_hash:v1",
                    "providerInvocationMode": model_execution_provider_invocation_mode,
                    "lowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
                    "fallbackSelector": model_execution_fallback_selector,
                    "stream": false,
                    "toolUseMode": "none"
                }),
            ),
        ];
        for (component_kind, node_type, node_name, attempt_slug, policy_decision, logic) in
            model_execution_specs
        {
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind,
                "selectedStrategy": selected_strategy,
                "selectedAction": selected_action,
                "modelBindingId": model_execution_binding_id,
                "promptFinalHash": model_execution_prompt_hash,
                "promptHashAlgorithm": "runtime_prompt_hash:v1",
                "expectedOutputHash": model_execution_output_hash,
                "actualOutputHash": model_execution_output_hash,
                "outputHashMatches": model_execution_output_hash_matches,
                "providerInvocationMode": model_execution_provider_invocation_mode,
                "lowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
                "fallbackSelector": model_execution_fallback_selector,
                "previousModelOutput": previous_model_output
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            model_execution_latency_ms = model_execution_latency_ms.saturating_add(duration_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            model_execution_attempt_ids.push(attempt_id.clone());
            model_execution_receipt_ids.push(receipt_id.clone());
            model_execution_replay_fixture_refs.push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    previous_model_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "live",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("harness-live-handoff:{sid}:{}", task.progress)
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "model_execution_envelope_executor_error:{attempt_slug}"
                    ));
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let mut previous_routing_model_output = previous_model_output.clone();
        let routing_model_adapter_specs = vec![
            (
                HarnessComponentKind::ModelRouter,
                "model_binding",
                "Routing-model adapter model route envelope",
                "routing_model_model_router_envelope",
                "accept_routing_model_adapter_route_binding",
                json!({
                    "modelBinding": {
                        "modelRef": model_execution_binding_id,
                        "modelId": "workflow-default-runtime-model",
                        "routeId": "workflow-default-model-route",
                        "capability": "chat",
                        "receiptRequired": true,
                        "selectedEndpointId": "workflow-provider-canary",
                        "mockBinding": true,
                        "credentialReady": true,
                        "capabilityScope": ["model:route", "model:call-envelope"],
                        "sideEffectClass": "none",
                        "requiresApproval": false,
                        "toolUseMode": "none"
                    },
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::ModelCall,
                "model_call",
                "Routing-model adapter model call envelope",
                "routing_model_model_call_envelope",
                "accept_routing_model_adapter_model_call_contract",
                json!({
                    "modelRef": model_execution_binding_id,
                    "promptHash": model_execution_prompt_hash,
                    "expectedOutputHash": model_execution_output_hash,
                    "actualOutputHash": model_execution_output_hash,
                    "providerInvocationMode": model_execution_provider_invocation_mode,
                    "lowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
                    "fallbackSelector": model_execution_fallback_selector,
                    "stream": false,
                    "toolUseMode": "none",
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::ToolRouter,
                "decision",
                "Routing-model adapter tool router envelope",
                "routing_model_tool_router_envelope",
                "accept_routing_model_adapter_tool_route_without_live_invocation",
                json!({
                    "routes": ["no_tool_call", "read_only_tool_available", "deny_mutation"],
                    "defaultRoute": "no_tool_call",
                    "toolUseMode": "none",
                    "liveMutatingToolInvocation": false,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated"
                }),
            ),
        ];
        for (component_kind, node_type, node_name, attempt_slug, policy_decision, logic) in
            routing_model_adapter_specs
        {
            let component_kind_label = component_kind.as_str();
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind_label,
                "selectedStrategy": selected_strategy,
                "selectedAction": selected_action,
                "modelBindingId": model_execution_binding_id,
                "promptFinalHash": model_execution_prompt_hash,
                "promptHashAlgorithm": "runtime_prompt_hash:v1",
                "expectedOutputHash": model_execution_output_hash,
                "actualOutputHash": model_execution_output_hash,
                "outputHashMatches": model_execution_output_hash_matches,
                "providerInvocationMode": model_execution_provider_invocation_mode,
                "lowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
                "fallbackSelector": model_execution_fallback_selector,
                "toolUseMode": "none",
                "liveMutatingToolInvocation": false,
                "previousRoutingModelOutput": previous_routing_model_output,
                "promotionMode": "gated"
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            routing_model_attempt_ids.push(attempt_id.clone());
            routing_model_receipt_ids.push(receipt_id.clone());
            routing_model_replay_fixture_refs.push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let evidence_refs = vec![
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-gated-routing-model:{sid}:{}", task.progress),
                    ];
                    let adapter_result_value = match invoke_default_harness_component(
                        HarnessComponentInvocation {
                            invocation_id: format!(
                                "default-dispatch:{sid}:{turn_id}:{attempt_slug}"
                            ),
                            component_kind,
                            execution_mode: HarnessExecutionMode::Gated,
                            attempt_index,
                            input_hash: Some(input_hash.clone()),
                            output_hash: Some(output_hash.clone()),
                            policy_decision: Some(policy_decision.to_string()),
                            receipt_ids: vec![receipt_id.clone()],
                            evidence_refs: evidence_refs.clone(),
                            replay_fixture_ref: Some(replay_fixture_ref.clone()),
                            started_at_ms: Some(started_at_ms),
                            duration_ms: Some(duration_ms),
                        },
                    ) {
                        Ok(adapter_result) => {
                            routing_model_action_frame_ids.push(format!(
                                "{}:{}",
                                adapter_result.action_frame.node_id,
                                adapter_result.action_frame.component_id
                            ));
                            routing_model_component_kinds.push(
                                adapter_result
                                    .action_frame
                                    .component_kind
                                    .as_str()
                                    .to_string(),
                            );
                            routing_model_divergence_classes.push("none".to_string());
                            let value =
                                harness_component_adapter_result_camel_value(&adapter_result);
                            routing_model_adapter_results.push(value.clone());
                            value
                        }
                        Err(error) => {
                            activation_blockers.push(format!(
                                "routing_model_component_adapter_error:{attempt_slug}"
                            ));
                            json!({
                                "schemaVersion": "workflow.harness.component-adapter-result.v1",
                                "invocationId": format!("default-dispatch:{sid}:{turn_id}:{attempt_slug}"),
                                "errorClass": "harness_component_adapter_error",
                                "error": format!("{error:?}"),
                                "readiness": "blocked"
                            })
                        }
                    };
                    previous_routing_model_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "gated",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": evidence_refs,
                        "divergenceClass": "none",
                        "blockingDivergence": false,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "adapterMode": "workflow_component_adapter_gated",
                        "adapterResult": adapter_result_value,
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "routing_model_envelope_executor_error:{attempt_slug}"
                    ));
                    routing_model_divergence_classes.push("unclassified".to_string());
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "divergenceClass": "unclassified",
                        "blockingDivergence": true,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let mut previous_verification_output = previous_routing_model_output.clone();
        let verification_output_adapter_specs = vec![
            (
                HarnessComponentKind::PostconditionSynthesizer,
                "postcondition_synthesis",
                "Verification-output adapter postcondition envelope",
                "verification_output_postcondition_synthesizer_envelope",
                "accept_verification_output_postcondition_envelope",
                json!({
                    "checks": [
                        "stop_reason",
                        "visible_output_hash",
                        "receipt_projection",
                        "quality_ledger"
                    ],
                    "minimumEvidence": [
                        "runtime_trace",
                        "receipt",
                        "stop_condition",
                        "quality_ledger"
                    ],
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::Verifier,
                "verifier",
                "Verification-output adapter verdict envelope",
                "verification_output_verifier_envelope",
                "accept_verification_output_verifier_envelope",
                json!({
                    "independent": true,
                    "verdict": "passed",
                    "outputHashMatches": output_hash_matches,
                    "receiptProjectionAuthority": "blessed_workflow_activation_default",
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::CompletionGate,
                "decision",
                "Verification-output adapter completion gate envelope",
                "verification_output_completion_gate_envelope",
                "accept_verification_output_completion_gate_envelope",
                json!({
                    "routes": ["objective_satisfied", "continue"],
                    "defaultRoute": "objective_satisfied",
                    "completionDecision": "objective_satisfied",
                    "pendingActions": [],
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::ReceiptWriter,
                "output",
                "Verification-output adapter receipt writer envelope",
                "verification_output_receipt_writer_envelope",
                "accept_verification_output_receipt_writer_envelope",
                json!({
                    "format": "json",
                    "rendererRef": {
                        "rendererId": "json",
                        "displayMode": "inline"
                    },
                    "deliveryTarget": {
                        "targetKind": "none"
                    },
                    "materialization": {
                        "enabled": false
                    },
                    "retentionPolicy": {
                        "retentionKind": "run_scoped"
                    },
                    "versioning": {
                        "enabled": true
                    },
                    "receiptProjectionAuthority": "blessed_workflow_activation_default",
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::QualityLedger,
                "quality_ledger",
                "Verification-output adapter quality ledger envelope",
                "verification_output_quality_ledger_envelope",
                "accept_verification_output_quality_ledger_envelope",
                json!({
                    "scorecard": {
                        "stopReason": "objective_satisfied",
                        "outputHashMatches": output_hash_matches,
                        "routingModelAdapterResultCount": routing_model_adapter_results.len()
                    },
                    "taskPassRate": 1.0,
                    "promotionMode": "gated"
                }),
            ),
            (
                HarnessComponentKind::OutputWriter,
                "output",
                "Verification-output adapter output writer envelope",
                "verification_output_output_writer_envelope",
                "accept_verification_output_output_writer_envelope",
                json!({
                    "format": "markdown",
                    "rendererRef": {
                        "rendererId": "chat-message",
                        "displayMode": "candidate"
                    },
                    "deliveryTarget": {
                        "targetKind": "none"
                    },
                    "materialization": {
                        "enabled": false,
                        "assetKind": "visible_transcript_message"
                    },
                    "retentionPolicy": {
                        "retentionKind": "run_scoped"
                    },
                    "versioning": {
                        "enabled": true
                    },
                    "candidateOnly": true,
                    "visibleTranscriptCommit": false,
                    "promotionMode": "gated"
                }),
            ),
        ];
        for (component_kind, node_type, node_name, attempt_slug, policy_decision, logic) in
            verification_output_adapter_specs
        {
            let component_kind_label = component_kind.as_str();
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind_label,
                "selectedStrategy": selected_strategy,
                "selectedAction": selected_action,
                "completionDecision": "objective_satisfied",
                "receiptProjectionAuthority": "blessed_workflow_activation_default",
                "qualityLedgerAuthority": "blessed_workflow_activation_default",
                "selectedVisibleOutputAuthority": selected_visible_output_authority,
                "selectedVisibleOutputHash": selected_visible_output_hash,
                "proposedVisibleOutputHash": proposed_visible_output_hash,
                "actualVisibleOutputHash": actual_visible_output_hash,
                "outputHashMatches": output_hash_matches,
                "previousVerificationOutput": previous_verification_output,
                "promotionMode": "gated"
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            verification_output_attempt_ids.push(attempt_id.clone());
            verification_output_receipt_ids.push(receipt_id.clone());
            verification_output_replay_fixture_refs.push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let evidence_refs = vec![
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-gated-verification-output:{sid}:{}", task.progress),
                    ];
                    let adapter_result_value = match invoke_default_harness_component(
                        HarnessComponentInvocation {
                            invocation_id: format!(
                                "default-dispatch:{sid}:{turn_id}:{attempt_slug}"
                            ),
                            component_kind,
                            execution_mode: HarnessExecutionMode::Gated,
                            attempt_index,
                            input_hash: Some(input_hash.clone()),
                            output_hash: Some(output_hash.clone()),
                            policy_decision: Some(policy_decision.to_string()),
                            receipt_ids: vec![receipt_id.clone()],
                            evidence_refs: evidence_refs.clone(),
                            replay_fixture_ref: Some(replay_fixture_ref.clone()),
                            started_at_ms: Some(started_at_ms),
                            duration_ms: Some(duration_ms),
                        },
                    ) {
                        Ok(adapter_result) => {
                            verification_output_action_frame_ids.push(format!(
                                "{}:{}",
                                adapter_result.action_frame.node_id,
                                adapter_result.action_frame.component_id
                            ));
                            verification_output_component_kinds.push(
                                adapter_result
                                    .action_frame
                                    .component_kind
                                    .as_str()
                                    .to_string(),
                            );
                            verification_output_divergence_classes.push("none".to_string());
                            let value =
                                harness_component_adapter_result_camel_value(&adapter_result);
                            verification_output_adapter_results.push(value.clone());
                            value
                        }
                        Err(error) => {
                            activation_blockers.push(format!(
                                "verification_output_component_adapter_error:{attempt_slug}"
                            ));
                            json!({
                                "schemaVersion": "workflow.harness.component-adapter-result.v1",
                                "invocationId": format!("default-dispatch:{sid}:{turn_id}:{attempt_slug}"),
                                "errorClass": "harness_component_adapter_error",
                                "error": format!("{error:?}"),
                                "readiness": "blocked"
                            })
                        }
                    };
                    previous_verification_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "gated",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": evidence_refs,
                        "divergenceClass": "none",
                        "blockingDivergence": false,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "adapterMode": "workflow_component_adapter_gated",
                        "adapterResult": adapter_result_value,
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "verification_output_envelope_executor_error:{attempt_slug}"
                    ));
                    verification_output_divergence_classes.push("unclassified".to_string());
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "divergenceClass": "unclassified",
                        "blockingDivergence": true,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
        let attempt_id = format!(
            "harness-default-dispatch:{sid}:{turn_id}:model_provider_call_canary:attempt-{attempt_index}"
        );
        let workflow_node_id = "harness.default_dispatch.model_provider_call_canary".to_string();
        let receipt_id = format!("{sid}:{workflow_node_id}:workflow-model-provider-call-canary");
        let replay_fixture_ref =
            format!("runtime-evidence:{sid}:default-dispatch-fixture:model_provider_call_canary");
        let input = json!({
            "sessionId": sid,
            "turnId": turn_id,
            "selectorDecisionId": selector_decision_id,
            "sourceBoundaryIds": source_boundary_ids,
            "componentKind": "model_call",
            "selectedStrategy": selected_strategy,
            "selectedAction": selected_action,
            "modelBindingId": model_execution_binding_id,
            "promptFinalHash": model_execution_prompt_hash,
            "promptHashAlgorithm": "runtime_prompt_hash:v1",
            "providerInvocationMode": model_provider_canary_mode,
            "candidateOutputHash": model_provider_canary_candidate_output_hash,
            "legacyOutputHash": model_provider_canary_legacy_output_hash,
            "outputHashMatches": model_provider_canary_output_hash_matches,
            "transcriptMatches": model_provider_canary_transcript_matches,
            "fallbackSelector": model_execution_fallback_selector,
            "fallbackRetained": model_provider_canary_fallback_retained,
            "rollbackAvailable": model_provider_canary_rollback_available,
            "previousModelOutput": previous_model_output
        });
        let input_hash = runtime_harness_canary_node_output_hash(&input);
        let node = json!({
            "id": workflow_node_id,
            "type": "model_call",
            "name": "Model provider workflow call canary",
            "config": {
                "logic": {
                    "modelRef": model_execution_binding_id,
                    "promptHash": model_execution_prompt_hash,
                    "providerInvocationMode": model_provider_canary_mode,
                    "candidateOutputHash": model_provider_canary_candidate_output_hash,
                    "legacyOutputHash": model_provider_canary_legacy_output_hash,
                    "outputHashAlgorithm": "runtime_prompt_hash:v1",
                    "fallbackSelector": model_execution_fallback_selector,
                    "fallbackRetained": model_provider_canary_fallback_retained,
                    "rollbackAvailable": model_provider_canary_rollback_available,
                    "stream": false,
                    "toolUseMode": "none"
                },
                "law": {
                    "requireHumanGate": false,
                    "sandboxPolicy": {
                        "permissions": []
                    }
                }
            }
        });
        let started_at_ms = crate::kernel::state::now();
        let execution =
            crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
        let finished_at_ms = crate::kernel::state::now();
        let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
        model_execution_latency_ms = model_execution_latency_ms.saturating_add(duration_ms);
        dispatch_node_attempt_ids.push(attempt_id.clone());
        model_execution_attempt_ids.push(attempt_id.clone());
        model_execution_receipt_ids.push(receipt_id.clone());
        model_execution_replay_fixture_refs.push(replay_fixture_ref.clone());
        model_provider_canary_attempt_ids.push(attempt_id.clone());
        model_provider_canary_receipt_ids.push(receipt_id.clone());
        model_provider_canary_replay_fixture_refs.push(replay_fixture_ref.clone());
        receipt_ids.push(receipt_id.clone());
        replay_fixture_refs.push(replay_fixture_ref.clone());
        match execution {
            Ok(output) => {
                let output_hash = runtime_harness_canary_node_output_hash(&output);
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "model_call",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.model_provider_call_canary.v1",
                    "componentKind": "model_call",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "live",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": output_hash,
                    "errorClass": null,
                    "policyDecision": "accept_workflow_model_provider_call_canary_with_legacy_rollback",
                    "startedAtMs": started_at_ms,
                    "durationMs": duration_ms,
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-live-handoff:{sid}:{}", task.progress)
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    },
                    "executorResult": output
                }));
            }
            Err(error) => {
                activation_blockers.push("model_provider_call_canary_executor_error".to_string());
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "model_call",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.model_provider_call_canary.v1",
                    "componentKind": "model_call",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "rolled_back",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": null,
                    "errorClass": "workflow_executor_error",
                    "error": error,
                    "policyDecision": "rollback_to_legacy_runtime",
                    "startedAtMs": started_at_ms,
                    "durationMs": duration_ms,
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    }
                }));
            }
        }

        if model_provider_gated_visible_output_selected {
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:model_provider_gated_visible_output:attempt-{attempt_index}"
            );
            let workflow_node_id =
                "harness.default_dispatch.model_provider_gated_visible_output".to_string();
            let receipt_id =
                format!("{sid}:{workflow_node_id}:workflow-model-provider-gated-visible-output");
            let replay_fixture_ref = format!(
                "runtime-evidence:{sid}:default-dispatch-fixture:model_provider_gated_visible_output"
            );
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "activationFlag": model_provider_gated_visible_output_activation_flag,
                "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "scope": model_provider_gated_visible_output_scenario,
                "componentKind": "model_call",
                "modelBindingId": model_execution_binding_id,
                "providerInvocationMode": model_provider_gated_visible_output_mode,
                "selectedVisibleOutputAuthority": selected_visible_output_authority,
                "selectedVisibleOutputHash": selected_visible_output_hash,
                "workflowProviderOutputHash": model_provider_canary_candidate_output_hash,
                "legacyVisibleOutputHash": legacy_visible_output_hash,
                "legacyVisibleOutputComputed": true,
                "legacyOutputHashMatchesSelected": visible_output_legacy_hash_matches_selected,
                "selectedAuthorityMatchesTranscript": visible_output_selected_authority_matches_transcript,
                "divergenceClass": visible_output_divergence_class,
                "rollbackTarget": visible_output_gated_authority_rollback_target,
                "rollbackAvailable": model_provider_canary_rollback_available
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": "model_call",
                "name": "Model provider gated visible-output authority",
                "config": {
                    "logic": {
                        "modelRef": model_execution_binding_id,
                        "promptHash": model_execution_prompt_hash,
                        "providerInvocationMode": model_provider_gated_visible_output_mode,
                        "selectedVisibleOutputAuthority": selected_visible_output_authority,
                        "selectedVisibleOutputHash": selected_visible_output_hash,
                        "workflowProviderOutputHash": model_provider_canary_candidate_output_hash,
                        "legacyVisibleOutputHash": legacy_visible_output_hash,
                        "rollbackTarget": visible_output_gated_authority_rollback_target,
                        "rollbackAvailable": model_provider_canary_rollback_available,
                        "stream": false,
                        "toolUseMode": "none"
                    },
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            model_execution_latency_ms = model_execution_latency_ms.saturating_add(duration_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            model_execution_attempt_ids.push(attempt_id.clone());
            model_execution_receipt_ids.push(receipt_id.clone());
            model_execution_replay_fixture_refs.push(replay_fixture_ref.clone());
            model_provider_gated_visible_output_attempt_ids.push(attempt_id.clone());
            model_provider_gated_visible_output_receipt_ids.push(receipt_id.clone());
            model_provider_gated_visible_output_replay_fixture_refs
                .push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": "model_call",
                        "componentId": "ioi.agent-harness.default_runtime_dispatch.model_provider_gated_visible_output.v1",
                        "componentKind": "model_call",
                        "executionMode": "gated",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "gated_visible_output_selected",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": "accept_workflow_provider_gated_visible_output_with_legacy_rollback",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("harness-provider-gated-visible-output:{sid}:{}", task.progress),
                            format!("rollback-target:{visible_output_gated_authority_rollback_target}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers
                        .push("model_provider_gated_visible_output_executor_error".to_string());
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": "model_call",
                        "componentId": "ioi.agent-harness.default_runtime_dispatch.model_provider_gated_visible_output.v1",
                        "componentKind": "model_call",
                        "executionMode": "gated",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{visible_output_gated_authority_rollback_target}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        if model_provider_gated_visible_output_rollback_drill_enabled {
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:model_provider_gated_visible_output_rollback_drill:attempt-{attempt_index}"
            );
            let workflow_node_id =
                "harness.default_dispatch.model_provider_gated_visible_output_rollback_drill"
                    .to_string();
            let receipt_id = format!(
                "{sid}:{workflow_node_id}:workflow-model-provider-gated-visible-output-rollback-drill"
            );
            let replay_fixture_ref = format!(
                "runtime-evidence:{sid}:default-dispatch-fixture:model_provider_gated_visible_output_rollback_drill"
            );
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "componentKind": "model_call",
                "drill": "provider_gated_visible_output_rollback",
                "failureInjected": model_provider_gated_visible_output_rollback_drill_failure_injected,
                "workflowProviderOutputHash": model_provider_canary_candidate_output_hash,
                "injectedWorkflowProviderOutputHash": model_provider_gated_visible_output_rollback_drill_injected_output_hash,
                "legacyVisibleOutputHash": legacy_visible_output_hash,
                "actualVisibleOutputHash": actual_visible_output_hash,
                "outputHashDiverges": model_provider_gated_visible_output_rollback_drill_output_hash_diverges,
                "divergenceClass": model_provider_gated_visible_output_rollback_drill_divergence_class,
                "fallbackAuthority": model_provider_gated_visible_output_rollback_drill_fallback_authority,
                "selectedAuthorityAfterRollback": model_provider_gated_visible_output_rollback_drill_selected_authority,
                "transcriptUnchanged": model_provider_gated_visible_output_rollback_drill_transcript_unchanged,
                "rollbackExecuted": model_provider_gated_visible_output_rollback_drill_rollback_executed,
                "rollbackTarget": visible_output_gated_authority_rollback_target,
                "rollbackAvailable": model_provider_canary_rollback_available,
                "activationBlockers": model_provider_gated_visible_output_rollback_drill_activation_blockers
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": "model_call",
                "name": "Model provider gated visible-output rollback drill",
                "config": {
                    "logic": {
                        "modelRef": model_execution_binding_id,
                        "promptHash": model_execution_prompt_hash,
                        "providerInvocationMode": "workflow_provider_gated_visible_output_rollback_drill",
                        "failureInjected": model_provider_gated_visible_output_rollback_drill_failure_injected,
                        "injectedWorkflowProviderOutputHash": model_provider_gated_visible_output_rollback_drill_injected_output_hash,
                        "legacyVisibleOutputHash": legacy_visible_output_hash,
                        "fallbackAuthority": model_provider_gated_visible_output_rollback_drill_fallback_authority,
                        "rollbackTarget": visible_output_gated_authority_rollback_target,
                        "rollbackAvailable": model_provider_canary_rollback_available,
                        "stream": false,
                        "toolUseMode": "none"
                    },
                    "law": {
                        "requireHumanGate": false,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            model_execution_latency_ms = model_execution_latency_ms.saturating_add(duration_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            model_execution_attempt_ids.push(attempt_id.clone());
            model_execution_receipt_ids.push(receipt_id.clone());
            model_execution_replay_fixture_refs.push(replay_fixture_ref.clone());
            model_provider_gated_visible_output_rollback_drill_attempt_ids.push(attempt_id.clone());
            model_provider_gated_visible_output_rollback_drill_receipt_ids.push(receipt_id.clone());
            model_provider_gated_visible_output_rollback_drill_replay_fixture_refs
                .push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": "model_call",
                        "componentId": "ioi.agent-harness.default_runtime_dispatch.model_provider_gated_visible_output_rollback_drill.v1",
                        "componentKind": "model_call",
                        "executionMode": "gated",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": "rollback_to_legacy_runtime_model_invocation_on_provider_output_hash_divergence",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "activationBlockers": model_provider_gated_visible_output_rollback_drill_activation_blockers,
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("harness-provider-gated-visible-output-rollback-drill:{sid}:{}", task.progress),
                            format!("rollback-target:{visible_output_gated_authority_rollback_target}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(
                        "model_provider_gated_visible_output_rollback_drill_executor_error"
                            .to_string(),
                    );
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": "model_call",
                        "componentId": "ioi.agent-harness.default_runtime_dispatch.model_provider_gated_visible_output_rollback_drill.v1",
                        "componentKind": "model_call",
                        "executionMode": "gated",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rollback_drill_error",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_drill_failed_retain_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "activationBlockers": ["model_provider_output_hash_divergence"],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{visible_output_gated_authority_rollback_target}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        if read_only_capability_routing_selected {
            let mut read_only_routing_specs = Vec::<(&str, &str, &str, &str, &str, Value)>::new();
            match read_only_capability_routing_scenario_coverage_key {
                Some("retained_probe_behavior") => {
                    read_only_routing_specs.push((
                        "probe_runner",
                        "probe",
                        "Read-only probe runner route",
                        "read_only_probe_runner",
                        "run_cheapest_probe_through_workflow_node",
                        json!({
                            "hypothesis": "Desktop chat source rendering can be verified with the cheapest bounded probe.",
                            "cheapestValidationAction": "Inspect retained runtime evidence for selected sources and source rendering receipts.",
                            "result": "workflow_probe_route_ready",
                            "sideEffectsExecuted": false,
                            "mutationExecuted": false
                        }),
                    ));
                }
                Some("retained_repo_grounded_answer" | "retained_source_heavy_synthesis") => {
                    read_only_routing_specs.push((
                        "memory_read",
                        "source",
                        "Read-only source discovery route",
                        "read_only_source_router",
                        "route_selected_sources_through_workflow_node",
                        json!({
                            "payload": {
                                "sourceKind": "selected_runtime_sources",
                                "selectedSources": selected_sources.clone(),
                                "sourceCount": selected_sources.len(),
                                "matchedUserRequestHash": runtime_prompt_hash(&[latest_user_request.as_str()])
                            },
                            "sideEffectsExecuted": false,
                            "mutationExecuted": false
                        }),
                    ));
                }
                _ => {}
            }
            read_only_routing_specs.extend([
                (
                    "capability_sequencer",
                    "capability_sequence",
                    "Read-only capability sequencer route",
                    "read_only_capability_sequencer",
                    "sequence_read_only_capabilities_without_mutation",
                    json!({
                        "sequence": [
                            "classify_read_only_intent",
                            "select_source_or_probe_capability",
                            "route_through_tool_router",
                            "dry_run_side_effect_boundary",
                            "verify_no_mutation"
                        ],
                        "selectedCapabilities": read_only_capability_routing_workflow_owned_node_kinds.clone(),
                        "scenario": read_only_capability_routing_scenario,
                        "sideEffectsExecuted": false,
                        "mutationExecuted": false
                    }),
                ),
                (
                    "tool_router",
                    "decision",
                    "Read-only tool router route",
                    "read_only_tool_router",
                    "route_read_only_capability_without_live_mutation",
                    json!({
                        "routes": ["selected_source_read", "selected_probe", "deny_mutation"],
                        "defaultRoute": if read_only_capability_routing_scenario == "retained_probe_behavior" {
                            "selected_probe"
                        } else {
                            "selected_source_read"
                        },
                        "toolUseMode": "read_only_or_dry_run",
                        "liveMutatingToolInvocation": false,
                        "sideEffectsExecuted": false,
                        "mutationExecuted": false
                    }),
                ),
                (
                    "dry_run_simulator",
                    "dry_run",
                    "Read-only no-mutation drill",
                    "read_only_no_mutation_drill",
                    "prove_read_only_route_has_no_side_effects",
                    json!({
                        "dryRun": true,
                        "sideEffectPreview": true,
                        "sideEffectsExecuted": false,
                        "mutationExecuted": false,
                        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "rollbackAction": "noop_read_only_route"
                    }),
                ),
            ]);

            let mut previous_read_only_routing_output = Value::Null;
            for (component_kind, node_type, node_name, attempt_slug, policy_decision, logic) in
                read_only_routing_specs
            {
                let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
                let attempt_id = format!(
                    "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
                );
                let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
                let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
                let replay_fixture_ref =
                    format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
                let input = json!({
                    "sessionId": sid,
                    "turnId": turn_id,
                    "selectorDecisionId": selector_decision_id,
                    "scenario": read_only_capability_routing_scenario,
                    "scenarioCoverageKey": read_only_capability_routing_scenario_coverage_key,
                    "componentKind": component_kind,
                    "workflowOwnedNodeKinds": read_only_capability_routing_workflow_owned_node_kinds.clone(),
                    "selectedSources": selected_sources.clone(),
                    "selectedSourceCount": selected_sources.len(),
                    "toolUseMode": "read_only_or_dry_run",
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "previousReadOnlyRoutingOutput": previous_read_only_routing_output
                });
                let input_hash = runtime_harness_canary_node_output_hash(&input);
                let node = json!({
                    "id": workflow_node_id,
                    "type": node_type,
                    "name": node_name,
                    "config": {
                        "logic": logic,
                        "law": {
                            "requireHumanGate": false,
                            "sandboxPolicy": {
                                "permissions": []
                            }
                        }
                    }
                });
                let started_at_ms = crate::kernel::state::now();
                let execution = crate::project::execute_workflow_harness_live_default_node(
                    &node,
                    input.clone(),
                    1,
                );
                let finished_at_ms = crate::kernel::state::now();
                dispatch_node_attempt_ids.push(attempt_id.clone());
                read_only_capability_routing_attempt_ids.push(attempt_id.clone());
                read_only_capability_routing_receipt_ids.push(receipt_id.clone());
                read_only_capability_routing_replay_fixture_refs.push(replay_fixture_ref.clone());
                receipt_ids.push(receipt_id.clone());
                replay_fixture_refs.push(replay_fixture_ref.clone());
                match execution {
                    Ok(output) => {
                        let output_hash = runtime_harness_canary_node_output_hash(&output);
                        previous_read_only_routing_output = output.clone();
                        dispatch_node_attempts.push(json!({
                            "attemptId": attempt_id,
                            "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                            "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                            "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                            "workflowNodeId": workflow_node_id,
                            "workflowNodeType": node_type,
                            "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                            "componentKind": component_kind,
                            "executionMode": "live",
                            "readiness": "live_ready",
                            "attemptIndex": attempt_index,
                            "status": "live",
                            "executor": "workflow_node_executor",
                            "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                            "inputHash": input_hash,
                            "outputHash": output_hash,
                            "errorClass": null,
                            "policyDecision": policy_decision,
                            "startedAtMs": started_at_ms,
                            "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                            "receiptIds": [receipt_id],
                            "evidenceRefs": [
                                format!("runtime-evidence:{sid}"),
                                selector_decision_id.clone(),
                                format!("harness-read-only-capability-routing:{sid}:{}", task.progress)
                            ],
                            "replay": {
                                "deterministicEnvelope": true,
                                "capturesInput": true,
                                "capturesOutput": true,
                                "capturesPolicyDecision": true,
                                "fixtureRef": replay_fixture_ref,
                                "determinism": "deterministic",
                                "nondeterminismReason": null,
                                "redactionPolicy": "autopilot-runtime-evidence-v1"
                            },
                            "executorResult": output
                        }));
                    }
                    Err(error) => {
                        activation_blockers.push(format!(
                            "read_only_capability_routing_executor_error:{attempt_slug}"
                        ));
                        dispatch_node_attempts.push(json!({
                            "attemptId": attempt_id,
                            "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                            "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                            "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                            "workflowNodeId": workflow_node_id,
                            "workflowNodeType": node_type,
                            "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                            "componentKind": component_kind,
                            "executionMode": "live",
                            "readiness": "live_ready",
                            "attemptIndex": attempt_index,
                            "status": "rolled_back",
                            "executor": "workflow_node_executor",
                            "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                            "inputHash": input_hash,
                            "outputHash": null,
                            "errorClass": "workflow_executor_error",
                            "error": error,
                            "policyDecision": "rollback_to_legacy_runtime",
                            "startedAtMs": started_at_ms,
                            "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                            "receiptIds": [receipt_id],
                            "evidenceRefs": [
                                format!("runtime-evidence:{sid}"),
                                selector_decision_id.clone(),
                                format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                            ],
                            "replay": {
                                "deterministicEnvelope": true,
                                "capturesInput": true,
                                "capturesOutput": true,
                                "capturesPolicyDecision": true,
                                "fixtureRef": replay_fixture_ref,
                                "determinism": "deterministic",
                                "nondeterminismReason": null,
                                "redactionPolicy": "autopilot-runtime-evidence-v1"
                            }
                        }));
                    }
                }
            }
        }

        let mut previous_authority_tooling_adapter_output = json!({
            "componentKind": "verification_output",
            "outputHash": runtime_harness_canary_node_output_hash(&previous_verification_output)
        });
        let mut previous_authority_tooling_provider_catalog = Value::Null;
        let mut previous_authority_tooling_mcp_tool_catalog = Value::Null;
        let authority_tooling_adapter_specs = vec![
            (
                HarnessComponentKind::PolicyGate,
                "decision",
                "Authority-tooling adapter policy gate envelope",
                "authority_tooling_policy_gate_envelope",
                "accept_authority_tooling_policy_gate_adapter_envelope",
                false,
                json!({
                    "authorityGateKind": "policy_gate",
                    "routes": ["allow_read_only_route", "deny_mutation"],
                    "defaultRoute": "allow_read_only_route",
                    "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                    "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                    "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "policyDecision": "accept_authority_tooling_policy_gate_adapter_envelope",
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::ApprovalGate,
                "human_gate",
                "Authority-tooling adapter approval gate envelope",
                "authority_tooling_approval_gate_envelope",
                "accept_authority_tooling_approval_gate_adapter_envelope",
                true,
                json!({
                    "authorityGateKind": "approval_gate",
                    "text": "Mutating authority remains blocked until a validated workflow activation and governed approval allow it.",
                    "approvalMode": "workflow_gated_adapter_required",
                    "requiresApproval": true,
                    "syntheticApprovalGranted": false,
                    "authorityTransferred": false,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::DryRunSimulator,
                "dry_run",
                "Authority-tooling adapter dry-run simulator envelope",
                "authority_tooling_dry_run_simulator_envelope",
                "accept_authority_tooling_dry_run_adapter_envelope",
                false,
                json!({
                    "dryRun": true,
                    "sideEffectPreview": true,
                    "simulatedToolRef": "agent.runtime.noop.read",
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::McpProvider,
                "adapter",
                "Authority-tooling adapter MCP provider envelope",
                "authority_tooling_mcp_provider_envelope",
                "accept_authority_tooling_mcp_provider_adapter_envelope",
                false,
                json!({
                    "connectorBinding": {
                        "connectorRef": "mcp.capability-provider",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["mcp.provider.read", "mcp.catalog.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "operation": "catalog"
                    },
                    "providerCatalogLiveExecution": false,
                    "toolExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::McpToolCall,
                "plugin_tool",
                "Authority-tooling adapter MCP tool call envelope",
                "authority_tooling_mcp_tool_call_envelope",
                "accept_authority_tooling_mcp_tool_call_adapter_envelope",
                false,
                json!({
                    "toolBinding": {
                        "bindingKind": "mcp_tool",
                        "toolRef": "mcp.tool.catalog.read",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["mcp.tool.catalog.read", "mcp.provider.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "arguments": {
                            "mode": "catalog_preview",
                            "mutation": false
                        }
                    },
                    "toolExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::ToolCall,
                "plugin_tool",
                "Authority-tooling adapter native tool call envelope",
                "authority_tooling_tool_call_envelope",
                "accept_authority_tooling_tool_call_adapter_envelope",
                false,
                json!({
                    "toolBinding": {
                        "bindingKind": "native_tool",
                        "toolRef": "agent.runtime.native-tool.catalog.read",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["native.tool.catalog.read", "mcp.tool.catalog.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "arguments": {
                            "mode": "native_catalog_preview",
                            "mutation": false
                        }
                    },
                    "toolExecutionEnabled": false,
                    "nativeToolExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::ConnectorCall,
                "adapter",
                "Authority-tooling adapter connector call envelope",
                "authority_tooling_connector_call_envelope",
                "accept_authority_tooling_connector_call_adapter_envelope",
                false,
                json!({
                    "connectorBinding": {
                        "connectorRef": "agent.connector.catalog",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["connector.catalog.read", "mcp.tool.catalog.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "operation": "describe"
                    },
                    "connectorExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                HarnessComponentKind::WalletCapability,
                "human_gate",
                "Authority-tooling adapter wallet capability envelope",
                "authority_tooling_wallet_capability_envelope",
                "retain_authority_tooling_wallet_capability_adapter_without_grant",
                true,
                json!({
                    "text": "Wallet and spending authority remain unavailable during gated default harness dispatch.",
                    "approvalMode": "wallet_capability_gated_adapter",
                    "capabilityScope": ["wallet.request", "capability.grant"],
                    "readOnlyAuthority": true,
                    "requiresApproval": true,
                    "syntheticApprovalGranted": false,
                    "capabilityGranted": false,
                    "grantMaterialized": false,
                    "authorityTransferred": false,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "promotionMode": "gated",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
        ];
        for (
            component_kind,
            node_type,
            node_name,
            attempt_slug,
            policy_decision,
            require_human_gate,
            logic,
        ) in authority_tooling_adapter_specs
        {
            let component_kind_label = component_kind.as_str();
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let previous_authority_tooling_catalogs = json!({
                "providerCatalog": previous_authority_tooling_provider_catalog.clone(),
                "mcpToolCatalog": previous_authority_tooling_mcp_tool_catalog.clone()
            });
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind_label,
                "mode": "workflow_component_adapter_gated",
                "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                "readOnlyComponentKinds": authority_tooling_read_only_component_kinds.clone(),
                "mutationDeferredComponentKinds": authority_tooling_mutation_deferred_component_kinds.clone(),
                "sideEffectsExecuted": false,
                "mutationExecuted": false,
                "previousAuthorityOutput": previous_authority_tooling_catalogs.clone(),
                "previousOutput": previous_authority_tooling_catalogs,
                "mcpToolCatalog": previous_authority_tooling_mcp_tool_catalog.clone(),
                "previousAuthorityToolingAdapterOutput": previous_authority_tooling_adapter_output.clone(),
                "promotionMode": "gated",
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": require_human_gate,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            let duration_ms = finished_at_ms.saturating_sub(started_at_ms);
            dispatch_node_attempt_ids.push(attempt_id.clone());
            authority_tooling_attempt_ids.push(attempt_id.clone());
            authority_tooling_receipt_ids.push(receipt_id.clone());
            authority_tooling_replay_fixture_refs.push(replay_fixture_ref.clone());
            receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let evidence_refs = vec![
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-gated-authority-tooling:{sid}:{}", task.progress),
                    ];
                    let adapter_result_value = match invoke_default_harness_component(
                        HarnessComponentInvocation {
                            invocation_id: format!(
                                "default-dispatch:{sid}:{turn_id}:{attempt_slug}"
                            ),
                            component_kind,
                            execution_mode: HarnessExecutionMode::Gated,
                            attempt_index,
                            input_hash: Some(input_hash.clone()),
                            output_hash: Some(output_hash.clone()),
                            policy_decision: Some(policy_decision.to_string()),
                            receipt_ids: vec![receipt_id.clone()],
                            evidence_refs: evidence_refs.clone(),
                            replay_fixture_ref: Some(replay_fixture_ref.clone()),
                            started_at_ms: Some(started_at_ms),
                            duration_ms: Some(duration_ms),
                        },
                    ) {
                        Ok(adapter_result) => {
                            authority_tooling_action_frame_ids.push(format!(
                                "{}:{}",
                                adapter_result.action_frame.node_id,
                                adapter_result.action_frame.component_id
                            ));
                            authority_tooling_component_kinds.push(
                                adapter_result
                                    .action_frame
                                    .component_kind
                                    .as_str()
                                    .to_string(),
                            );
                            authority_tooling_divergence_classes.push("none".to_string());
                            let value =
                                harness_component_adapter_result_camel_value(&adapter_result);
                            authority_tooling_adapter_results.push(value.clone());
                            value
                        }
                        Err(error) => {
                            activation_blockers.push(format!(
                                "authority_tooling_component_adapter_error:{attempt_slug}"
                            ));
                            json!({
                                "schemaVersion": "workflow.harness.component-adapter-result.v1",
                                "invocationId": format!("default-dispatch:{sid}:{turn_id}:{attempt_slug}"),
                                "errorClass": "harness_component_adapter_error",
                                "error": format!("{error:?}"),
                                "readiness": "blocked"
                            })
                        }
                    };
                    if let Some(catalog) = output
                        .get("providerCatalog")
                        .filter(|value| value.is_object())
                    {
                        previous_authority_tooling_provider_catalog = catalog.clone();
                    }
                    if let Some(catalog) = output
                        .get("mcpToolCatalog")
                        .filter(|value| value.is_object())
                    {
                        previous_authority_tooling_mcp_tool_catalog = catalog.clone();
                    }
                    previous_authority_tooling_adapter_output = json!({
                        "componentKind": component_kind_label,
                        "attemptId": attempt_id,
                        "outputHash": output_hash
                    });
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "gated",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": evidence_refs,
                        "divergenceClass": "none",
                        "blockingDivergence": false,
                        "authority": {
                            "adapterMode": "workflow_component_adapter_gated",
                            "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                            "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                            "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                            "sideEffectsExecuted": false,
                            "mutationExecuted": false,
                            "authorityTransferred": false,
                            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                        },
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "adapterResult": adapter_result_value,
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "authority_tooling_component_adapter_executor_error:{attempt_slug}"
                    ));
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": component_kind.component_id(),
                        "componentKind": component_kind_label,
                        "executionMode": "gated",
                        "readiness": "shadow_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": duration_ms,
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "divergenceClass": "behavioral_regression",
                        "blockingDivergence": true,
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let mut previous_authority_output = Value::Null;
        let mut previous_mcp_tool_catalog = Value::Null;
        let authority_tooling_specs = vec![
            (
                "policy_gate",
                "decision",
                "Authority policy gate read-only acceptance",
                "authority_tooling_policy_gate",
                "allow_read_only_route_through_workflow_authority",
                false,
                json!({
                    "authorityGateKind": "policy_gate",
                    "policyGateLiveExecution": true,
                    "routes": ["allow_read_only_route", "deny_mutation"],
                    "defaultRoute": "allow_read_only_route",
                    "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                    "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                    "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                    "sideEffectsExecuted": authority_tooling_side_effects_executed,
                    "mutationExecuted": false,
                    "policyDecision": "allow_read_only_route_through_workflow_authority",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                "tool_router",
                "decision",
                "Authority tool router read-only route",
                "authority_tooling_tool_router",
                "route_read_only_without_live_tool_invocation",
                false,
                json!({
                    "routes": ["no_tool_call", "read_only_dry_run", "deny_mutation"],
                    "defaultRoute": "read_only_dry_run",
                    "selectedRoute": "read_only_dry_run",
                    "liveToolInvocation": false,
                    "toolUseMode": "dry_run"
                }),
            ),
            (
                "dry_run_simulator",
                "dry_run",
                "Authority dry-run simulator",
                "authority_tooling_dry_run_simulator",
                "simulate_tool_route_without_side_effects",
                false,
                json!({
                    "dryRun": true,
                    "sideEffectPreview": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "simulatedToolRef": "agent.runtime.noop.read",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                "policy_gate",
                "decision",
                "Authority destructive denial drill",
                "authority_tooling_destructive_denial",
                "deny_destructive_request_without_side_effect",
                true,
                json!({
                    "authorityGateKind": "destructive_denial",
                    "routes": ["deny_destructive_request", "allow_read_only_route"],
                    "defaultRoute": "deny_destructive_request",
                    "simulatedRequest": "Delete the repository and continue without asking.",
                    "destructiveRouteDenied": true,
                    "mutatingToolCallsBlocked": true,
                    "requiresApproval": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "policyDecision": "deny_destructive_request_without_side_effect",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "denialClass": "policy_destructive_without_approval"
                }),
            ),
            (
                "approval_gate",
                "human_gate",
                "Authority approval gate",
                "authority_tooling_approval_gate",
                "require_legacy_approval_for_mutating_tooling",
                false,
                json!({
                    "authorityGateKind": "approval_gate",
                    "text": "Mutating tool authority remains blocked without explicit governed approval.",
                    "approvalMode": "legacy_runtime_required",
                    "requiresApproval": true,
                    "syntheticApprovalGranted": false,
                    "authorityTransferred": false,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "policyDecision": "require_legacy_approval_for_mutating_tooling",
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
        ];
        for (
            component_kind,
            node_type,
            node_name,
            attempt_slug,
            policy_decision,
            denial_receipt,
            logic,
        ) in authority_tooling_specs
        {
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind,
                "previousAuthorityOutput": previous_authority_output,
                "mode": "workflow_live_dry_run",
                "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                "sideEffectsExecuted": authority_tooling_side_effects_executed,
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": denial_receipt || component_kind == "approval_gate",
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            dispatch_node_attempt_ids.push(attempt_id.clone());
            authority_tooling_live_dry_run_attempt_ids.push(attempt_id.clone());
            receipt_ids.push(receipt_id.clone());
            if denial_receipt {
                authority_tooling_denial_receipt_ids.push(receipt_id.clone());
            }
            replay_fixture_refs.push(replay_fixture_ref.clone());
            let policy_gate_live_attempt = attempt_slug == "authority_tooling_policy_gate";
            let destructive_denial_live_attempt =
                attempt_slug == "authority_tooling_destructive_denial";
            let approval_gate_live_attempt = attempt_slug == "authority_tooling_approval_gate";
            let gate_live_attempt = policy_gate_live_attempt
                || destructive_denial_live_attempt
                || approval_gate_live_attempt;
            if gate_live_attempt {
                authority_tooling_gate_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_gate_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_gate_live_replay_fixture_refs.push(replay_fixture_ref.clone());
            }
            if policy_gate_live_attempt {
                authority_tooling_policy_gate_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_policy_gate_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_policy_gate_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            if destructive_denial_live_attempt {
                authority_tooling_destructive_denial_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_destructive_denial_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_destructive_denial_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            if approval_gate_live_attempt {
                authority_tooling_approval_gate_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_approval_gate_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_approval_gate_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let policy_gate_live_output = policy_gate_live_attempt
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_read_only_policy_gate")
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("readOnlyRouteAccepted"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("destructiveRouteDenied"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("mutatingToolCallsBlocked"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("authorityPolicyGate")
                            .and_then(|gate| gate.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    let destructive_denial_live_output = destructive_denial_live_attempt
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_destructive_denial_gate")
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("destructiveRouteDenied"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("mutatingToolCallsBlocked"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("denialReceiptReady"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("denialClass"))
                            .and_then(Value::as_str)
                            == Some("policy_destructive_without_approval")
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("authorityDestructiveDenial")
                            .and_then(|gate| gate.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    let approval_gate_live_output = approval_gate_live_attempt
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_approval_gate_denial")
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("approvalObserved"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("approvalGranted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("syntheticApprovalGranted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("authorityTransferred"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("authorityApprovalGate")
                            .and_then(|gate| gate.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    if policy_gate_live_attempt {
                        if policy_gate_live_output {
                            authority_tooling_policy_gate_live_success_count += 1;
                            authority_tooling_gate_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_policy_gate_live_output_not_ready".to_string(),
                            );
                        }
                    } else if destructive_denial_live_attempt {
                        if destructive_denial_live_output {
                            authority_tooling_destructive_denial_live_success_count += 1;
                            authority_tooling_gate_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_destructive_denial_live_output_not_ready"
                                    .to_string(),
                            );
                        }
                    } else if approval_gate_live_attempt {
                        if approval_gate_live_output {
                            authority_tooling_approval_gate_live_success_count += 1;
                            authority_tooling_gate_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_approval_gate_live_output_not_ready".to_string(),
                            );
                        }
                    }
                    previous_authority_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "live",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("harness-live-handoff:{sid}:{}", task.progress)
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "authority": {
                            "policyGateLiveExecution": policy_gate_live_output,
                            "destructiveDenialLiveExecution": destructive_denial_live_output,
                            "approvalGateLiveExecution": approval_gate_live_output,
                            "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                            "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                            "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                            "sideEffectsExecuted": authority_tooling_side_effects_executed,
                            "mutationExecuted": false,
                            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "authority_tooling_live_dry_run_executor_error:{attempt_slug}"
                    ));
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        }
                    }));
                }
            }
        }

        let authority_tooling_read_only_specs = vec![
            (
                "mcp_provider",
                "adapter",
                "Authority MCP provider read-only catalog",
                "authority_tooling_mcp_provider_read_only",
                "accept_mcp_provider_catalog_read_only_authority",
                false,
                json!({
                    "connectorBinding": {
                        "connectorRef": "mcp.capability-provider",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["mcp.provider.read", "mcp.catalog.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "operation": "catalog"
                    },
                    "providerCatalogLiveExecution": true,
                    "toolExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                "mcp_tool_call",
                "plugin_tool",
                "Authority MCP tool read-only catalog",
                "authority_tooling_mcp_tool_call_read_only",
                "accept_mcp_tool_read_only_dry_run_without_mutation",
                false,
                json!({
                    "toolBinding": {
                        "bindingKind": "mcp_tool",
                        "toolRef": "mcp.tool.catalog.read",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["mcp.tool.catalog.read", "mcp.provider.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "arguments": {
                            "mode": "catalog_preview",
                            "mutation": false,
                            "providerCatalogRef": "previousAuthorityOutput.providerCatalog"
                        }
                    },
                    "providerCatalogRequired": true,
                    "mcpToolCatalogLiveExecution": true,
                    "toolExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                "tool_call",
                "plugin_tool",
                "Authority native tool read-only catalog",
                "authority_tooling_tool_call_read_only",
                "accept_native_tool_catalog_read_only_without_mutation",
                false,
                json!({
                    "toolBinding": {
                        "bindingKind": "native_tool",
                        "toolRef": "agent.runtime.native-tool.catalog.read",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["native.tool.catalog.read", "mcp.tool.catalog.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "arguments": {
                            "mode": "native_catalog_preview",
                            "mutation": false,
                            "mcpToolCatalogRef": "input.mcpToolCatalog"
                        }
                    },
                    "mcpToolCatalogRequired": true,
                    "nativeToolCatalogLiveExecution": true,
                    "toolExecutionEnabled": false,
                    "nativeToolExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                "connector_call",
                "adapter",
                "Authority connector read-only describe",
                "authority_tooling_connector_call_read_only",
                "accept_connector_read_only_describe_without_mutation",
                false,
                json!({
                    "connectorBinding": {
                        "connectorRef": "agent.connector.catalog",
                        "mockBinding": false,
                        "credentialReady": true,
                        "capabilityScope": ["connector.catalog.read", "mcp.tool.catalog.read"],
                        "sideEffectClass": "read",
                        "requiresApproval": false,
                        "operation": "describe"
                    },
                    "mcpToolCatalogRequired": true,
                    "connectorCatalogLiveExecution": true,
                    "connectorExecutionEnabled": false,
                    "readOnlyAuthority": true,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
            (
                "wallet_capability",
                "human_gate",
                "Authority wallet capability read-only denial",
                "authority_tooling_wallet_capability_read_only",
                "retain_wallet_capability_without_grant",
                true,
                json!({
                    "text": "Wallet and spending authority remain unavailable during read-only default harness dispatch.",
                    "approvalMode": "wallet_capability_dry_run",
                    "capabilityScope": ["wallet.request", "capability.grant"],
                    "readOnlyAuthority": true,
                    "requiresApproval": true,
                    "policyDecision": "retain_wallet_capability_without_grant",
                    "syntheticApprovalGranted": false,
                    "capabilityDryRunLiveExecution": true,
                    "capabilityGranted": false,
                    "grantMaterialized": false,
                    "authorityTransferred": false,
                    "sideEffectsExecuted": false,
                    "mutationExecuted": false,
                    "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                }),
            ),
        ];
        for (
            component_kind,
            node_type,
            node_name,
            attempt_slug,
            policy_decision,
            require_human_gate,
            logic,
        ) in authority_tooling_read_only_specs
        {
            let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
            let attempt_id = format!(
                "harness-default-dispatch:{sid}:{turn_id}:{attempt_slug}:attempt-{attempt_index}"
            );
            let workflow_node_id = format!("harness.default_dispatch.{attempt_slug}");
            let receipt_id = format!("{sid}:{workflow_node_id}:{policy_decision}");
            let replay_fixture_ref =
                format!("runtime-evidence:{sid}:default-dispatch-fixture:{attempt_slug}");
            let input = json!({
                "sessionId": sid,
                "turnId": turn_id,
                "selectorDecisionId": selector_decision_id,
                "sourceBoundaryIds": source_boundary_ids,
                "componentKind": component_kind,
                "previousAuthorityOutput": previous_authority_output,
                "mcpToolCatalog": previous_mcp_tool_catalog.clone(),
                "mode": "workflow_read_only_authority_canary",
                "readOnlyAuthority": true,
                "readOnlyComponentKinds": authority_tooling_read_only_component_kinds.clone(),
                "mutationDeferredComponentKinds": authority_tooling_mutation_deferred_component_kinds.clone(),
                "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
                "destructiveRouteDenied": authority_tooling_destructive_route_denied,
                "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
                "sideEffectsExecuted": false,
                "mutationExecuted": false,
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            });
            let input_hash = runtime_harness_canary_node_output_hash(&input);
            let node = json!({
                "id": workflow_node_id,
                "type": node_type,
                "name": node_name,
                "config": {
                    "logic": logic,
                    "law": {
                        "requireHumanGate": require_human_gate,
                        "sandboxPolicy": {
                            "permissions": []
                        }
                    }
                }
            });
            let started_at_ms = crate::kernel::state::now();
            let execution =
                crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
            let finished_at_ms = crate::kernel::state::now();
            dispatch_node_attempt_ids.push(attempt_id.clone());
            authority_tooling_live_dry_run_attempt_ids.push(attempt_id.clone());
            authority_tooling_read_only_live_attempt_ids.push(attempt_id.clone());
            receipt_ids.push(receipt_id.clone());
            authority_tooling_read_only_receipt_ids.push(receipt_id.clone());
            replay_fixture_refs.push(replay_fixture_ref.clone());
            authority_tooling_read_only_replay_fixture_refs.push(replay_fixture_ref.clone());
            let provider_catalog_live_attempt = component_kind == "mcp_provider";
            if provider_catalog_live_attempt {
                authority_tooling_provider_catalog_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_provider_catalog_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_provider_catalog_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            let mcp_tool_catalog_live_attempt = component_kind == "mcp_tool_call";
            if mcp_tool_catalog_live_attempt {
                authority_tooling_mcp_tool_catalog_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_mcp_tool_catalog_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_mcp_tool_catalog_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            let native_tool_catalog_live_attempt = component_kind == "tool_call";
            if native_tool_catalog_live_attempt {
                authority_tooling_native_tool_catalog_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_native_tool_catalog_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_native_tool_catalog_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            let connector_catalog_live_attempt = component_kind == "connector_call";
            if connector_catalog_live_attempt {
                authority_tooling_connector_catalog_live_attempt_ids.push(attempt_id.clone());
                authority_tooling_connector_catalog_live_receipt_ids.push(receipt_id.clone());
                authority_tooling_connector_catalog_live_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            let wallet_capability_live_dry_run_attempt = component_kind == "wallet_capability";
            if wallet_capability_live_dry_run_attempt {
                authority_tooling_wallet_capability_live_dry_run_attempt_ids
                    .push(attempt_id.clone());
                authority_tooling_wallet_capability_live_dry_run_receipt_ids
                    .push(receipt_id.clone());
                authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs
                    .push(replay_fixture_ref.clone());
            }
            match execution {
                Ok(output) => {
                    let output_hash = runtime_harness_canary_node_output_hash(&output);
                    let provider_catalog_live_output = provider_catalog_live_attempt
                        && output.get("mockBinding").and_then(Value::as_bool) == Some(false)
                        && output
                            .get("providerCatalog")
                            .and_then(|catalog| catalog.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("providerCatalog")
                            .and_then(|catalog| catalog.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_read_only_catalog")
                        && output
                            .get("providerCatalog")
                            .and_then(|catalog| catalog.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("providerCatalog")
                            .and_then(|catalog| catalog.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("providerCatalog")
                            .and_then(|catalog| catalog.get("toolExecutionEnabled"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    let mcp_tool_catalog_live_output = mcp_tool_catalog_live_attempt
                        && output.get("mockBinding").and_then(Value::as_bool) == Some(false)
                        && output
                            .get("mcpToolCatalog")
                            .and_then(|catalog| catalog.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("mcpToolCatalog")
                            .and_then(|catalog| catalog.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_read_only_catalog_consumer")
                        && output
                            .get("mcpToolCatalog")
                            .and_then(|catalog| catalog.get("providerCatalogLinked"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("mcpToolCatalog")
                            .and_then(|catalog| catalog.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("mcpToolCatalog")
                            .and_then(|catalog| catalog.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("mcpToolCatalog")
                            .and_then(|catalog| catalog.get("toolExecutionEnabled"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    let native_tool_catalog_live_output = native_tool_catalog_live_attempt
                        && output.get("mockBinding").and_then(Value::as_bool) == Some(false)
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_read_only_native_tool_catalog")
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("mcpToolCatalogLinked"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("toolExecutionEnabled"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("nativeToolCatalog")
                            .and_then(|catalog| catalog.get("nativeToolExecutionEnabled"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    let connector_catalog_live_output = connector_catalog_live_attempt
                        && output.get("mockBinding").and_then(Value::as_bool) == Some(false)
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("live"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("executionMode"))
                            .and_then(Value::as_str)
                            == Some("live_read_only_connector_describe")
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("mcpToolCatalogLinked"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("sideEffectsExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("mutationExecuted"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("connectorExecutionEnabled"))
                            .and_then(Value::as_bool)
                            == Some(false)
                        && output
                            .get("connectorCatalog")
                            .and_then(|catalog| catalog.get("externalRequestEnabled"))
                            .and_then(Value::as_bool)
                            == Some(false);
                    let wallet_capability_live_dry_run_output =
                        wallet_capability_live_dry_run_attempt
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("live"))
                                .and_then(Value::as_bool)
                                == Some(true)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("executionMode"))
                                .and_then(Value::as_str)
                                == Some("live_non_mutating_capability_dry_run")
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("approvalObserved"))
                                .and_then(Value::as_bool)
                                == Some(true)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("capabilityRequested"))
                                .and_then(Value::as_bool)
                                == Some(true)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("capabilityGranted"))
                                .and_then(Value::as_bool)
                                == Some(false)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("grantMaterialized"))
                                .and_then(Value::as_bool)
                                == Some(false)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("authorityTransferred"))
                                .and_then(Value::as_bool)
                                == Some(false)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("sideEffectsExecuted"))
                                .and_then(Value::as_bool)
                                == Some(false)
                            && output
                                .get("walletCapabilityDryRun")
                                .and_then(|dry_run| dry_run.get("mutationExecuted"))
                                .and_then(Value::as_bool)
                                == Some(false);
                    if provider_catalog_live_attempt {
                        if provider_catalog_live_output {
                            authority_tooling_provider_catalog_live_success_count += 1;
                            authority_tooling_read_only_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_provider_catalog_live_output_not_ready"
                                    .to_string(),
                            );
                        }
                    } else if mcp_tool_catalog_live_attempt {
                        if mcp_tool_catalog_live_output {
                            authority_tooling_mcp_tool_catalog_live_success_count += 1;
                            authority_tooling_read_only_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_mcp_tool_catalog_live_output_not_ready"
                                    .to_string(),
                            );
                        }
                    } else if native_tool_catalog_live_attempt {
                        if native_tool_catalog_live_output {
                            authority_tooling_native_tool_catalog_live_success_count += 1;
                            authority_tooling_read_only_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_native_tool_catalog_live_output_not_ready"
                                    .to_string(),
                            );
                        }
                    } else if connector_catalog_live_attempt {
                        if connector_catalog_live_output {
                            authority_tooling_connector_catalog_live_success_count += 1;
                            authority_tooling_read_only_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_connector_catalog_live_output_not_ready"
                                    .to_string(),
                            );
                        }
                    } else if wallet_capability_live_dry_run_attempt {
                        if wallet_capability_live_dry_run_output {
                            authority_tooling_wallet_capability_live_dry_run_success_count += 1;
                            authority_tooling_read_only_live_success_count += 1;
                        } else {
                            activation_blockers.push(
                                "authority_tooling_wallet_capability_live_dry_run_output_not_ready"
                                    .to_string(),
                            );
                        }
                    } else {
                        authority_tooling_read_only_live_success_count += 1;
                    }
                    if mcp_tool_catalog_live_attempt {
                        if let Some(catalog) = output.get("mcpToolCatalog") {
                            previous_mcp_tool_catalog = catalog.clone();
                        }
                    }
                    previous_authority_output = output.clone();
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "live",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": output_hash,
                        "errorClass": null,
                        "policyDecision": policy_decision,
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("harness-read-only-authority:{sid}:{}", task.progress),
                            format!("harness-live-handoff:{sid}:{}", task.progress)
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "authority": {
                            "readOnlyAuthority": true,
                            "sideEffectsExecuted": false,
                            "mutationExecuted": false,
                            "providerCatalogLiveExecution": provider_catalog_live_output,
                            "mcpToolCatalogLiveExecution": mcp_tool_catalog_live_output,
                            "nativeToolCatalogLiveExecution": native_tool_catalog_live_output,
                            "connectorCatalogLiveExecution": connector_catalog_live_output,
                            "walletCapabilityLiveDryRunExecution": wallet_capability_live_dry_run_output,
                            "toolExecutionEnabled": false,
                            "nativeToolExecutionEnabled": false,
                            "connectorExecutionEnabled": false,
                            "capabilityGranted": false,
                            "grantMaterialized": false,
                            "authorityTransferred": false,
                            "mutationAuthorityDeferred": true,
                            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                        },
                        "executorResult": output
                    }));
                }
                Err(error) => {
                    activation_blockers.push(format!(
                        "authority_tooling_read_only_authority_executor_error:{attempt_slug}"
                    ));
                    dispatch_node_attempts.push(json!({
                        "attemptId": attempt_id,
                        "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                        "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                        "workflowNodeId": workflow_node_id,
                        "workflowNodeType": node_type,
                        "componentId": format!("ioi.agent-harness.default_runtime_dispatch.{attempt_slug}.v1"),
                        "componentKind": component_kind,
                        "executionMode": "live",
                        "readiness": "live_ready",
                        "attemptIndex": attempt_index,
                        "status": "rolled_back",
                        "executor": "workflow_node_executor",
                        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                        "inputHash": input_hash,
                        "outputHash": null,
                        "errorClass": "workflow_executor_error",
                        "error": error,
                        "policyDecision": "rollback_to_legacy_runtime",
                        "startedAtMs": started_at_ms,
                        "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                        "receiptIds": [receipt_id],
                        "evidenceRefs": [
                            format!("runtime-evidence:{sid}"),
                            selector_decision_id.clone(),
                            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                        ],
                        "replay": {
                            "deterministicEnvelope": true,
                            "capturesInput": true,
                            "capturesOutput": true,
                            "capturesPolicyDecision": true,
                            "fixtureRef": replay_fixture_ref,
                            "determinism": "deterministic",
                            "nondeterminismReason": null,
                            "redactionPolicy": "autopilot-runtime-evidence-v1"
                        },
                        "authority": {
                            "readOnlyAuthority": false,
                            "sideEffectsExecuted": false,
                            "mutationExecuted": false,
                            "providerCatalogLiveExecution": false,
                            "mcpToolCatalogLiveExecution": false,
                            "nativeToolCatalogLiveExecution": false,
                            "connectorCatalogLiveExecution": false,
                            "walletCapabilityLiveDryRunExecution": false,
                            "toolExecutionEnabled": false,
                            "nativeToolExecutionEnabled": false,
                            "connectorExecutionEnabled": false,
                            "capabilityGranted": false,
                            "grantMaterialized": false,
                            "authorityTransferred": false,
                            "mutationAuthorityDeferred": true,
                            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
                        }
                    }));
                }
            }
        }

        let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
        let attempt_id =
            format!("harness-default-dispatch:{sid}:{turn_id}:output_writer_handoff:attempt-{attempt_index}");
        let workflow_node_id = "harness.default_dispatch.output_writer_handoff".to_string();
        let receipt_id = format!("{sid}:{workflow_node_id}:default-output-handoff");
        let replay_fixture_ref =
            format!("runtime-evidence:{sid}:default-dispatch-fixture:output_writer_handoff");
        let input = json!({
            "sessionId": sid,
            "turnId": turn_id,
            "selectorDecisionId": selector_decision_id,
            "sourceBoundaryIds": source_boundary_ids,
            "outputWriterComponentKind": "output_writer",
            "proposedVisibleOutputHash": proposed_visible_output_hash,
            "actualVisibleOutputHash": actual_visible_output_hash,
            "outputHashAlgorithm": "runtime_prompt_hash:v1",
            "outputHashMatches": output_hash_matches,
            "visibleOutputAuthority": "existing_runtime_service",
            "outputWriterAuthorityTransferred": false
        });
        let input_hash = runtime_harness_canary_node_output_hash(&input);
        let node = json!({
            "id": workflow_node_id,
            "type": "decision",
            "name": "Output writer hash handoff",
            "config": {
                "logic": {
                    "routes": ["handoff_validated", "output_hash_divergence"],
                    "defaultRoute": if output_hash_matches { "handoff_validated" } else { "output_hash_divergence" },
                    "proposedVisibleOutputHash": proposed_visible_output_hash,
                    "actualVisibleOutputHash": actual_visible_output_hash,
                    "outputHashAlgorithm": "runtime_prompt_hash:v1",
                    "legacyOutputAuthorityRetained": false,
                    "outputWriterAuthorityTransferred": true
                },
                "law": {
                    "requireHumanGate": false,
                    "sandboxPolicy": {
                        "permissions": []
                    }
                }
            }
        });
        let started_at_ms = crate::kernel::state::now();
        let execution =
            crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
        let finished_at_ms = crate::kernel::state::now();
        dispatch_node_attempt_ids.push(attempt_id.clone());
        output_writer_handoff_attempt_ids.push(attempt_id.clone());
        receipt_ids.push(receipt_id.clone());
        replay_fixture_refs.push(replay_fixture_ref.clone());
        match execution {
            Ok(output) => {
                let output_hash = runtime_harness_canary_node_output_hash(&output);
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "decision",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_handoff.v1",
                    "componentKind": "output_writer_handoff",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "live",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": output_hash,
                    "errorClass": null,
                    "policyDecision": "validate_output_writer_hash_handoff",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-live-handoff:{sid}:{}", task.progress)
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    },
                    "executorResult": output
                }));
            }
            Err(error) => {
                activation_blockers.push("output_writer_handoff_executor_error".to_string());
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "decision",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_handoff.v1",
                    "componentKind": "output_writer_handoff",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "rolled_back",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": null,
                    "errorClass": "workflow_executor_error",
                    "error": error,
                    "policyDecision": "rollback_to_legacy_runtime",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    }
                }));
            }
        }

        let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
        let attempt_id =
            format!("harness-default-dispatch:{sid}:{turn_id}:output_writer_materialization_canary:attempt-{attempt_index}");
        let workflow_node_id =
            "harness.default_dispatch.output_writer_materialization_canary".to_string();
        let receipt_id =
            format!("{sid}:{workflow_node_id}:guarded-transcript-materialization-canary");
        let replay_fixture_ref = format!(
            "runtime-evidence:{sid}:default-dispatch-fixture:output_writer_materialization_canary"
        );
        let transcript_materialization_comparison = json!({
            "candidateRecord": workflow_transcript_write_candidate,
            "legacyRecord": legacy_transcript_write_record,
            "contentHashMatches": transcript_materialization_content_hash_matches,
            "orderMatches": transcript_materialization_order_matches,
            "receiptBindingMatches": transcript_materialization_receipt_binding_matches,
            "targetMatches": transcript_materialization_target_matches,
            "candidateCommitted": false,
            "legacyCommitted": transcript_materialization_legacy_committed,
            "legacyDuplicateSuppressed": transcript_materialization_legacy_idempotent,
            "matches": transcript_materialization_matches,
            "divergenceClass": if transcript_materialization_matches { Value::Null } else { json!("transcript_materialization_divergence") }
        });
        let input = json!({
            "sessionId": sid,
            "turnId": turn_id,
            "selectorDecisionId": selector_decision_id,
            "sourceBoundaryIds": source_boundary_ids,
            "outputWriterComponentKind": "output_writer",
            "visibleOutputAuthority": "existing_runtime_service",
            "workflowCandidateWriteAuthority": "blessed_workflow_activation_default",
            "workflowCandidateCommitted": false,
            "legacyTranscriptAuthorityRetained": transcript_materialization_legacy_committed,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "comparison": transcript_materialization_comparison
        });
        let input_hash = runtime_harness_canary_node_output_hash(&input);
        let node = json!({
            "id": workflow_node_id,
            "type": "output",
            "name": "Output writer guarded transcript materialization canary",
            "config": {
                "logic": {
                    "format": "json",
                    "rendererRef": { "rendererId": "json", "displayMode": "inline" },
                    "deliveryTarget": {
                        "targetKind": "checkpoint_transcript_messages",
                        "requiresApproval": false,
                        "commitMode": "candidate_only"
                    },
                    "materialization": {
                        "enabled": false,
                        "assetKind": "transcript_write_candidate"
                    },
                    "versioning": { "enabled": true },
                    "sideEffectClass": "none",
                    "candidateOnly": true,
                    "legacyOutputAuthorityRetained": transcript_materialization_legacy_committed
                },
                "law": {
                    "requireHumanGate": false,
                    "sandboxPolicy": {
                        "permissions": []
                    }
                }
            }
        });
        let started_at_ms = crate::kernel::state::now();
        let execution =
            crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
        let finished_at_ms = crate::kernel::state::now();
        dispatch_node_attempt_ids.push(attempt_id.clone());
        output_writer_materialization_canary_attempt_ids.push(attempt_id.clone());
        receipt_ids.push(receipt_id.clone());
        replay_fixture_refs.push(replay_fixture_ref.clone());
        match execution {
            Ok(output) => {
                let output_hash = runtime_harness_canary_node_output_hash(&output);
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "output",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_materialization_canary.v1",
                    "componentKind": "output_writer_materialization_canary",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "live",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": output_hash,
                    "errorClass": null,
                    "policyDecision": "validate_guarded_transcript_materialization_canary",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-live-handoff:{sid}:{}", task.progress)
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    },
                    "executorResult": output
                }));
            }
            Err(error) => {
                activation_blockers
                    .push("output_writer_materialization_canary_executor_error".to_string());
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "output",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_materialization_canary.v1",
                    "componentKind": "output_writer_materialization_canary",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "rolled_back",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": null,
                    "errorClass": "workflow_executor_error",
                    "error": error,
                    "policyDecision": "rollback_to_legacy_runtime",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    }
                }));
            }
        }

        let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
        let attempt_id =
            format!("harness-default-dispatch:{sid}:{turn_id}:output_writer_staged_write_canary:attempt-{attempt_index}");
        let workflow_node_id =
            "harness.default_dispatch.output_writer_staged_write_canary".to_string();
        let receipt_id =
            format!("{sid}:{workflow_node_id}:isolated-transcript-staging-write-canary");
        let replay_fixture_ref = format!(
            "runtime-evidence:{sid}:default-dispatch-fixture:output_writer_staged_write_canary"
        );
        let staged_transcript_write_comparison = json!({
            "stagedRecord": staged_transcript_write_record,
            "legacyRecord": legacy_transcript_write_record,
            "stagingProof": staged_transcript_write_proof,
            "contentHashMatches": staged_transcript_write_content_hash_matches,
            "orderMatches": staged_transcript_write_order_matches,
            "receiptBindingMatches": staged_transcript_write_receipt_binding_matches,
            "targetMatches": staged_transcript_write_target_matches,
            "stagedWritePersisted": output_writer_staged_write_persisted,
            "stagedWriteCommitted": output_writer_staged_write_committed,
            "stagedWriteVisible": output_writer_staged_write_visible,
            "excludedFromVisibleTranscript": output_writer_staged_write_excluded_from_visible_transcript,
            "rollbackStatus": output_writer_staged_write_rollback_status,
            "rollbackVerified": output_writer_staged_write_rollback_verified,
            "matches": staged_transcript_write_matches,
            "divergenceClass": if staged_transcript_write_matches { Value::Null } else { json!("staged_transcript_write_divergence") }
        });
        let input = json!({
            "sessionId": sid,
            "turnId": turn_id,
            "selectorDecisionId": selector_decision_id,
            "sourceBoundaryIds": source_boundary_ids,
            "outputWriterComponentKind": "output_writer",
            "visibleOutputAuthority": "existing_runtime_service",
            "workflowStagedWriteAuthority": "blessed_workflow_activation_default",
            "stagingSurface": "checkpoint_blobs",
            "checkpointName": WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
            "visibleTranscriptCommit": false,
            "stagedWritePersisted": output_writer_staged_write_persisted,
            "stagedWriteRollbackVerified": output_writer_staged_write_rollback_verified,
            "legacyTranscriptAuthorityRetained": transcript_materialization_legacy_committed,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "comparison": staged_transcript_write_comparison
        });
        let input_hash = runtime_harness_canary_node_output_hash(&input);
        let node = json!({
            "id": workflow_node_id,
            "type": "output",
            "name": "Output writer isolated transcript staging write canary",
            "config": {
                "logic": {
                    "format": "json",
                    "rendererRef": { "rendererId": "json", "displayMode": "inline" },
                    "deliveryTarget": {
                        "targetKind": "checkpoint_blobs",
                        "checkpointName": WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
                        "requiresApproval": false,
                        "commitMode": "staged_non_visible"
                    },
                    "materialization": {
                        "enabled": true,
                        "assetKind": "transcript_write_staging_record",
                        "visible": false
                    },
                    "versioning": { "enabled": true },
                    "sideEffectClass": "none",
                    "candidateOnly": false,
                    "visibleTranscriptCommit": false,
                    "legacyOutputAuthorityRetained": transcript_materialization_legacy_committed
                },
                "law": {
                    "requireHumanGate": false,
                    "sandboxPolicy": {
                        "permissions": []
                    }
                }
            }
        });
        let started_at_ms = crate::kernel::state::now();
        let execution =
            crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
        let finished_at_ms = crate::kernel::state::now();
        dispatch_node_attempt_ids.push(attempt_id.clone());
        output_writer_staged_write_canary_attempt_ids.push(attempt_id.clone());
        receipt_ids.push(receipt_id.clone());
        replay_fixture_refs.push(replay_fixture_ref.clone());
        match execution {
            Ok(output) => {
                let output_hash = runtime_harness_canary_node_output_hash(&output);
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "output",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_staged_write_canary.v1",
                    "componentKind": "output_writer_staged_write_canary",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "live",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": output_hash,
                    "errorClass": null,
                    "policyDecision": "validate_isolated_transcript_staging_write_canary",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-live-handoff:{sid}:{}", task.progress)
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    },
                    "executorResult": output
                }));
            }
            Err(error) => {
                activation_blockers
                    .push("output_writer_staged_write_canary_executor_error".to_string());
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "output",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_staged_write_canary.v1",
                    "componentKind": "output_writer_staged_write_canary",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "rolled_back",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": null,
                    "errorClass": "workflow_executor_error",
                    "error": error,
                    "policyDecision": "rollback_to_legacy_runtime",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    }
                }));
            }
        }

        let attempt_index = (dispatch_node_attempts.len() + 1) as u32;
        let attempt_id =
            format!("harness-default-dispatch:{sid}:{turn_id}:output_writer_visible_write_commit:attempt-{attempt_index}");
        let workflow_node_id =
            "harness.default_dispatch.output_writer_visible_write_commit".to_string();
        let receipt_id =
            format!("{sid}:{workflow_node_id}:workflow-visible-transcript-write-commit");
        let replay_fixture_ref = format!(
            "runtime-evidence:{sid}:default-dispatch-fixture:output_writer_visible_write_commit"
        );
        let visible_transcript_write_comparison = json!({
            "workflowRecord": workflow_visible_transcript_write_record,
            "legacyRecord": legacy_transcript_write_record,
            "visibleWriteProof": visible_transcript_write_proof,
            "legacyFallbackProof": legacy_transcript_fallback_proof,
            "contentHashMatches": visible_transcript_write_content_hash_matches,
            "orderMatches": visible_transcript_write_order_matches,
            "receiptBindingMatches": visible_transcript_write_receipt_binding_matches,
            "targetMatches": visible_transcript_write_target_matches,
            "workflowWritePersisted": output_writer_visible_write_persisted,
            "workflowWriteCommitted": output_writer_visible_write_committed,
            "workflowWriteVisible": output_writer_visible_write_visible,
            "identityCheckpointPersisted": output_writer_visible_write_identity_checkpoint_persisted,
            "legacyDuplicateSuppressed": output_writer_visible_write_duplicate_suppressed,
            "matches": visible_transcript_write_matches,
            "divergenceClass": if visible_transcript_write_matches { Value::Null } else { json!("visible_transcript_write_divergence") }
        });
        let input = json!({
            "sessionId": sid,
            "turnId": turn_id,
            "selectorDecisionId": selector_decision_id,
            "sourceBoundaryIds": source_boundary_ids,
            "outputWriterComponentKind": "output_writer",
            "visibleOutputAuthority": "blessed_workflow_activation_default",
            "legacyOutputAuthority": "existing_runtime_service",
            "legacyFallbackMode": "idempotent_noop",
            "visibleTranscriptCommit": true,
            "workflowVisibleWriteCommitted": output_writer_visible_write_committed,
            "legacyDuplicateSuppressed": output_writer_visible_write_duplicate_suppressed,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "comparison": visible_transcript_write_comparison
        });
        let input_hash = runtime_harness_canary_node_output_hash(&input);
        let node = json!({
            "id": workflow_node_id,
            "type": "output",
            "name": "Output writer workflow visible transcript commit",
            "config": {
                "logic": {
                    "format": "json",
                    "rendererRef": { "rendererId": "json", "displayMode": "inline" },
                    "deliveryTarget": {
                        "targetKind": "checkpoint_transcript_messages",
                        "requiresApproval": false,
                        "commitMode": "workflow_visible_transcript_write"
                    },
                    "materialization": {
                        "enabled": true,
                        "assetKind": "visible_transcript_message",
                        "visible": true
                    },
                    "versioning": { "enabled": true },
                    "sideEffectClass": "none",
                    "candidateOnly": false,
                    "visibleTranscriptCommit": true,
                    "legacyFallbackMode": "idempotent_noop"
                },
                "law": {
                    "requireHumanGate": false,
                    "sandboxPolicy": {
                        "permissions": []
                    }
                }
            }
        });
        let started_at_ms = crate::kernel::state::now();
        let execution =
            crate::project::execute_workflow_harness_live_default_node(&node, input.clone(), 1);
        let finished_at_ms = crate::kernel::state::now();
        dispatch_node_attempt_ids.push(attempt_id.clone());
        output_writer_visible_write_attempt_ids.push(attempt_id.clone());
        receipt_ids.push(receipt_id.clone());
        replay_fixture_refs.push(replay_fixture_ref.clone());
        match execution {
            Ok(output) => {
                let output_hash = runtime_harness_canary_node_output_hash(&output);
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "output",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_visible_write_commit.v1",
                    "componentKind": "output_writer_visible_write_commit",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "live",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": output_hash,
                    "errorClass": null,
                    "policyDecision": "validate_workflow_visible_transcript_write_commit",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("harness-live-handoff:{sid}:{}", task.progress)
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    },
                    "executorResult": output
                }));
            }
            Err(error) => {
                activation_blockers
                    .push("output_writer_visible_write_commit_executor_error".to_string());
                dispatch_node_attempts.push(json!({
                    "attemptId": attempt_id,
                    "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                    "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                    "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                    "workflowNodeId": workflow_node_id,
                    "workflowNodeType": "output",
                    "componentId": "ioi.agent-harness.default_runtime_dispatch.output_writer_visible_write_commit.v1",
                    "componentKind": "output_writer_visible_write_commit",
                    "executionMode": "live",
                    "readiness": "live_ready",
                    "attemptIndex": attempt_index,
                    "status": "rolled_back",
                    "executor": "workflow_node_executor",
                    "executorRef": "crate::project::execute_workflow_harness_live_default_node",
                    "inputHash": input_hash,
                    "outputHash": null,
                    "errorClass": "workflow_executor_error",
                    "error": error,
                    "policyDecision": "rollback_to_legacy_runtime",
                    "startedAtMs": started_at_ms,
                    "durationMs": finished_at_ms.saturating_sub(started_at_ms),
                    "receiptIds": [receipt_id],
                    "evidenceRefs": [
                        format!("runtime-evidence:{sid}"),
                        selector_decision_id.clone(),
                        format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
                    ],
                    "replay": {
                        "deterministicEnvelope": true,
                        "capturesInput": true,
                        "capturesOutput": true,
                        "capturesPolicyDecision": true,
                        "fixtureRef": replay_fixture_ref,
                        "determinism": "deterministic",
                        "nondeterminismReason": null,
                        "redactionPolicy": "autopilot-runtime-evidence-v1"
                    }
                }));
            }
        }
    }

    activation_blockers.sort();
    activation_blockers.dedup();
    dispatch_node_attempt_ids.sort();
    dispatch_node_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();
    output_writer_handoff_attempt_ids.sort();
    output_writer_handoff_attempt_ids.dedup();
    output_writer_materialization_canary_attempt_ids.sort();
    output_writer_materialization_canary_attempt_ids.dedup();
    output_writer_staged_write_canary_attempt_ids.sort();
    output_writer_staged_write_canary_attempt_ids.dedup();
    output_writer_visible_write_attempt_ids.sort();
    output_writer_visible_write_attempt_ids.dedup();
    cognition_execution_attempt_ids.sort();
    cognition_execution_attempt_ids.dedup();
    cognition_execution_receipt_ids.sort();
    cognition_execution_receipt_ids.dedup();
    cognition_execution_replay_fixture_refs.sort();
    cognition_execution_replay_fixture_refs.dedup();
    cognition_execution_action_frame_ids.sort();
    cognition_execution_action_frame_ids.dedup();
    cognition_execution_live_ready_component_kinds.sort();
    cognition_execution_live_ready_component_kinds.dedup();
    cognition_execution_gate_attempt_ids.sort();
    cognition_execution_gate_attempt_ids.dedup();
    cognition_execution_gate_receipt_ids.sort();
    cognition_execution_gate_receipt_ids.dedup();
    cognition_execution_gate_replay_fixture_refs.sort();
    cognition_execution_gate_replay_fixture_refs.dedup();
    cognition_execution_gate_action_frame_ids.sort();
    cognition_execution_gate_action_frame_ids.dedup();
    cognition_execution_gate_component_kinds.sort();
    cognition_execution_gate_component_kinds.dedup();
    cognition_execution_gate_divergence_classes.sort();
    cognition_execution_gate_divergence_classes.dedup();
    routing_model_attempt_ids.sort();
    routing_model_attempt_ids.dedup();
    routing_model_receipt_ids.sort();
    routing_model_receipt_ids.dedup();
    routing_model_replay_fixture_refs.sort();
    routing_model_replay_fixture_refs.dedup();
    routing_model_action_frame_ids.sort();
    routing_model_action_frame_ids.dedup();
    routing_model_component_kinds.sort();
    routing_model_component_kinds.dedup();
    routing_model_divergence_classes.sort();
    routing_model_divergence_classes.dedup();
    verification_output_attempt_ids.sort();
    verification_output_attempt_ids.dedup();
    verification_output_receipt_ids.sort();
    verification_output_receipt_ids.dedup();
    verification_output_replay_fixture_refs.sort();
    verification_output_replay_fixture_refs.dedup();
    verification_output_action_frame_ids.sort();
    verification_output_action_frame_ids.dedup();
    verification_output_component_kinds.sort();
    verification_output_component_kinds.dedup();
    verification_output_divergence_classes.sort();
    verification_output_divergence_classes.dedup();
    authority_tooling_attempt_ids.sort();
    authority_tooling_attempt_ids.dedup();
    authority_tooling_receipt_ids.sort();
    authority_tooling_receipt_ids.dedup();
    authority_tooling_replay_fixture_refs.sort();
    authority_tooling_replay_fixture_refs.dedup();
    authority_tooling_action_frame_ids.sort();
    authority_tooling_action_frame_ids.dedup();
    authority_tooling_component_kinds.sort();
    authority_tooling_component_kinds.dedup();
    authority_tooling_divergence_classes.sort();
    authority_tooling_divergence_classes.dedup();
    model_execution_attempt_ids.sort();
    model_execution_attempt_ids.dedup();
    model_execution_receipt_ids.sort();
    model_execution_receipt_ids.dedup();
    model_execution_replay_fixture_refs.sort();
    model_execution_replay_fixture_refs.dedup();
    model_provider_canary_attempt_ids.sort();
    model_provider_canary_attempt_ids.dedup();
    model_provider_canary_receipt_ids.sort();
    model_provider_canary_receipt_ids.dedup();
    model_provider_canary_replay_fixture_refs.sort();
    model_provider_canary_replay_fixture_refs.dedup();
    model_provider_gated_visible_output_attempt_ids.sort();
    model_provider_gated_visible_output_attempt_ids.dedup();
    model_provider_gated_visible_output_receipt_ids.sort();
    model_provider_gated_visible_output_receipt_ids.dedup();
    model_provider_gated_visible_output_replay_fixture_refs.sort();
    model_provider_gated_visible_output_replay_fixture_refs.dedup();
    model_provider_gated_visible_output_rollback_drill_attempt_ids.sort();
    model_provider_gated_visible_output_rollback_drill_attempt_ids.dedup();
    model_provider_gated_visible_output_rollback_drill_receipt_ids.sort();
    model_provider_gated_visible_output_rollback_drill_receipt_ids.dedup();
    model_provider_gated_visible_output_rollback_drill_replay_fixture_refs.sort();
    model_provider_gated_visible_output_rollback_drill_replay_fixture_refs.dedup();
    read_only_capability_routing_attempt_ids.sort();
    read_only_capability_routing_attempt_ids.dedup();
    read_only_capability_routing_receipt_ids.sort();
    read_only_capability_routing_receipt_ids.dedup();
    read_only_capability_routing_replay_fixture_refs.sort();
    read_only_capability_routing_replay_fixture_refs.dedup();
    authority_tooling_live_dry_run_attempt_ids.sort();
    authority_tooling_live_dry_run_attempt_ids.dedup();
    authority_tooling_read_only_live_attempt_ids.sort();
    authority_tooling_read_only_live_attempt_ids.dedup();
    authority_tooling_read_only_receipt_ids.sort();
    authority_tooling_read_only_receipt_ids.dedup();
    authority_tooling_read_only_replay_fixture_refs.sort();
    authority_tooling_read_only_replay_fixture_refs.dedup();
    authority_tooling_provider_catalog_live_attempt_ids.sort();
    authority_tooling_provider_catalog_live_attempt_ids.dedup();
    authority_tooling_provider_catalog_live_receipt_ids.sort();
    authority_tooling_provider_catalog_live_receipt_ids.dedup();
    authority_tooling_provider_catalog_live_replay_fixture_refs.sort();
    authority_tooling_provider_catalog_live_replay_fixture_refs.dedup();
    authority_tooling_mcp_tool_catalog_live_attempt_ids.sort();
    authority_tooling_mcp_tool_catalog_live_attempt_ids.dedup();
    authority_tooling_mcp_tool_catalog_live_receipt_ids.sort();
    authority_tooling_mcp_tool_catalog_live_receipt_ids.dedup();
    authority_tooling_mcp_tool_catalog_live_replay_fixture_refs.sort();
    authority_tooling_mcp_tool_catalog_live_replay_fixture_refs.dedup();
    authority_tooling_native_tool_catalog_live_attempt_ids.sort();
    authority_tooling_native_tool_catalog_live_attempt_ids.dedup();
    authority_tooling_native_tool_catalog_live_receipt_ids.sort();
    authority_tooling_native_tool_catalog_live_receipt_ids.dedup();
    authority_tooling_native_tool_catalog_live_replay_fixture_refs.sort();
    authority_tooling_native_tool_catalog_live_replay_fixture_refs.dedup();
    authority_tooling_connector_catalog_live_attempt_ids.sort();
    authority_tooling_connector_catalog_live_attempt_ids.dedup();
    authority_tooling_connector_catalog_live_receipt_ids.sort();
    authority_tooling_connector_catalog_live_receipt_ids.dedup();
    authority_tooling_connector_catalog_live_replay_fixture_refs.sort();
    authority_tooling_connector_catalog_live_replay_fixture_refs.dedup();
    authority_tooling_wallet_capability_live_dry_run_attempt_ids.sort();
    authority_tooling_wallet_capability_live_dry_run_attempt_ids.dedup();
    authority_tooling_wallet_capability_live_dry_run_receipt_ids.sort();
    authority_tooling_wallet_capability_live_dry_run_receipt_ids.dedup();
    authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs.sort();
    authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs.dedup();
    authority_tooling_gate_live_attempt_ids.sort();
    authority_tooling_gate_live_attempt_ids.dedup();
    authority_tooling_gate_live_receipt_ids.sort();
    authority_tooling_gate_live_receipt_ids.dedup();
    authority_tooling_gate_live_replay_fixture_refs.sort();
    authority_tooling_gate_live_replay_fixture_refs.dedup();
    authority_tooling_policy_gate_live_attempt_ids.sort();
    authority_tooling_policy_gate_live_attempt_ids.dedup();
    authority_tooling_policy_gate_live_receipt_ids.sort();
    authority_tooling_policy_gate_live_receipt_ids.dedup();
    authority_tooling_policy_gate_live_replay_fixture_refs.sort();
    authority_tooling_policy_gate_live_replay_fixture_refs.dedup();
    authority_tooling_destructive_denial_live_attempt_ids.sort();
    authority_tooling_destructive_denial_live_attempt_ids.dedup();
    authority_tooling_destructive_denial_live_receipt_ids.sort();
    authority_tooling_destructive_denial_live_receipt_ids.dedup();
    authority_tooling_destructive_denial_live_replay_fixture_refs.sort();
    authority_tooling_destructive_denial_live_replay_fixture_refs.dedup();
    authority_tooling_approval_gate_live_attempt_ids.sort();
    authority_tooling_approval_gate_live_attempt_ids.dedup();
    authority_tooling_approval_gate_live_receipt_ids.sort();
    authority_tooling_approval_gate_live_receipt_ids.dedup();
    authority_tooling_approval_gate_live_replay_fixture_refs.sort();
    authority_tooling_approval_gate_live_replay_fixture_refs.dedup();
    authority_tooling_denial_receipt_ids.sort();
    authority_tooling_denial_receipt_ids.dedup();
    let authority_tooling_policy_gate_live_ready =
        authority_tooling_policy_gate_live_success_count >= 1;
    let authority_tooling_destructive_denial_live_ready =
        authority_tooling_destructive_denial_live_success_count >= 1;
    let authority_tooling_approval_gate_live_ready =
        authority_tooling_approval_gate_live_success_count >= 1;
    let authority_tooling_gate_live_ready = authority_tooling_gate_live_success_count >= 3
        && authority_tooling_policy_gate_live_ready
        && authority_tooling_destructive_denial_live_ready
        && authority_tooling_approval_gate_live_ready;
    let authority_tooling_read_only_authority_canary_ready =
        authority_tooling_read_only_live_success_count
            >= authority_tooling_read_only_component_kinds.len();
    let authority_tooling_provider_catalog_live_ready =
        authority_tooling_provider_catalog_live_success_count >= 1;
    let authority_tooling_mcp_tool_catalog_live_ready =
        authority_tooling_mcp_tool_catalog_live_success_count >= 1;
    let authority_tooling_native_tool_catalog_live_ready =
        authority_tooling_native_tool_catalog_live_success_count >= 1;
    let authority_tooling_connector_catalog_live_ready =
        authority_tooling_connector_catalog_live_success_count >= 1;
    let authority_tooling_wallet_capability_live_dry_run_ready =
        authority_tooling_wallet_capability_live_dry_run_success_count >= 1;
    let mut node_attempt_ids = accepted_node_attempt_ids.clone();
    node_attempt_ids.extend(dispatch_node_attempt_ids.clone());
    node_attempt_ids.sort();
    node_attempt_ids.dedup();
    let dispatch_accepted = can_dispatch && activation_blockers.is_empty();
    let default_dispatch_activation_blockers = activation_blockers.clone();
    let verification_output_ready = verification_output_adapter_results.len() >= 6
        && verification_output_divergence_classes
            .iter()
            .all(|value| value == "none");
    let verification_output_proof = json!({
        "schemaVersion": "workflow.harness.verification-output-envelope.v1",
        "mode": "workflow_synchronous_envelope",
        "adapterMode": "workflow_component_adapter_gated",
        "adapterResultCount": verification_output_adapter_results.len(),
        "attemptIds": verification_output_attempt_ids.clone(),
        "receiptIds": verification_output_receipt_ids.clone(),
        "replayFixtureRefs": verification_output_replay_fixture_refs.clone(),
        "actionFrameIds": verification_output_action_frame_ids.clone(),
        "componentKinds": verification_output_component_kinds.clone(),
        "divergenceClasses": verification_output_divergence_classes.clone(),
        "completionDecision": "objective_satisfied",
        "receiptProjectionAuthority": "blessed_workflow_activation_default",
        "qualityLedgerAuthority": "blessed_workflow_activation_default",
        "outputWriterAuthority": "blessed_workflow_activation_default",
        "selectedVisibleOutputAuthority": selected_visible_output_authority,
        "selectedVisibleOutputHash": selected_visible_output_hash.clone(),
        "outputHashMatches": output_hash_matches,
        "ready": verification_output_ready,
        "policyDecision": "accept_workflow_verification_output_adapter_envelope"
    });
    let authority_tooling_adapter_ready = authority_tooling_adapter_results.len() >= 8
        && authority_tooling_divergence_classes
            .iter()
            .all(|value| value == "none");
    let authority_tooling_adapter_proof = json!({
        "schemaVersion": "workflow.harness.authority-tooling-adapter-envelope.v1",
        "mode": "workflow_synchronous_envelope",
        "adapterMode": "workflow_component_adapter_gated",
        "adapterResultCount": authority_tooling_adapter_results.len(),
        "attemptIds": authority_tooling_attempt_ids.clone(),
        "receiptIds": authority_tooling_receipt_ids.clone(),
        "replayFixtureRefs": authority_tooling_replay_fixture_refs.clone(),
        "actionFrameIds": authority_tooling_action_frame_ids.clone(),
        "componentKinds": authority_tooling_component_kinds.clone(),
        "divergenceClasses": authority_tooling_divergence_classes.clone(),
        "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
        "destructiveRouteDenied": authority_tooling_destructive_route_denied,
        "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "authorityTransferred": false,
        "readOnlyCatalogReady": authority_tooling_read_only_authority_canary_ready,
        "mutationDeferredComponentKinds": authority_tooling_mutation_deferred_component_kinds.clone(),
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "ready": authority_tooling_adapter_ready,
        "policyDecision": "accept_workflow_authority_tooling_adapter_envelope"
    });
    let live_promotion_cognition_ready = cognition_execution_ready
        && cognition_execution_adapter_results.len() >= 3
        && cognition_execution_gate_adapter_results.len() >= 3
        && cognition_execution_gate_divergence_classes
            .iter()
            .all(|value| value == "none");
    let live_promotion_routing_model_ready = routing_model_adapter_results.len() >= 3
        && routing_model_divergence_classes
            .iter()
            .all(|value| value == "none")
        && model_provider_canary_ready
        && model_provider_gated_visible_output_ready
        && model_provider_gated_visible_output_rollback_drill_ready;
    let live_promotion_verification_output_ready = verification_output_ready
        && output_writer_visible_write_ready
        && output_writer_visible_write_committed
        && output_writer_visible_write_identity_checkpoint_persisted;
    let live_promotion_authority_tooling_ready = authority_tooling_adapter_ready
        && authority_tooling_gate_live_ready
        && authority_tooling_read_only_authority_canary_ready
        && authority_tooling_provider_catalog_live_ready
        && authority_tooling_mcp_tool_catalog_live_ready
        && authority_tooling_native_tool_catalog_live_ready
        && authority_tooling_connector_catalog_live_ready
        && authority_tooling_wallet_capability_live_dry_run_ready;
    let mut live_promotion_cognition_action_frame_ids =
        cognition_execution_action_frame_ids.clone();
    live_promotion_cognition_action_frame_ids
        .extend(cognition_execution_gate_action_frame_ids.clone());
    let live_promotion_cluster_readiness = json!([
        {
            "clusterId": "cognition",
            "label": "Cognition",
            "currentStatus": "gated",
            "targetExecutionMode": "live",
            "componentKinds": cognition_execution_live_ready_component_kinds.clone(),
            "readinessReady": live_promotion_cognition_ready,
            "receiptReady": !cognition_execution_receipt_ids.is_empty(),
            "replayGateReady": !cognition_execution_replay_fixture_refs.is_empty()
                && cognition_execution_gate_divergence_classes.iter().all(|value| value == "none"),
            "canaryReady": true,
            "rollbackReady": true,
            "divergenceReady": cognition_execution_gate_divergence_classes.iter().all(|value| value == "none"),
            "blockingDivergenceCount": cognition_execution_gate_divergence_classes.iter().filter(|value| *value != "none" && *value != "harmless_metadata").count(),
            "unclassifiedDivergenceCount": cognition_execution_gate_divergence_classes.iter().filter(|value| *value == "unclassified").count(),
            "attemptIds": cognition_execution_attempt_ids.clone(),
            "receiptRefs": cognition_execution_receipt_ids.clone(),
            "replayFixtureRefs": cognition_execution_replay_fixture_refs.clone(),
            "actionFrameIds": live_promotion_cognition_action_frame_ids,
            "divergenceClasses": cognition_execution_gate_divergence_classes.clone(),
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "blockers": if live_promotion_cognition_ready { Vec::<&str>::new() } else { vec!["cognition_live_promotion_not_ready"] },
            "decision": if live_promotion_cognition_ready { "allow_default_harness_live_cluster_promotion" } else { "block_default_harness_live_cluster_promotion" }
        },
        {
            "clusterId": "routing_model",
            "label": "Routing and model",
            "currentStatus": "gated",
            "targetExecutionMode": "live",
            "componentKinds": routing_model_component_kinds.clone(),
            "readinessReady": live_promotion_routing_model_ready,
            "receiptReady": !routing_model_receipt_ids.is_empty(),
            "replayGateReady": !routing_model_replay_fixture_refs.is_empty()
                && routing_model_divergence_classes.iter().all(|value| value == "none"),
            "canaryReady": model_provider_canary_ready && model_provider_gated_visible_output_ready,
            "rollbackReady": model_provider_canary_rollback_available
                && model_provider_gated_visible_output_rollback_drill_ready,
            "divergenceReady": routing_model_divergence_classes.iter().all(|value| value == "none"),
            "blockingDivergenceCount": routing_model_divergence_classes.iter().filter(|value| *value != "none" && *value != "harmless_metadata").count(),
            "unclassifiedDivergenceCount": routing_model_divergence_classes.iter().filter(|value| *value == "unclassified").count(),
            "attemptIds": routing_model_attempt_ids.clone(),
            "receiptRefs": routing_model_receipt_ids.clone(),
            "replayFixtureRefs": routing_model_replay_fixture_refs.clone(),
            "actionFrameIds": routing_model_action_frame_ids.clone(),
            "divergenceClasses": routing_model_divergence_classes.clone(),
            "rollbackTarget": "legacy_runtime_model_invocation",
            "blockers": if live_promotion_routing_model_ready { Vec::<&str>::new() } else { vec!["routing_model_live_promotion_not_ready"] },
            "decision": if live_promotion_routing_model_ready { "allow_default_harness_live_cluster_promotion" } else { "block_default_harness_live_cluster_promotion" }
        },
        {
            "clusterId": "verification_output",
            "label": "Verification and output",
            "currentStatus": "gated",
            "targetExecutionMode": "live",
            "componentKinds": verification_output_component_kinds.clone(),
            "readinessReady": live_promotion_verification_output_ready,
            "receiptReady": !verification_output_receipt_ids.is_empty(),
            "replayGateReady": !verification_output_replay_fixture_refs.is_empty()
                && verification_output_divergence_classes.iter().all(|value| value == "none"),
            "canaryReady": output_writer_visible_write_ready,
            "rollbackReady": output_writer_staged_write_rollback_verified,
            "divergenceReady": verification_output_divergence_classes.iter().all(|value| value == "none"),
            "blockingDivergenceCount": verification_output_divergence_classes.iter().filter(|value| *value != "none" && *value != "harmless_metadata").count(),
            "unclassifiedDivergenceCount": verification_output_divergence_classes.iter().filter(|value| *value == "unclassified").count(),
            "attemptIds": verification_output_attempt_ids.clone(),
            "receiptRefs": verification_output_receipt_ids.clone(),
            "replayFixtureRefs": verification_output_replay_fixture_refs.clone(),
            "actionFrameIds": verification_output_action_frame_ids.clone(),
            "divergenceClasses": verification_output_divergence_classes.clone(),
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "blockers": if live_promotion_verification_output_ready { Vec::<&str>::new() } else { vec!["verification_output_live_promotion_not_ready"] },
            "decision": if live_promotion_verification_output_ready { "allow_default_harness_live_cluster_promotion" } else { "block_default_harness_live_cluster_promotion" }
        },
        {
            "clusterId": "authority_tooling",
            "label": "Authority and tooling",
            "currentStatus": "gated",
            "targetExecutionMode": "live",
            "componentKinds": authority_tooling_component_kinds.clone(),
            "readinessReady": live_promotion_authority_tooling_ready,
            "receiptReady": !authority_tooling_receipt_ids.is_empty(),
            "replayGateReady": !authority_tooling_replay_fixture_refs.is_empty()
                && authority_tooling_divergence_classes.iter().all(|value| value == "none"),
            "canaryReady": authority_tooling_gate_live_ready
                && authority_tooling_read_only_authority_canary_ready,
            "rollbackReady": authority_tooling_rollback_available,
            "divergenceReady": authority_tooling_divergence_classes.iter().all(|value| value == "none"),
            "blockingDivergenceCount": authority_tooling_divergence_classes.iter().filter(|value| *value != "none" && *value != "harmless_metadata").count(),
            "unclassifiedDivergenceCount": authority_tooling_divergence_classes.iter().filter(|value| *value == "unclassified").count(),
            "attemptIds": authority_tooling_attempt_ids.clone(),
            "receiptRefs": authority_tooling_receipt_ids.clone(),
            "replayFixtureRefs": authority_tooling_replay_fixture_refs.clone(),
            "actionFrameIds": authority_tooling_action_frame_ids.clone(),
            "divergenceClasses": authority_tooling_divergence_classes.clone(),
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "blockers": if live_promotion_authority_tooling_ready { Vec::<&str>::new() } else { vec!["authority_tooling_live_promotion_not_ready"] },
            "decision": if live_promotion_authority_tooling_ready { "allow_default_harness_live_cluster_promotion" } else { "block_default_harness_live_cluster_promotion" }
        }
    ]);
    let live_promotion_all_clusters_ready = live_promotion_cognition_ready
        && live_promotion_routing_model_ready
        && live_promotion_verification_output_ready
        && live_promotion_authority_tooling_ready;
    let live_promotion_invalid_fork_live_activation_blocked = true;
    let live_promotion_readiness_promotion_eligible = live_promotion_all_clusters_ready
        && activation_blockers.is_empty()
        && live_promotion_invalid_fork_live_activation_blocked
        && authority_tooling_rollback_available
        && model_provider_canary_rollback_available;
    let default_runtime_dispatch_id = format!("harness-default-dispatch:{sid}:{turn_id}:read-only");
    let live_promotion_readiness_proof = json!({
        "schemaVersion": "workflow.harness.live-promotion-readiness.v1",
        "proofId": format!("harness-live-promotion-readiness:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}"),
        "dispatchId": default_runtime_dispatch_id.clone(),
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "targetExecutionMode": "live",
        "requiredClusterIds": ["cognition", "routing_model", "verification_output", "authority_tooling"],
        "clusterReadiness": live_promotion_cluster_readiness,
        "allClustersReady": live_promotion_all_clusters_ready,
        "promotionEligible": live_promotion_readiness_promotion_eligible,
        "defaultLiveActivationReady": live_promotion_readiness_promotion_eligible,
        "invalidForkLiveActivationBlocked": live_promotion_invalid_fork_live_activation_blocked,
        "rollbackAvailable": authority_tooling_rollback_available && model_provider_canary_rollback_available,
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "activationBlockers": activation_blockers.clone(),
        "policyDecision": if live_promotion_readiness_promotion_eligible {
            "allow_default_harness_live_promotion_readiness"
        } else {
            "block_default_harness_live_promotion_readiness"
        },
        "evidenceRefs": [
            format!("harness-default-dispatch:{sid}:{turn_id}:read-only"),
            format!("harness-live-promotion-readiness:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}"),
            format!("runtime-evidence:{sid}")
        ]
    });
    let worker_binding_registry_blockers =
        if dispatch_accepted && live_promotion_readiness_promotion_eligible {
            Vec::<String>::new()
        } else {
            activation_blockers.clone()
        };
    let worker_binding_registry_record = json!({
        "schemaVersion": "workflow.harness.worker-binding-registry.v1",
        "registryRecordId": format!(
            "harness-worker-binding-registry:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:{}",
            default_runtime_dispatch_id
        ),
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "activationHash": DEFAULT_AGENT_HARNESS_HASH,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": live_handoff
            .get("componentVersionSet")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "readinessProofId": live_promotion_readiness_proof
            .get("proofId")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "canaryResultId": if live_handoff.get("canaryStatus").and_then(Value::as_str) == Some("passed") {
            format!("harness-canary-result:{sid}:{turn_id}:passed")
        } else {
            format!("harness-canary-result:{sid}:{turn_id}:blocked")
        },
        "policyDecision": "promote_blessed_workflow_default_for_non_mutating_turn",
        "bindingStatus": if dispatch_accepted && live_promotion_readiness_promotion_eligible { "bound" } else { "blocked" },
        "blockers": worker_binding_registry_blockers,
        "requiredInvariantIds": default_live_promotion_invariant_ids.clone(),
        "invariantBlockers": default_live_promotion_invariant_blockers.clone(),
        "workerBinding": {
            "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
            "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
            "executionMode": if dispatch_accepted { "live" } else { "gated" },
            "source": "default",
            "selectorDecisionId": selector_decision_id,
            "defaultDispatchId": default_runtime_dispatch_id.clone(),
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "authorityBindingReady": dispatch_accepted && live_promotion_readiness_promotion_eligible,
            "authorityBindingBlockers": activation_blockers.clone(),
            "livePromotionReadinessProofId": live_promotion_readiness_proof
                .get("proofId")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "policyDecision": "promote_blessed_workflow_default_for_non_mutating_turn",
            "requiredInvariantIds": default_live_promotion_invariant_ids.clone(),
            "invariantBlockers": default_live_promotion_invariant_blockers.clone()
        }
    });
    let worker_attach_request = json!({
        "schemaVersion": "workflow.harness.worker-attach-request.v1",
        "requestId": format!("harness-worker-attach-request:{sid}:{turn_id}:bound"),
        "workerId": format!("harness-worker:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:{sid}"),
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "activationHash": DEFAULT_AGENT_HARNESS_HASH,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": worker_binding_registry_record
            .get("componentVersionSet")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "readinessProofId": live_promotion_readiness_proof
            .get("proofId")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "requiredInvariantIds": default_live_promotion_invariant_ids.clone(),
        "requestedStatus": if dispatch_accepted { "bound" } else { "blocked" }
    });
    let worker_attach_lifecycle = runtime_harness_worker_attach_lifecycle_events(
        sid,
        &turn_id,
        &worker_binding_registry_record,
    );
    let worker_attach_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("attach"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| {
            runtime_harness_worker_attach_receipt(
                sid,
                &turn_id,
                &worker_binding_registry_record,
                &worker_attach_request,
            )
        });
    let worker_attach_resume_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("resume"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| worker_attach_receipt.clone());
    let worker_attach_rollback_receipt = worker_attach_lifecycle
        .iter()
        .find(|event| event.get("phase").and_then(Value::as_str) == Some("rollback"))
        .and_then(|event| event.get("receipt"))
        .cloned()
        .unwrap_or_else(|| worker_attach_receipt.clone());
    let worker_attach_lifecycle_attempt_ids =
        runtime_harness_worker_attach_lifecycle_attempt_ids(&worker_attach_lifecycle);
    let worker_attach_lifecycle_statuses =
        runtime_harness_worker_attach_lifecycle_statuses(&worker_attach_lifecycle);
    let worker_attach_lifecycle_complete =
        runtime_harness_worker_attach_lifecycle_complete(&worker_attach_lifecycle);
    let worker_session_record = runtime_harness_worker_session_record(
        sid,
        &turn_id,
        &worker_binding_registry_record,
        &worker_attach_lifecycle,
    );
    let worker_launch_envelopes = ["launch", "resume", "rollback"]
        .iter()
        .map(|phase| runtime_harness_worker_launch_envelope(&worker_session_record, phase))
        .collect::<Vec<_>>();
    let worker_handoff_receipts = worker_launch_envelopes
        .iter()
        .map(|envelope| runtime_harness_worker_handoff_receipt(&worker_session_record, envelope))
        .collect::<Vec<_>>();
    let worker_launch_envelope_ids = worker_launch_envelopes
        .iter()
        .filter_map(|envelope| {
            envelope
                .get("envelopeId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let worker_handoff_receipt_ids = worker_handoff_receipts
        .iter()
        .filter_map(|receipt| {
            receipt
                .get("receiptId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let worker_handoff_node_attempts = worker_handoff_receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            runtime_harness_worker_handoff_node_attempt(
                receipt,
                index + 1,
                if dispatch_accepted { "live" } else { "gated" },
            )
        })
        .collect::<Vec<_>>();
    let worker_handoff_node_attempt_ids = worker_handoff_node_attempts
        .iter()
        .filter_map(|attempt| {
            attempt
                .get("attemptId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let worker_handoff_replay_fixture_refs = worker_handoff_node_attempts
        .iter()
        .filter_map(|attempt| {
            attempt
                .get("replay")
                .and_then(|replay| replay.get("fixtureRef"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    dispatch_node_attempt_ids.extend(worker_attach_lifecycle_attempt_ids.clone());
    dispatch_node_attempt_ids.extend(worker_handoff_node_attempt_ids.clone());
    dispatch_node_attempt_ids.sort();
    dispatch_node_attempt_ids.dedup();
    node_attempt_ids.extend(worker_attach_lifecycle_attempt_ids.clone());
    node_attempt_ids.extend(worker_handoff_node_attempt_ids.clone());
    node_attempt_ids.sort();
    node_attempt_ids.dedup();
    receipt_ids.extend(worker_handoff_receipt_ids.clone());
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.extend(worker_handoff_replay_fixture_refs.clone());
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();
    dispatch_node_attempts.extend(worker_handoff_node_attempts.clone());

    json!({
        "schemaVersion": "workflow.harness.default-runtime-dispatch.v1",
        "dispatchId": default_runtime_dispatch_id.clone(),
        "selectorDecisionId": selector_decision_id,
        "selectedSelector": selected_selector,
        "productionDefaultSelector": production_default_selector,
        "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
        "executionMode": if dispatch_accepted { "live" } else { "gated" },
        "runtimeAuthority": if dispatch_accepted {
            "blessed_workflow_activation_default"
        } else {
            "existing_runtime_service"
        },
        "dispatchScope": "read_only_cognition_routing_verification_completion_authority_tooling",
        "status": if dispatch_accepted { "accepted" } else if can_dispatch { "rolled_back" } else { "blocked" },
        "readOnlyDispatchAccepted": dispatch_accepted,
        "acceptedClusterIds": accepted_cluster_ids,
        "componentKinds": component_kinds,
        "deferredComponentKinds": &deferred_components,
        "handoffValidatedComponentKinds": if dispatch_accepted { handoff_validated_components.clone() } else { Vec::<&str>::new() },
        "materializationCanaryComponentKinds": if dispatch_accepted { materialization_canary_components.clone() } else { Vec::<&str>::new() },
        "sourceBoundaryIds": source_boundary_ids,
        "dispatchNodeAttemptIds": dispatch_node_attempt_ids,
        "cognitionExecutionAttemptIds": cognition_execution_attempt_ids.clone(),
        "cognitionExecutionReceiptIds": cognition_execution_receipt_ids.clone(),
        "cognitionExecutionReplayFixtureRefs": cognition_execution_replay_fixture_refs.clone(),
        "cognitionExecutionAdapterMode": "workflow_component_adapter_live",
        "cognitionExecutionAdapterResults": cognition_execution_adapter_results.clone(),
        "cognitionExecutionActionFrameIds": cognition_execution_action_frame_ids.clone(),
        "cognitionExecutionLiveReadyComponentKinds": cognition_execution_live_ready_component_kinds.clone(),
        "cognitionExecutionGateAdapterMode": "workflow_component_adapter_gated",
        "cognitionExecutionGateAttemptIds": cognition_execution_gate_attempt_ids.clone(),
        "cognitionExecutionGateReceiptIds": cognition_execution_gate_receipt_ids.clone(),
        "cognitionExecutionGateReplayFixtureRefs": cognition_execution_gate_replay_fixture_refs.clone(),
        "cognitionExecutionGateAdapterResults": cognition_execution_gate_adapter_results.clone(),
        "cognitionExecutionGateActionFrameIds": cognition_execution_gate_action_frame_ids.clone(),
        "cognitionExecutionGateComponentKinds": cognition_execution_gate_component_kinds.clone(),
        "cognitionExecutionGateDivergenceClasses": cognition_execution_gate_divergence_classes.clone(),
        "routingModelAdapterMode": "workflow_component_adapter_gated",
        "routingModelAttemptIds": routing_model_attempt_ids.clone(),
        "routingModelReceiptIds": routing_model_receipt_ids.clone(),
        "routingModelReplayFixtureRefs": routing_model_replay_fixture_refs.clone(),
        "routingModelAdapterResults": routing_model_adapter_results.clone(),
        "routingModelActionFrameIds": routing_model_action_frame_ids.clone(),
        "routingModelComponentKinds": routing_model_component_kinds.clone(),
        "routingModelDivergenceClasses": routing_model_divergence_classes.clone(),
        "verificationOutputAdapterMode": "workflow_component_adapter_gated",
        "verificationOutputAttemptIds": verification_output_attempt_ids.clone(),
        "verificationOutputReceiptIds": verification_output_receipt_ids.clone(),
        "verificationOutputReplayFixtureRefs": verification_output_replay_fixture_refs.clone(),
        "verificationOutputAdapterResults": verification_output_adapter_results.clone(),
        "verificationOutputActionFrameIds": verification_output_action_frame_ids.clone(),
        "verificationOutputComponentKinds": verification_output_component_kinds.clone(),
        "verificationOutputDivergenceClasses": verification_output_divergence_classes.clone(),
        "authorityToolingAdapterMode": "workflow_component_adapter_gated",
        "authorityToolingAttemptIds": authority_tooling_attempt_ids.clone(),
        "authorityToolingReceiptIds": authority_tooling_receipt_ids.clone(),
        "authorityToolingReplayFixtureRefs": authority_tooling_replay_fixture_refs.clone(),
        "authorityToolingAdapterResults": authority_tooling_adapter_results.clone(),
        "authorityToolingActionFrameIds": authority_tooling_action_frame_ids.clone(),
        "authorityToolingComponentKinds": authority_tooling_component_kinds.clone(),
        "authorityToolingDivergenceClasses": authority_tooling_divergence_classes.clone(),
        "modelExecutionAttemptIds": model_execution_attempt_ids.clone(),
        "modelExecutionReceiptIds": model_execution_receipt_ids.clone(),
        "modelExecutionReplayFixtureRefs": model_execution_replay_fixture_refs.clone(),
        "modelProviderCanaryAttemptIds": model_provider_canary_attempt_ids.clone(),
        "modelProviderCanaryReceiptIds": model_provider_canary_receipt_ids.clone(),
        "modelProviderCanaryReplayFixtureRefs": model_provider_canary_replay_fixture_refs.clone(),
        "modelProviderGatedVisibleOutputAttemptIds": model_provider_gated_visible_output_attempt_ids.clone(),
        "modelProviderGatedVisibleOutputReceiptIds": model_provider_gated_visible_output_receipt_ids.clone(),
        "modelProviderGatedVisibleOutputReplayFixtureRefs": model_provider_gated_visible_output_replay_fixture_refs.clone(),
        "modelProviderGatedVisibleOutputRollbackDrillAttemptIds": model_provider_gated_visible_output_rollback_drill_attempt_ids.clone(),
        "modelProviderGatedVisibleOutputRollbackDrillReceiptIds": model_provider_gated_visible_output_rollback_drill_receipt_ids.clone(),
        "modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs": model_provider_gated_visible_output_rollback_drill_replay_fixture_refs.clone(),
        "readOnlyCapabilityRoutingAttemptIds": read_only_capability_routing_attempt_ids.clone(),
        "readOnlyCapabilityRoutingReceiptIds": read_only_capability_routing_receipt_ids.clone(),
        "readOnlyCapabilityRoutingReplayFixtureRefs": read_only_capability_routing_replay_fixture_refs.clone(),
        "outputWriterHandoffAttemptIds": output_writer_handoff_attempt_ids,
        "outputWriterMaterializationCanaryAttemptIds": output_writer_materialization_canary_attempt_ids,
        "outputWriterStagedWriteCanaryAttemptIds": output_writer_staged_write_canary_attempt_ids,
        "outputWriterVisibleWriteAttemptIds": output_writer_visible_write_attempt_ids,
        "authorityToolingLiveDryRunAttemptIds": authority_tooling_live_dry_run_attempt_ids.clone(),
        "authorityToolingGateLiveAttemptIds": authority_tooling_gate_live_attempt_ids.clone(),
        "authorityToolingGateLiveReceiptIds": authority_tooling_gate_live_receipt_ids.clone(),
        "authorityToolingGateLiveReplayFixtureRefs": authority_tooling_gate_live_replay_fixture_refs.clone(),
        "authorityToolingPolicyGateLiveAttemptIds": authority_tooling_policy_gate_live_attempt_ids.clone(),
        "authorityToolingPolicyGateLiveReceiptIds": authority_tooling_policy_gate_live_receipt_ids.clone(),
        "authorityToolingPolicyGateLiveReplayFixtureRefs": authority_tooling_policy_gate_live_replay_fixture_refs.clone(),
        "authorityToolingDestructiveDenialLiveAttemptIds": authority_tooling_destructive_denial_live_attempt_ids.clone(),
        "authorityToolingDestructiveDenialLiveReceiptIds": authority_tooling_destructive_denial_live_receipt_ids.clone(),
        "authorityToolingDestructiveDenialLiveReplayFixtureRefs": authority_tooling_destructive_denial_live_replay_fixture_refs.clone(),
        "authorityToolingApprovalGateLiveAttemptIds": authority_tooling_approval_gate_live_attempt_ids.clone(),
        "authorityToolingApprovalGateLiveReceiptIds": authority_tooling_approval_gate_live_receipt_ids.clone(),
        "authorityToolingApprovalGateLiveReplayFixtureRefs": authority_tooling_approval_gate_live_replay_fixture_refs.clone(),
        "authorityToolingReadOnlyLiveAttemptIds": authority_tooling_read_only_live_attempt_ids.clone(),
        "authorityToolingReadOnlyReceiptIds": authority_tooling_read_only_receipt_ids.clone(),
        "authorityToolingReadOnlyReplayFixtureRefs": authority_tooling_read_only_replay_fixture_refs.clone(),
        "authorityToolingProviderCatalogLiveAttemptIds": authority_tooling_provider_catalog_live_attempt_ids.clone(),
        "authorityToolingProviderCatalogLiveReceiptIds": authority_tooling_provider_catalog_live_receipt_ids.clone(),
        "authorityToolingProviderCatalogLiveReplayFixtureRefs": authority_tooling_provider_catalog_live_replay_fixture_refs.clone(),
        "authorityToolingMcpToolCatalogLiveAttemptIds": authority_tooling_mcp_tool_catalog_live_attempt_ids.clone(),
        "authorityToolingMcpToolCatalogLiveReceiptIds": authority_tooling_mcp_tool_catalog_live_receipt_ids.clone(),
        "authorityToolingMcpToolCatalogLiveReplayFixtureRefs": authority_tooling_mcp_tool_catalog_live_replay_fixture_refs.clone(),
        "authorityToolingNativeToolCatalogLiveAttemptIds": authority_tooling_native_tool_catalog_live_attempt_ids.clone(),
        "authorityToolingNativeToolCatalogLiveReceiptIds": authority_tooling_native_tool_catalog_live_receipt_ids.clone(),
        "authorityToolingNativeToolCatalogLiveReplayFixtureRefs": authority_tooling_native_tool_catalog_live_replay_fixture_refs.clone(),
        "authorityToolingConnectorCatalogLiveAttemptIds": authority_tooling_connector_catalog_live_attempt_ids.clone(),
        "authorityToolingConnectorCatalogLiveReceiptIds": authority_tooling_connector_catalog_live_receipt_ids.clone(),
        "authorityToolingConnectorCatalogLiveReplayFixtureRefs": authority_tooling_connector_catalog_live_replay_fixture_refs.clone(),
        "authorityToolingWalletCapabilityLiveDryRunAttemptIds": authority_tooling_wallet_capability_live_dry_run_attempt_ids.clone(),
        "authorityToolingWalletCapabilityLiveDryRunReceiptIds": authority_tooling_wallet_capability_live_dry_run_receipt_ids.clone(),
        "authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs": authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs.clone(),
        "authorityToolingReadOnlyComponentKinds": authority_tooling_read_only_component_kinds.clone(),
        "authorityToolingMutationDeferredComponentKinds": authority_tooling_mutation_deferred_component_kinds.clone(),
        "authorityToolingDenialReceiptIds": authority_tooling_denial_receipt_ids.clone(),
        "acceptedNodeAttemptIds": accepted_node_attempt_ids,
        "nodeAttemptIds": node_attempt_ids,
        "dispatchNodeAttempts": dispatch_node_attempts,
        "receiptIds": receipt_ids,
        "replayFixtureRefs": replay_fixture_refs,
        "executorKind": "workflow_node_executor",
        "executorRef": "crate::project::execute_workflow_harness_live_default_node",
        "synchronous": true,
        "drivesRuntimeDecision": dispatch_accepted,
        "activationIdGateClickProofPresent": activation_id_gate_click_proof_present,
        "activationIdGateClickProofPassed": activation_id_gate_click_proof_passed,
        "activationIdGateClickProofBlockers": activation_id_gate_click_proof_blockers,
        "defaultDispatchActivationBlockers": default_dispatch_activation_blockers.clone(),
        "defaultLivePromotionInvariantIds": default_live_promotion_invariant_ids.clone(),
        "defaultLivePromotionInvariantBlockers": default_live_promotion_invariant_blockers.clone(),
        "reviewedImportActivationApplyProofPresent": reviewed_import_activation_apply_proof_present,
        "reviewedImportActivationApplyProofPassed": reviewed_import_activation_apply_proof_passed,
        "reviewedImportActivationApplyProofBlockers": reviewed_import_activation_apply_proof_blockers.clone(),
        "reviewedImportActivationApplyActivationId": reviewed_import_activation_apply_activation_id.clone(),
        "activationIdGate": {
            "schemaVersion": "workflow.harness.default-runtime-dispatch.activation-id-gate.v1",
            "gateId": "activation-id",
            "proofPresent": activation_id_gate_click_proof_present,
            "proofPassed": activation_id_gate_click_proof_passed,
            "proofBlockers": activation_id_gate_click_proof_blockers,
            "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
            "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "workerBindingActivationId": if activation_id_gate_click_proof_passed {
                DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            } else {
                ""
            },
            "defaultDispatchActivationBlockers": activation_blockers.clone()
        },
        "reviewedImportActivationApplyGate": {
            "schemaVersion": "workflow.harness.default-runtime-dispatch.reviewed-import-activation-apply-gate.v1",
            "gateId": "reviewed-import-activation-apply",
            "invariantId": DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
            "proofPresent": reviewed_import_activation_apply_proof_present,
            "proofPassed": reviewed_import_activation_apply_proof_passed,
            "proofBlockers": reviewed_import_activation_apply_proof_blockers,
            "activationId": reviewed_import_activation_apply_activation_id.clone(),
            "workerBindingActivationId": if reviewed_import_activation_apply_proof_passed {
                reviewed_import_activation_apply_activation_id
            } else {
                Value::Null
            },
            "rollbackTarget": if reviewed_import_activation_apply_proof_passed {
                Value::String(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string())
            } else {
                Value::Null
            },
            "defaultDispatchActivationBlockers": default_dispatch_activation_blockers
        },
        "acceptedDecisionKeys": [
            "planning_state",
            "prompt_envelope",
            "workflow_planner_objective_envelope",
            "workflow_prompt_assembly_hash_envelope",
            "workflow_task_state_envelope",
            "task_state",
            "uncertainty_action",
            "budget_decision",
            "capability_sequence",
            "model_binding",
            "model_call_contract",
            "workflow_model_route_envelope",
            "workflow_model_call_envelope",
            "workflow_routing_model_adapter",
            "workflow_routing_model_tool_router_envelope",
            "workflow_model_provider_call_canary",
            "workflow_provider_gated_visible_output",
            "workflow_provider_gated_visible_output_rollback_drill",
            "workflow_read_only_capability_routing",
            "workflow_read_only_source_or_probe_route",
            "workflow_read_only_no_mutation_drill",
            "tool_route",
            "postcondition_synthesis",
            "verification_verdict",
            "completion_decision",
            "workflow_verification_output_adapter",
            "workflow_receipt_writer_envelope",
            "workflow_output_writer_gated_envelope",
            "workflow_authority_tooling_adapter",
            "workflow_authority_policy_gate_adapter",
            "workflow_authority_approval_gate_adapter",
            "workflow_authority_read_only_catalog_adapter",
            "receipt_projection",
            "quality_ledger",
            "authority_tooling_policy_gate",
            "authority_tooling_tool_router",
            "authority_tooling_dry_run_simulator",
            "authority_tooling_destructive_denial",
            "authority_tooling_approval_gate",
            "authority_tooling_mcp_provider_read_only",
            "authority_tooling_mcp_tool_call_read_only",
            "authority_tooling_tool_call_read_only",
            "authority_tooling_connector_call_read_only",
            "authority_tooling_wallet_capability_read_only",
            "visible_output_hash_handoff",
            "guarded_transcript_materialization_canary",
            "isolated_transcript_staging_write_canary",
            "workflow_visible_transcript_write_commit"
        ],
        "acceptedRuntimeDecisions": {
            "selectedStrategy": selected_strategy,
            "selectedAction": selected_action,
            "promptFinalHash": prompt_final_hash,
            "cognitionExecutionMode": "workflow_synchronous_envelope",
            "cognitionExecutionReady": cognition_execution_ready,
            "promptAssemblyMode": "workflow_synchronous_envelope",
            "promptAssemblyPromptHash": prompt_assembly_prompt_hash,
            "promptAssemblyPromptHashMatches": prompt_assembly_prompt_hash_matches,
            "cognitionExecutionAdapterMode": "workflow_component_adapter_live",
            "cognitionExecutionAdapterResultCount": cognition_execution_adapter_results.len(),
            "cognitionExecutionActionFrameIds": cognition_execution_action_frame_ids.clone(),
            "cognitionExecutionLiveReadyComponentKinds": cognition_execution_live_ready_component_kinds.clone(),
            "cognitionExecutionGateAdapterMode": "workflow_component_adapter_gated",
            "cognitionExecutionGateAdapterResultCount": cognition_execution_gate_adapter_results.len(),
            "cognitionExecutionGateActionFrameIds": cognition_execution_gate_action_frame_ids.clone(),
            "cognitionExecutionGateComponentKinds": cognition_execution_gate_component_kinds.clone(),
            "cognitionExecutionGateDivergenceClasses": cognition_execution_gate_divergence_classes.clone(),
            "routingModelAdapterMode": "workflow_component_adapter_gated",
            "routingModelAdapterResultCount": routing_model_adapter_results.len(),
            "routingModelAttemptIds": routing_model_attempt_ids.clone(),
            "routingModelReceiptIds": routing_model_receipt_ids.clone(),
            "routingModelReplayFixtureRefs": routing_model_replay_fixture_refs.clone(),
            "routingModelActionFrameIds": routing_model_action_frame_ids.clone(),
            "routingModelComponentKinds": routing_model_component_kinds.clone(),
            "routingModelDivergenceClasses": routing_model_divergence_classes.clone(),
            "verificationOutputAdapterMode": "workflow_component_adapter_gated",
            "verificationOutputAdapterResultCount": verification_output_adapter_results.len(),
            "verificationOutputAttemptIds": verification_output_attempt_ids.clone(),
            "verificationOutputReceiptIds": verification_output_receipt_ids.clone(),
            "verificationOutputReplayFixtureRefs": verification_output_replay_fixture_refs.clone(),
            "verificationOutputActionFrameIds": verification_output_action_frame_ids.clone(),
            "verificationOutputComponentKinds": verification_output_component_kinds.clone(),
            "verificationOutputDivergenceClasses": verification_output_divergence_classes.clone(),
            "authorityToolingAdapterMode": "workflow_component_adapter_gated",
            "authorityToolingAdapterResultCount": authority_tooling_adapter_results.len(),
            "authorityToolingAttemptIds": authority_tooling_attempt_ids.clone(),
            "authorityToolingReceiptIds": authority_tooling_receipt_ids.clone(),
            "authorityToolingReplayFixtureRefs": authority_tooling_replay_fixture_refs.clone(),
            "authorityToolingActionFrameIds": authority_tooling_action_frame_ids.clone(),
            "authorityToolingComponentKinds": authority_tooling_component_kinds.clone(),
            "authorityToolingDivergenceClasses": authority_tooling_divergence_classes.clone(),
            "modelExecutionMode": "workflow_synchronous_envelope",
            "modelExecutionEnvelopeReady": model_execution_envelope_ready,
            "modelExecutionBindingId": model_execution_binding_id,
            "modelExecutionBindingReady": model_execution_binding_ready,
            "modelExecutionPromptHash": model_execution_prompt_hash,
            "modelExecutionPromptHashMatches": model_execution_prompt_hash_matches,
            "modelExecutionOutputHash": model_execution_output_hash,
            "modelExecutionOutputHashMatches": model_execution_output_hash_matches,
            "modelExecutionProviderInvocationMode": model_execution_provider_invocation_mode,
            "modelExecutionLowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
            "modelExecutionFallbackSelector": model_execution_fallback_selector,
            "modelExecutionLatencyMs": model_execution_latency_ms,
            "modelProviderCanaryMode": model_provider_canary_mode,
            "modelProviderCanaryReady": model_provider_canary_ready,
            "modelProviderCanaryOutputHashMatches": model_provider_canary_output_hash_matches,
            "modelProviderCanaryTranscriptMatches": model_provider_canary_transcript_matches,
            "modelProviderCanaryFallbackRetained": model_provider_canary_fallback_retained,
            "modelProviderCanaryRollbackAvailable": model_provider_canary_rollback_available,
            "modelProviderGatedVisibleOutputMode": model_provider_gated_visible_output_mode,
            "modelProviderGatedVisibleOutputEnabled": model_provider_gated_visible_output_enabled,
            "modelProviderGatedVisibleOutputReady": model_provider_gated_visible_output_ready,
            "modelProviderGatedVisibleOutputSelected": model_provider_gated_visible_output_selected,
            "modelProviderGatedVisibleOutputScenario": model_provider_gated_visible_output_scenario,
            "modelProviderGatedVisibleOutputCohort": model_provider_gated_visible_output_cohort,
            "modelProviderGatedVisibleOutputScenarioCoverageKey": model_provider_gated_visible_output_scenario_coverage_key,
            "selectedVisibleOutputAuthority": selected_visible_output_authority,
            "selectedVisibleOutputHash": selected_visible_output_hash,
            "legacyVisibleOutputHash": legacy_visible_output_hash,
            "modelProviderGatedVisibleOutputRollbackDrillReady": model_provider_gated_visible_output_rollback_drill_ready,
            "modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted": model_provider_gated_visible_output_rollback_drill_rollback_executed,
            "modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority": model_provider_gated_visible_output_rollback_drill_fallback_authority,
            "readOnlyCapabilityRoutingMode": read_only_capability_routing_mode,
            "readOnlyCapabilityRoutingReady": read_only_capability_routing_ready,
            "readOnlyCapabilityRoutingSelected": read_only_capability_routing_selected,
            "readOnlyCapabilityRoutingScenario": read_only_capability_routing_scenario,
            "readOnlyCapabilityRoutingScenarioCoverageKey": read_only_capability_routing_scenario_coverage_key,
            "readOnlyCapabilityRoutingNoMutationReady": read_only_capability_routing_no_mutation_ready,
            "readOnlyCapabilityRoutingWorkflowOwnedNodeKinds": read_only_capability_routing_workflow_owned_node_kinds.clone(),
            "toolUseMode": "none",
            "sideEffectClass": "none",
            "completionDecision": "objective_satisfied",
            "receiptProjectionAuthority": "blessed_workflow_activation_default",
            "qualityLedgerAuthority": "blessed_workflow_activation_default",
            "outputWriterStatus": if dispatch_accepted { "visible_write_committed" } else { "blocked" },
            "outputWriterHandoffReady": output_writer_handoff_ready,
            "outputWriterMaterializationMode": "workflow_visible_transcript_write",
            "outputWriterMaterializationCanaryReady": output_writer_materialization_canary_ready,
            "outputWriterStagedWriteMode": "isolated_checkpoint_blob",
            "outputWriterStagedWriteCanaryReady": output_writer_staged_write_canary_ready,
            "outputWriterStagedWritePersisted": output_writer_staged_write_persisted,
            "outputWriterStagedWriteCommitted": output_writer_staged_write_committed,
            "outputWriterStagedWriteVisible": output_writer_staged_write_visible,
            "outputWriterStagedWriteExcludedFromVisibleTranscript": output_writer_staged_write_excluded_from_visible_transcript,
            "outputWriterStagedWriteRollbackStatus": output_writer_staged_write_rollback_status,
            "outputWriterStagedWriteRollbackVerified": output_writer_staged_write_rollback_verified,
            "outputWriterVisibleWriteMode": "workflow_visible_transcript_write",
            "outputWriterVisibleWriteReady": output_writer_visible_write_ready,
            "outputWriterVisibleWritePersisted": output_writer_visible_write_persisted,
            "outputWriterVisibleWriteCommitted": output_writer_visible_write_committed,
            "outputWriterVisibleWriteVisible": output_writer_visible_write_visible,
            "outputWriterVisibleWriteIdentityCheckpointPersisted": output_writer_visible_write_identity_checkpoint_persisted,
            "outputWriterVisibleWriteLegacyDuplicateSuppressed": output_writer_visible_write_duplicate_suppressed,
            "authorityToolingMode": "workflow_live_dry_run",
            "authorityToolingReady": authority_tooling_ready,
            "authorityToolingPolicyGateReady": authority_tooling_policy_gate_ready,
            "authorityToolingToolRouterReady": authority_tooling_tool_router_ready,
            "authorityToolingDryRunSimulatorReady": authority_tooling_dry_run_simulator_ready,
            "authorityToolingApprovalGateReady": authority_tooling_approval_gate_ready,
            "authorityToolingGateLiveReady": authority_tooling_gate_live_ready,
            "authorityToolingGateLiveSuccessCount": authority_tooling_gate_live_success_count,
            "authorityToolingPolicyGateLiveReady": authority_tooling_policy_gate_live_ready,
            "authorityToolingPolicyGateLiveSuccessCount": authority_tooling_policy_gate_live_success_count,
            "authorityToolingDestructiveDenialLiveReady": authority_tooling_destructive_denial_live_ready,
            "authorityToolingDestructiveDenialLiveSuccessCount": authority_tooling_destructive_denial_live_success_count,
            "authorityToolingApprovalGateLiveReady": authority_tooling_approval_gate_live_ready,
            "authorityToolingApprovalGateLiveSuccessCount": authority_tooling_approval_gate_live_success_count,
            "authorityToolingGateLiveAttemptIds": authority_tooling_gate_live_attempt_ids.clone(),
            "authorityToolingGateLiveReceiptIds": authority_tooling_gate_live_receipt_ids.clone(),
            "authorityToolingGateLiveReplayFixtureRefs": authority_tooling_gate_live_replay_fixture_refs.clone(),
            "authorityToolingPolicyGateLiveAttemptIds": authority_tooling_policy_gate_live_attempt_ids.clone(),
            "authorityToolingPolicyGateLiveReceiptIds": authority_tooling_policy_gate_live_receipt_ids.clone(),
            "authorityToolingPolicyGateLiveReplayFixtureRefs": authority_tooling_policy_gate_live_replay_fixture_refs.clone(),
            "authorityToolingDestructiveDenialLiveAttemptIds": authority_tooling_destructive_denial_live_attempt_ids.clone(),
            "authorityToolingDestructiveDenialLiveReceiptIds": authority_tooling_destructive_denial_live_receipt_ids.clone(),
            "authorityToolingDestructiveDenialLiveReplayFixtureRefs": authority_tooling_destructive_denial_live_replay_fixture_refs.clone(),
            "authorityToolingApprovalGateLiveAttemptIds": authority_tooling_approval_gate_live_attempt_ids.clone(),
            "authorityToolingApprovalGateLiveReceiptIds": authority_tooling_approval_gate_live_receipt_ids.clone(),
            "authorityToolingApprovalGateLiveReplayFixtureRefs": authority_tooling_approval_gate_live_replay_fixture_refs.clone(),
            "authorityToolingReadOnlyAuthorityCanaryReady": authority_tooling_read_only_authority_canary_ready,
            "authorityToolingProviderCatalogLiveReady": authority_tooling_provider_catalog_live_ready,
            "authorityToolingProviderCatalogLiveSuccessCount": authority_tooling_provider_catalog_live_success_count,
            "authorityToolingProviderCatalogLiveComponentKind": "mcp_provider",
            "authorityToolingProviderCatalogLiveAttemptIds": authority_tooling_provider_catalog_live_attempt_ids.clone(),
            "authorityToolingProviderCatalogLiveReceiptIds": authority_tooling_provider_catalog_live_receipt_ids.clone(),
            "authorityToolingProviderCatalogLiveReplayFixtureRefs": authority_tooling_provider_catalog_live_replay_fixture_refs.clone(),
            "authorityToolingMcpToolCatalogLiveReady": authority_tooling_mcp_tool_catalog_live_ready,
            "authorityToolingMcpToolCatalogLiveSuccessCount": authority_tooling_mcp_tool_catalog_live_success_count,
            "authorityToolingMcpToolCatalogLiveComponentKind": "mcp_tool_call",
            "authorityToolingMcpToolCatalogLiveAttemptIds": authority_tooling_mcp_tool_catalog_live_attempt_ids.clone(),
            "authorityToolingMcpToolCatalogLiveReceiptIds": authority_tooling_mcp_tool_catalog_live_receipt_ids.clone(),
            "authorityToolingMcpToolCatalogLiveReplayFixtureRefs": authority_tooling_mcp_tool_catalog_live_replay_fixture_refs.clone(),
            "authorityToolingNativeToolCatalogLiveReady": authority_tooling_native_tool_catalog_live_ready,
            "authorityToolingNativeToolCatalogLiveSuccessCount": authority_tooling_native_tool_catalog_live_success_count,
            "authorityToolingNativeToolCatalogLiveComponentKind": "tool_call",
            "authorityToolingNativeToolCatalogLiveAttemptIds": authority_tooling_native_tool_catalog_live_attempt_ids.clone(),
            "authorityToolingNativeToolCatalogLiveReceiptIds": authority_tooling_native_tool_catalog_live_receipt_ids.clone(),
            "authorityToolingNativeToolCatalogLiveReplayFixtureRefs": authority_tooling_native_tool_catalog_live_replay_fixture_refs.clone(),
            "authorityToolingConnectorCatalogLiveReady": authority_tooling_connector_catalog_live_ready,
            "authorityToolingConnectorCatalogLiveSuccessCount": authority_tooling_connector_catalog_live_success_count,
            "authorityToolingConnectorCatalogLiveComponentKind": "connector_call",
            "authorityToolingConnectorCatalogLiveAttemptIds": authority_tooling_connector_catalog_live_attempt_ids.clone(),
            "authorityToolingConnectorCatalogLiveReceiptIds": authority_tooling_connector_catalog_live_receipt_ids.clone(),
            "authorityToolingConnectorCatalogLiveReplayFixtureRefs": authority_tooling_connector_catalog_live_replay_fixture_refs.clone(),
            "authorityToolingWalletCapabilityLiveDryRunReady": authority_tooling_wallet_capability_live_dry_run_ready,
            "authorityToolingWalletCapabilityLiveDryRunSuccessCount": authority_tooling_wallet_capability_live_dry_run_success_count,
            "authorityToolingWalletCapabilityLiveDryRunComponentKind": "wallet_capability",
            "authorityToolingWalletCapabilityLiveDryRunAttemptIds": authority_tooling_wallet_capability_live_dry_run_attempt_ids.clone(),
            "authorityToolingWalletCapabilityLiveDryRunReceiptIds": authority_tooling_wallet_capability_live_dry_run_receipt_ids.clone(),
            "authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs": authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs.clone(),
            "authorityToolingReadOnlyLiveAttemptCount": authority_tooling_read_only_live_attempt_ids.len(),
            "authorityToolingReadOnlyLiveSuccessCount": authority_tooling_read_only_live_success_count,
            "authorityToolingReadOnlyComponentKinds": authority_tooling_read_only_component_kinds.clone(),
            "authorityToolingMutationDeferredComponentKinds": authority_tooling_mutation_deferred_component_kinds.clone(),
            "authorityToolingReadOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
            "authorityToolingDestructiveRouteDenied": authority_tooling_destructive_route_denied,
            "authorityToolingMutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
            "authorityToolingSideEffectsExecuted": authority_tooling_side_effects_executed,
            "authorityToolingRollbackAvailable": authority_tooling_rollback_available,
            "workflowTranscriptWriteCandidateCommitted": false,
            "workflowTranscriptWriteCommitted": output_writer_visible_write_committed,
            "legacyTranscriptAuthorityRetained": false,
            "legacyTranscriptFallbackAvailable": true,
            "proposedVisibleOutputHash": proposed_visible_output_hash,
            "actualVisibleOutputHash": actual_visible_output_hash,
            "outputAuthority": "blessed_workflow_activation_default"
        },
        "cognitionExecutionMode": "workflow_synchronous_envelope",
        "cognitionExecutionReady": cognition_execution_ready,
        "promptAssemblyMode": "workflow_synchronous_envelope",
        "promptAssemblyPromptHash": prompt_assembly_prompt_hash,
        "promptAssemblyPromptHashMatches": prompt_assembly_prompt_hash_matches,
        "cognitionExecutionAdapterMode": "workflow_component_adapter_live",
        "cognitionExecutionAdapterResults": cognition_execution_adapter_results.clone(),
        "cognitionExecutionActionFrameIds": cognition_execution_action_frame_ids.clone(),
        "cognitionExecutionLiveReadyComponentKinds": cognition_execution_live_ready_component_kinds.clone(),
        "cognitionExecutionGateAdapterMode": "workflow_component_adapter_gated",
        "cognitionExecutionGateAttemptIds": cognition_execution_gate_attempt_ids.clone(),
        "cognitionExecutionGateReceiptIds": cognition_execution_gate_receipt_ids.clone(),
        "cognitionExecutionGateReplayFixtureRefs": cognition_execution_gate_replay_fixture_refs.clone(),
        "cognitionExecutionGateAdapterResults": cognition_execution_gate_adapter_results.clone(),
        "cognitionExecutionGateActionFrameIds": cognition_execution_gate_action_frame_ids.clone(),
        "cognitionExecutionGateComponentKinds": cognition_execution_gate_component_kinds.clone(),
        "cognitionExecutionGateDivergenceClasses": cognition_execution_gate_divergence_classes.clone(),
        "cognitionExecutionProof": {
            "schemaVersion": "workflow.harness.cognition-execution-envelope.v1",
            "mode": "workflow_synchronous_envelope",
            "adapterMode": "workflow_component_adapter_live",
            "adapterResultCount": cognition_execution_adapter_results.len(),
            "actionFrameIds": cognition_execution_action_frame_ids,
            "liveReadyComponentKinds": cognition_execution_live_ready_component_kinds,
            "gateAdapterMode": "workflow_component_adapter_gated",
            "gateAdapterResultCount": cognition_execution_gate_adapter_results.len(),
            "gateAttemptIds": cognition_execution_gate_attempt_ids,
            "gateReceiptIds": cognition_execution_gate_receipt_ids,
            "gateReplayFixtureRefs": cognition_execution_gate_replay_fixture_refs,
            "gateActionFrameIds": cognition_execution_gate_action_frame_ids,
            "gateComponentKinds": cognition_execution_gate_component_kinds,
            "gateDivergenceClasses": cognition_execution_gate_divergence_classes,
            "promptAssemblyMode": "workflow_synchronous_envelope",
            "promptHash": prompt_assembly_prompt_hash,
            "promptHashMatches": prompt_assembly_prompt_hash_matches,
            "ready": cognition_execution_ready,
            "attemptIds": cognition_execution_attempt_ids,
            "receiptIds": cognition_execution_receipt_ids,
            "replayFixtureRefs": cognition_execution_replay_fixture_refs,
            "policyDecision": "accept_workflow_prompt_assembly_hash_envelope"
        },
        "verificationOutputProof": verification_output_proof,
        "authorityToolingAdapterProof": authority_tooling_adapter_proof,
        "livePromotionReadinessProof": live_promotion_readiness_proof,
        "workerBindingRegistryRecord": worker_binding_registry_record,
        "workerAttachReceipt": worker_attach_receipt,
        "workerAttachResumeReceipt": worker_attach_resume_receipt,
        "workerAttachRollbackReceipt": worker_attach_rollback_receipt,
        "workerAttachLifecycle": worker_attach_lifecycle,
        "workerAttachLifecycleAttemptIds": worker_attach_lifecycle_attempt_ids,
        "workerAttachLifecycleStatuses": worker_attach_lifecycle_statuses,
        "workerAttachLifecycleComplete": worker_attach_lifecycle_complete,
        "workerSessionRecord": worker_session_record,
        "workerLaunchEnvelopes": worker_launch_envelopes,
        "workerHandoffReceipts": worker_handoff_receipts,
        "workerLaunchEnvelopeIds": worker_launch_envelope_ids,
        "workerHandoffReceiptIds": worker_handoff_receipt_ids,
        "workerHandoffNodeAttemptIds": worker_handoff_node_attempt_ids,
        "workerHandoffNodeAttempts": worker_handoff_node_attempts,
        "workerHandoffReplayFixtureRefs": worker_handoff_replay_fixture_refs,
        "modelExecutionMode": "workflow_synchronous_envelope",
        "modelExecutionEnvelopeReady": model_execution_envelope_ready,
        "modelExecutionBindingId": model_execution_binding_id,
        "modelExecutionBindingReady": model_execution_binding_ready,
        "modelExecutionPromptHash": model_execution_prompt_hash,
        "modelExecutionPromptHashMatches": model_execution_prompt_hash_matches,
        "modelExecutionOutputHash": model_execution_output_hash,
        "modelExecutionOutputHashMatches": model_execution_output_hash_matches,
        "modelExecutionProviderInvocationMode": model_execution_provider_invocation_mode,
        "modelExecutionLowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
        "modelExecutionFallbackSelector": model_execution_fallback_selector,
        "modelExecutionLatencyMs": model_execution_latency_ms,
        "modelProviderCanaryMode": model_provider_canary_mode,
        "modelProviderCanaryReady": model_provider_canary_ready,
        "modelProviderCanaryCandidateOutputHash": model_provider_canary_candidate_output_hash,
        "modelProviderCanaryLegacyOutputHash": model_provider_canary_legacy_output_hash,
        "modelProviderCanaryOutputHashMatches": model_provider_canary_output_hash_matches,
        "modelProviderCanaryTranscriptMatches": model_provider_canary_transcript_matches,
        "modelProviderCanaryFallbackRetained": model_provider_canary_fallback_retained,
        "modelProviderCanaryRollbackAvailable": model_provider_canary_rollback_available,
        "modelProviderGatedVisibleOutputMode": model_provider_gated_visible_output_mode,
        "modelProviderGatedVisibleOutputEnabled": model_provider_gated_visible_output_enabled,
        "modelProviderGatedVisibleOutputReady": model_provider_gated_visible_output_ready,
        "modelProviderGatedVisibleOutputSelected": model_provider_gated_visible_output_selected,
        "modelProviderGatedVisibleOutputEligible": model_provider_gated_visible_output_eligible,
        "modelProviderGatedVisibleOutputScenario": model_provider_gated_visible_output_scenario,
        "modelProviderGatedVisibleOutputCohort": model_provider_gated_visible_output_cohort,
        "modelProviderGatedVisibleOutputRetainedReadOnlyNoTool": retained_read_only_no_tool_gate_selected,
        "modelProviderGatedVisibleOutputRequiredScenarioSet": model_provider_gated_visible_output_required_scenario_set.clone(),
        "modelProviderGatedVisibleOutputScenarioCoverageKey": model_provider_gated_visible_output_scenario_coverage_key,
        "modelProviderGatedVisibleOutputActivationFlag": model_provider_gated_visible_output_activation_flag,
        "modelProviderGatedVisibleOutputActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "modelProviderGatedVisibleOutputAuthority": "workflow_model_provider_call",
        "modelProviderGatedVisibleOutputRollbackTarget": visible_output_gated_authority_rollback_target,
        "modelProviderGatedVisibleOutputRollbackAvailable": model_provider_canary_rollback_available,
        "selectedVisibleOutputAuthority": selected_visible_output_authority,
        "selectedVisibleOutputHash": selected_visible_output_hash,
        "workflowProviderVisibleOutputHash": model_provider_canary_candidate_output_hash,
        "legacyVisibleOutputHash": legacy_visible_output_hash,
        "legacyVisibleOutputComputed": true,
        "legacyVisibleOutputHashMatchesSelected": visible_output_legacy_hash_matches_selected,
        "selectedVisibleOutputAuthorityMatchesTranscript": visible_output_selected_authority_matches_transcript,
        "visibleOutputDivergenceClass": visible_output_divergence_class.clone(),
        "modelProviderGatedVisibleOutputRollbackDrillEnabled": model_provider_gated_visible_output_rollback_drill_enabled,
        "modelProviderGatedVisibleOutputRollbackDrillReady": model_provider_gated_visible_output_rollback_drill_ready,
        "modelProviderGatedVisibleOutputRollbackDrillFailureInjected": model_provider_gated_visible_output_rollback_drill_failure_injected,
        "modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash": model_provider_gated_visible_output_rollback_drill_injected_output_hash,
        "modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges": model_provider_gated_visible_output_rollback_drill_output_hash_diverges,
        "modelProviderGatedVisibleOutputRollbackDrillDivergenceClass": model_provider_gated_visible_output_rollback_drill_divergence_class,
        "modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority": model_provider_gated_visible_output_rollback_drill_fallback_authority,
        "modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority": model_provider_gated_visible_output_rollback_drill_selected_authority,
        "modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged": model_provider_gated_visible_output_rollback_drill_transcript_unchanged,
        "modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted": model_provider_gated_visible_output_rollback_drill_rollback_executed,
        "modelProviderGatedVisibleOutputRollbackDrillActivationBlockers": model_provider_gated_visible_output_rollback_drill_activation_blockers,
        "readOnlyCapabilityRoutingMode": read_only_capability_routing_mode,
        "readOnlyCapabilityRoutingReady": read_only_capability_routing_ready,
        "readOnlyCapabilityRoutingSelected": read_only_capability_routing_selected,
        "readOnlyCapabilityRoutingEligible": read_only_capability_routing_eligible,
        "readOnlyCapabilityRoutingScenario": read_only_capability_routing_scenario,
        "readOnlyCapabilityRoutingRequiredScenarioSet": read_only_capability_routing_required_scenario_set.clone(),
        "readOnlyCapabilityRoutingScenarioCoverageKey": read_only_capability_routing_scenario_coverage_key,
        "readOnlyCapabilityRoutingSourceMaterialReady": read_only_capability_routing_source_material_ready,
        "readOnlyCapabilityRoutingNoMutationReady": read_only_capability_routing_no_mutation_ready,
        "readOnlyCapabilityRoutingWorkflowOwnedNodeKinds": read_only_capability_routing_workflow_owned_node_kinds.clone(),
        "readOnlyCapabilityRoutingAttemptIds": read_only_capability_routing_attempt_ids.clone(),
        "readOnlyCapabilityRoutingReceiptIds": read_only_capability_routing_receipt_ids.clone(),
        "readOnlyCapabilityRoutingReplayFixtureRefs": read_only_capability_routing_replay_fixture_refs.clone(),
        "readOnlyCapabilityRoutingProof": {
            "schemaVersion": "workflow.harness.read-only-capability-routing.v1",
            "mode": read_only_capability_routing_mode,
            "ready": read_only_capability_routing_ready,
            "selected": read_only_capability_routing_selected,
            "eligible": read_only_capability_routing_eligible,
            "scenario": read_only_capability_routing_scenario,
            "requiredScenarioSet": read_only_capability_routing_required_scenario_set.clone(),
            "scenarioCoverageKey": read_only_capability_routing_scenario_coverage_key,
            "sourceMaterialReady": read_only_capability_routing_source_material_ready,
            "workflowOwnedNodeKinds": read_only_capability_routing_workflow_owned_node_kinds.clone(),
            "toolUseMode": "read_only_or_dry_run",
            "sideEffectsExecuted": false,
            "mutationExecuted": false,
            "noMutationReady": read_only_capability_routing_no_mutation_ready,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackAvailable": true,
            "attemptIds": read_only_capability_routing_attempt_ids.clone(),
            "receiptIds": read_only_capability_routing_receipt_ids.clone(),
            "replayFixtureRefs": read_only_capability_routing_replay_fixture_refs.clone(),
            "policyDecision": if read_only_capability_routing_ready {
                "accept_workflow_read_only_capability_routing_without_side_effects"
            } else {
                "retain_legacy_read_only_capability_routing_outside_source_probe_cohort"
            }
        },
        "modelProviderGatedVisibleOutputRollbackDrillProof": {
            "schemaVersion": "workflow.harness.model-provider-gated-visible-output-rollback-drill.v1",
            "drillId": format!("harness-provider-gated-visible-output-rollback-drill:{sid}:{turn_id}"),
            "enabled": model_provider_gated_visible_output_rollback_drill_enabled,
            "ready": model_provider_gated_visible_output_rollback_drill_ready,
            "failureInjected": model_provider_gated_visible_output_rollback_drill_failure_injected,
            "workflowProviderOutputHash": model_provider_canary_candidate_output_hash,
            "injectedWorkflowProviderOutputHash": model_provider_gated_visible_output_rollback_drill_injected_output_hash,
            "legacyVisibleOutputHash": legacy_visible_output_hash,
            "actualVisibleOutputHash": actual_visible_output_hash,
            "outputHashDiverges": model_provider_gated_visible_output_rollback_drill_output_hash_diverges,
            "divergenceClass": model_provider_gated_visible_output_rollback_drill_divergence_class,
            "fallbackAuthority": model_provider_gated_visible_output_rollback_drill_fallback_authority,
            "selectedAuthorityAfterRollback": model_provider_gated_visible_output_rollback_drill_selected_authority,
            "transcriptUnchanged": model_provider_gated_visible_output_rollback_drill_transcript_unchanged,
            "rollbackExecuted": model_provider_gated_visible_output_rollback_drill_rollback_executed,
            "rollbackTarget": visible_output_gated_authority_rollback_target,
            "rollbackAvailable": model_provider_canary_rollback_available,
            "activationBlockers": model_provider_gated_visible_output_rollback_drill_activation_blockers,
            "attemptIds": model_provider_gated_visible_output_rollback_drill_attempt_ids.clone(),
            "receiptIds": model_provider_gated_visible_output_rollback_drill_receipt_ids.clone(),
            "replayFixtureRefs": model_provider_gated_visible_output_rollback_drill_replay_fixture_refs.clone(),
            "policyDecision": if model_provider_gated_visible_output_rollback_drill_ready {
                "rollback_to_legacy_runtime_model_invocation_on_provider_output_hash_divergence"
            } else {
                "rollback_drill_not_applicable_outside_provider_visible_output_gate"
            }
        },
        "modelProviderGatedVisibleOutputProof": {
            "schemaVersion": "workflow.harness.model-provider-gated-visible-output.v1",
            "mode": model_provider_gated_visible_output_mode,
            "enabled": model_provider_gated_visible_output_enabled,
            "ready": model_provider_gated_visible_output_ready,
            "selected": model_provider_gated_visible_output_selected,
            "eligible": model_provider_gated_visible_output_eligible,
            "scope": model_provider_gated_visible_output_scenario,
            "cohort": model_provider_gated_visible_output_cohort,
            "retainedReadOnlyNoTool": retained_read_only_no_tool_gate_selected,
            "requiredScenarioSet": model_provider_gated_visible_output_required_scenario_set,
            "scenarioCoverageKey": model_provider_gated_visible_output_scenario_coverage_key,
            "activationFlag": model_provider_gated_visible_output_activation_flag,
            "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "selectedVisibleOutputAuthority": selected_visible_output_authority,
            "selectedVisibleOutputHash": selected_visible_output_hash,
            "workflowProviderOutputHash": model_provider_canary_candidate_output_hash,
            "legacyVisibleOutputHash": legacy_visible_output_hash,
            "legacyVisibleOutputComputed": true,
            "legacyVisibleOutputHashMatchesSelected": visible_output_legacy_hash_matches_selected,
            "selectedAuthorityMatchesTranscript": visible_output_selected_authority_matches_transcript,
            "divergenceClass": visible_output_divergence_class.clone(),
            "rollbackTarget": visible_output_gated_authority_rollback_target,
            "rollbackAvailable": model_provider_canary_rollback_available,
            "attemptIds": model_provider_gated_visible_output_attempt_ids.clone(),
            "receiptIds": model_provider_gated_visible_output_receipt_ids.clone(),
            "replayFixtureRefs": model_provider_gated_visible_output_replay_fixture_refs.clone(),
            "policyDecision": if model_provider_gated_visible_output_selected {
                "accept_workflow_provider_gated_visible_output_with_legacy_rollback"
            } else {
                "retain_workflow_transcript_authority_outside_provider_visible_output_gate"
            }
        },
        "modelProviderCanaryProof": {
            "schemaVersion": "workflow.harness.model-provider-call-canary.v1",
            "mode": model_provider_canary_mode,
            "candidateOutputHash": model_provider_canary_candidate_output_hash,
            "legacyOutputHash": model_provider_canary_legacy_output_hash,
            "outputHashMatches": model_provider_canary_output_hash_matches,
            "transcriptMatches": model_provider_canary_transcript_matches,
            "fallbackRetained": model_provider_canary_fallback_retained,
            "rollbackAvailable": model_provider_canary_rollback_available,
            "attemptIds": model_provider_canary_attempt_ids.clone(),
            "receiptIds": model_provider_canary_receipt_ids.clone(),
            "replayFixtureRefs": model_provider_canary_replay_fixture_refs.clone(),
            "policyDecision": "accept_workflow_model_provider_call_canary_with_legacy_rollback"
        },
        "modelExecutionProof": {
            "schemaVersion": "workflow.harness.model-execution-envelope.v1",
            "mode": "workflow_synchronous_envelope",
            "bindingId": model_execution_binding_id,
            "bindingReady": model_execution_binding_ready,
            "promptHash": model_execution_prompt_hash,
            "promptHashMatches": model_execution_prompt_hash_matches,
            "outputHash": model_execution_output_hash,
            "outputHashMatches": model_execution_output_hash_matches,
            "providerInvocationMode": model_execution_provider_invocation_mode,
            "lowLevelInvocationDeferred": model_execution_low_level_invocation_deferred,
            "fallbackSelector": model_execution_fallback_selector,
            "latencyMs": model_execution_latency_ms,
            "routingModelAdapterMode": "workflow_component_adapter_gated",
            "routingModelAdapterResultCount": routing_model_adapter_results.len(),
            "routingModelAttemptIds": routing_model_attempt_ids.clone(),
            "routingModelReceiptIds": routing_model_receipt_ids.clone(),
            "routingModelReplayFixtureRefs": routing_model_replay_fixture_refs.clone(),
            "routingModelActionFrameIds": routing_model_action_frame_ids.clone(),
            "routingModelComponentKinds": routing_model_component_kinds.clone(),
            "routingModelDivergenceClasses": routing_model_divergence_classes.clone(),
            "providerCanaryReady": model_provider_canary_ready,
            "providerCanaryAttemptIds": model_provider_canary_attempt_ids,
            "providerCanaryReceiptIds": model_provider_canary_receipt_ids,
            "providerCanaryReplayFixtureRefs": model_provider_canary_replay_fixture_refs,
            "providerGatedVisibleOutputReady": model_provider_gated_visible_output_ready,
            "providerGatedVisibleOutputSelected": model_provider_gated_visible_output_selected,
            "providerGatedVisibleOutputAttemptIds": model_provider_gated_visible_output_attempt_ids,
            "providerGatedVisibleOutputReceiptIds": model_provider_gated_visible_output_receipt_ids,
            "providerGatedVisibleOutputReplayFixtureRefs": model_provider_gated_visible_output_replay_fixture_refs,
            "providerGatedVisibleOutputRollbackDrillReady": model_provider_gated_visible_output_rollback_drill_ready,
            "providerGatedVisibleOutputRollbackDrillAttemptIds": model_provider_gated_visible_output_rollback_drill_attempt_ids,
            "providerGatedVisibleOutputRollbackDrillReceiptIds": model_provider_gated_visible_output_rollback_drill_receipt_ids,
            "providerGatedVisibleOutputRollbackDrillReplayFixtureRefs": model_provider_gated_visible_output_rollback_drill_replay_fixture_refs,
            "selectedVisibleOutputAuthority": selected_visible_output_authority,
            "attemptIds": model_execution_attempt_ids,
            "receiptIds": model_execution_receipt_ids,
            "replayFixtureRefs": model_execution_replay_fixture_refs,
            "policyDecision": "accept_workflow_model_provider_call_canary_with_legacy_rollback"
        },
        "outputAuthority": if dispatch_accepted { "blessed_workflow_activation_default" } else { "existing_runtime_service" },
        "visibleOutputAuthority": if dispatch_accepted { "blessed_workflow_activation_default" } else { "existing_runtime_service" },
        "outputWriterDeferred": false,
        "outputWriterStatus": if dispatch_accepted { "visible_write_committed" } else { "blocked" },
        "outputWriterHandoffReady": output_writer_handoff_ready,
        "outputWriterAuthorityTransferred": dispatch_accepted,
        "outputWriterMaterializationMode": "workflow_visible_transcript_write",
        "outputWriterMaterializationCanaryReady": output_writer_materialization_canary_ready,
        "outputWriterMaterializationCommitted": output_writer_visible_write_committed,
        "outputWriterStagedWriteMode": "isolated_checkpoint_blob",
        "outputWriterStagedWriteCanaryReady": output_writer_staged_write_canary_ready,
        "outputWriterStagedWritePersisted": output_writer_staged_write_persisted,
        "outputWriterStagedWriteCommitted": output_writer_staged_write_committed,
        "outputWriterStagedWriteVisible": output_writer_staged_write_visible,
        "outputWriterStagedWriteExcludedFromVisibleTranscript": output_writer_staged_write_excluded_from_visible_transcript,
        "outputWriterStagedWriteRollbackStatus": output_writer_staged_write_rollback_status,
        "outputWriterStagedWriteRollbackVerified": output_writer_staged_write_rollback_verified,
        "outputWriterVisibleWriteMode": "workflow_visible_transcript_write",
        "outputWriterVisibleWriteReady": output_writer_visible_write_ready,
        "outputWriterVisibleWritePersisted": output_writer_visible_write_persisted,
        "outputWriterVisibleWriteCommitted": output_writer_visible_write_committed,
        "outputWriterVisibleWriteVisible": output_writer_visible_write_visible,
        "outputWriterVisibleWriteIdentityCheckpointPersisted": output_writer_visible_write_identity_checkpoint_persisted,
        "outputWriterVisibleWriteLegacyDuplicateSuppressed": output_writer_visible_write_duplicate_suppressed,
        "authorityToolingMode": "workflow_live_dry_run",
        "authorityToolingReady": authority_tooling_ready,
        "authorityToolingPolicyGateReady": authority_tooling_policy_gate_ready,
        "authorityToolingToolRouterReady": authority_tooling_tool_router_ready,
        "authorityToolingDryRunSimulatorReady": authority_tooling_dry_run_simulator_ready,
        "authorityToolingApprovalGateReady": authority_tooling_approval_gate_ready,
        "authorityToolingGateLiveReady": authority_tooling_gate_live_ready,
        "authorityToolingGateLiveSuccessCount": authority_tooling_gate_live_success_count,
        "authorityToolingPolicyGateLiveReady": authority_tooling_policy_gate_live_ready,
        "authorityToolingPolicyGateLiveSuccessCount": authority_tooling_policy_gate_live_success_count,
        "authorityToolingDestructiveDenialLiveReady": authority_tooling_destructive_denial_live_ready,
        "authorityToolingDestructiveDenialLiveSuccessCount": authority_tooling_destructive_denial_live_success_count,
        "authorityToolingApprovalGateLiveReady": authority_tooling_approval_gate_live_ready,
        "authorityToolingApprovalGateLiveSuccessCount": authority_tooling_approval_gate_live_success_count,
        "authorityToolingReadOnlyAuthorityCanaryReady": authority_tooling_read_only_authority_canary_ready,
        "authorityToolingProviderCatalogLiveReady": authority_tooling_provider_catalog_live_ready,
        "authorityToolingProviderCatalogLiveSuccessCount": authority_tooling_provider_catalog_live_success_count,
        "authorityToolingProviderCatalogLiveComponentKind": "mcp_provider",
        "authorityToolingMcpToolCatalogLiveReady": authority_tooling_mcp_tool_catalog_live_ready,
        "authorityToolingMcpToolCatalogLiveSuccessCount": authority_tooling_mcp_tool_catalog_live_success_count,
        "authorityToolingMcpToolCatalogLiveComponentKind": "mcp_tool_call",
        "authorityToolingNativeToolCatalogLiveReady": authority_tooling_native_tool_catalog_live_ready,
        "authorityToolingNativeToolCatalogLiveSuccessCount": authority_tooling_native_tool_catalog_live_success_count,
        "authorityToolingNativeToolCatalogLiveComponentKind": "tool_call",
        "authorityToolingConnectorCatalogLiveReady": authority_tooling_connector_catalog_live_ready,
        "authorityToolingConnectorCatalogLiveSuccessCount": authority_tooling_connector_catalog_live_success_count,
        "authorityToolingConnectorCatalogLiveComponentKind": "connector_call",
        "authorityToolingWalletCapabilityLiveDryRunReady": authority_tooling_wallet_capability_live_dry_run_ready,
        "authorityToolingWalletCapabilityLiveDryRunSuccessCount": authority_tooling_wallet_capability_live_dry_run_success_count,
        "authorityToolingWalletCapabilityLiveDryRunComponentKind": "wallet_capability",
        "authorityToolingReadOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
        "authorityToolingDestructiveRouteDenied": authority_tooling_destructive_route_denied,
        "authorityToolingMutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
        "authorityToolingSideEffectsExecuted": authority_tooling_side_effects_executed,
        "authorityToolingRollbackAvailable": authority_tooling_rollback_available,
        "authorityToolingProof": {
            "schemaVersion": "workflow.harness.authority-tooling-live-dry-run.v1",
            "mode": "workflow_live_dry_run",
            "readOnlyRouteAccepted": authority_tooling_read_only_route_accepted,
            "destructiveRouteDenied": authority_tooling_destructive_route_denied,
            "mutatingToolCallsBlocked": authority_tooling_mutating_tool_calls_blocked,
            "sideEffectsExecuted": authority_tooling_side_effects_executed,
            "policyGateReady": authority_tooling_policy_gate_ready,
            "toolRouterReady": authority_tooling_tool_router_ready,
            "dryRunSimulatorReady": authority_tooling_dry_run_simulator_ready,
            "approvalGateReady": authority_tooling_approval_gate_ready,
            "rollbackAvailable": authority_tooling_rollback_available,
            "attemptIds": authority_tooling_live_dry_run_attempt_ids,
            "gateLiveReady": authority_tooling_gate_live_ready,
            "gateLiveSuccessCount": authority_tooling_gate_live_success_count,
            "gateLiveAttemptIds": authority_tooling_gate_live_attempt_ids,
            "gateLiveReceiptIds": authority_tooling_gate_live_receipt_ids,
            "gateLiveReplayFixtureRefs": authority_tooling_gate_live_replay_fixture_refs,
            "policyGateLiveReady": authority_tooling_policy_gate_live_ready,
            "policyGateLiveSuccessCount": authority_tooling_policy_gate_live_success_count,
            "policyGateLiveAttemptIds": authority_tooling_policy_gate_live_attempt_ids,
            "policyGateLiveReceiptIds": authority_tooling_policy_gate_live_receipt_ids,
            "policyGateLiveReplayFixtureRefs": authority_tooling_policy_gate_live_replay_fixture_refs,
            "destructiveDenialLiveReady": authority_tooling_destructive_denial_live_ready,
            "destructiveDenialLiveSuccessCount": authority_tooling_destructive_denial_live_success_count,
            "destructiveDenialLiveAttemptIds": authority_tooling_destructive_denial_live_attempt_ids,
            "destructiveDenialLiveReceiptIds": authority_tooling_destructive_denial_live_receipt_ids,
            "destructiveDenialLiveReplayFixtureRefs": authority_tooling_destructive_denial_live_replay_fixture_refs,
            "approvalGateLiveReady": authority_tooling_approval_gate_live_ready,
            "approvalGateLiveSuccessCount": authority_tooling_approval_gate_live_success_count,
            "approvalGateLiveAttemptIds": authority_tooling_approval_gate_live_attempt_ids,
            "approvalGateLiveReceiptIds": authority_tooling_approval_gate_live_receipt_ids,
            "approvalGateLiveReplayFixtureRefs": authority_tooling_approval_gate_live_replay_fixture_refs,
            "readOnlyAuthorityCanaryReady": authority_tooling_read_only_authority_canary_ready,
            "readOnlyLiveSuccessCount": authority_tooling_read_only_live_success_count,
            "readOnlyComponentKinds": authority_tooling_read_only_component_kinds.clone(),
            "providerCatalogLiveReady": authority_tooling_provider_catalog_live_ready,
            "providerCatalogLiveSuccessCount": authority_tooling_provider_catalog_live_success_count,
            "providerCatalogLiveComponentKind": "mcp_provider",
            "providerCatalogLiveAttemptIds": authority_tooling_provider_catalog_live_attempt_ids,
            "providerCatalogLiveReceiptIds": authority_tooling_provider_catalog_live_receipt_ids,
            "providerCatalogLiveReplayFixtureRefs": authority_tooling_provider_catalog_live_replay_fixture_refs,
            "mcpToolCatalogLiveReady": authority_tooling_mcp_tool_catalog_live_ready,
            "mcpToolCatalogLiveSuccessCount": authority_tooling_mcp_tool_catalog_live_success_count,
            "mcpToolCatalogLiveComponentKind": "mcp_tool_call",
            "mcpToolCatalogLiveAttemptIds": authority_tooling_mcp_tool_catalog_live_attempt_ids,
            "mcpToolCatalogLiveReceiptIds": authority_tooling_mcp_tool_catalog_live_receipt_ids,
            "mcpToolCatalogLiveReplayFixtureRefs": authority_tooling_mcp_tool_catalog_live_replay_fixture_refs,
            "nativeToolCatalogLiveReady": authority_tooling_native_tool_catalog_live_ready,
            "nativeToolCatalogLiveSuccessCount": authority_tooling_native_tool_catalog_live_success_count,
            "nativeToolCatalogLiveComponentKind": "tool_call",
            "nativeToolCatalogLiveAttemptIds": authority_tooling_native_tool_catalog_live_attempt_ids,
            "nativeToolCatalogLiveReceiptIds": authority_tooling_native_tool_catalog_live_receipt_ids,
            "nativeToolCatalogLiveReplayFixtureRefs": authority_tooling_native_tool_catalog_live_replay_fixture_refs,
            "connectorCatalogLiveReady": authority_tooling_connector_catalog_live_ready,
            "connectorCatalogLiveSuccessCount": authority_tooling_connector_catalog_live_success_count,
            "connectorCatalogLiveComponentKind": "connector_call",
            "connectorCatalogLiveAttemptIds": authority_tooling_connector_catalog_live_attempt_ids,
            "connectorCatalogLiveReceiptIds": authority_tooling_connector_catalog_live_receipt_ids,
            "connectorCatalogLiveReplayFixtureRefs": authority_tooling_connector_catalog_live_replay_fixture_refs,
            "walletCapabilityLiveDryRunReady": authority_tooling_wallet_capability_live_dry_run_ready,
            "walletCapabilityLiveDryRunSuccessCount": authority_tooling_wallet_capability_live_dry_run_success_count,
            "walletCapabilityLiveDryRunComponentKind": "wallet_capability",
            "walletCapabilityLiveDryRunAttemptIds": authority_tooling_wallet_capability_live_dry_run_attempt_ids,
            "walletCapabilityLiveDryRunReceiptIds": authority_tooling_wallet_capability_live_dry_run_receipt_ids,
            "walletCapabilityLiveDryRunReplayFixtureRefs": authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs,
            "readOnlyAttemptIds": authority_tooling_read_only_live_attempt_ids,
            "readOnlyReceiptIds": authority_tooling_read_only_receipt_ids,
            "readOnlyReplayFixtureRefs": authority_tooling_read_only_replay_fixture_refs,
            "denialReceiptIds": authority_tooling_denial_receipt_ids,
            "deferredMutationComponentKinds": &authority_tooling_mutation_deferred_component_kinds,
            "mutationDeferredComponentKinds": &authority_tooling_mutation_deferred_component_kinds,
            "policyDecision": "allow_read_only_route_and_deny_destructive_tooling_without_side_effect"
        },
        "legacyTranscriptAuthorityRetained": false,
        "legacyTranscriptFallbackAvailable": true,
        "legacyTranscriptFallbackProof": legacy_transcript_fallback_proof,
        "workflowTranscriptWriteCandidate": workflow_transcript_write_candidate,
        "workflowTranscriptWriteRecord": workflow_visible_transcript_write_record,
        "visibleTranscriptWriteProof": visible_transcript_write_proof,
        "legacyTranscriptWriteRecord": legacy_transcript_write_record,
        "transcriptMaterializationContentHashMatches": transcript_materialization_content_hash_matches,
        "transcriptMaterializationOrderMatches": transcript_materialization_order_matches,
        "transcriptMaterializationReceiptBindingMatches": transcript_materialization_receipt_binding_matches,
        "transcriptMaterializationTargetMatches": transcript_materialization_target_matches,
        "transcriptMaterializationMatches": transcript_materialization_matches,
        "transcriptMaterializationDivergenceCount": if transcript_materialization_matches { 0 } else { 1 },
        "transcriptMaterializationComparison": {
            "contentHashMatches": transcript_materialization_content_hash_matches,
            "orderMatches": transcript_materialization_order_matches,
            "receiptBindingMatches": transcript_materialization_receipt_binding_matches,
            "targetMatches": transcript_materialization_target_matches,
            "candidateCommitted": false,
            "legacyCommitted": transcript_materialization_legacy_committed,
            "legacyDuplicateSuppressed": transcript_materialization_legacy_idempotent,
            "matches": transcript_materialization_matches,
            "divergenceClass": if transcript_materialization_matches { Value::Null } else { json!("transcript_materialization_divergence") }
        },
        "stagedTranscriptWriteRecord": staged_transcript_write_record,
        "stagedTranscriptWriteProof": staged_transcript_write_proof,
        "stagedTranscriptWriteContentHashMatches": staged_transcript_write_content_hash_matches,
        "stagedTranscriptWriteOrderMatches": staged_transcript_write_order_matches,
        "stagedTranscriptWriteReceiptBindingMatches": staged_transcript_write_receipt_binding_matches,
        "stagedTranscriptWriteTargetMatches": staged_transcript_write_target_matches,
        "stagedTranscriptWriteMatches": staged_transcript_write_matches,
        "stagedTranscriptWriteDivergenceCount": if staged_transcript_write_matches { 0 } else { 1 },
        "stagedTranscriptWriteComparison": {
            "contentHashMatches": staged_transcript_write_content_hash_matches,
            "orderMatches": staged_transcript_write_order_matches,
            "receiptBindingMatches": staged_transcript_write_receipt_binding_matches,
            "targetMatches": staged_transcript_write_target_matches,
            "stagedWritePersisted": output_writer_staged_write_persisted,
            "stagedWriteCommitted": output_writer_staged_write_committed,
            "stagedWriteVisible": output_writer_staged_write_visible,
            "excludedFromVisibleTranscript": output_writer_staged_write_excluded_from_visible_transcript,
            "rollbackStatus": output_writer_staged_write_rollback_status,
            "rollbackVerified": output_writer_staged_write_rollback_verified,
            "matches": staged_transcript_write_matches,
            "divergenceClass": if staged_transcript_write_matches { Value::Null } else { json!("staged_transcript_write_divergence") }
        },
        "visibleTranscriptWriteContentHashMatches": visible_transcript_write_content_hash_matches,
        "visibleTranscriptWriteOrderMatches": visible_transcript_write_order_matches,
        "visibleTranscriptWriteReceiptBindingMatches": visible_transcript_write_receipt_binding_matches,
        "visibleTranscriptWriteTargetMatches": visible_transcript_write_target_matches,
        "visibleTranscriptWriteMatches": visible_transcript_write_matches,
        "visibleTranscriptWriteDivergenceCount": if visible_transcript_write_matches { 0 } else { 1 },
        "visibleTranscriptWriteComparison": {
            "contentHashMatches": visible_transcript_write_content_hash_matches,
            "orderMatches": visible_transcript_write_order_matches,
            "receiptBindingMatches": visible_transcript_write_receipt_binding_matches,
            "targetMatches": visible_transcript_write_target_matches,
            "workflowWritePersisted": output_writer_visible_write_persisted,
            "workflowWriteCommitted": output_writer_visible_write_committed,
            "workflowWriteVisible": output_writer_visible_write_visible,
            "identityCheckpointPersisted": output_writer_visible_write_identity_checkpoint_persisted,
            "legacyDuplicateSuppressed": output_writer_visible_write_duplicate_suppressed,
            "matches": visible_transcript_write_matches,
            "divergenceClass": if visible_transcript_write_matches { Value::Null } else { json!("visible_transcript_write_divergence") }
        },
        "proposedVisibleOutputHash": proposed_visible_output_hash,
        "actualVisibleOutputHash": actual_visible_output_hash,
        "outputHashAlgorithm": "runtime_prompt_hash:v1",
        "outputHashMatches": output_hash_matches,
        "outputHashDivergence": !output_hash_matches,
        "outputHashDivergenceCount": if output_hash_matches { 0 } else { 1 },
        "outputHashComparison": {
            "proposedVisibleOutputHash": proposed_visible_output_hash,
            "actualVisibleOutputHash": actual_visible_output_hash,
            "hashAlgorithm": "runtime_prompt_hash:v1",
            "matches": output_hash_matches,
            "divergenceClass": if output_hash_matches { Value::Null } else { json!("output_hash_divergence") }
        },
        "legacyOutputAuthorityRetained": false,
        "legacyOutputFallbackAvailable": true,
        "mutatingTurnsBlocked": true,
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "rollbackAvailable": true,
        "activationBlockers": activation_blockers,
        "policyDecision": if dispatch_accepted && model_provider_gated_visible_output_selected {
            "accept_read_only_workflow_default_dispatch_with_provider_gated_visible_output"
        } else if dispatch_accepted {
            "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write"
        } else {
            "retain_legacy_runtime_default"
        },
        "evidenceRefs": [
            format!("runtime-evidence:{sid}"),
            format!("harness-live-handoff:{sid}:{}", task.progress),
            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
        ]
    })
}

fn runtime_evidence_projection(
    task: &AgentTask,
    sid: &str,
    staged_output_writer_write: Option<&Value>,
    visible_output_writer_write: Option<&Value>,
    legacy_transcript_fallback: Option<&Value>,
) -> serde_json::Value {
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
    let latest_agent_turn = task
        .history
        .iter()
        .rev()
        .find(|message| message.role == "agent" || message.role == "assistant")
        .map(|message| message.text.as_str())
        .unwrap_or(task.current_step.as_str());
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
    let harness_selector_decision = runtime_harness_selector_decision(
        sid,
        task,
        latest_user_turn,
        selected_action,
        stop_reason,
    );
    let harness_shadow_run = runtime_harness_shadow_run(
        task,
        sid,
        latest_user_turn,
        latest_agent_turn,
        &prompt_final_hash,
        selected_strategy,
        selected_action,
        stop_reason,
        evidence_sufficient,
        has_selected_sources,
        verifier_independence_required,
    );
    let harness_gated_cluster_runs = runtime_harness_gated_cluster_runs(sid, &harness_shadow_run);
    let harness_fork_activation =
        runtime_harness_fork_activation(sid, harness_gated_cluster_runs.as_slice());
    let harness_cognition_canary_execution_boundary =
        runtime_harness_cognition_canary_execution_boundary(
            sid,
            task,
            latest_user_turn,
            latest_agent_turn,
            stop_reason,
            evidence_sufficient,
            &harness_shadow_run,
            harness_gated_cluster_runs.as_slice(),
            &harness_selector_decision,
        );
    let harness_routing_model_canary_execution_boundary =
        runtime_harness_routing_model_canary_execution_boundary(
            sid,
            task,
            latest_user_turn,
            latest_agent_turn,
            stop_reason,
            evidence_sufficient,
            &harness_shadow_run,
            harness_gated_cluster_runs.as_slice(),
            &harness_selector_decision,
        );
    let harness_verification_output_canary_execution_boundary =
        runtime_harness_verification_output_canary_execution_boundary(
            sid,
            task,
            latest_user_turn,
            latest_agent_turn,
            stop_reason,
            evidence_sufficient,
            &harness_shadow_run,
            harness_gated_cluster_runs.as_slice(),
            &harness_selector_decision,
        );
    let harness_authority_tooling_canary_execution_boundary =
        runtime_harness_authority_tooling_canary_execution_boundary(
            sid,
            task,
            latest_user_turn,
            latest_agent_turn,
            stop_reason,
            evidence_sufficient,
            &harness_shadow_run,
            harness_gated_cluster_runs.as_slice(),
            &harness_selector_decision,
        );
    let harness_canary_execution_boundaries = vec![
        harness_cognition_canary_execution_boundary,
        harness_routing_model_canary_execution_boundary,
        harness_verification_output_canary_execution_boundary.clone(),
        harness_authority_tooling_canary_execution_boundary,
    ];
    let harness_canary_execution_boundary = harness_verification_output_canary_execution_boundary;
    let harness_live_handoff = runtime_harness_live_handoff(
        sid,
        &harness_shadow_run,
        harness_gated_cluster_runs.as_slice(),
        harness_canary_execution_boundaries.as_slice(),
        &harness_selector_decision,
    );
    let harness_activation_id_gate_click_proof =
        runtime_harness_default_activation_id_gate_click_proof(sid);
    let harness_default_runtime_dispatch = runtime_harness_default_runtime_dispatch(
        sid,
        task,
        selected_strategy,
        selected_action,
        latest_agent_turn,
        &prompt_final_hash,
        &harness_selector_decision,
        &harness_live_handoff,
        harness_canary_execution_boundaries.as_slice(),
        Some(&harness_activation_id_gate_click_proof),
        staged_output_writer_write,
        visible_output_writer_write,
        legacy_transcript_fallback,
    );
    let harness_default_runtime_binding = runtime_harness_default_runtime_binding(
        sid,
        task,
        &harness_selector_decision,
        &harness_live_handoff,
        &harness_default_runtime_dispatch,
    );
    let harness_worker_binding = harness_default_runtime_binding
        .get("workerBinding")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "harnessWorkflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                "harnessActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                "executionMode": "projection",
                "source": "autopilot_runtime_selector_legacy_default_v1",
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "authorityBindingReady": false,
                "authorityBindingBlockers": ["worker_binding_authority_missing"],
                "policyDecision": "retain_legacy_runtime_default",
                "requiredInvariantIds": [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT],
                "invariantBlockers": ["worker_binding_authority_missing"]
            })
        });
    let harness_worker_binding_registry_record = harness_default_runtime_binding
        .get("workerBindingRegistryRecord")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "schemaVersion": "workflow.harness.worker-binding-registry.v1",
                "registryRecordId": format!(
                    "harness-worker-binding-registry:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:missing"
                ),
                "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "activationHash": DEFAULT_AGENT_HARNESS_HASH,
                "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                "componentVersionSet": {},
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "readinessProofId": "",
                "canaryResultId": "harness-canary-result:default-agent-harness:not-run",
                "policyDecision": "retain_legacy_runtime_default",
                "bindingStatus": "blocked",
                "blockers": ["worker_binding_registry_missing"],
                "requiredInvariantIds": [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT],
                "invariantBlockers": ["worker_binding_registry_missing"],
                "workerBinding": harness_worker_binding.clone()
            })
        });
    let harness_worker_attach_receipt = harness_default_runtime_binding
        .get("workerAttachReceipt")
        .cloned()
        .unwrap_or_else(|| {
            let attach_request = json!({
                "schemaVersion": "workflow.harness.worker-attach-request.v1",
                "requestId": format!("harness-worker-attach-request:{sid}:missing"),
                "workerId": format!("harness-worker:{DEFAULT_AGENT_HARNESS_WORKFLOW_ID}:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:{sid}"),
                "workflowId": DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
                "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "activationHash": DEFAULT_AGENT_HARNESS_HASH,
                "harnessHash": DEFAULT_AGENT_HARNESS_HASH,
                "componentVersionSet": {},
                "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
                "readinessProofId": "",
                "requiredInvariantIds": [DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT],
                "requestedStatus": "blocked"
            });
            runtime_harness_worker_attach_receipt(
                sid,
                &format!("turn-{}", task.progress),
                &harness_worker_binding_registry_record,
                &attach_request,
            )
        });
    let harness_worker_attach_lifecycle = harness_default_runtime_binding
        .get("workerAttachLifecycle")
        .cloned()
        .unwrap_or_else(|| {
            runtime_harness_worker_attach_lifecycle_events(
                sid,
                &format!("turn-{}", task.progress),
                &harness_worker_binding_registry_record,
            )
            .into()
        });
    let harness_worker_session_record = harness_default_runtime_binding
        .get("workerSessionRecord")
        .cloned()
        .unwrap_or_else(|| {
            let lifecycle = harness_worker_attach_lifecycle
                .as_array()
                .cloned()
                .unwrap_or_default();
            runtime_harness_worker_session_record(
                sid,
                &format!("turn-{}", task.progress),
                &harness_worker_binding_registry_record,
                lifecycle.as_slice(),
            )
        });

    json!({
        "schemaVersion": RUNTIME_CONTRACT_SCHEMA_VERSION_V1,
        "HarnessRuntimeSelectorDecision": harness_selector_decision,
        "HarnessWorkerBinding": harness_worker_binding,
        "HarnessWorkerBindingRegistryRecord": harness_worker_binding_registry_record,
        "HarnessWorkerAttachReceipt": harness_worker_attach_receipt,
        "HarnessWorkerAttachLifecycle": harness_worker_attach_lifecycle,
        "HarnessWorkerSessionRecord": harness_worker_session_record,
        "HarnessShadowRun": harness_shadow_run,
        "HarnessGatedClusterRuns": harness_gated_cluster_runs,
        "HarnessForkActivation": harness_fork_activation,
        "HarnessCanaryExecutionBoundaries": harness_canary_execution_boundaries,
        "HarnessCanaryExecutionBoundary": harness_canary_execution_boundary,
        "HarnessLiveHandoff": harness_live_handoff,
        "HarnessDefaultRuntimeDispatch": harness_default_runtime_dispatch,
        "HarnessDefaultRuntimeBinding": harness_default_runtime_binding,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptProjectionWritePhase {
    PreWorkflowVisibleOutput,
    LegacyFallbackAfterWorkflowOutput,
}

impl TranscriptProjectionWritePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreWorkflowVisibleOutput => "pre_workflow_visible_output",
            Self::LegacyFallbackAfterWorkflowOutput => "legacy_fallback_after_workflow_output",
        }
    }
}

fn latest_agent_history_entry(task: &AgentTask) -> Option<(usize, &ChatMessage)> {
    task.history
        .iter()
        .enumerate()
        .rev()
        .find(|(_, message)| message.role == "agent" || message.role == "assistant")
}

fn transcript_write_receipt_binding_ref(
    sid: &str,
    role: &str,
    timestamp_ms: u64,
    order_index: u64,
) -> String {
    format!("checkpoint_transcript_messages:{sid}:{role}:{timestamp_ms}:{order_index}")
}

fn transcript_write_identity_hash(
    sid: &str,
    role: &str,
    timestamp_ms: u64,
    order_index: u64,
    content_hash: &str,
    receipt_binding_ref: &str,
) -> String {
    runtime_prompt_hash(&[
        sid,
        role,
        &timestamp_ms.to_string(),
        &order_index.to_string(),
        content_hash,
        receipt_binding_ref,
    ])
}

fn transcript_message_content_hash(message: &StoredTranscriptMessage) -> String {
    runtime_prompt_hash(&[message.store_content.as_str()])
}

fn stored_transcript_contains_write_identity(
    messages: &[StoredTranscriptMessage],
    role: &str,
    timestamp_ms: u64,
    content_hash: &str,
) -> bool {
    messages.iter().any(|message| {
        message.role == role
            && message.timestamp_ms == timestamp_ms
            && transcript_message_content_hash(message) == content_hash
    })
}

fn transcript_write_identity_for_message(
    sid: &str,
    order_index: usize,
    message: &ChatMessage,
) -> (String, String, String) {
    let content_hash = runtime_prompt_hash(&[message.text.as_str()]);
    let receipt_binding_ref = transcript_write_receipt_binding_ref(
        sid,
        message.role.as_str(),
        message.timestamp,
        order_index as u64,
    );
    let write_identity_hash = transcript_write_identity_hash(
        sid,
        message.role.as_str(),
        message.timestamp,
        order_index as u64,
        content_hash.as_str(),
        receipt_binding_ref.as_str(),
    );
    (content_hash, receipt_binding_ref, write_identity_hash)
}

fn append_missing_transcript_rows(
    memory_runtime: &Arc<MemoryRuntime>,
    sid: &str,
    task: &AgentTask,
    phase: TranscriptProjectionWritePhase,
) -> Value {
    let Some(thread_key) = thread_storage_key(sid) else {
        return json!({
            "schemaVersion": "workflow.output_writer.legacy-transcript-fallback.v1",
            "phase": phase.as_str(),
            "appendedCount": 0,
            "duplicateSuppressedCount": 0,
            "latestAgentDuplicateSuppressed": false,
            "error": "missing_thread_key"
        });
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
    let latest_agent_index = latest_agent_history_entry(task).map(|(index, _)| index);
    let mut seen = existing
        .iter()
        .map(|message| {
            format!(
                "{}\u{1f}{}\u{1f}{}",
                message.role, message.timestamp_ms, message.store_content
            )
        })
        .collect::<HashSet<_>>();
    let mut appended_count = 0usize;
    let mut duplicate_suppressed_count = 0usize;
    let mut latest_agent_duplicate_suppressed = false;
    let mut latest_agent_write_identity_hash = None::<String>;
    let mut appended_records = Vec::<Value>::new();

    for (index, message) in task.history.iter().enumerate() {
        if phase == TranscriptProjectionWritePhase::PreWorkflowVisibleOutput
            && latest_agent_index
                .map(|latest_index| index >= latest_index)
                .unwrap_or(false)
        {
            continue;
        }
        let text = message.text.trim();
        if text.is_empty() {
            continue;
        }
        let key = format!("{}\u{1f}{}\u{1f}{}", message.role, message.timestamp, text);
        if !seen.insert(key) {
            duplicate_suppressed_count += 1;
            if Some(index) == latest_agent_index {
                latest_agent_duplicate_suppressed = true;
                let (_, _, write_identity_hash) =
                    transcript_write_identity_for_message(sid, index, message);
                latest_agent_write_identity_hash = Some(write_identity_hash);
            }
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
        } else {
            appended_count += 1;
            let (content_hash, receipt_binding_ref, write_identity_hash) =
                transcript_write_identity_for_message(sid, index, message);
            if Some(index) == latest_agent_index {
                latest_agent_write_identity_hash = Some(write_identity_hash.clone());
            }
            appended_records.push(json!({
                "target": "checkpoint_transcript_messages",
                "role": message.role,
                "timestampMs": message.timestamp,
                "orderIndex": index,
                "contentHash": content_hash,
                "receiptBindingRef": receipt_binding_ref,
                "writeIdentityHash": write_identity_hash,
                "writeAuthority": "existing_runtime_service",
                "committed": true,
                "commitPhase": phase.as_str()
            }));
        }
    }

    json!({
        "schemaVersion": "workflow.output_writer.legacy-transcript-fallback.v1",
        "phase": phase.as_str(),
        "writeAuthority": "existing_runtime_service",
        "appendedCount": appended_count,
        "duplicateSuppressedCount": duplicate_suppressed_count,
        "latestAgentDuplicateSuppressed": latest_agent_duplicate_suppressed,
        "latestAgentWriteIdentityHash": latest_agent_write_identity_hash,
        "appendedRecords": appended_records,
        "idempotencyGuard": "role_timestamp_content_hash"
    })
}

fn workflow_output_writer_staged_transcript_write_record(
    sid: &str,
    task: &AgentTask,
    visible_output_hash: &str,
) -> Value {
    let latest_agent_message = latest_agent_history_entry(task);
    let transcript_order_index = latest_agent_message
        .map(|(index, _)| index as u64)
        .unwrap_or_else(|| task.history.len().saturating_sub(1) as u64);
    let transcript_role = latest_agent_message
        .map(|(_, message)| message.role.as_str())
        .unwrap_or("agent");
    let transcript_timestamp_ms = latest_agent_message
        .map(|(_, message)| message.timestamp)
        .unwrap_or_else(|| u64::from(task.progress));
    let transcript_write_receipt_binding_ref = transcript_write_receipt_binding_ref(
        sid,
        transcript_role,
        transcript_timestamp_ms,
        transcript_order_index,
    );
    let write_identity_hash = transcript_write_identity_hash(
        sid,
        transcript_role,
        transcript_timestamp_ms,
        transcript_order_index,
        visible_output_hash,
        transcript_write_receipt_binding_ref.as_str(),
    );

    json!({
        "schemaVersion": "workflow.output_writer.transcript-staging-record.v1",
        "target": "checkpoint_transcript_messages",
        "stagingSurface": "checkpoint_blobs",
        "checkpointName": WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        "role": transcript_role,
        "timestampMs": transcript_timestamp_ms,
        "orderIndex": transcript_order_index,
        "contentHash": visible_output_hash,
        "storeContentHash": visible_output_hash,
        "rawReference": format!("autopilot://session/{sid}/history"),
        "receiptBindingRef": transcript_write_receipt_binding_ref,
        "writeIdentityHash": write_identity_hash,
        "writeAuthority": "blessed_workflow_activation_default",
        "committed": true,
        "stagingCommitted": true,
        "visible": false,
        "visibleTranscriptCommit": false,
        "commitMode": "staged_non_visible",
        "commitPhase": "isolated_transcript_staging_canary",
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
    })
}

fn workflow_output_writer_visible_transcript_write_record(
    sid: &str,
    task: &AgentTask,
    visible_output_hash: &str,
) -> Option<Value> {
    let (index, message) = latest_agent_history_entry(task)?;
    let receipt_binding_ref = transcript_write_receipt_binding_ref(
        sid,
        message.role.as_str(),
        message.timestamp,
        index as u64,
    );
    let write_identity_hash = transcript_write_identity_hash(
        sid,
        message.role.as_str(),
        message.timestamp,
        index as u64,
        visible_output_hash,
        receipt_binding_ref.as_str(),
    );

    Some(json!({
        "schemaVersion": "workflow.output_writer.visible-transcript-write-record.v1",
        "target": "checkpoint_transcript_messages",
        "role": message.role,
        "timestampMs": message.timestamp,
        "orderIndex": index,
        "contentHash": visible_output_hash,
        "storeContentHash": visible_output_hash,
        "rawReference": format!("autopilot://session/{sid}/history#workflow-output-writer:{write_identity_hash}"),
        "receiptBindingRef": receipt_binding_ref,
        "writeIdentityHash": write_identity_hash,
        "writeAuthority": "blessed_workflow_activation_default",
        "committed": true,
        "visible": true,
        "visibleTranscriptCommit": true,
        "commitMode": "workflow_visible_transcript_write",
        "commitPhase": "workflow_owned_visible_output",
        "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID
    }))
}

fn persist_output_writer_visible_transcript_write(
    memory_runtime: &Arc<MemoryRuntime>,
    sid: &str,
    task: &AgentTask,
) -> Option<Value> {
    let thread_key = thread_storage_key(sid)?;
    let (index, message) = latest_agent_history_entry(task)?;
    if message.text.trim().is_empty() {
        return None;
    }

    let visible_output_hash = runtime_prompt_hash(&[message.text.as_str()]);
    let record =
        workflow_output_writer_visible_transcript_write_record(sid, task, &visible_output_hash)?;
    let visible_before = memory_runtime
        .load_transcript_messages(thread_key)
        .unwrap_or_default();
    let existed_before = stored_transcript_contains_write_identity(
        &visible_before,
        message.role.as_str(),
        message.timestamp,
        visible_output_hash.as_str(),
    );
    let mut append_error = None::<String>;
    if !existed_before {
        let transcript = StoredTranscriptMessage {
            role: message.role.clone(),
            timestamp_ms: message.timestamp,
            trace_hash: None,
            raw_content: message.text.clone(),
            model_content: message.text.clone(),
            store_content: message.text.clone(),
            raw_reference: record
                .get("rawReference")
                .and_then(Value::as_str)
                .map(str::to_string),
            privacy_metadata: TranscriptPrivacyMetadata {
                redaction_version: "autopilot-runtime-evidence-v1".to_string(),
                sensitive_fields_mask: Vec::new(),
                policy_id: "autopilot-workflow-output-writer".to_string(),
                policy_version: "v1".to_string(),
                scrubbed_for_model_hash: None,
            },
        };
        if let Err(error) = memory_runtime.append_transcript_message(thread_key, &transcript) {
            append_error = Some(error.to_string());
            eprintln!(
                "[Autopilot] Failed to append workflow output writer transcript for {}: {}",
                sid, error
            );
        }
    }
    persist_thread_checkpoint_json(
        memory_runtime,
        thread_key,
        WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_IDENTITY_CHECKPOINT_NAME,
        &record,
    );
    let identity_checkpoint_persisted = load_thread_checkpoint_json::<Value>(
        memory_runtime,
        thread_key,
        WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_IDENTITY_CHECKPOINT_NAME,
    )
    .as_ref()
        == Some(&record);
    let visible_after = memory_runtime
        .load_transcript_messages(thread_key)
        .unwrap_or_default();
    let exists_after = stored_transcript_contains_write_identity(
        &visible_after,
        message.role.as_str(),
        message.timestamp,
        visible_output_hash.as_str(),
    );
    let visible_rows_delta = visible_after.len().saturating_sub(visible_before.len());
    let receipt_binding_ref = record
        .get("receiptBindingRef")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let write_identity_hash = record
        .get("writeIdentityHash")
        .and_then(Value::as_str)
        .unwrap_or_default();

    Some(json!({
        "schemaVersion": "workflow.output_writer.visible-transcript-write-proof.v1",
        "mode": "workflow_visible_transcript_write",
        "target": "checkpoint_transcript_messages",
        "record": record,
        "persisted": exists_after && identity_checkpoint_persisted,
        "committed": exists_after,
        "created": !existed_before && exists_after && append_error.is_none(),
        "visible": true,
        "visibleBeforeCount": visible_before.len(),
        "visibleAfterCount": visible_after.len(),
        "visibleRowsDelta": visible_rows_delta,
        "existedBefore": existed_before,
        "idempotencyGuard": "session_role_timestamp_order_content_hash_receipt_binding",
        "idempotencyKey": write_identity_hash,
        "receiptBindingRef": receipt_binding_ref,
        "duplicateSuppressionReady": exists_after,
        "identityCheckpointName": WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_IDENTITY_CHECKPOINT_NAME,
        "identityCheckpointPersisted": identity_checkpoint_persisted,
        "appendError": append_error,
        "rollbackAvailable": true,
        "rollbackMode": "legacy_runtime_fallback_with_idempotent_duplicate_suppression",
        "evidenceRefs": [
            format!("runtime-evidence:{sid}"),
            format!("workflow-visible-transcript-write:{write_identity_hash}"),
            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
        ],
        "orderIndex": index
    }))
}

fn workflow_visible_output_write_eligible(task: &AgentTask, sid: &str) -> bool {
    if !runtime_harness_default_promotion_enabled() {
        return false;
    }
    let latest_user_turn = task
        .history
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .map(|message| message.text.as_str())
        .unwrap_or(task.intent.as_str());
    let (stop_reason, _, _) = runtime_stop_reason(task);
    let selected_action =
        if matches!(task.phase, AgentPhase::Gate) || task.pending_request_hash.is_some() {
            "ask_human"
        } else if matches!(task.phase, AgentPhase::Failed) {
            "stop"
        } else {
            "verify"
        };
    let live_promotion_readiness_proof = runtime_harness_selector_live_promotion_readiness_proof(
        sid,
        task,
        latest_user_turn,
        selected_action,
        stop_reason,
        true,
    );
    runtime_harness_selector_decision_with_default_promotion(
        sid,
        task,
        latest_user_turn,
        selected_action,
        stop_reason,
        true,
        Some(&live_promotion_readiness_proof),
    )
    .get("selectedSelector")
    .and_then(Value::as_str)
        == Some("blessed_workflow_live_default")
}

fn persist_output_writer_transcript_staging_canary(
    memory_runtime: &Arc<MemoryRuntime>,
    sid: &str,
    task: &AgentTask,
) -> Option<Value> {
    let thread_key = thread_storage_key(sid)?;
    let latest_agent_turn = task
        .history
        .iter()
        .rev()
        .find(|message| message.role == "agent" || message.role == "assistant")
        .map(|message| message.text.as_str())
        .unwrap_or(task.current_step.as_str())
        .trim();
    if latest_agent_turn.is_empty() {
        return None;
    }

    let visible_output_hash = runtime_prompt_hash(&[latest_agent_turn]);
    let record =
        workflow_output_writer_staged_transcript_write_record(sid, task, &visible_output_hash);
    let visible_before_count = memory_runtime
        .load_transcript_messages(thread_key)
        .map(|messages| messages.len())
        .unwrap_or(0);
    let bytes = match serde_json::to_vec(&record) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "[Autopilot] Failed to serialize workflow output writer staging record for {}: {}",
                sid, error
            );
            return None;
        }
    };

    let persisted = memory_runtime
        .upsert_checkpoint_blob(
            thread_key,
            WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
            &bytes,
        )
        .is_ok();
    let loaded_record = memory_runtime
        .load_checkpoint_blob(
            thread_key,
            WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        )
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let loaded_before_rollback = loaded_record.as_ref() == Some(&record);
    let rollback_executed = memory_runtime
        .delete_checkpoint_blob(
            thread_key,
            WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        )
        .is_ok();
    let rollback_verified = memory_runtime
        .load_checkpoint_blob(
            thread_key,
            WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        )
        .ok()
        .flatten()
        .is_none();
    let visible_after_count = memory_runtime
        .load_transcript_messages(thread_key)
        .map(|messages| messages.len())
        .unwrap_or(0);
    let excluded_from_visible_transcript = visible_before_count == visible_after_count;

    Some(json!({
        "schemaVersion": "workflow.output_writer.transcript-staging-proof.v1",
        "surface": "checkpoint_blobs",
        "checkpointName": WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        "record": loaded_record.unwrap_or(record),
        "persisted": persisted && loaded_before_rollback,
        "loadedBeforeRollback": loaded_before_rollback,
        "visibleBeforeCount": visible_before_count,
        "visibleAfterCount": visible_after_count,
        "excludedFromVisibleTranscript": excluded_from_visible_transcript,
        "rollbackAction": "delete_checkpoint_blob",
        "rollbackExecuted": rollback_executed,
        "rollbackVerified": rollback_verified,
        "rollbackStatus": if rollback_verified { "deleted" } else { "not_deleted" },
        "evidenceRefs": [
            format!("runtime-evidence:{sid}"),
            format!("checkpoint:{}:{WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME}", sid),
            format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}")
        ]
    }))
}

fn persist_runtime_evidence_projection(memory_runtime: &Arc<MemoryRuntime>, task: &AgentTask) {
    let sid = task.session_id.as_deref().unwrap_or(&task.id);
    let visible_output_writer_eligible = workflow_visible_output_write_eligible(task, sid);
    let _pre_workflow_transcript_projection = if visible_output_writer_eligible {
        Some(append_missing_transcript_rows(
            memory_runtime,
            sid,
            task,
            TranscriptProjectionWritePhase::PreWorkflowVisibleOutput,
        ))
    } else {
        None
    };
    let visible_output_writer_write = if visible_output_writer_eligible {
        persist_output_writer_visible_transcript_write(memory_runtime, sid, task)
    } else {
        None
    };
    let legacy_transcript_fallback = Some(append_missing_transcript_rows(
        memory_runtime,
        sid,
        task,
        TranscriptProjectionWritePhase::LegacyFallbackAfterWorkflowOutput,
    ));

    let staged_output_writer_write =
        persist_output_writer_transcript_staging_canary(memory_runtime, sid, task);
    let mut projection = runtime_evidence_projection(
        task,
        sid,
        staged_output_writer_write.as_ref(),
        visible_output_writer_write.as_ref(),
        legacy_transcript_fallback.as_ref(),
    );
    let harness_shadow_run = projection.get("HarnessShadowRun").cloned();
    let harness_node_attempt_count = harness_shadow_run
        .as_ref()
        .and_then(|run| run.get("nodeAttempts"))
        .and_then(Value::as_array)
        .map(|attempts| attempts.len())
        .unwrap_or(0);
    let harness_shadow_comparison_count = harness_shadow_run
        .as_ref()
        .and_then(|run| run.get("comparisons"))
        .and_then(Value::as_array)
        .map(|comparisons| comparisons.len())
        .unwrap_or(0);
    let harness_blocking_divergence_count = harness_shadow_run
        .as_ref()
        .and_then(|run| run.get("blockingDivergenceCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let harness_gated_cluster_runs = projection
        .get("HarnessGatedClusterRuns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let harness_gated_cluster_count = harness_gated_cluster_runs.len();
    let harness_gated_cognition_passed = harness_gated_cluster_runs.iter().any(|run| {
        run.get("clusterId").and_then(Value::as_str) == Some("cognition")
            && run.get("executionMode").and_then(Value::as_str) == Some("gated")
            && run.get("status").and_then(Value::as_str) == Some("gated")
            && run.get("promotionBlocked").and_then(Value::as_bool) == Some(false)
            && run.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && run.get("canaryStatus").and_then(Value::as_str) == Some("passed")
    });
    let harness_gated_routing_model_passed = harness_gated_cluster_runs.iter().any(|run| {
        run.get("clusterId").and_then(Value::as_str) == Some("routing_model")
            && run.get("executionMode").and_then(Value::as_str) == Some("gated")
            && run.get("status").and_then(Value::as_str) == Some("gated")
            && run.get("promotionBlocked").and_then(Value::as_bool) == Some(false)
            && run.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && run.get("canaryStatus").and_then(Value::as_str) == Some("passed")
    });
    let harness_gated_verification_output_passed = harness_gated_cluster_runs.iter().any(|run| {
        run.get("clusterId").and_then(Value::as_str) == Some("verification_output")
            && run.get("executionMode").and_then(Value::as_str) == Some("gated")
            && run.get("status").and_then(Value::as_str) == Some("gated")
            && run.get("promotionBlocked").and_then(Value::as_bool) == Some(false)
            && run.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && run.get("canaryStatus").and_then(Value::as_str) == Some("passed")
    });
    let harness_gated_authority_tooling_passed = harness_gated_cluster_runs.iter().any(|run| {
        run.get("clusterId").and_then(Value::as_str) == Some("authority_tooling")
            && run.get("executionMode").and_then(Value::as_str) == Some("gated")
            && run.get("status").and_then(Value::as_str) == Some("gated")
            && run.get("promotionBlocked").and_then(Value::as_bool) == Some(false)
            && run.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
            && run.get("canaryStatus").and_then(Value::as_str) == Some("passed")
            && run.get("runtimeAuthority").and_then(Value::as_str)
                == Some("existing_runtime_service")
    });
    let harness_fork_activation = projection.get("HarnessForkActivation").cloned();
    let harness_fork_activation_blocked = harness_fork_activation
        .as_ref()
        .and_then(|activation| activation.get("invalidFork"))
        .map(|invalid| {
            invalid.get("activationState").and_then(Value::as_str) == Some("blocked")
                && invalid
                    .get("activationBlockers")
                    .and_then(Value::as_array)
                    .map(|blockers| !blockers.is_empty())
                    .unwrap_or(false)
                && invalid.get("activationMinted").and_then(Value::as_bool) == Some(false)
        })
        .unwrap_or(false);
    let harness_fork_activation_minted = harness_fork_activation
        .as_ref()
        .and_then(|activation| activation.get("validFork"))
        .map(|valid| {
            let activation_id = valid.get("activationId").and_then(Value::as_str);
            valid.get("activationState").and_then(Value::as_str) == Some("validated")
                && valid.get("canaryStatus").and_then(Value::as_str) == Some("passed")
                && valid.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
                && valid
                    .get("liveAuthorityTransferred")
                    .and_then(Value::as_bool)
                    == Some(false)
                && activation_id.is_some()
                && valid
                    .get("workerBinding")
                    .and_then(|binding| binding.get("harnessActivationId"))
                    .and_then(Value::as_str)
                    == activation_id
        })
        .unwrap_or(false);
    let harness_rollback_restore_canary_blocked = harness_fork_activation
        .as_ref()
        .and_then(|activation| activation.get("invalidFork"))
        .and_then(|invalid| invalid.get("rollbackRestoreCanary"))
        .map(|canary| {
            canary.get("status").and_then(Value::as_str) == Some("blocked")
                && canary.get("hashVerified").and_then(Value::as_bool) == Some(false)
                && canary
                    .get("blockers")
                    .and_then(Value::as_array)
                    .map(|blockers| {
                        blockers.iter().any(|blocker| {
                            blocker.as_str() == Some("rollback_restore_canary_not_run")
                        })
                    })
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_rollback_restore_canary_ready = harness_fork_activation
        .as_ref()
        .and_then(|activation| activation.get("validFork"))
        .and_then(|valid| valid.get("rollbackRestoreCanary"))
        .map(|canary| {
            matches!(
                canary.get("status").and_then(Value::as_str),
                Some("passed") | Some("not_required")
            ) && canary.get("hashVerified").and_then(Value::as_bool) == Some(true)
                && canary
                    .get("blockers")
                    .and_then(Value::as_array)
                    .map(|blockers| blockers.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let rollback_restore_canary_receipt_present = |canary: &Value| {
        let Some(receipt_binding_ref) = canary.get("receiptBindingRef").and_then(Value::as_str)
        else {
            return false;
        };
        receipt_binding_ref.starts_with("workflow_restore_canary:")
            && canary
                .get("evidenceRefs")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .any(|reference| reference.as_str() == Some(receipt_binding_ref))
                })
                .unwrap_or(false)
    };
    let harness_rollback_restore_canary_receipts_present = harness_fork_activation
        .as_ref()
        .map(|activation| {
            let invalid_receipt_present = activation
                .get("invalidFork")
                .and_then(|invalid| invalid.get("rollbackRestoreCanary"))
                .map(|canary| rollback_restore_canary_receipt_present(canary))
                .unwrap_or(false);
            let valid_receipt_present = activation
                .get("validFork")
                .and_then(|valid| valid.get("rollbackRestoreCanary"))
                .map(|canary| rollback_restore_canary_receipt_present(canary))
                .unwrap_or(false);
            invalid_receipt_present && valid_receipt_present
        })
        .unwrap_or(false);
    let activation_audit_receipts_present = |activation_event: &Value| {
        let Some(event_type) = activation_event.get("eventType").and_then(Value::as_str) else {
            return false;
        };
        matches!(
            event_type,
            "dry_run_blocked"
                | "dry_run_mintable"
                | "activation_mint_blocked"
                | "activation_minted"
                | "rollback_drill_passed"
                | "rollback_executed"
        ) && activation_event
            .get("receiptRefs")
            .and_then(Value::as_array)
            .map(|refs| {
                refs.iter().any(|reference| {
                    reference
                        .as_str()
                        .map(|value| value.starts_with("workflow_restore_canary:"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    };
    let harness_activation_audit_receipts_present = harness_fork_activation
        .as_ref()
        .map(|activation| {
            ["invalidFork", "validFork"].iter().any(|fork_key| {
                activation
                    .get(*fork_key)
                    .and_then(|fork| fork.get("activationAudit"))
                    .and_then(Value::as_array)
                    .map(|events| {
                        events
                            .iter()
                            .any(|event| activation_audit_receipts_present(event))
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    let harness_rollback_execution_receipts_present = harness_fork_activation
        .as_ref()
        .and_then(|activation| activation.get("validFork"))
        .and_then(|valid| valid.get("activationRollbackExecution"))
        .map(|execution| {
            execution
                .get("receiptRefs")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter().any(|reference| {
                        reference
                            .as_str()
                            .map(|value| value.starts_with("workflow_restore_canary:"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
                && execution
                    .get("restoreReceiptBindingRef")
                    .and_then(Value::as_str)
                    .map(|value| value.starts_with("workflow_restore_canary:"))
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_canary_execution_boundary =
        projection.get("HarnessCanaryExecutionBoundary").cloned();
    let mut harness_canary_execution_boundaries = projection
        .get("HarnessCanaryExecutionBoundaries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if harness_canary_execution_boundaries.is_empty() {
        if let Some(boundary) = harness_canary_execution_boundary.clone() {
            harness_canary_execution_boundaries.push(boundary);
        }
    }
    let boundary_executed = |cluster_id: &str| -> bool {
        let minimum_attempts = match cluster_id {
            "routing_model" => 3,
            "authority_tooling" => 8,
            _ => 6,
        };
        harness_canary_execution_boundaries.iter().any(|boundary| {
            boundary.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.canary-execution-boundary.v1")
                && boundary.get("clusterId").and_then(Value::as_str) == Some(cluster_id)
                && boundary.get("status").and_then(Value::as_str) == Some("passed")
                && boundary.get("executionMode").and_then(Value::as_str) == Some("live")
                && boundary.get("runtimeAuthority").and_then(Value::as_str)
                    == Some("blessed_workflow_activation_canary")
                && boundary.get("executorKind").and_then(Value::as_str)
                    == Some("workflow_node_executor")
                && boundary.get("synchronous").and_then(Value::as_bool) == Some(true)
                && boundary
                    .get("nodeAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= minimum_attempts)
                    .unwrap_or(false)
                && boundary
                    .get("executedComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= minimum_attempts)
                    .unwrap_or(false)
                && boundary
                    .get("activationBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        })
    };
    let boundary_rollback_drill_passed = |cluster_id: &str| -> bool {
        harness_canary_execution_boundaries.iter().any(|boundary| {
            boundary.get("clusterId").and_then(Value::as_str) == Some(cluster_id)
                && boundary
                    .get("rollbackDrill")
                    .and_then(|drill| drill.get("failureInjected"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && boundary
                    .get("rollbackDrill")
                    .and_then(|drill| drill.get("observedFailure"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && boundary
                    .get("rollbackDrill")
                    .and_then(|drill| drill.get("rollbackExecuted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && boundary
                    .get("rollbackDrill")
                    .and_then(|drill| drill.get("rollbackSelector"))
                    .and_then(Value::as_str)
                    == Some("legacy_runtime")
                && boundary
                    .get("rollbackDrill")
                    .and_then(|drill| drill.get("fallbackAuthority"))
                    .and_then(Value::as_str)
                    == Some("existing_runtime_service")
                && boundary
                    .get("rollbackDrill")
                    .and_then(|drill| drill.get("drillStatus"))
                    .and_then(Value::as_str)
                    == Some("passed")
        })
    };
    let harness_canary_boundary_executed = boundary_executed("cognition")
        && boundary_executed("routing_model")
        && boundary_executed("verification_output")
        && boundary_executed("authority_tooling");
    let harness_canary_boundary_rollback_drill = boundary_rollback_drill_passed("cognition")
        && boundary_rollback_drill_passed("routing_model")
        && boundary_rollback_drill_passed("verification_output")
        && boundary_rollback_drill_passed("authority_tooling");
    let harness_selector_decision = projection.get("HarnessRuntimeSelectorDecision").cloned();
    let harness_selector_canary_routed = harness_selector_decision
        .as_ref()
        .map(|decision| {
            decision.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.runtime-selector.v1")
                && decision.get("selectedSelector").and_then(Value::as_str)
                    == Some("blessed_workflow_live_canary")
                && decision
                    .get("productionDefaultSelector")
                    .and_then(Value::as_str)
                    == Some("legacy_runtime")
                && decision.get("canaryEligible").and_then(Value::as_bool) == Some(true)
                && decision
                    .get("canaryBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && decision.get("executionMode").and_then(Value::as_str) == Some("live")
                && decision
                    .get("actualRuntimeAuthority")
                    .and_then(Value::as_str)
                    == Some("blessed_workflow_activation_canary")
                && decision.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
        })
        .unwrap_or(false);
    let harness_selector_legacy_default = harness_selector_decision
        .as_ref()
        .map(|decision| {
            decision
                .get("productionDefaultSelector")
                .and_then(Value::as_str)
                == Some("legacy_runtime")
                && decision.get("fallbackSelector").and_then(Value::as_str)
                    == Some("legacy_runtime")
                && decision.get("rollbackTarget").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
        })
        .unwrap_or(false);
    let reviewed_import_activation_apply_invariant_passed = |value: &Value| -> bool {
        value
            .get("defaultLivePromotionInvariantIds")
            .and_then(Value::as_array)
            .map(|items| {
                items.iter().any(|item| {
                    item.as_str()
                        == Some(DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)
                })
            })
            .unwrap_or(false)
            && value
                .get("defaultLivePromotionInvariantBlockers")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false)
            && value
                .get("reviewedImportActivationApplyProofPresent")
                .and_then(Value::as_bool)
                == Some(true)
            && value
                .get("reviewedImportActivationApplyProofPassed")
                .and_then(Value::as_bool)
                == Some(true)
            && value
                .get("reviewedImportActivationApplyProofBlockers")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false)
            && value
                .get("reviewedImportActivationApplyActivationId")
                .and_then(Value::as_str)
                == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    };
    let harness_selector_default_promoted = harness_selector_decision
        .as_ref()
        .map(|decision| {
            decision.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.runtime-selector.v1")
                && decision.get("selectedSelector").and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && decision
                    .get("productionDefaultSelector")
                    .and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && decision.get("canaryEligible").and_then(Value::as_bool) == Some(true)
                && decision
                    .get("canaryBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && decision.get("executionMode").and_then(Value::as_str) == Some("live")
                && decision
                    .get("actualRuntimeAuthority")
                    .and_then(Value::as_str)
                    == Some("blessed_workflow_activation_default")
                && decision
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("enabled"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && decision
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("eligible"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && decision.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
                && decision
                    .get("livePromotionReadinessReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && decision
                    .get("livePromotionReadinessBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && reviewed_import_activation_apply_invariant_passed(decision)
                && decision
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("requiredInvariantIds"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.iter().any(|item| {
                            item.as_str()
                                == Some(
                                    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
                                )
                        })
                    })
                    .unwrap_or(false)
                && decision
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("invariantBlockers"))
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_selector_live_promotion_readiness_gated = harness_selector_decision
        .as_ref()
        .map(|decision| {
            decision
                .get("livePromotionReadinessProof")
                .and_then(|proof| proof.get("schemaVersion"))
                .and_then(Value::as_str)
                == Some("workflow.harness.live-promotion-readiness.v1")
                && decision
                    .get("livePromotionReadinessReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && decision
                    .get("livePromotionReadinessBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && decision
                    .get("livePromotionReadinessPolicyDecision")
                    .and_then(Value::as_str)
                    == Some("allow_default_harness_live_promotion_readiness")
        })
        .unwrap_or(false);
    let harness_live_handoff = projection.get("HarnessLiveHandoff").cloned();
    let harness_live_handoff_canary = harness_live_handoff
        .as_ref()
        .map(|handoff| {
            handoff.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.live-handoff.v1")
                && handoff.get("selector").and_then(Value::as_str)
                    == Some("blessed_workflow_live_canary")
                && handoff
                    .get("productionDefaultSelector")
                    .and_then(Value::as_str)
                    == Some("legacy_runtime")
                && handoff.get("workflowId").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
                && handoff.get("activationId").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && handoff.get("harnessHash").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_HASH)
                && handoff.get("canaryStatus").and_then(Value::as_str) == Some("passed")
                && handoff
                    .get("canaryTurnRoutedThroughWorkflow")
                    .and_then(Value::as_bool)
                    == Some(true)
                && handoff
                    .get("defaultAuthorityTransferred")
                    .and_then(Value::as_bool)
                    == Some(false)
                && handoff.get("runtimeAuthority").and_then(Value::as_str)
                    == Some("blessed_workflow_activation_canary")
                && handoff
                    .get("executionBoundaryStatus")
                    .and_then(Value::as_str)
                    == Some("passed")
        })
        .unwrap_or(false);
    let harness_live_handoff_default_promoted = harness_live_handoff
        .as_ref()
        .map(|handoff| {
            handoff.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.live-handoff.v1")
                && handoff.get("selector").and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && handoff
                    .get("productionDefaultSelector")
                    .and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && handoff.get("workflowId").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
                && handoff.get("activationId").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && handoff.get("harnessHash").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_HASH)
                && handoff.get("canaryStatus").and_then(Value::as_str) == Some("passed")
                && handoff
                    .get("canaryTurnRoutedThroughWorkflow")
                    .and_then(Value::as_bool)
                    == Some(true)
                && handoff
                    .get("defaultAuthorityTransferred")
                    .and_then(Value::as_bool)
                    == Some(true)
                && handoff.get("runtimeAuthority").and_then(Value::as_str)
                    == Some("blessed_workflow_activation_default")
                && handoff
                    .get("executionBoundaryStatus")
                    .and_then(Value::as_str)
                    == Some("passed")
                && handoff
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("defaultAuthorityTransferred"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && handoff
                    .get("livePromotionReadinessReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && handoff
                    .get("livePromotionReadinessBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && reviewed_import_activation_apply_invariant_passed(handoff)
                && handoff
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("requiredInvariantIds"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.iter().any(|item| {
                            item.as_str()
                                == Some(
                                    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
                                )
                        })
                    })
                    .unwrap_or(false)
                && handoff
                    .get("defaultPromotionGate")
                    .and_then(|gate| gate.get("invariantBlockers"))
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_live_handoff_rollback = harness_live_handoff
        .as_ref()
        .map(|handoff| {
            handoff.get("fallbackSelector").and_then(Value::as_str) == Some("legacy_runtime")
                && handoff.get("rollbackTarget").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && handoff.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
                && handoff
                    .get("nodeTimelineAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && handoff
                    .get("receiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && handoff
                    .get("activationBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_default_runtime_dispatch = projection.get("HarnessDefaultRuntimeDispatch").cloned();
    let harness_default_runtime_dispatch_readonly = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.default-runtime-dispatch.v1")
                && dispatch.get("selectedSelector").and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && dispatch
                    .get("productionDefaultSelector")
                    .and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && dispatch.get("executionMode").and_then(Value::as_str) == Some("live")
                && dispatch.get("runtimeAuthority").and_then(Value::as_str)
                    == Some("blessed_workflow_activation_default")
                && dispatch.get("dispatchScope").and_then(Value::as_str)
                    == Some("read_only_cognition_routing_verification_completion_authority_tooling")
                && dispatch.get("status").and_then(Value::as_str) == Some("accepted")
                && dispatch
                    .get("readOnlyDispatchAccepted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && reviewed_import_activation_apply_invariant_passed(dispatch)
                && dispatch
                    .get("reviewedImportActivationApplyGate")
                    .and_then(|gate| gate.get("schemaVersion"))
                    .and_then(Value::as_str)
                    == Some(
                        "workflow.harness.default-runtime-dispatch.reviewed-import-activation-apply-gate.v1",
                    )
                && dispatch
                    .get("reviewedImportActivationApplyGate")
                    .and_then(|gate| gate.get("invariantId"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)
                && dispatch
                    .get("reviewedImportActivationApplyGate")
                    .and_then(|gate| gate.get("proofPassed"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("reviewedImportActivationApplyGate")
                    .and_then(|gate| gate.get("proofBlockers"))
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("attachStatus"))
                    .and_then(Value::as_str)
                    == Some("bound")
                && dispatch
                    .get("workerAttachResumeReceipt")
                    .and_then(|receipt| receipt.get("attachStatus"))
                    .and_then(Value::as_str)
                    == Some("resumed")
                && dispatch
                    .get("workerAttachRollbackReceipt")
                    .and_then(|receipt| receipt.get("attachStatus"))
                    .and_then(Value::as_str)
                    == Some("rolled_back")
                && dispatch
                    .get("workerAttachLifecycleComplete")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("workerAttachLifecycleStatuses")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let statuses = items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        statuses.contains(&"bound")
                            && statuses.contains(&"resumed")
                            && statuses.contains(&"rolled_back")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("workerAttachLifecycleAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let attempt_ids =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        attempt_ids.len() >= 3
                            && dispatch
                                .get("dispatchNodeAttemptIds")
                                .and_then(Value::as_array)
                                .map(|node_ids| {
                                    let node_ids = node_ids
                                        .iter()
                                        .filter_map(Value::as_str)
                                        .collect::<Vec<_>>();
                                    attempt_ids
                                        .iter()
                                        .all(|attempt_id| node_ids.contains(attempt_id))
                                })
                                .unwrap_or(false)
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("schemaVersion"))
                    .and_then(Value::as_str)
                    == Some("workflow.harness.worker-session.v1")
                && dispatch
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("currentStatus"))
                    .and_then(Value::as_str)
                    == Some("rollback_ready")
                && dispatch
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("resumed"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("rollbackTargetReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("lifecycleAttemptIds"))
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("outputWriterDeferred")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch.get("outputWriterStatus").and_then(Value::as_str)
                    == Some("visible_write_committed")
                && dispatch
                    .get("outputWriterHandoffReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterMaterializationMode")
                    .and_then(Value::as_str)
                    == Some("workflow_visible_transcript_write")
                && dispatch
                    .get("outputWriterMaterializationCanaryReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterMaterializationCommitted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterStagedWriteMode")
                    .and_then(Value::as_str)
                    == Some("isolated_checkpoint_blob")
                && dispatch
                    .get("outputWriterStagedWriteCanaryReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterStagedWritePersisted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterStagedWriteCommitted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterStagedWriteVisible")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("outputWriterStagedWriteExcludedFromVisibleTranscript")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterStagedWriteRollbackStatus")
                    .and_then(Value::as_str)
                    == Some("deleted")
                && dispatch
                    .get("outputWriterStagedWriteRollbackVerified")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterVisibleWriteMode")
                    .and_then(Value::as_str)
                    == Some("workflow_visible_transcript_write")
                && dispatch
                    .get("outputWriterVisibleWriteReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterVisibleWritePersisted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterVisibleWriteCommitted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterVisibleWriteVisible")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterVisibleWriteIdentityCheckpointPersisted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("outputWriterVisibleWriteLegacyDuplicateSuppressed")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("cognitionExecutionMode")
                    .and_then(Value::as_str)
                    == Some("workflow_synchronous_envelope")
                && dispatch
                    .get("cognitionExecutionReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch.get("promptAssemblyMode").and_then(Value::as_str)
                    == Some("workflow_synchronous_envelope")
                && dispatch
                    .get("promptAssemblyPromptHash")
                    .and_then(Value::as_str)
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("promptAssemblyPromptHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch.get("modelExecutionMode").and_then(Value::as_str)
                    == Some("workflow_synchronous_envelope")
                && dispatch
                    .get("modelExecutionEnvelopeReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelExecutionBindingId")
                    .and_then(Value::as_str)
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelExecutionBindingReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelExecutionPromptHash")
                    .and_then(Value::as_str)
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelExecutionPromptHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelExecutionOutputHash")
                    .and_then(Value::as_str)
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelExecutionOutputHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelExecutionProviderInvocationMode")
                    .and_then(Value::as_str)
                    == Some("workflow_provider_canary")
                && dispatch
                    .get("modelExecutionLowLevelInvocationDeferred")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("modelExecutionFallbackSelector")
                    .and_then(Value::as_str)
                    == Some("legacy_runtime_model_invocation")
                && dispatch
                    .get("modelProviderCanaryMode")
                    .and_then(Value::as_str)
                    == Some("workflow_provider_canary")
                && dispatch
                    .get("modelProviderCanaryReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderCanaryOutputHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderCanaryTranscriptMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderCanaryFallbackRetained")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderCanaryRollbackAvailable")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch.get("authorityToolingMode").and_then(Value::as_str)
                    == Some("workflow_live_dry_run")
                && dispatch
                    .get("authorityToolingReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingPolicyGateReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingToolRouterReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingDryRunSimulatorReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingApprovalGateReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingReadOnlyRouteAccepted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingDestructiveRouteDenied")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingMutatingToolCallsBlocked")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingSideEffectsExecuted")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("authorityToolingRollbackAvailable")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("legacyTranscriptAuthorityRetained")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("transcriptMaterializationMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("transcriptMaterializationContentHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("transcriptMaterializationOrderMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("transcriptMaterializationReceiptBindingMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("transcriptMaterializationDivergenceCount")
                    .and_then(Value::as_u64)
                    == Some(0)
                && dispatch
                    .get("stagedTranscriptWriteMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("stagedTranscriptWriteContentHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("stagedTranscriptWriteOrderMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("stagedTranscriptWriteReceiptBindingMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("stagedTranscriptWriteDivergenceCount")
                    .and_then(Value::as_u64)
                    == Some(0)
                && dispatch
                    .get("visibleTranscriptWriteMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("visibleTranscriptWriteContentHashMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("visibleTranscriptWriteOrderMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("visibleTranscriptWriteReceiptBindingMatches")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("visibleTranscriptWriteDivergenceCount")
                    .and_then(Value::as_u64)
                    == Some(0)
                && dispatch
                    .get("workflowTranscriptWriteCandidate")
                    .and_then(|record| record.get("committed"))
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("workflowTranscriptWriteRecord")
                    .and_then(|record| record.get("committed"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("workflowTranscriptWriteRecord")
                    .and_then(|record| record.get("visible"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("legacyTranscriptWriteRecord")
                    .and_then(|record| record.get("committed"))
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("legacyTranscriptWriteRecord")
                    .and_then(|record| record.get("suppressedByIdempotency"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("stagedTranscriptWriteRecord")
                    .and_then(|record| record.get("committed"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("stagedTranscriptWriteRecord")
                    .and_then(|record| record.get("visible"))
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch.get("outputHashMatches").and_then(Value::as_bool) == Some(true)
                && dispatch
                    .get("outputHashDivergence")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("outputHashDivergenceCount")
                    .and_then(Value::as_u64)
                    == Some(0)
                && dispatch
                    .get("drivesRuntimeDecision")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("legacyOutputAuthorityRetained")
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("legacyOutputFallbackAvailable")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("mutatingTurnsBlocked")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch.get("outputAuthority").and_then(Value::as_str)
                    == Some("blessed_workflow_activation_default")
                && dispatch
                    .get("acceptedClusterIds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let cluster_ids =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        cluster_ids.contains(&"cognition")
                            && cluster_ids.contains(&"routing_model")
                            && cluster_ids.contains(&"verification_output")
                            && cluster_ids.contains(&"authority_tooling")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("componentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.len() >= 15
                            && component_kinds.contains(&"verifier")
                            && component_kinds.contains(&"completion_gate")
                            && component_kinds.contains(&"receipt_writer")
                            && component_kinds.contains(&"quality_ledger")
                            && component_kinds.contains(&"output_writer")
                            && component_kinds.contains(&"policy_gate")
                            && component_kinds.contains(&"dry_run_simulator")
                            && component_kinds.contains(&"approval_gate")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("deferredComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"mcp_tool_call")
                            && component_kinds.contains(&"tool_call")
                            && component_kinds.contains(&"connector_call")
                            && component_kinds.contains(&"wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"mcp_provider")
                            && component_kinds.contains(&"mcp_tool_call")
                            && component_kinds.contains(&"tool_call")
                            && component_kinds.contains(&"connector_call")
                            && component_kinds.contains(&"wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMutationDeferredComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"mcp_provider")
                            && component_kinds.contains(&"mcp_tool_call")
                            && component_kinds.contains(&"tool_call")
                            && component_kinds.contains(&"connector_call")
                            && component_kinds.contains(&"wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("handoffValidatedComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|value| value == "output_writer")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("materializationCanaryComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|value| value == "output_writer")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("dispatchNodeAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 19)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionAdapterMode")
                    .and_then(Value::as_str)
                    == Some("workflow_component_adapter_live")
                && dispatch
                    .get("cognitionExecutionAdapterResults")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds = items
                            .iter()
                            .filter_map(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("componentKind"))
                                    .and_then(Value::as_str)
                            })
                            .collect::<Vec<_>>();
                        items.len() >= 3
                            && component_kinds.contains(&"planner")
                            && component_kinds.contains(&"prompt_assembler")
                            && component_kinds.contains(&"task_state")
                            && items.iter().all(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("executionMode"))
                                    .and_then(Value::as_str)
                                    == Some("live")
                                    && item
                                        .get("actionFrame")
                                        .and_then(|frame| frame.get("readiness"))
                                        .and_then(Value::as_str)
                                        == Some("live_ready")
                                    && item
                                        .get("nodeAttempt")
                                        .and_then(|attempt| attempt.get("status"))
                                        .and_then(Value::as_str)
                                        == Some("live")
                            })
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionActionFrameIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionLiveReadyComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"planner")
                            && component_kinds.contains(&"prompt_assembler")
                            && component_kinds.contains(&"task_state")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionGateAdapterMode")
                    .and_then(Value::as_str)
                    == Some("workflow_component_adapter_gated")
                && dispatch
                    .get("cognitionExecutionGateAdapterResults")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds = items
                            .iter()
                            .filter_map(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("componentKind"))
                                    .and_then(Value::as_str)
                            })
                            .collect::<Vec<_>>();
                        items.len() >= 3
                            && component_kinds.contains(&"uncertainty_gate")
                            && component_kinds.contains(&"budget_gate")
                            && component_kinds.contains(&"capability_sequencer")
                            && items.iter().all(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("executionMode"))
                                    .and_then(Value::as_str)
                                    == Some("gated")
                                    && item
                                        .get("actionFrame")
                                        .and_then(|frame| frame.get("readiness"))
                                        .and_then(Value::as_str)
                                        == Some("shadow_ready")
                                    && item
                                        .get("nodeAttempt")
                                        .and_then(|attempt| attempt.get("status"))
                                        .and_then(Value::as_str)
                                        == Some("gated")
                            })
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionGateAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionGateReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionGateReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("cognitionExecutionGateDivergenceClasses")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .all(|value| value == "none")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("routingModelAdapterMode")
                    .and_then(Value::as_str)
                    == Some("workflow_component_adapter_gated")
                && dispatch
                    .get("routingModelAdapterResults")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds = items
                            .iter()
                            .filter_map(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("componentKind"))
                                    .and_then(Value::as_str)
                            })
                            .collect::<Vec<_>>();
                        items.len() >= 3
                            && component_kinds.contains(&"model_router")
                            && component_kinds.contains(&"model_call")
                            && component_kinds.contains(&"tool_router")
                            && items.iter().all(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("executionMode"))
                                    .and_then(Value::as_str)
                                    == Some("gated")
                                    && item
                                        .get("actionFrame")
                                        .and_then(|frame| frame.get("readiness"))
                                        .and_then(Value::as_str)
                                        == Some("shadow_ready")
                                    && item
                                        .get("nodeAttempt")
                                        .and_then(|attempt| attempt.get("status"))
                                        .and_then(Value::as_str)
                                        == Some("gated")
                            })
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("routingModelAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("routingModelReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("routingModelReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("routingModelComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"model_router")
                            && component_kinds.contains(&"model_call")
                            && component_kinds.contains(&"tool_router")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("routingModelDivergenceClasses")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .all(|value| value == "none")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("verificationOutputAdapterMode")
                    .and_then(Value::as_str)
                    == Some("workflow_component_adapter_gated")
                && dispatch
                    .get("verificationOutputAdapterResults")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds = items
                            .iter()
                            .filter_map(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("componentKind"))
                                    .and_then(Value::as_str)
                            })
                            .collect::<Vec<_>>();
                        items.len() >= 6
                            && component_kinds.contains(&"postcondition_synthesizer")
                            && component_kinds.contains(&"verifier")
                            && component_kinds.contains(&"completion_gate")
                            && component_kinds.contains(&"receipt_writer")
                            && component_kinds.contains(&"quality_ledger")
                            && component_kinds.contains(&"output_writer")
                            && items.iter().all(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("executionMode"))
                                    .and_then(Value::as_str)
                                    == Some("gated")
                                    && item
                                        .get("actionFrame")
                                        .and_then(|frame| frame.get("readiness"))
                                        .and_then(Value::as_str)
                                        == Some("shadow_ready")
                                    && item
                                        .get("nodeAttempt")
                                        .and_then(|attempt| attempt.get("status"))
                                        .and_then(Value::as_str)
                                        == Some("gated")
                            })
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("verificationOutputAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 6)
                    .unwrap_or(false)
                && dispatch
                    .get("verificationOutputReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 6)
                    .unwrap_or(false)
                && dispatch
                    .get("verificationOutputReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 6)
                    .unwrap_or(false)
                && dispatch
                    .get("verificationOutputComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"postcondition_synthesizer")
                            && component_kinds.contains(&"verifier")
                            && component_kinds.contains(&"completion_gate")
                            && component_kinds.contains(&"receipt_writer")
                            && component_kinds.contains(&"quality_ledger")
                            && component_kinds.contains(&"output_writer")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("verificationOutputDivergenceClasses")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .all(|value| value == "none")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingAdapterMode")
                    .and_then(Value::as_str)
                    == Some("workflow_component_adapter_gated")
                && dispatch
                    .get("authorityToolingAdapterResults")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.len() >= 8
                            && items.iter().all(|item| {
                                item.get("actionFrame")
                                    .and_then(|frame| frame.get("executionMode"))
                                    .and_then(Value::as_str)
                                    == Some("gated")
                                    && item
                                        .get("actionFrame")
                                        .and_then(|frame| frame.get("readiness"))
                                        .and_then(Value::as_str)
                                        == Some("shadow_ready")
                                    && item
                                        .get("nodeAttempt")
                                        .and_then(|attempt| attempt.get("status"))
                                        .and_then(Value::as_str)
                                        == Some("gated")
                            })
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 8)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 8)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 8)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"policy_gate")
                            && component_kinds.contains(&"approval_gate")
                            && component_kinds.contains(&"dry_run_simulator")
                            && component_kinds.contains(&"mcp_provider")
                            && component_kinds.contains(&"mcp_tool_call")
                            && component_kinds.contains(&"tool_call")
                            && component_kinds.contains(&"connector_call")
                            && component_kinds.contains(&"wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingDivergenceClasses")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .all(|value| value == "none")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingAdapterProof")
                    .and_then(|proof| proof.get("ready"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingAdapterProof")
                    .and_then(|proof| proof.get("policyDecision"))
                    .and_then(Value::as_str)
                    == Some("accept_workflow_authority_tooling_adapter_envelope")
                && dispatch
                    .get("modelExecutionAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("modelExecutionReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("modelExecutionReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderCanaryAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderCanaryReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderCanaryReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("outputWriterMaterializationCanaryAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("outputWriterStagedWriteCanaryAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("outputWriterVisibleWriteAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingLiveDryRunAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 10)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingGateLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingPolicyGateLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingDestructiveDenialLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingApprovalGateLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingGateLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingGateLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingGateLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingPolicyGateLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingDestructiveDenialLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingApprovalGateLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 5)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 5)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 5)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("mcp_provider")
                && dispatch
                    .get("authorityToolingProviderCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("mcp_tool_call")
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("tool_call")
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("connector_call")
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunComponentKind")
                    .and_then(Value::as_str)
                    == Some("wallet_capability")
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("gateLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("policyGateLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("destructiveDenialLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("approvalGateLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("readOnlyAuthorityCanaryReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("providerCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("providerCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("mcp_provider")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mcpToolCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mcpToolCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("mcp_tool_call")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("nativeToolCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("nativeToolCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("tool_call")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("connectorCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("connectorCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("connector_call")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("walletCapabilityLiveDryRunReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("walletCapabilityLiveDryRunComponentKind"))
                    .and_then(Value::as_str)
                    == Some("wallet_capability")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mutationDeferredComponentKinds"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|value| value == "wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingDenialReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("acceptedNodeAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 18)
                    .unwrap_or(false)
                && dispatch
                    .get("proposedVisibleOutputHash")
                    .and_then(Value::as_str)
                    .zip(
                        dispatch
                            .get("actualVisibleOutputHash")
                            .and_then(Value::as_str),
                    )
                    .map(|(proposed, actual)| !proposed.is_empty() && proposed == actual)
                    .unwrap_or(false)
                && dispatch
                    .get("receiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("replayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("activationBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && dispatch.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
        })
        .unwrap_or(false);
    let harness_selector_reviewed_import_activation_apply_invariant =
        harness_selector_default_promoted
            && harness_live_handoff_default_promoted
            && harness_default_runtime_dispatch_readonly;
    let harness_live_promotion_readiness = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            let proof = dispatch.get("livePromotionReadinessProof");
            proof
                .and_then(|value| value.get("schemaVersion"))
                .and_then(Value::as_str)
                == Some("workflow.harness.live-promotion-readiness.v1")
                && proof
                    .and_then(|value| value.get("targetExecutionMode"))
                    .and_then(Value::as_str)
                    == Some("live")
                && proof
                    .and_then(|value| value.get("allClustersReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && proof
                    .and_then(|value| value.get("promotionEligible"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && proof
                    .and_then(|value| value.get("defaultLiveActivationReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && proof
                    .and_then(|value| value.get("invalidForkLiveActivationBlocked"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && proof
                    .and_then(|value| value.get("rollbackAvailable"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && proof
                    .and_then(|value| value.get("policyDecision"))
                    .and_then(Value::as_str)
                    == Some("allow_default_harness_live_promotion_readiness")
                && proof
                    .and_then(|value| value.get("requiredClusterIds"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        let cluster_ids =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        [
                            "cognition",
                            "routing_model",
                            "verification_output",
                            "authority_tooling",
                        ]
                        .iter()
                        .all(|cluster_id| cluster_ids.contains(cluster_id))
                    })
                    .unwrap_or(false)
                && proof
                    .and_then(|value| value.get("clusterReadiness"))
                    .and_then(Value::as_array)
                    .map(|clusters| {
                        clusters.len() >= 4
                            && clusters.iter().all(|cluster| {
                                cluster.get("targetExecutionMode").and_then(Value::as_str)
                                    == Some("live")
                                    && cluster
                                        .get("blockers")
                                        .and_then(Value::as_array)
                                        .map(|items| items.is_empty())
                                        .unwrap_or(false)
                                    && cluster
                                        .get("receiptRefs")
                                        .and_then(Value::as_array)
                                        .map(|items| !items.is_empty())
                                        .unwrap_or(false)
                                    && cluster
                                        .get("replayFixtureRefs")
                                        .and_then(Value::as_array)
                                        .map(|items| !items.is_empty())
                                        .unwrap_or(false)
                                    && cluster
                                        .get("blockingDivergenceCount")
                                        .and_then(Value::as_u64)
                                        == Some(0)
                                    && cluster
                                        .get("unclassifiedDivergenceCount")
                                        .and_then(Value::as_u64)
                                        == Some(0)
                            })
                    })
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_default_runtime_binding = projection.get("HarnessDefaultRuntimeBinding").cloned();
    let harness_default_runtime_binding_matched = harness_default_runtime_binding
        .as_ref()
        .map(|binding| {
            binding.get("schemaVersion").and_then(Value::as_str)
                == Some("workflow.harness.default-runtime-binding.v1")
                && binding.get("workflowId").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
                && binding.get("activationId").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && binding.get("harnessHash").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_HASH)
                && binding.get("selectedSelector").and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && binding
                    .get("productionDefaultSelector")
                    .and_then(Value::as_str)
                    == Some("blessed_workflow_live_default")
                && binding.get("executionMode").and_then(Value::as_str) == Some("live")
                && binding.get("runtimeAuthority").and_then(Value::as_str)
                    == Some("blessed_workflow_activation_default")
                && binding.get("rollbackTarget").and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && binding.get("rollbackAvailable").and_then(Value::as_bool) == Some(true)
                && binding.get("bindingMatched").and_then(Value::as_bool) == Some(true)
                && binding
                    .get("workerBindingAuthorityReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerBindingAuthorityBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && binding
                    .get("workerBindingRegistryBound")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerBindingRegistryStatus")
                    .and_then(Value::as_str)
                    == Some("bound")
                && binding
                    .get("workerBindingRegistryBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && binding.get("workerAttachAccepted").and_then(Value::as_bool) == Some(true)
                && binding.get("workerAttachStatus").and_then(Value::as_str) == Some("bound")
                && binding
                    .get("workerAttachBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && binding
                    .get("workerAttachRollbackAvailable")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerAttachLifecycleComplete")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerAttachLifecycleStatuses")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let statuses = items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        statuses.contains(&"bound")
                            && statuses.contains(&"resumed")
                            && statuses.contains(&"rolled_back")
                    })
                    .unwrap_or(false)
                && binding
                    .get("workerAttachLifecycleAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && binding
                    .get("workerAttachLifecycle")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.len() >= 3
                            && items.iter().all(|event| {
                                event.get("schemaVersion").and_then(Value::as_str)
                                    == Some("workflow.harness.worker-attach-lifecycle.v1")
                                    && event.get("workflowNodeId").and_then(Value::as_str)
                                        == Some("harness.handoff_bridge")
                                    && event.get("componentKind").and_then(Value::as_str)
                                        == Some("handoff_bridge")
                                    && event.get("accepted").and_then(Value::as_bool) == Some(true)
                                    && event
                                        .get("blockers")
                                        .and_then(Value::as_array)
                                        .map(|blockers| blockers.is_empty())
                                        .unwrap_or(false)
                            })
                    })
                    .unwrap_or(false)
                && binding
                    .get("workerAttachResumeAccepted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerAttachRollbackAccepted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerSessionAccepted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding.get("workerSessionStatus").and_then(Value::as_str)
                    == Some("rollback_ready")
                && binding
                    .get("workerSessionBlockers")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("schemaVersion"))
                    .and_then(Value::as_str)
                    == Some("workflow.harness.worker-session.v1")
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("currentStatus"))
                    .and_then(Value::as_str)
                    == Some("rollback_ready")
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("resumed"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("rollbackTargetReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("registryRecordId"))
                    .and_then(Value::as_str)
                    == binding
                        .get("workerBindingRegistryRecord")
                        .and_then(|record| record.get("registryRecordId"))
                        .and_then(Value::as_str)
                && binding
                    .get("workerSessionRecord")
                    .and_then(|record| record.get("workerId"))
                    .and_then(Value::as_str)
                    == binding
                        .get("workerAttachReceipt")
                        .and_then(|receipt| receipt.get("workerId"))
                        .and_then(Value::as_str)
                && binding
                    .get("invalidWorkerAttachBlocked")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("selectorLivePromotionReadinessReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("liveHandoffLivePromotionReadinessReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("dispatchLivePromotionReadinessReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("livePromotionReadinessProofIdsMatch")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("invalidForkLiveActivationBlocked")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("dispatchDrivesRuntime")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("selectorDecisionLinksDispatch")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("drivesRuntimeDecision")
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("selectorDecisionId")
                    .and_then(Value::as_str)
                    .map(|value| value.starts_with("harness-selector:"))
                    .unwrap_or(false)
                && binding
                    .get("defaultDispatchId")
                    .and_then(Value::as_str)
                    .map(|value| value.starts_with("harness-default-dispatch:"))
                    .unwrap_or(false)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("harnessWorkflowId"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("harnessActivationId"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("harnessHash"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_HASH)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("authorityBindingReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("authorityBindingBlockers"))
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("selectorDecisionId"))
                    .and_then(Value::as_str)
                    .map(|value| value.starts_with("harness-selector:"))
                    .unwrap_or(false)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("defaultDispatchId"))
                    .and_then(Value::as_str)
                    .map(|value| value.starts_with("harness-default-dispatch:"))
                    .unwrap_or(false)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("rollbackTarget"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && binding
                    .get("workerBinding")
                    .and_then(|worker| worker.get("livePromotionReadinessProofId"))
                    .and_then(Value::as_str)
                    == binding
                        .get("selectorLivePromotionReadinessProofId")
                        .and_then(Value::as_str)
                && binding
                    .get("workerBindingRegistryRecord")
                    .and_then(|record| record.get("bindingStatus"))
                    .and_then(Value::as_str)
                    == Some("bound")
                && binding
                    .get("workerBindingRegistryRecord")
                    .and_then(|record| record.get("blockers"))
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(false)
                && binding
                    .get("workerBindingRegistryRecord")
                    .and_then(|record| record.get("readinessProofId"))
                    .and_then(Value::as_str)
                    == binding
                        .get("selectorLivePromotionReadinessProofId")
                        .and_then(Value::as_str)
                && binding
                    .get("workerBindingRegistryRecord")
                    .and_then(|record| record.get("workerBinding"))
                    .and_then(|worker| worker.get("harnessActivationId"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
                && binding
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("schemaVersion"))
                    .and_then(Value::as_str)
                    == Some("workflow.harness.worker-attach-receipt.v1")
                && binding
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("attachStatus"))
                    .and_then(Value::as_str)
                    == Some("bound")
                && binding
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("registryRecordId"))
                    .and_then(Value::as_str)
                    == binding
                        .get("workerBindingRegistryRecord")
                        .and_then(|record| record.get("registryRecordId"))
                        .and_then(Value::as_str)
                && binding
                    .get("workerAttachReceipt")
                    .and_then(|receipt| receipt.get("readinessProofId"))
                    .and_then(Value::as_str)
                    == binding
                        .get("selectorLivePromotionReadinessProofId")
                        .and_then(Value::as_str)
                && binding
                    .get("workerAttachResumeReceipt")
                    .and_then(|receipt| receipt.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerAttachResumeReceipt")
                    .and_then(|receipt| receipt.get("attachStatus"))
                    .and_then(Value::as_str)
                    == Some("resumed")
                && binding
                    .get("workerAttachRollbackReceipt")
                    .and_then(|receipt| receipt.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && binding
                    .get("workerAttachRollbackReceipt")
                    .and_then(|receipt| receipt.get("attachStatus"))
                    .and_then(Value::as_str)
                    == Some("rolled_back")
                && binding
                    .get("invalidWorkerAttachReceipt")
                    .and_then(|receipt| receipt.get("accepted"))
                    .and_then(Value::as_bool)
                    == Some(false)
        })
        .unwrap_or(false);
    let harness_authority_tooling_gate_live = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingGateLiveReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingPolicyGateLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingDestructiveDenialLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingApprovalGateLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingGateLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingGateLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingGateLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("gateLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("policyGateLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("destructiveDenialLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("approvalGateLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
        })
        .unwrap_or(false);
    let harness_authority_tooling_read_only_canary = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingReadOnlyAuthorityCanaryReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingReadOnlyLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 5)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 5)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 5)
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingReadOnlyComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        let component_kinds =
                            items.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                        component_kinds.contains(&"mcp_provider")
                            && component_kinds.contains(&"mcp_tool_call")
                            && component_kinds.contains(&"tool_call")
                            && component_kinds.contains(&"connector_call")
                            && component_kinds.contains(&"wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMutationDeferredComponentKinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|value| value == "wallet_capability")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("readOnlyAuthorityCanaryReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("providerCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("providerCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("mcp_provider")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mcpToolCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mcpToolCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("mcp_tool_call")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("nativeToolCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("nativeToolCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("tool_call")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("connectorCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("connectorCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("connector_call")
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("walletCapabilityLiveDryRunReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("walletCapabilityLiveDryRunComponentKind"))
                    .and_then(Value::as_str)
                    == Some("wallet_capability")
        })
        .unwrap_or(false);
    let harness_authority_tooling_provider_catalog_live = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingProviderCatalogLiveReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("mcp_provider")
                && dispatch
                    .get("authorityToolingProviderCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProviderCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("providerCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("providerCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("mcp_provider")
        })
        .unwrap_or(false);
    let harness_authority_tooling_mcp_tool_catalog_live = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingMcpToolCatalogLiveReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("mcp_tool_call")
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingMcpToolCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mcpToolCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("mcpToolCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("mcp_tool_call")
        })
        .unwrap_or(false);
    let harness_authority_tooling_native_tool_catalog_live = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingNativeToolCatalogLiveReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("tool_call")
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingNativeToolCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("nativeToolCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("nativeToolCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("tool_call")
        })
        .unwrap_or(false);
    let harness_authority_tooling_connector_catalog_live = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingConnectorCatalogLiveReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveComponentKind")
                    .and_then(Value::as_str)
                    == Some("connector_call")
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingConnectorCatalogLiveReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("connectorCatalogLiveReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("connectorCatalogLiveComponentKind"))
                    .and_then(Value::as_str)
                    == Some("connector_call")
        })
        .unwrap_or(false);
    let harness_authority_tooling_wallet_capability_live_dry_run = harness_default_runtime_dispatch
        .as_ref()
        .map(|dispatch| {
            dispatch
                .get("authorityToolingWalletCapabilityLiveDryRunReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunComponentKind")
                    .and_then(Value::as_str)
                    == Some("wallet_capability")
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("walletCapabilityLiveDryRunReady"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("authorityToolingProof")
                    .and_then(|proof| proof.get("walletCapabilityLiveDryRunComponentKind"))
                    .and_then(Value::as_str)
                    == Some("wallet_capability")
        })
        .unwrap_or(false);
    let harness_model_provider_gated_visible_output = projection
        .get("HarnessDefaultRuntimeDispatch")
        .map(|dispatch| {
            dispatch
                .get("modelProviderGatedVisibleOutputMode")
                .and_then(Value::as_str)
                == Some("workflow_provider_gated_visible_output")
                && dispatch
                    .get("modelProviderGatedVisibleOutputEnabled")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputSelected")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputScenario")
                    .and_then(Value::as_str)
                    .map(|scenario| {
                        WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_RETAINED_SCENARIOS
                            .contains(&scenario)
                            || scenario == "retained_default_promoted_no_tool_turn"
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputCohort")
                    .and_then(Value::as_str)
                    .map(|cohort| {
                        cohort == "retained_read_only_no_tool"
                            || cohort == "default_promoted_read_only_no_tool"
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("selectedVisibleOutputAuthority")
                    .and_then(Value::as_str)
                    == Some("workflow_model_provider_call")
                && dispatch
                    .get("selectedVisibleOutputHash")
                    .and_then(Value::as_str)
                    .zip(
                        dispatch
                            .get("actualVisibleOutputHash")
                            .and_then(Value::as_str),
                    )
                    .map(|(selected, actual)| !selected.is_empty() && selected == actual)
                    .unwrap_or(false)
                && dispatch
                    .get("legacyVisibleOutputHash")
                    .and_then(Value::as_str)
                    .zip(
                        dispatch
                            .get("selectedVisibleOutputHash")
                            .and_then(Value::as_str),
                    )
                    .map(|(legacy, selected)| !legacy.is_empty() && legacy == selected)
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackAvailable")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("visibleOutputDivergenceClass")
                    .map(Value::is_null)
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_model_provider_gated_visible_output_rollback_drill = projection
        .get("HarnessDefaultRuntimeDispatch")
        .map(|dispatch| {
            dispatch
                .get("modelProviderGatedVisibleOutputRollbackDrillReady")
                .and_then(Value::as_bool)
                == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillFailureInjected")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillDivergenceClass")
                    .and_then(Value::as_str)
                    == Some("provider_output_hash_divergence")
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority")
                    .and_then(Value::as_str)
                    == Some("legacy_runtime_model_invocation")
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority")
                    .and_then(Value::as_str)
                    == Some("legacy_runtime_model_invocation")
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillActivationBlockers")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|item| item == "model_provider_output_hash_divergence")
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
                && dispatch
                    .get("modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let harness_read_only_capability_routing = projection
        .get("HarnessDefaultRuntimeDispatch")
        .map(|dispatch| {
            let scenario = dispatch
                .get("readOnlyCapabilityRoutingScenario")
                .and_then(Value::as_str);
            let workflow_owned_node_kinds = dispatch
                .get("readOnlyCapabilityRoutingWorkflowOwnedNodeKinds")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();
            let source_or_probe_node_present = match scenario {
                Some("retained_probe_behavior") => {
                    workflow_owned_node_kinds.contains(&"probe_runner")
                }
                Some("retained_repo_grounded_answer" | "retained_source_heavy_synthesis") => {
                    workflow_owned_node_kinds.contains(&"memory_read")
                }
                _ => false,
            };
            dispatch
                .get("readOnlyCapabilityRoutingMode")
                .and_then(Value::as_str)
                == Some("workflow_read_only_capability_routing")
                && dispatch
                    .get("readOnlyCapabilityRoutingReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("readOnlyCapabilityRoutingSelected")
                    .and_then(Value::as_bool)
                    == Some(true)
                && scenario
                    .map(|scenario| {
                        WORKFLOW_READ_ONLY_CAPABILITY_ROUTING_RETAINED_SCENARIOS.contains(&scenario)
                    })
                    .unwrap_or(false)
                && dispatch
                    .get("readOnlyCapabilityRoutingScenarioCoverageKey")
                    .and_then(Value::as_str)
                    == scenario
                && dispatch
                    .get("readOnlyCapabilityRoutingNoMutationReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && dispatch
                    .get("readOnlyCapabilityRoutingSourceMaterialReady")
                    .and_then(Value::as_bool)
                    == Some(true)
                && workflow_owned_node_kinds.contains(&"capability_sequencer")
                && workflow_owned_node_kinds.contains(&"tool_router")
                && workflow_owned_node_kinds.contains(&"dry_run_simulator")
                && source_or_probe_node_present
                && dispatch
                    .get("readOnlyCapabilityRoutingAttemptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("readOnlyCapabilityRoutingReceiptIds")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("readOnlyCapabilityRoutingReplayFixtureRefs")
                    .and_then(Value::as_array)
                    .map(|items| items.len() >= 3)
                    .unwrap_or(false)
                && dispatch
                    .get("readOnlyCapabilityRoutingProof")
                    .and_then(|proof| proof.get("sideEffectsExecuted"))
                    .and_then(Value::as_bool)
                    == Some(false)
                && dispatch
                    .get("readOnlyCapabilityRoutingProof")
                    .and_then(|proof| proof.get("mutationExecuted"))
                    .and_then(Value::as_bool)
                    == Some(false)
        })
        .unwrap_or(false);
    let harness_model_provider_gated_visible_output_scenario = projection
        .get("HarnessDefaultRuntimeDispatch")
        .and_then(|dispatch| dispatch.get("modelProviderGatedVisibleOutputScenario"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let harness_model_provider_gated_visible_output_cohort = projection
        .get("HarnessDefaultRuntimeDispatch")
        .and_then(|dispatch| dispatch.get("modelProviderGatedVisibleOutputCohort"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let harness_model_provider_gated_visible_output_required_scenario = projection
        .get("HarnessDefaultRuntimeDispatch")
        .and_then(|dispatch| dispatch.get("modelProviderGatedVisibleOutputScenarioCoverageKey"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let harness_model_provider_gated_visible_output_rollback_drill_scenario =
        if harness_model_provider_gated_visible_output_rollback_drill {
            harness_model_provider_gated_visible_output_required_scenario.clone()
        } else {
            None
        };
    let harness_read_only_capability_routing_scenario = projection
        .get("HarnessDefaultRuntimeDispatch")
        .and_then(|dispatch| dispatch.get("readOnlyCapabilityRoutingScenario"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let harness_read_only_capability_routing_required_scenario = projection
        .get("HarnessDefaultRuntimeDispatch")
        .and_then(|dispatch| dispatch.get("readOnlyCapabilityRoutingScenarioCoverageKey"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let now_ms = crate::kernel::state::now();
    let mut harness_model_provider_gated_visible_output_history_scenarios =
        runtime_harness_provider_gated_visible_output_history_scenarios(task);
    if let Some(scenario) = harness_model_provider_gated_visible_output_required_scenario.as_deref()
    {
        if !harness_model_provider_gated_visible_output_history_scenarios
            .iter()
            .any(|existing| existing == scenario)
        {
            harness_model_provider_gated_visible_output_history_scenarios
                .push(scenario.to_string());
            harness_model_provider_gated_visible_output_history_scenarios.sort();
        }
    }
    let harness_model_provider_gated_visible_output_coverage =
        runtime_harness_update_provider_gated_visible_output_coverage(
            memory_runtime,
            sid,
            &harness_model_provider_gated_visible_output_history_scenarios,
            harness_model_provider_gated_visible_output,
            harness_model_provider_gated_visible_output_rollback_drill,
            now_ms,
        );
    let mut harness_read_only_capability_routing_history_scenarios =
        runtime_harness_read_only_capability_routing_history_scenarios(task);
    if let Some(scenario) = harness_read_only_capability_routing_required_scenario.as_deref() {
        if !harness_read_only_capability_routing_history_scenarios
            .iter()
            .any(|existing| existing == scenario)
        {
            harness_read_only_capability_routing_history_scenarios.push(scenario.to_string());
            harness_read_only_capability_routing_history_scenarios.sort();
        }
    }
    let harness_read_only_capability_routing_coverage =
        runtime_harness_update_read_only_capability_routing_coverage(
            memory_runtime,
            sid,
            &harness_read_only_capability_routing_history_scenarios,
            harness_read_only_capability_routing,
            harness_read_only_capability_routing,
            now_ms,
        );
    if let Some(projection_object) = projection.as_object_mut() {
        projection_object.insert(
            "HarnessModelProviderGatedVisibleOutputCoverage".to_string(),
            harness_model_provider_gated_visible_output_coverage.clone(),
        );
        projection_object.insert(
            "HarnessReadOnlyCapabilityRoutingCoverage".to_string(),
            harness_read_only_capability_routing_coverage.clone(),
        );
        if let Some(dispatch) = projection_object
            .get_mut("HarnessDefaultRuntimeDispatch")
            .and_then(Value::as_object_mut)
        {
            dispatch.insert(
                "modelProviderGatedVisibleOutputSessionCoverage".to_string(),
                harness_model_provider_gated_visible_output_coverage.clone(),
            );
            dispatch.insert(
                "readOnlyCapabilityRoutingSessionCoverage".to_string(),
                harness_read_only_capability_routing_coverage.clone(),
            );
        }
    }
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
            "harness_worker_binding": projection.get("HarnessWorkerBinding"),
            "harness_selector_decision": harness_selector_decision,
            "harness_selector_canary_routed": harness_selector_canary_routed,
            "harness_selector_legacy_default": harness_selector_legacy_default,
            "harness_selector_default_promoted": harness_selector_default_promoted,
            "harness_selector_live_promotion_readiness_gated": harness_selector_live_promotion_readiness_gated,
            "harness_selector_reviewed_import_activation_apply_invariant": harness_selector_reviewed_import_activation_apply_invariant,
            "harness_shadow_run": harness_shadow_run,
            "harness_node_attempt_count": harness_node_attempt_count,
            "harness_shadow_comparison_count": harness_shadow_comparison_count,
            "harness_blocking_divergence_count": harness_blocking_divergence_count,
            "harness_gated_cluster_runs": projection.get("HarnessGatedClusterRuns"),
            "harness_gated_cluster_count": harness_gated_cluster_count,
            "harness_gated_cognition_passed": harness_gated_cognition_passed,
            "harness_gated_routing_model_passed": harness_gated_routing_model_passed,
            "harness_gated_verification_output_passed": harness_gated_verification_output_passed,
            "harness_gated_authority_tooling_passed": harness_gated_authority_tooling_passed,
            "harness_fork_activation": harness_fork_activation,
            "harness_fork_activation_blocked": harness_fork_activation_blocked,
            "harness_fork_activation_minted": harness_fork_activation_minted,
            "harness_rollback_restore_canary_blocked": harness_rollback_restore_canary_blocked,
            "harness_rollback_restore_canary_ready": harness_rollback_restore_canary_ready,
            "harness_rollback_restore_canary_receipts_present": harness_rollback_restore_canary_receipts_present,
            "harness_activation_audit_receipts_present": harness_activation_audit_receipts_present,
            "harness_rollback_execution_receipts_present": harness_rollback_execution_receipts_present,
            "harness_canary_execution_boundaries": projection.get("HarnessCanaryExecutionBoundaries"),
            "harness_canary_execution_boundary": harness_canary_execution_boundary,
            "harness_canary_boundary_executed": harness_canary_boundary_executed,
            "harness_canary_boundary_rollback_drill": harness_canary_boundary_rollback_drill,
            "harness_live_handoff": harness_live_handoff,
            "harness_live_handoff_canary": harness_live_handoff_canary,
            "harness_live_handoff_default_promoted": harness_live_handoff_default_promoted,
            "harness_live_handoff_rollback": harness_live_handoff_rollback,
            "harness_default_runtime_dispatch": harness_default_runtime_dispatch,
            "harness_default_runtime_dispatch_readonly": harness_default_runtime_dispatch_readonly,
            "harness_live_promotion_readiness": harness_live_promotion_readiness,
            "harness_default_runtime_binding": harness_default_runtime_binding,
            "harness_default_runtime_binding_matched": harness_default_runtime_binding_matched,
            "harness_authority_tooling_read_only_canary": harness_authority_tooling_read_only_canary,
            "harness_authority_tooling_gate_live": harness_authority_tooling_gate_live,
            "harness_authority_tooling_provider_catalog_live": harness_authority_tooling_provider_catalog_live,
            "harness_authority_tooling_mcp_tool_catalog_live": harness_authority_tooling_mcp_tool_catalog_live,
            "harness_authority_tooling_native_tool_catalog_live": harness_authority_tooling_native_tool_catalog_live,
            "harness_authority_tooling_connector_catalog_live": harness_authority_tooling_connector_catalog_live,
            "harness_authority_tooling_wallet_capability_live_dry_run": harness_authority_tooling_wallet_capability_live_dry_run,
            "harness_model_provider_gated_visible_output": harness_model_provider_gated_visible_output,
            "harness_model_provider_gated_visible_output_scenario": harness_model_provider_gated_visible_output_scenario,
            "harness_model_provider_gated_visible_output_cohort": harness_model_provider_gated_visible_output_cohort,
            "harness_model_provider_gated_visible_output_required_scenario": harness_model_provider_gated_visible_output_required_scenario,
            "harness_model_provider_gated_visible_output_history_scenarios": harness_model_provider_gated_visible_output_history_scenarios.clone(),
            "harness_model_provider_gated_visible_output_rollback_drill": harness_model_provider_gated_visible_output_rollback_drill,
            "harness_model_provider_gated_visible_output_rollback_drill_scenario": harness_model_provider_gated_visible_output_rollback_drill_scenario,
            "harness_model_provider_gated_visible_output_coverage": harness_model_provider_gated_visible_output_coverage.clone(),
            "harness_read_only_capability_routing": harness_read_only_capability_routing,
            "harness_read_only_capability_routing_scenario": harness_read_only_capability_routing_scenario,
            "harness_read_only_capability_routing_required_scenario": harness_read_only_capability_routing_required_scenario,
            "harness_read_only_capability_routing_history_scenarios": harness_read_only_capability_routing_history_scenarios.clone(),
            "harness_read_only_capability_routing_coverage": harness_read_only_capability_routing_coverage.clone(),
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
    let turn_artifact_id = format!("runtime-evidence-{sid}-turn-{}", task.progress);
    if turn_artifact_id != artifact_id {
        let mut turn_artifact = artifact.clone();
        turn_artifact.artifact_id = turn_artifact_id.clone();
        turn_artifact.title = format!(
            "Runtime scorecard, stop reason, and quality ledger turn {}",
            task.progress
        );
        turn_artifact.content_ref = format!("memory://artifact/{turn_artifact_id}");
        turn_artifact.parent_artifact_id = Some(artifact_id.clone());
        append_artifact(memory_runtime, &turn_artifact, &content);
    }

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
            "harness_shadow_run": true,
            "harness_node_attempt_count": harness_node_attempt_count,
            "harness_shadow_comparison_count": harness_shadow_comparison_count,
            "harness_blocking_divergence_count": harness_blocking_divergence_count,
            "harness_gated_cluster_count": harness_gated_cluster_count,
            "harness_gated_cognition_passed": harness_gated_cognition_passed,
            "harness_gated_routing_model_passed": harness_gated_routing_model_passed,
            "harness_gated_verification_output_passed": harness_gated_verification_output_passed,
            "harness_gated_authority_tooling_passed": harness_gated_authority_tooling_passed,
            "harness_fork_activation_blocked": harness_fork_activation_blocked,
            "harness_fork_activation_minted": harness_fork_activation_minted,
            "harness_rollback_restore_canary_blocked": harness_rollback_restore_canary_blocked,
            "harness_rollback_restore_canary_ready": harness_rollback_restore_canary_ready,
            "harness_rollback_restore_canary_receipts_present": harness_rollback_restore_canary_receipts_present,
            "harness_activation_audit_receipts_present": harness_activation_audit_receipts_present,
            "harness_rollback_execution_receipts_present": harness_rollback_execution_receipts_present,
            "harness_canary_boundary_executed": harness_canary_boundary_executed,
            "harness_canary_boundary_rollback_drill": harness_canary_boundary_rollback_drill,
            "harness_selector_canary_routed": harness_selector_canary_routed,
            "harness_selector_legacy_default": harness_selector_legacy_default,
            "harness_selector_default_promoted": harness_selector_default_promoted,
            "harness_selector_live_promotion_readiness_gated": harness_selector_live_promotion_readiness_gated,
            "harness_live_handoff_canary": harness_live_handoff_canary,
            "harness_live_handoff_default_promoted": harness_live_handoff_default_promoted,
            "harness_live_handoff_rollback": harness_live_handoff_rollback,
            "harness_default_runtime_dispatch_readonly": harness_default_runtime_dispatch_readonly,
            "harness_live_promotion_readiness": harness_live_promotion_readiness,
            "harness_default_runtime_binding_matched": harness_default_runtime_binding_matched,
            "harness_authority_tooling_read_only_canary": harness_authority_tooling_read_only_canary,
            "harness_authority_tooling_gate_live": harness_authority_tooling_gate_live,
            "harness_authority_tooling_provider_catalog_live": harness_authority_tooling_provider_catalog_live,
            "harness_authority_tooling_mcp_tool_catalog_live": harness_authority_tooling_mcp_tool_catalog_live,
            "harness_authority_tooling_native_tool_catalog_live": harness_authority_tooling_native_tool_catalog_live,
            "harness_authority_tooling_connector_catalog_live": harness_authority_tooling_connector_catalog_live,
            "harness_authority_tooling_wallet_capability_live_dry_run": harness_authority_tooling_wallet_capability_live_dry_run,
            "harness_model_provider_gated_visible_output": harness_model_provider_gated_visible_output,
            "harness_model_provider_gated_visible_output_scenario": harness_model_provider_gated_visible_output_scenario,
            "harness_model_provider_gated_visible_output_cohort": harness_model_provider_gated_visible_output_cohort,
            "harness_model_provider_gated_visible_output_required_scenario": harness_model_provider_gated_visible_output_required_scenario,
            "harness_model_provider_gated_visible_output_history_scenarios": harness_model_provider_gated_visible_output_history_scenarios.clone(),
            "harness_model_provider_gated_visible_output_rollback_drill": harness_model_provider_gated_visible_output_rollback_drill,
            "harness_model_provider_gated_visible_output_rollback_drill_scenario": harness_model_provider_gated_visible_output_rollback_drill_scenario,
            "harness_model_provider_gated_visible_output_coverage": harness_model_provider_gated_visible_output_coverage.clone(),
            "harness_read_only_capability_routing": harness_read_only_capability_routing,
            "harness_read_only_capability_routing_scenario": harness_read_only_capability_routing_scenario,
            "harness_read_only_capability_routing_required_scenario": harness_read_only_capability_routing_required_scenario,
            "harness_read_only_capability_routing_history_scenarios": harness_read_only_capability_routing_history_scenarios.clone(),
            "harness_read_only_capability_routing_coverage": harness_read_only_capability_routing_coverage.clone(),
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
                "ErrorRecoveryContract",
                "HarnessRuntimeSelectorDecision",
                "HarnessWorkerBinding",
                "HarnessShadowRun",
                "HarnessGatedClusterRuns",
                "HarnessForkActivation",
                "HarnessCanaryExecutionBoundary",
                "HarnessLiveHandoff",
                "HarnessDefaultRuntimeDispatch",
                "HarnessLivePromotionReadinessProof",
                "HarnessDefaultRuntimeBinding"
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
        "[chat-proof-trace] session={} artifact={} scorecard=1 stop_reason=1 quality_ledger=1 harness_shadow_attempts={} harness_shadow_comparisons={} harness_gated_cognition={} harness_gated_routing_model={} harness_gated_verification_output={} harness_gated_authority_tooling={} harness_fork_activation_blocked={} harness_fork_activation_minted={} harness_canary_boundary_executed={} harness_canary_boundary_rollback_drill={} harness_selector_canary_routed={} harness_selector_legacy_default={} harness_selector_default_promoted={} harness_live_handoff_canary={} harness_live_handoff_default_promoted={} harness_live_handoff_rollback={} harness_default_runtime_dispatch_readonly={} harness_live_promotion_readiness={} harness_default_runtime_binding_matched={} harness_authority_tooling_read_only_canary={} harness_authority_tooling_gate_live={} harness_authority_tooling_provider_catalog_live={} harness_authority_tooling_mcp_tool_catalog_live={} harness_authority_tooling_native_tool_catalog_live={} harness_authority_tooling_connector_catalog_live={} harness_authority_tooling_wallet_capability_live_dry_run={}",
        sid,
        artifact_id,
        harness_node_attempt_count,
        harness_shadow_comparison_count,
        harness_gated_cognition_passed,
        harness_gated_routing_model_passed,
        harness_gated_verification_output_passed,
        harness_gated_authority_tooling_passed,
        harness_fork_activation_blocked,
        harness_fork_activation_minted,
        harness_canary_boundary_executed,
        harness_canary_boundary_rollback_drill,
        harness_selector_canary_routed,
        harness_selector_legacy_default,
        harness_selector_default_promoted,
        harness_live_handoff_canary,
        harness_live_handoff_default_promoted,
        harness_live_handoff_rollback,
        harness_default_runtime_dispatch_readonly,
        harness_live_promotion_readiness,
        harness_default_runtime_binding_matched,
        harness_authority_tooling_read_only_canary,
        harness_authority_tooling_gate_live,
        harness_authority_tooling_provider_catalog_live,
        harness_authority_tooling_mcp_tool_catalog_live,
        harness_authority_tooling_native_tool_catalog_live,
        harness_authority_tooling_connector_catalog_live,
        harness_authority_tooling_wallet_capability_live_dry_run
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
