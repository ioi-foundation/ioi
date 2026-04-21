use crate::identity;
use crate::kernel::state::get_rpc_client;
use crate::models::{
    AgentPhase, AppState, SessionCompactionCarryForwardState, SessionCompactionDisposition,
    SessionCompactionMemoryItem, SessionCompactionMode, SessionCompactionPolicy,
    SessionCompactionPreview, SessionCompactionPruneDecision, SessionCompactionRecommendation,
    SessionCompactionRecord, SessionCompactionResumeSafetyReceipt,
    SessionCompactionResumeSafetyStatus, SessionCompactionSnapshot, SessionDurabilityPortfolio,
    SessionMemoryClass, SessionProjection, SessionRewindCandidate, SessionRewindSnapshot,
    SessionSummary, TeamMemoryRedactionSummary, TeamMemoryScopeKind, TeamMemorySyncEntry,
    TeamMemorySyncSnapshot, TeamMemorySyncStatus,
};
use crate::orchestrator;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_pii::scrub_text;
use ioi_types::app::{
    account_id_from_key_material, ChainId, ChainTransaction, RedactionType, SignHeader,
    SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

const SESSION_HISTORY_RPC_TIMEOUT_MS: u64 = 1_500;
const SESSION_HISTORY_MONITOR_INTERVAL_MS: u64 = 2_000;
const AUTO_COMPACTION_HISTORY_THRESHOLD: usize = 24;
const AUTO_COMPACTION_EVENT_THRESHOLD: usize = 24;
const AUTO_COMPACTION_ARTIFACT_THRESHOLD: usize = 8;
const AUTO_COMPACTION_FILE_CONTEXT_THRESHOLD: usize = 4;
const AUTO_COMPACTION_IDLE_THRESHOLD_MS: u64 = 5 * 60 * 1000;
const AUTO_COMPACTION_BLOCKED_THRESHOLD_MS: u64 = 2 * 60 * 1000;
const TEAM_MEMORY_SYNC_REDACTION_VERSION: &str = "team_memory_sync.redaction.v1";
const TEAM_MEMORY_SYNC_MAX_ENTRIES: usize = 48;
const TEAM_MEMORY_SYNC_MAX_ITEM_VALUES: usize = 3;
const TEAM_MEMORY_SYNC_MAX_ITEM_VALUE_CHARS: usize = 96;

#[derive(Decode, Encode)]
struct RemoteSessionSummary {
    pub session_id: [u8; 32],
    pub title: String,
    pub timestamp: u64,
}

fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
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

fn enrich_local_session_summary(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    summary: SessionSummary,
) -> SessionSummary {
    let mut enriched = summary.clone();
    if enriched.workspace_root.is_none() {
        enriched.workspace_root = orchestrator::persisted_workspace_root_for_session(
            memory_runtime,
            Some(summary.session_id.as_str()),
        );
    }

    let Some(task) = orchestrator::load_local_task(memory_runtime, &summary.session_id) else {
        return enriched;
    };

    enriched = orchestrator::session_summary_from_task(&task, Some(&enriched));
    if enriched.workspace_root.is_none() {
        enriched.workspace_root = workspace_root_from_task(&task).or_else(|| {
            orchestrator::persisted_workspace_root_for_session(
                memory_runtime,
                Some(summary.session_id.as_str()),
            )
        });
    }
    enriched
}

fn local_session_history_snapshot(
    memory_runtime: Option<&Arc<ioi_memory::MemoryRuntime>>,
) -> Vec<SessionSummary> {
    memory_runtime
        .map(|memory_runtime| {
            orchestrator::get_local_sessions(memory_runtime)
                .into_iter()
                .map(|summary| enrich_local_session_summary(memory_runtime, summary))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) async fn fetch_remote_session_history(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    let mut client = get_rpc_client(state)
        .await
        .map_err(|error| format!("RPC client unavailable for history: {}", error))?;
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let key = [ns_prefix.as_slice(), b"agent::history"].concat();
    let req = tonic::Request::new(QueryRawStateRequest { key });

    let resp = timeout(
        Duration::from_millis(SESSION_HISTORY_RPC_TIMEOUT_MS),
        client.query_raw_state(req),
    )
    .await
    .map_err(|_| {
        format!(
            "Session history RPC timed out after {}ms",
            SESSION_HISTORY_RPC_TIMEOUT_MS
        )
    })?
    .map_err(|error| format!("Failed to query remote session history: {}", error))?
    .into_inner();

    if !resp.found || resp.value.is_empty() {
        return Ok(Vec::new());
    }

    codec::from_bytes_canonical::<Vec<RemoteSessionSummary>>(&resp.value)
        .map(|raw_history| {
            raw_history
                .into_iter()
                .map(|summary| SessionSummary {
                    session_id: hex::encode(summary.session_id),
                    title: summary.title,
                    timestamp: summary.timestamp,
                    phase: None,
                    current_step: None,
                    resume_hint: None,
                    workspace_root: None,
                })
                .collect()
        })
        .map_err(|error| format!("Failed to decode remote session history: {}", error))
}

pub(crate) fn merge_remote_session_history(
    all_sessions: &mut Vec<SessionSummary>,
    remote_sessions: Vec<SessionSummary>,
) -> usize {
    let mut overlap_count = 0;

    for remote in remote_sessions {
        if let Some(position) = all_sessions
            .iter()
            .position(|local| local.session_id == remote.session_id)
        {
            overlap_count += 1;
            let existing = all_sessions[position].clone();
            all_sessions[position] = SessionSummary {
                phase: existing.phase,
                current_step: existing.current_step,
                resume_hint: existing.resume_hint,
                workspace_root: existing.workspace_root,
                ..remote
            };
        } else {
            all_sessions.push(remote);
        }
    }

    overlap_count
}

fn merge_session_summaries(
    mut base: Vec<SessionSummary>,
    overlay: Vec<SessionSummary>,
) -> Vec<SessionSummary> {
    for summary in overlay {
        if let Some(position) = base
            .iter()
            .position(|existing| existing.session_id == summary.session_id)
        {
            base[position] = summary;
        } else {
            base.push(summary);
        }
    }

    base.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    base
}

fn current_task_snapshot(state: &State<'_, Mutex<AppState>>) -> Option<crate::models::AgentTask> {
    state.lock().ok().and_then(|guard| {
        guard.current_task.clone().map(|mut task| {
            task.sync_runtime_views();
            task
        })
    })
}

fn cached_session_history_snapshot(state: &State<'_, Mutex<AppState>>) -> Vec<SessionSummary> {
    state
        .lock()
        .map(|guard| guard.session_history_projection.clone())
        .unwrap_or_default()
}

fn projected_cached_session_history(state: &State<'_, Mutex<AppState>>) -> Vec<SessionSummary> {
    let (cached_sessions, memory_runtime) = match state.lock() {
        Ok(guard) => (
            guard.session_history_projection.clone(),
            guard.memory_runtime.clone(),
        ),
        Err(_) => return Vec::new(),
    };

    merge_session_summaries(
        cached_sessions,
        local_session_history_snapshot(memory_runtime.as_ref()),
    )
}

fn title_for_session(summary: &SessionSummary) -> String {
    let trimmed = summary.title.trim();
    if trimmed.is_empty() {
        format!(
            "Session {}",
            &summary.session_id[..summary.session_id.len().min(8)]
        )
    } else {
        trimmed.to_string()
    }
}

fn workspace_label(workspace_root: Option<&str>) -> Option<String> {
    let trimmed = workspace_root?.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed.replace('\\', "/");
    normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .last()
        .map(|segment| segment.to_string())
        .or_else(|| Some(normalized))
}

fn unique_session_parts(parts: &[Option<String>]) -> Vec<String> {
    let mut unique = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for part in parts.iter().flatten() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            unique.push(trimmed.to_string());
        }
    }

    unique
}

fn waiting_step(step: &str) -> bool {
    let normalized = step.trim().to_ascii_lowercase();
    normalized.contains("waiting for")
        || normalized.contains("initializing")
        || normalized.contains("routing the request")
        || normalized.contains("sending message")
        || normalized.contains("approval required")
        || normalized.contains("clarification required")
}

fn stable_session(summary: &SessionSummary, active_session_id: Option<&str>) -> bool {
    if active_session_id == Some(summary.session_id.as_str()) {
        return false;
    }

    match summary.phase.as_ref() {
        Some(AgentPhase::Running) | Some(AgentPhase::Gate) => false,
        Some(_) => true,
        None => summary
            .current_step
            .as_deref()
            .map(|step| !waiting_step(step))
            .unwrap_or(true),
    }
}

fn session_preview_detail(summary: &SessionSummary) -> String {
    let parts = unique_session_parts(&[
        summary.phase.as_ref().map(|phase| format!("{phase:?}")),
        summary.current_step.clone(),
        summary.resume_hint.clone(),
        workspace_label(summary.workspace_root.as_deref()),
    ]);

    if parts.is_empty() {
        "Retained session checkpoint.".to_string()
    } else {
        parts.join(" · ")
    }
}

fn compaction_excerpt(value: &str, max_chars: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut chars = trimmed.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        Some(format!("{}...", shortened))
    } else {
        Some(trimmed.to_string())
    }
}

fn compaction_latest_output_excerpt(task: &crate::models::AgentTask) -> Option<String> {
    task.history
        .iter()
        .rev()
        .find(|message| {
            !message.text.trim().is_empty()
                && matches!(message.role.as_str(), "assistant" | "agent" | "system")
        })
        .and_then(|message| compaction_excerpt(&message.text, 120))
        .or_else(|| compaction_excerpt(&task.current_step, 120))
}

fn event_timestamp_ms(event: &crate::models::AgentEvent) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(event.timestamp.trim())
        .ok()
        .and_then(|value| u64::try_from(value.timestamp_millis()).ok())
}

fn compaction_blocked_on(task: &crate::models::AgentTask) -> Option<String> {
    if let Some(request) = task.clarification_request.as_ref() {
        return compaction_excerpt(&request.question, 96)
            .map(|question| format!("Clarification: {question}"));
    }

    if let Some(request) = task.credential_request.as_ref() {
        return compaction_excerpt(&request.prompt, 96)
            .or_else(|| compaction_excerpt(&request.kind, 64))
            .map(|prompt| format!("Credential: {prompt}"));
    }

    if task.phase == AgentPhase::Gate || task.pending_request_hash.is_some() {
        return task
            .gate_info
            .as_ref()
            .and_then(|gate| {
                compaction_excerpt(&gate.description, 96)
                    .or_else(|| compaction_excerpt(&gate.title, 64))
            })
            .map(|detail| format!("Approval: {detail}"))
            .or_else(|| Some("Approval: operator review is still required.".to_string()));
    }

    None
}

fn compaction_pending_decision_context(task: &crate::models::AgentTask) -> Option<String> {
    let gate = task.gate_info.as_ref()?;
    let mut parts = Vec::new();

    if let Some(scope) = gate
        .scope_label
        .as_deref()
        .and_then(|value| compaction_excerpt(value, 48))
    {
        parts.push(scope);
    }
    if let Some(operation) = gate
        .operation_label
        .as_deref()
        .and_then(|value| compaction_excerpt(value, 48))
    {
        parts.push(operation);
    }
    if let Some(target) = gate
        .target_label
        .as_deref()
        .and_then(|value| compaction_excerpt(value, 48))
    {
        parts.push(target);
    }
    if parts.is_empty() {
        compaction_excerpt(&gate.title, 96)
            .or_else(|| compaction_excerpt(&gate.description, 96))
            .map(|value| format!("Pending decision: {value}"))
    } else {
        Some(format!("Pending decision: {}", parts.join(" -> ")))
    }
}

fn compaction_latest_artifact_outcome(task: &crate::models::AgentTask) -> Option<String> {
    task.artifacts
        .iter()
        .rev()
        .find_map(|artifact| {
            let title = compaction_excerpt(&artifact.title, 72)?;
            Some(format!("{:?}: {title}", artifact.artifact_type))
        })
        .or_else(|| {
            task.build_session.as_ref().and_then(|session| {
                session.receipts.iter().rev().find_map(|receipt| {
                    compaction_excerpt(&receipt.summary, 96)
                        .or_else(|| compaction_excerpt(&receipt.title, 72))
                        .map(|summary| format!("Build {}: {summary}", receipt.status))
                })
            })
        })
        .or_else(|| {
            task.renderer_session.as_ref().and_then(|session| {
                session.receipts.iter().rev().find_map(|receipt| {
                    compaction_excerpt(&receipt.summary, 96)
                        .or_else(|| compaction_excerpt(&receipt.title, 72))
                        .map(|summary| format!("Renderer {}: {summary}", receipt.status))
                })
            })
        })
        .or_else(|| {
            task.chat_session
                .as_ref()
                .and_then(|session| compaction_excerpt(&session.summary, 96))
                .map(|summary| format!("Studio artifact: {summary}"))
        })
}

fn compaction_execution_targets(
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
) -> Vec<String> {
    let mut targets = BTreeSet::new();

    for path in &file_context.pinned_files {
        if let Some(value) = compaction_excerpt(path, 96) {
            targets.insert(value);
        }
    }

    if let Some(task) = task {
        if let Some(session) = task.build_session.as_ref() {
            if let Some(value) = compaction_excerpt(&session.entry_document, 96) {
                targets.insert(value);
            }
        }
        if let Some(session) = task.renderer_session.as_ref() {
            if let Some(value) = compaction_excerpt(&session.entry_document, 96) {
                targets.insert(value);
            }
        }
        if let Some(session) = task.chat_session.as_ref() {
            for selection in &session.selected_targets {
                if let Some(value) = selection
                    .path
                    .as_deref()
                    .and_then(|path| compaction_excerpt(path, 96))
                    .or_else(|| compaction_excerpt(&selection.label, 96))
                {
                    targets.insert(value);
                }
            }
        }
    }

    targets.into_iter().collect()
}

fn recent_history_excerpts(
    task: &crate::models::AgentTask,
    max_items: usize,
    max_chars: usize,
) -> Vec<String> {
    task.history
        .iter()
        .rev()
        .filter_map(|message| {
            if message.text.trim().is_empty() {
                return None;
            }
            let role = message.role.trim();
            let excerpt = compaction_excerpt(&message.text, max_chars)?;
            if role.is_empty() {
                Some(excerpt)
            } else {
                Some(format!("{role}: {excerpt}"))
            }
        })
        .take(max_items)
        .collect()
}

fn push_memory_item(
    items: &mut Vec<SessionCompactionMemoryItem>,
    key: &str,
    label: &str,
    memory_class: SessionMemoryClass,
    values: Vec<String>,
) {
    let normalized = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return;
    }
    items.push(SessionCompactionMemoryItem {
        key: key.to_string(),
        label: label.to_string(),
        memory_class,
        values: normalized,
    });
}

fn push_prune_decision(
    decisions: &mut Vec<SessionCompactionPruneDecision>,
    key: &str,
    label: &str,
    disposition: SessionCompactionDisposition,
    detail_count: usize,
    rationale: &str,
    summary: String,
    examples: Vec<String>,
) {
    if detail_count == 0 && examples.is_empty() {
        return;
    }

    decisions.push(SessionCompactionPruneDecision {
        key: key.to_string(),
        label: label.to_string(),
        disposition,
        detail_count,
        rationale: rationale.to_string(),
        summary,
        examples: examples
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect(),
    });
}

fn compaction_memory_items(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    policy: &SessionCompactionPolicy,
) -> Vec<SessionCompactionMemoryItem> {
    let mut items = Vec::new();

    push_memory_item(
        &mut items,
        "workspace_root",
        "Workspace root",
        SessionMemoryClass::CarryForward,
        Some(file_context.workspace_root.clone())
            .filter(|value| !value.trim().is_empty())
            .or_else(|| summary.workspace_root.clone())
            .into_iter()
            .collect(),
    );
    push_memory_item(
        &mut items,
        "pinned_files",
        "Pinned files",
        SessionMemoryClass::Pinned,
        file_context.pinned_files.clone(),
    );
    if !policy.carry_pinned_only {
        push_memory_item(
            &mut items,
            "explicit_includes",
            "Explicit includes",
            SessionMemoryClass::CarryForward,
            file_context.explicit_includes.clone(),
        );
        push_memory_item(
            &mut items,
            "explicit_excludes",
            "Explicit excludes",
            SessionMemoryClass::CarryForward,
            file_context.explicit_excludes.clone(),
        );
    }
    if let Some(task) = task {
        if policy.preserve_checklist_state {
            push_memory_item(
                &mut items,
                "checklist_labels",
                "Checklist labels",
                SessionMemoryClass::CarryForward,
                task.session_checklist
                    .iter()
                    .map(|item| item.label.clone())
                    .collect(),
            );
        }
        if policy.preserve_background_tasks {
            push_memory_item(
                &mut items,
                "background_task_labels",
                "Background task labels",
                SessionMemoryClass::CarryForward,
                task.background_tasks
                    .iter()
                    .map(|item| format!("{} ({})", item.label, item.status))
                    .collect(),
            );
        }
        if policy.preserve_governance_blockers {
            push_memory_item(
                &mut items,
                "blocked_on",
                "Active blocker context",
                SessionMemoryClass::GovernanceCritical,
                compaction_blocked_on(task).into_iter().collect(),
            );
            push_memory_item(
                &mut items,
                "pending_decision_context",
                "Pending decision context",
                SessionMemoryClass::GovernanceCritical,
                compaction_pending_decision_context(task)
                    .into_iter()
                    .collect(),
            );
        }
        push_memory_item(
            &mut items,
            "latest_artifact_outcome",
            "Latest artifact outcome",
            SessionMemoryClass::CarryForward,
            compaction_latest_artifact_outcome(task)
                .into_iter()
                .collect(),
        );
        if policy.preserve_latest_output_excerpt {
            push_memory_item(
                &mut items,
                "latest_output_excerpt",
                "Latest output excerpt",
                SessionMemoryClass::Ephemeral,
                compaction_latest_output_excerpt(task).into_iter().collect(),
            );
        }
    }
    push_memory_item(
        &mut items,
        "execution_targets",
        "Execution targets",
        SessionMemoryClass::Pinned,
        compaction_execution_targets(task, file_context),
    );

    items
}

fn prune_examples(values: impl Iterator<Item = String>, max_items: usize) -> Vec<String> {
    values
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .take(max_items)
        .collect()
}

fn memory_values(items: &[SessionCompactionMemoryItem], key: &str) -> Vec<String> {
    items
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.values.clone())
        .unwrap_or_default()
}

fn first_memory_value(items: &[SessionCompactionMemoryItem], key: &str) -> Option<String> {
    memory_values(items, key).into_iter().next()
}

fn compaction_prune_decisions(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    policy: &SessionCompactionPolicy,
    memory_items: &[SessionCompactionMemoryItem],
) -> Vec<SessionCompactionPruneDecision> {
    let mut decisions = Vec::new();

    let workspace_root = first_memory_value(memory_items, "workspace_root");
    push_prune_decision(
        &mut decisions,
        "workspace_root",
        "Workspace root",
        SessionCompactionDisposition::CarryForward,
        usize::from(workspace_root.is_some()),
        "The workspace root stays explicit so Spotlight, Studio, and the standalone REPL can reopen the same repo.",
        if workspace_root.is_some() {
            "Keep the active workspace root in carried-forward state.".to_string()
        } else {
            "No workspace root is retained for this session.".to_string()
        },
        workspace_root.into_iter().collect(),
    );

    let pinned_files = memory_values(memory_items, "pinned_files");
    push_prune_decision(
        &mut decisions,
        "pinned_files",
        "Pinned files",
        SessionCompactionDisposition::CarryForward,
        pinned_files.len(),
        "Pinned files are preserved because operators explicitly marked them as resume-critical context.",
        format!(
            "Carry forward {} pinned file(s) into the compacted resume context.",
            pinned_files.len()
        ),
        prune_examples(pinned_files.into_iter(), 3),
    );

    let explicit_includes = file_context.explicit_includes.clone();
    push_prune_decision(
        &mut decisions,
        "explicit_includes",
        "Explicit includes",
        if policy.carry_pinned_only {
            SessionCompactionDisposition::Pruned
        } else {
            SessionCompactionDisposition::CarryForward
        },
        explicit_includes.len(),
        if policy.carry_pinned_only {
            "Pinned-only mode drops explicit include paths from carried-forward state so the compacted session keeps just the repo root and pinned files."
        } else {
            "Explicit include paths stay attached so follow-up runs keep the same operator-scoped file context."
        },
        if policy.carry_pinned_only {
            format!(
                "Prune {} explicit include path(s) from carried-forward state in pinned-only mode.",
                explicit_includes.len()
            )
        } else {
            format!(
                "Carry forward {} explicit include path(s).",
                explicit_includes.len()
            )
        },
        prune_examples(explicit_includes.into_iter(), 3),
    );

    let explicit_excludes = file_context.explicit_excludes.clone();
    push_prune_decision(
        &mut decisions,
        "explicit_excludes",
        "Explicit excludes",
        if policy.carry_pinned_only {
            SessionCompactionDisposition::Pruned
        } else {
            SessionCompactionDisposition::CarryForward
        },
        explicit_excludes.len(),
        if policy.carry_pinned_only {
            "Pinned-only mode drops explicit excludes from the carried-forward state to keep the resume context minimal."
        } else {
            "Explicit excludes remain in carried-forward state so resumed runs preserve the operator's narrowed scope."
        },
        if policy.carry_pinned_only {
            format!(
                "Prune {} explicit exclude path(s) from carried-forward state in pinned-only mode.",
                explicit_excludes.len()
            )
        } else {
            format!(
                "Carry forward {} explicit exclude path(s).",
                explicit_excludes.len()
            )
        },
        prune_examples(explicit_excludes.into_iter(), 3),
    );

    let checklist_labels = task
        .map(|task| {
            task.session_checklist
                .iter()
                .map(|item| item.label.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    push_prune_decision(
        &mut decisions,
        "checklist_labels",
        "Checklist labels",
        if policy.preserve_checklist_state {
            SessionCompactionDisposition::CarryForward
        } else {
            SessionCompactionDisposition::Pruned
        },
        checklist_labels.len(),
        if policy.preserve_checklist_state {
            "Checklist labels stay available so the resumed shell can keep its operator-visible to-do state."
        } else {
            "Checklist labels are omitted from the carried-forward resume context under the current memory policy."
        },
        if policy.preserve_checklist_state {
            format!(
                "Carry forward {} checklist label(s).",
                checklist_labels.len()
            )
        } else {
            format!(
                "Prune {} checklist label(s) from the compacted resume context.",
                checklist_labels.len()
            )
        },
        prune_examples(checklist_labels.into_iter(), 3),
    );

    let background_task_labels = task
        .map(|task| {
            task.background_tasks
                .iter()
                .map(|item| format!("{} ({})", item.label, item.status))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    push_prune_decision(
        &mut decisions,
        "background_task_labels",
        "Background task labels",
        if policy.preserve_background_tasks {
            SessionCompactionDisposition::CarryForward
        } else {
            SessionCompactionDisposition::Pruned
        },
        background_task_labels.len(),
        if policy.preserve_background_tasks {
            "Background task labels survive compaction so operators can see which parallel work is still relevant."
        } else {
            "Background task labels are omitted from the carried-forward resume context under the current memory policy."
        },
        if policy.preserve_background_tasks {
            format!(
                "Carry forward {} background task label(s).",
                background_task_labels.len()
            )
        } else {
            format!(
                "Prune {} background task label(s) from the compacted resume context.",
                background_task_labels.len()
            )
        },
        prune_examples(background_task_labels.into_iter(), 3),
    );

    let blocked_on = task.and_then(compaction_blocked_on);
    push_prune_decision(
        &mut decisions,
        "blocked_on",
        "Active blocker context",
        if policy.preserve_governance_blockers {
            SessionCompactionDisposition::CarryForward
        } else {
            SessionCompactionDisposition::RetainedSummary
        },
        usize::from(blocked_on.is_some()),
        if policy.preserve_governance_blockers {
            "Governance-critical blockers stay explicit so resumed runs do not hide pending approvals or clarifications."
        } else {
            "Governance blockers are summarized but not carried as dedicated blocker state under the current memory policy."
        },
        if blocked_on.is_some() {
            if policy.preserve_governance_blockers {
                "Carry forward the active blocker into the compacted resume state.".to_string()
            } else {
                "Retain the blocker as summary text without preserving a dedicated carried-forward blocker field.".to_string()
            }
        } else if policy.preserve_governance_blockers {
            "No active blocker needs to be carried forward.".to_string()
        } else {
            "No blocker summary needs to be retained.".to_string()
        },
        blocked_on.into_iter().collect(),
    );

    let pending_decision_context = task.and_then(compaction_pending_decision_context);
    push_prune_decision(
        &mut decisions,
        "pending_decision_context",
        "Pending decision context",
        if policy.preserve_governance_blockers {
            SessionCompactionDisposition::CarryForward
        } else {
            SessionCompactionDisposition::RetainedSummary
        },
        usize::from(pending_decision_context.is_some()),
        if policy.preserve_governance_blockers {
            "Pending approval details stay explicit so resumed runs know which decision is waiting and what it applies to."
        } else {
            "Pending approval details are summarized, but not preserved as a dedicated carried-forward decision context under the current memory policy."
        },
        if pending_decision_context.is_some() {
            if policy.preserve_governance_blockers {
                "Carry forward the pending decision details into the compacted resume state."
                    .to_string()
            } else {
                "Retain the pending decision details as summary text without preserving a dedicated carried-forward decision field.".to_string()
            }
        } else if policy.preserve_governance_blockers {
            "No pending decision context needs to be carried forward.".to_string()
        } else {
            "No pending decision details need to be summarized.".to_string()
        },
        pending_decision_context.into_iter().collect(),
    );

    let request_summary = task
        .and_then(|task| compaction_excerpt(&task.intent, 120))
        .unwrap_or_else(|| title_for_session(summary));
    push_prune_decision(
        &mut decisions,
        "request_summary",
        "Request summary",
        SessionCompactionDisposition::RetainedSummary,
        1,
        "The session goal is retained in the compacted summary so the next shell can resume from intent instead of replaying the full transcript.",
        "Retain the operator intent as summary text inside the compacted checkpoint.".to_string(),
        vec![request_summary],
    );

    let latest_step_summary = task
        .and_then(|task| compaction_excerpt(&task.current_step, 120))
        .or_else(|| {
            summary
                .current_step
                .as_deref()
                .and_then(|value| compaction_excerpt(value, 120))
        });
    push_prune_decision(
        &mut decisions,
        "latest_step_summary",
        "Latest step summary",
        SessionCompactionDisposition::RetainedSummary,
        usize::from(latest_step_summary.is_some()),
        "The most recent step is retained in the summary so the resumed shell can re-enter the right part of the workflow.",
        if latest_step_summary.is_some() {
            "Retain the most recent step as summary text instead of replaying the full step-by-step history.".to_string()
        } else {
            "No latest step needs to be summarized.".to_string()
        },
        latest_step_summary.into_iter().collect(),
    );

    let latest_output_summary = task.and_then(compaction_latest_output_excerpt);
    let latest_artifact_outcome = task.and_then(compaction_latest_artifact_outcome);
    push_prune_decision(
        &mut decisions,
        "latest_artifact_outcome",
        "Latest artifact outcome",
        SessionCompactionDisposition::CarryForward,
        usize::from(latest_artifact_outcome.is_some()),
        "The latest artifact or build outcome stays explicit so the resumed shell can see what the last concrete deliverable or runtime result was.",
        if latest_artifact_outcome.is_some() {
            "Carry forward the latest artifact or build outcome into the compacted resume state.".to_string()
        } else {
            "No artifact outcome needs to be carried forward.".to_string()
        },
        latest_artifact_outcome.into_iter().collect(),
    );

    let execution_targets = compaction_execution_targets(task, file_context);
    push_prune_decision(
        &mut decisions,
        "execution_targets",
        "Execution targets",
        SessionCompactionDisposition::CarryForward,
        execution_targets.len(),
        "Execution targets stay visible so the resumed shell knows which files, documents, or selected artifact targets were in scope.",
        if execution_targets.is_empty() {
            "No explicit execution targets need to be carried forward.".to_string()
        } else {
            format!(
                "Carry forward {} execution target(s) into the compacted resume state.",
                execution_targets.len()
            )
        },
        prune_examples(execution_targets.into_iter(), 3),
    );

    push_prune_decision(
        &mut decisions,
        "latest_output_excerpt",
        "Latest output excerpt",
        if policy.preserve_latest_output_excerpt {
            SessionCompactionDisposition::RetainedSummary
        } else {
            SessionCompactionDisposition::Pruned
        },
        usize::from(latest_output_summary.is_some()),
        if policy.preserve_latest_output_excerpt {
            "A short output excerpt is retained so the resume anchor has concrete recent context without carrying the entire transcript."
        } else {
            "The latest output excerpt is dropped from the compacted summary under the current memory policy."
        },
        if latest_output_summary.is_some() {
            if policy.preserve_latest_output_excerpt {
                "Retain a short excerpt from the latest output in the compacted summary."
                    .to_string()
            } else {
                "Prune the latest output excerpt from the compacted resume context.".to_string()
            }
        } else if policy.preserve_latest_output_excerpt {
            "No output excerpt is needed for the compacted summary.".to_string()
        } else {
            "No latest output excerpt is retained.".to_string()
        },
        latest_output_summary.into_iter().collect(),
    );

    if let Some(task) = task {
        let history_examples = recent_history_excerpts(task, 2, 64);
        push_prune_decision(
            &mut decisions,
            "history_transcript",
            "Detailed conversation transcript",
            if policy.aggressive_transcript_pruning {
                SessionCompactionDisposition::Pruned
            } else {
                SessionCompactionDisposition::RetainedSummary
            },
            task.history.len(),
            if policy.aggressive_transcript_pruning {
                "Detailed transcript turns are dropped from the carry-forward resume context after the summary is captured. Retained evidence stays stored on the session."
            } else {
                "The latest transcript turns are summarized into the compacted checkpoint so operators keep a little conversational texture without carrying the full transcript."
            },
            if policy.aggressive_transcript_pruning {
                format!(
                    "Prune {} detailed history message(s) from the compacted resume context.",
                    task.history.len()
                )
            } else {
                format!(
                    "Retain up to {} recent transcript turn(s) in the compacted summary.",
                    history_examples.len()
                )
            },
            history_examples,
        );

        let event_examples = prune_examples(
            task.events
                .iter()
                .rev()
                .filter_map(|event| compaction_excerpt(&event.title, 64)),
            2,
        );
        push_prune_decision(
            &mut decisions,
            "event_stream",
            "Event stream details",
            SessionCompactionDisposition::Pruned,
            task.events.len(),
            "Step-by-step runtime events stay in retained evidence but are excluded from the compacted resume context.",
            format!(
                "Prune {} event entr{} from the compacted resume context.",
                task.events.len(),
                if task.events.len() == 1 { "y" } else { "ies" }
            ),
            event_examples,
        );

        let artifact_examples = prune_examples(
            task.artifacts
                .iter()
                .rev()
                .filter_map(|artifact| compaction_excerpt(&artifact.title, 64)),
            2,
        );
        push_prune_decision(
            &mut decisions,
            "artifact_roster",
            "Artifact roster details",
            SessionCompactionDisposition::Pruned,
            task.artifacts.len(),
            "Artifact evidence remains stored with the retained session, but the full artifact roster is not carried into the compacted resume context.",
            format!(
                "Prune {} artifact reference(s) from the compacted resume context.",
                task.artifacts.len()
            ),
            artifact_examples,
        );
    }

    decisions
}

fn latest_activity_timestamp_ms(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
) -> u64 {
    let mut latest = summary.timestamp.max(file_context.updated_at_ms);
    if let Some(task) = task {
        latest = latest.max(
            task.history
                .iter()
                .map(|message| message.timestamp)
                .max()
                .unwrap_or(0),
        );
        latest = latest.max(
            task.events
                .iter()
                .filter_map(event_timestamp_ms)
                .max()
                .unwrap_or(0),
        );
        latest = latest.max(
            task.session_checklist
                .iter()
                .map(|item| item.updated_at_ms)
                .max()
                .unwrap_or(0),
        );
        latest = latest.max(
            task.background_tasks
                .iter()
                .map(|item| item.updated_at_ms)
                .max()
                .unwrap_or(0),
        );
    }
    latest
}

fn latest_durability_activity_timestamp_ms(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
) -> u64 {
    let persisted_file_context = crate::orchestrator::store::load_persisted_session_file_context(
        memory_runtime,
        Some(summary.session_id.as_str()),
    );
    let baseline_updated_at_ms = persisted_file_context
        .as_ref()
        .map(|context| context.updated_at_ms)
        .unwrap_or_default();

    let mut latest = summary.timestamp.max(baseline_updated_at_ms);
    if let Some(task) = task {
        latest = latest.max(
            task.history
                .iter()
                .map(|message| message.timestamp)
                .max()
                .unwrap_or(0),
        );
        latest = latest.max(
            task.events
                .iter()
                .filter_map(event_timestamp_ms)
                .max()
                .unwrap_or(0),
        );
        latest = latest.max(
            task.session_checklist
                .iter()
                .map(|item| item.updated_at_ms)
                .max()
                .unwrap_or(0),
        );
        latest = latest.max(
            task.background_tasks
                .iter()
                .map(|item| item.updated_at_ms)
                .max()
                .unwrap_or(0),
        );
    }
    if persisted_file_context.is_some() {
        latest = latest.max(file_context.updated_at_ms);
    }
    latest
}

fn compaction_resume_anchor(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
) -> String {
    summary
        .resume_hint
        .as_deref()
        .and_then(|value| compaction_excerpt(value, 96))
        .or_else(|| task.and_then(compaction_blocked_on))
        .or_else(|| {
            task.and_then(|task| compaction_excerpt(&task.current_step, 96))
                .or_else(|| {
                    summary
                        .current_step
                        .as_deref()
                        .and_then(|value| compaction_excerpt(value, 96))
                })
        })
        .unwrap_or_else(|| "Resume from the retained session summary.".to_string())
}

fn compaction_pre_span(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
) -> String {
    let mut parts = Vec::new();
    if let Some(task) = task {
        parts.push(format!("{} history messages", task.history.len()));
        parts.push(format!("{} events", task.events.len()));
        parts.push(format!("{} artifacts", task.artifacts.len()));
        parts.push(format!("{} checklist items", task.session_checklist.len()));
    }
    if !file_context.pinned_files.is_empty() {
        parts.push(format!("{} pinned files", file_context.pinned_files.len()));
    }
    if !file_context.explicit_includes.is_empty() {
        parts.push(format!(
            "{} explicit includes",
            file_context.explicit_includes.len()
        ));
    }
    if parts.is_empty() {
        parts.push("Retained session summary only".to_string());
    }
    if let Some(phase) = summary.phase.as_ref() {
        parts.push(format!("{phase:?}"));
    }
    parts.join(" · ")
}

fn compaction_summary_text(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    policy: &SessionCompactionPolicy,
) -> String {
    let mut lines = Vec::new();
    let request = task
        .and_then(|task| compaction_excerpt(&task.intent, 120))
        .unwrap_or_else(|| title_for_session(summary));
    lines.push(format!("Request: {request}."));

    if let Some(blocked) = task.and_then(compaction_blocked_on) {
        if policy.preserve_governance_blockers {
            lines.push(format!("Blocked on {blocked}."));
        } else {
            lines.push(format!("Recent blocker note: {blocked}."));
        }
    } else if let Some(step) = task
        .and_then(|task| compaction_excerpt(&task.current_step, 120))
        .or_else(|| {
            summary
                .current_step
                .as_deref()
                .and_then(|value| compaction_excerpt(value, 120))
        })
    {
        lines.push(format!("Latest step: {step}."));
    }

    if policy.preserve_latest_output_excerpt {
        if let Some(output) = task.and_then(compaction_latest_output_excerpt) {
            lines.push(format!("Latest output: {output}."));
        }
    }

    if !policy.aggressive_transcript_pruning {
        if let Some(task) = task {
            let excerpts = recent_history_excerpts(task, 2, 80);
            if !excerpts.is_empty() {
                lines.push(format!(
                    "Recent transcript context: {}.",
                    excerpts.join(" | ")
                ));
            }
        }
    }

    if policy.carry_pinned_only {
        if !file_context.pinned_files.is_empty() {
            lines.push(format!(
                "Carry forward {} pinned file(s); explicit include and exclude paths are pruned in pinned-only mode.",
                file_context.pinned_files.len()
            ));
        }
    } else if !file_context.pinned_files.is_empty() || !file_context.explicit_includes.is_empty() {
        lines.push(format!(
            "Carry forward {} pinned file(s) and {} explicit include(s).",
            file_context.pinned_files.len(),
            file_context.explicit_includes.len()
        ));
    }

    if let Some(pending_decision) = task.and_then(compaction_pending_decision_context) {
        if policy.preserve_governance_blockers {
            lines.push(format!("Pending decision context: {pending_decision}."));
        }
    }

    if let Some(outcome) = task.and_then(compaction_latest_artifact_outcome) {
        lines.push(format!("Latest artifact outcome: {outcome}."));
    }

    let execution_targets = compaction_execution_targets(task, file_context);
    if !execution_targets.is_empty() {
        lines.push(format!(
            "Execution targets: {}.",
            execution_targets
                .into_iter()
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }

    lines.join(" ")
}

fn compaction_resume_safety_receipt(
    summary: &SessionSummary,
    task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    policy: &SessionCompactionPolicy,
) -> SessionCompactionResumeSafetyReceipt {
    let mut reasons = Vec::new();
    let mut degraded = false;

    let blocked_on = task.and_then(compaction_blocked_on);
    let pending_decision_context = task.and_then(compaction_pending_decision_context);
    let latest_output_excerpt = task.and_then(compaction_latest_output_excerpt);
    let latest_artifact_outcome = task.and_then(compaction_latest_artifact_outcome);
    let execution_targets = compaction_execution_targets(task, file_context);
    let open_checklist_count = task
        .map(|task| {
            task.session_checklist
                .iter()
                .filter(|item| checklist_item_is_open(item))
                .count()
        })
        .unwrap_or(0);
    let active_background_count = task
        .map(|task| {
            task.background_tasks
                .iter()
                .filter(|item| background_task_is_active(item))
                .count()
        })
        .unwrap_or(0);
    let has_live_execution = task
        .map(|task| matches!(task.phase, AgentPhase::Running | AgentPhase::Gate))
        .unwrap_or_else(|| matches!(summary.phase, Some(AgentPhase::Running | AgentPhase::Gate)));

    if blocked_on.is_some() {
        if policy.preserve_governance_blockers {
            reasons.push(
                "Active blocker context remains explicit in the compacted resume state."
                    .to_string(),
            );
        } else {
            degraded = true;
            reasons.push(
                "Active blocker context would be reduced to summary text under this policy."
                    .to_string(),
            );
        }
    }

    if pending_decision_context.is_some() {
        if policy.preserve_governance_blockers {
            reasons.push(
                "Pending decision details stay attached so resume keeps the same approval target and scope."
                    .to_string(),
            );
        } else {
            degraded = true;
            reasons.push(
                "Pending decision details would not survive as a dedicated resume field under this policy."
                    .to_string(),
            );
        }
    }

    if open_checklist_count > 0 {
        if policy.preserve_checklist_state {
            reasons.push(format!(
                "{} open checklist item(s) remain available after resume.",
                open_checklist_count
            ));
        } else {
            degraded = true;
            reasons.push(format!(
                "{} open checklist item(s) would be pruned from the carried-forward resume context.",
                open_checklist_count
            ));
        }
    }

    if active_background_count > 0 {
        if policy.preserve_background_tasks {
            reasons.push(format!(
                "{} active background task label(s) remain visible after resume.",
                active_background_count
            ));
        } else {
            degraded = true;
            reasons.push(format!(
                "{} active background task label(s) would be pruned from the carried-forward resume context.",
                active_background_count
            ));
        }
    }

    if latest_output_excerpt.is_some() && has_live_execution {
        if policy.preserve_latest_output_excerpt {
            reasons.push(
                "Latest output excerpt stays available so resume starts from the freshest runtime result."
                    .to_string(),
            );
        } else {
            degraded = true;
            reasons.push(
                "Latest output excerpt would be dropped even though execution is still active."
                    .to_string(),
            );
        }
    }

    if latest_artifact_outcome.is_some() {
        reasons.push(
            "Latest artifact outcome remains explicit so the resumed shell can see the last concrete deliverable or runtime result."
                .to_string(),
        );
    }

    if !execution_targets.is_empty() {
        reasons.push(format!(
            "{} execution target(s) remain pinned into the compacted resume state.",
            execution_targets.len()
        ));
    }

    if reasons.is_empty() {
        reasons.push(
            "This session is stable enough to resume from the compacted summary and anchor alone."
                .to_string(),
        );
    }

    SessionCompactionResumeSafetyReceipt {
        status: if degraded {
            SessionCompactionResumeSafetyStatus::Degraded
        } else {
            SessionCompactionResumeSafetyStatus::Protected
        },
        reasons,
    }
}

fn load_compaction_context(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    summary: &SessionSummary,
) -> (
    Option<crate::models::AgentTask>,
    crate::models::SessionFileContext,
) {
    let local_task = orchestrator::load_local_task(memory_runtime, &summary.session_id);
    let file_context = orchestrator::load_session_file_context(
        memory_runtime,
        Some(summary.session_id.as_str()),
        summary.workspace_root.as_deref(),
    );
    (local_task, file_context)
}

fn build_compaction_record_from_context(
    summary: &SessionSummary,
    local_task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    policy: &SessionCompactionPolicy,
    mode: SessionCompactionMode,
    compacted_at_ms: u64,
) -> SessionCompactionRecord {
    let preview = build_compaction_preview_from_context(summary, local_task, file_context, policy);

    build_compaction_record_from_preview(preview, mode, compacted_at_ms)
}

fn build_compaction_preview_from_context(
    summary: &SessionSummary,
    local_task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    policy: &SessionCompactionPolicy,
) -> SessionCompactionPreview {
    let memory_items = compaction_memory_items(summary, local_task, file_context, policy);
    let blocked_on = first_memory_value(&memory_items, "blocked_on");
    let pending_decision_context = first_memory_value(&memory_items, "pending_decision_context");
    let latest_artifact_outcome = first_memory_value(&memory_items, "latest_artifact_outcome");
    let execution_targets = memory_values(&memory_items, "execution_targets");
    let latest_output_excerpt = first_memory_value(&memory_items, "latest_output_excerpt");
    let carried_forward_state = SessionCompactionCarryForwardState {
        workspace_root: first_memory_value(&memory_items, "workspace_root"),
        pinned_files: memory_values(&memory_items, "pinned_files"),
        explicit_includes: memory_values(&memory_items, "explicit_includes"),
        explicit_excludes: memory_values(&memory_items, "explicit_excludes"),
        checklist_labels: memory_values(&memory_items, "checklist_labels"),
        background_task_labels: memory_values(&memory_items, "background_task_labels"),
        blocked_on,
        pending_decision_context,
        latest_artifact_outcome,
        execution_targets,
        latest_output_excerpt,
        memory_items: memory_items.clone(),
    };
    let prune_decisions =
        compaction_prune_decisions(summary, local_task, file_context, policy, &memory_items);
    let resume_safety = compaction_resume_safety_receipt(summary, local_task, file_context, policy);

    SessionCompactionPreview {
        session_id: summary.session_id.clone(),
        title: title_for_session(summary),
        phase: summary.phase.clone(),
        policy: policy.clone(),
        pre_compaction_span: compaction_pre_span(summary, local_task, file_context),
        summary: compaction_summary_text(summary, local_task, file_context, policy),
        resume_anchor: compaction_resume_anchor(summary, local_task),
        carried_forward_state,
        resume_safety,
        prune_decisions,
    }
}

fn build_compaction_record_from_preview(
    preview: SessionCompactionPreview,
    mode: SessionCompactionMode,
    compacted_at_ms: u64,
) -> SessionCompactionRecord {
    SessionCompactionRecord {
        compaction_id: format!("{}:{compacted_at_ms}", preview.session_id),
        session_id: preview.session_id,
        title: preview.title,
        compacted_at_ms,
        mode,
        phase: preview.phase,
        policy: preview.policy,
        pre_compaction_span: preview.pre_compaction_span,
        summary: preview.summary,
        resume_anchor: preview.resume_anchor,
        carried_forward_state: preview.carried_forward_state,
        resume_safety: preview.resume_safety,
        prune_decisions: preview.prune_decisions,
    }
}

fn build_compaction_record(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    summary: &SessionSummary,
    mode: SessionCompactionMode,
    policy: &SessionCompactionPolicy,
) -> SessionCompactionRecord {
    let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
    build_compaction_record_from_context(
        summary,
        local_task.as_ref(),
        &file_context,
        policy,
        mode,
        crate::kernel::state::now(),
    )
}

fn compaction_state_matches(
    existing: &SessionCompactionRecord,
    candidate: &SessionCompactionRecord,
) -> bool {
    existing.session_id == candidate.session_id
        && existing.title == candidate.title
        && existing.phase == candidate.phase
        && existing.policy == candidate.policy
        && existing.pre_compaction_span == candidate.pre_compaction_span
        && existing.summary == candidate.summary
        && existing.resume_anchor == candidate.resume_anchor
        && existing.carried_forward_state == candidate.carried_forward_state
        && existing.resume_safety == candidate.resume_safety
        && existing.prune_decisions == candidate.prune_decisions
}

fn checklist_item_is_open(item: &crate::models::SessionChecklistItem) -> bool {
    !matches!(item.status.trim(), "completed")
}

fn background_task_is_active(task: &crate::models::SessionBackgroundTaskRecord) -> bool {
    !matches!(task.status.trim(), "completed" | "failed" | "cancelled")
}

fn recommended_compaction_policy_label(policy: &SessionCompactionPolicy) -> String {
    if policy.carry_pinned_only && policy.aggressive_transcript_pruning {
        "Focused pinned-context policy".to_string()
    } else if policy.aggressive_transcript_pruning {
        "Lean transcript policy".to_string()
    } else if policy.preserve_checklist_state
        || policy.preserve_background_tasks
        || policy.preserve_governance_blockers
    {
        "Balanced working-context policy".to_string()
    } else {
        "Minimal resume-context policy".to_string()
    }
}

fn build_recommended_compaction_policy(
    local_task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    history_count: usize,
    event_count: usize,
    artifact_count: usize,
) -> (SessionCompactionPolicy, Vec<String>, Vec<String>) {
    let mut policy = SessionCompactionPolicy::default();
    let mut policy_reasons = Vec::new();
    let mut safeguard_labels = Vec::new();

    let open_checklist_count = local_task
        .map(|task| {
            task.session_checklist
                .iter()
                .filter(|item| checklist_item_is_open(item))
                .count()
        })
        .unwrap_or(0);
    let active_background_count = local_task
        .map(|task| {
            task.background_tasks
                .iter()
                .filter(|item| background_task_is_active(item))
                .count()
        })
        .unwrap_or(0);
    let blocked_on = local_task.and_then(compaction_blocked_on);
    let pending_decision_context = local_task.and_then(compaction_pending_decision_context);
    let latest_output_excerpt = local_task.and_then(compaction_latest_output_excerpt);
    let latest_artifact_outcome = local_task.and_then(compaction_latest_artifact_outcome);
    let execution_targets = compaction_execution_targets(local_task, file_context);
    let has_live_execution = local_task
        .map(|task| matches!(task.phase, AgentPhase::Running | AgentPhase::Gate))
        .unwrap_or(false);

    let transcript_pressure = history_count >= AUTO_COMPACTION_HISTORY_THRESHOLD * 2
        || event_count >= AUTO_COMPACTION_EVENT_THRESHOLD * 2
        || artifact_count >= AUTO_COMPACTION_ARTIFACT_THRESHOLD * 2;
    let rich_file_scope =
        !file_context.pinned_files.is_empty() && !file_context.explicit_includes.is_empty();

    let has_unresolved_execution_work = has_live_execution
        || open_checklist_count > 0
        || active_background_count > 0
        || blocked_on.is_some()
        || pending_decision_context.is_some();

    if transcript_pressure && !has_unresolved_execution_work {
        policy.aggressive_transcript_pruning = true;
        policy_reasons.push(
            "Transcript pressure is high, so favor a leaner summary over carrying extra conversational texture."
                .to_string(),
        );
    } else if transcript_pressure {
        policy_reasons.push(
            "Transcript pressure is high, but resume-safety guardrails keep a richer working context because execution is still active."
                .to_string(),
        );
    }

    if policy.aggressive_transcript_pruning && rich_file_scope && !has_unresolved_execution_work {
        policy.carry_pinned_only = true;
        policy_reasons.push(
            "Pinned files already capture the critical repo context, so explicit include paths can be pruned."
                .to_string(),
        );
    }

    if open_checklist_count > 0 {
        safeguard_labels.push(format!(
            "Keep {} open checklist item(s) so the resumed shell still shows unfinished operator work.",
            open_checklist_count
        ));
    } else if policy.aggressive_transcript_pruning {
        policy.preserve_checklist_state = false;
        policy_reasons.push(
            "The checklist is already closed, so it can be pruned from carried-forward state."
                .to_string(),
        );
    }

    if active_background_count > 0 {
        safeguard_labels.push(format!(
            "Keep {} active background task label(s) so parallel work is still visible after resume.",
            active_background_count
        ));
    } else if policy.aggressive_transcript_pruning {
        policy.preserve_background_tasks = false;
        policy_reasons.push(
            "No live background tasks remain, so their labels can be pruned from the resume context."
                .to_string(),
        );
    }

    if blocked_on.is_some() {
        safeguard_labels.push(
            "Keep the live blocker note so the resumed shell knows exactly what approval or credential is still outstanding."
                .to_string(),
        );
    } else if pending_decision_context.is_some() {
        safeguard_labels.push(
            "Keep the pending decision details so resume keeps the same approval target and scope."
                .to_string(),
        );
    } else if policy.aggressive_transcript_pruning {
        policy.preserve_governance_blockers = false;
        policy_reasons.push(
            "No active blocker is present, so governance blocker context can be omitted."
                .to_string(),
        );
    }

    if latest_output_excerpt.is_some() {
        if open_checklist_count > 0 || active_background_count > 0 || blocked_on.is_some() {
            safeguard_labels.push(
                "Keep the latest output excerpt so resume starts with the freshest operator-visible result."
                    .to_string(),
            );
        } else if policy.aggressive_transcript_pruning {
            policy.preserve_latest_output_excerpt = false;
            policy_reasons.push(
                "Recent output can be summarized away because the session is stable and transcript pressure is high."
                    .to_string(),
            );
        }
    }

    if latest_artifact_outcome.is_some() {
        safeguard_labels.push(
            "Keep the latest artifact outcome so resume starts with the last concrete deliverable or runtime result."
                .to_string(),
        );
    }

    if !execution_targets.is_empty() {
        safeguard_labels.push(format!(
            "Keep {} execution target(s) so resume stays anchored to the same files or selected artifact targets.",
            execution_targets.len()
        ));
    }

    if policy_reasons.is_empty() && !safeguard_labels.is_empty() {
        policy_reasons.push(
            "The balanced default policy is already the safest fit because the session still has active work in flight."
                .to_string(),
        );
    }

    if policy_reasons.is_empty() && safeguard_labels.is_empty() {
        policy_reasons.push(
            "The balanced default policy already matches this session's current working context."
                .to_string(),
        );
    }

    (policy, policy_reasons, safeguard_labels)
}

fn build_compaction_recommendation(
    summary: &SessionSummary,
    local_task: Option<&crate::models::AgentTask>,
    file_context: &crate::models::SessionFileContext,
    latest_record: Option<&SessionCompactionRecord>,
) -> SessionCompactionRecommendation {
    let history_count = local_task.map(|task| task.history.len()).unwrap_or(0);
    let event_count = local_task.map(|task| task.events.len()).unwrap_or(0);
    let artifact_count = local_task.map(|task| task.artifacts.len()).unwrap_or(0);
    let pinned_file_count = file_context.pinned_files.len();
    let explicit_include_count = file_context.explicit_includes.len();
    let blocked_on = local_task.and_then(compaction_blocked_on);
    let now = crate::kernel::state::now();
    let last_activity_ms = latest_activity_timestamp_ms(summary, local_task, file_context);
    let idle_age_ms = now.saturating_sub(last_activity_ms);
    let blocked_age_ms = blocked_on
        .as_ref()
        .map(|_| now.saturating_sub(last_activity_ms));
    let (recommended_policy, recommended_policy_reason_labels, resume_safeguard_labels) =
        build_recommended_compaction_policy(
            local_task,
            file_context,
            history_count,
            event_count,
            artifact_count,
        );

    let mut reason_labels = Vec::new();
    if history_count >= AUTO_COMPACTION_HISTORY_THRESHOLD {
        reason_labels.push(format!("History reached {} messages", history_count));
    }
    if event_count >= AUTO_COMPACTION_EVENT_THRESHOLD {
        reason_labels.push(format!("Event stream reached {} entries", event_count));
    }
    if artifact_count >= AUTO_COMPACTION_ARTIFACT_THRESHOLD {
        reason_labels.push(format!("Artifacts reached {}", artifact_count));
    }
    if pinned_file_count + explicit_include_count >= AUTO_COMPACTION_FILE_CONTEXT_THRESHOLD {
        reason_labels.push(format!(
            "Carried-forward file context reached {} items",
            pinned_file_count + explicit_include_count
        ));
    }
    if blocked_on.is_some()
        && blocked_age_ms.unwrap_or_default() >= AUTO_COMPACTION_BLOCKED_THRESHOLD_MS
    {
        reason_labels.push("Blocked session has been waiting".to_string());
    } else if idle_age_ms >= AUTO_COMPACTION_IDLE_THRESHOLD_MS {
        reason_labels.push("Session has been idle long enough to summarize".to_string());
    }

    let mut should_compact = !reason_labels.is_empty();
    if should_compact {
        let candidate = build_compaction_record_from_context(
            summary,
            local_task,
            file_context,
            &recommended_policy,
            SessionCompactionMode::Auto,
            now,
        );
        if latest_record.is_some_and(|record| compaction_state_matches(record, &candidate)) {
            should_compact = false;
            reason_labels = vec!["Current retained state is already compacted".to_string()];
        }
    }

    SessionCompactionRecommendation {
        should_compact,
        reason_labels,
        recommended_policy: recommended_policy.clone(),
        recommended_policy_label: recommended_compaction_policy_label(&recommended_policy),
        recommended_policy_reason_labels,
        resume_safeguard_labels,
        history_count,
        event_count,
        artifact_count,
        pinned_file_count,
        explicit_include_count,
        idle_age_ms,
        blocked_age_ms,
    }
}

fn maybe_auto_compact_active_session(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: &[SessionSummary],
    active_session_id: Option<&str>,
) {
    let Some(active_session_id) = active_session_id else {
        return;
    };
    let Some(summary) = sessions
        .iter()
        .find(|summary| summary.session_id == active_session_id)
    else {
        return;
    };

    let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
    let existing_records =
        orchestrator::load_session_compaction_records(memory_runtime, Some(active_session_id));
    let latest_record = existing_records.first();
    let recommendation =
        build_compaction_recommendation(summary, local_task.as_ref(), &file_context, latest_record);
    if !recommendation.should_compact {
        return;
    }

    let candidate = build_compaction_record_from_context(
        summary,
        local_task.as_ref(),
        &file_context,
        &recommendation.recommended_policy,
        SessionCompactionMode::Auto,
        crate::kernel::state::now(),
    );
    if latest_record.is_some_and(|record| compaction_state_matches(record, &candidate)) {
        return;
    }

    orchestrator::append_session_compaction_record(
        memory_runtime,
        Some(active_session_id),
        candidate,
    );
}

fn collect_compaction_records(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: &[SessionSummary],
) -> Vec<SessionCompactionRecord> {
    let mut records = sessions
        .iter()
        .flat_map(|summary| {
            orchestrator::load_session_compaction_records(
                memory_runtime,
                Some(summary.session_id.as_str()),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| right.compacted_at_ms.cmp(&left.compacted_at_ms));
    if records.len() > 16 {
        records.truncate(16);
    }
    records
}

fn build_session_durability_portfolio(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: &[SessionSummary],
) -> SessionDurabilityPortfolio {
    let team_memory_entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    let team_memory_covered_sessions = team_memory_entries
        .iter()
        .map(|entry| entry.session_id.as_str())
        .collect::<BTreeSet<_>>();
    let team_memory_redacted_sessions = team_memory_entries
        .iter()
        .filter(|entry| matches!(entry.sync_status, TeamMemorySyncStatus::Redacted))
        .map(|entry| entry.session_id.as_str())
        .collect::<BTreeSet<_>>();
    let team_memory_review_required_sessions = team_memory_entries
        .iter()
        .filter(|entry| matches!(entry.sync_status, TeamMemorySyncStatus::ReviewRequired))
        .map(|entry| entry.session_id.as_str())
        .collect::<BTreeSet<_>>();

    let retained_session_count = sessions.len();
    let mut compacted_session_count = 0usize;
    let mut replay_ready_session_count = 0usize;
    let mut stale_compaction_count = 0usize;
    let mut degraded_compaction_count = 0usize;
    let mut recommended_compaction_count = 0usize;
    let mut compacted_without_team_memory_count = 0usize;

    for summary in sessions {
        let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
        let latest_record = orchestrator::load_session_compaction_records(
            memory_runtime,
            Some(summary.session_id.as_str()),
        )
        .into_iter()
        .next();

        let recommendation = build_compaction_recommendation(
            summary,
            local_task.as_ref(),
            &file_context,
            latest_record.as_ref(),
        );
        if recommendation.should_compact {
            recommended_compaction_count += 1;
        }

        if let Some(record) = latest_record {
            compacted_session_count += 1;
            if !team_memory_covered_sessions.contains(summary.session_id.as_str()) {
                compacted_without_team_memory_count += 1;
            }

            let last_activity_ms = latest_durability_activity_timestamp_ms(
                memory_runtime,
                summary,
                local_task.as_ref(),
                &file_context,
            );
            let is_fresh = record.compacted_at_ms >= last_activity_ms;
            if !is_fresh {
                stale_compaction_count += 1;
            }
            if matches!(
                record.resume_safety.status,
                SessionCompactionResumeSafetyStatus::Degraded
            ) {
                degraded_compaction_count += 1;
            }
            if is_fresh
                && matches!(
                    record.resume_safety.status,
                    SessionCompactionResumeSafetyStatus::Protected
                )
            {
                replay_ready_session_count += 1;
            }
        }
    }

    let uncompacted_session_count = retained_session_count.saturating_sub(compacted_session_count);
    let team_memory_covered_session_count = team_memory_covered_sessions.len();
    let team_memory_redacted_session_count = team_memory_redacted_sessions.len();
    let team_memory_review_required_session_count = team_memory_review_required_sessions.len();

    let coverage_summary = if retained_session_count == 0 {
        "No retained sessions are available yet, so cross-session durability coverage has not started."
            .to_string()
    } else {
        format!(
            "{} of {} retained session(s) are replay-ready with fresh protected compaction records; {} session(s) have any compaction record.",
            replay_ready_session_count, retained_session_count, compacted_session_count
        )
    };
    let team_memory_summary = if team_memory_entries.is_empty() {
        "No retained sessions are represented in team memory yet.".to_string()
    } else {
        format!(
            "{} retained session(s) are represented across {} team-memory entr{}; {} require review and {} were redacted.",
            team_memory_covered_session_count,
            team_memory_entries.len(),
            if team_memory_entries.len() == 1 { "y" } else { "ies" },
            team_memory_review_required_session_count,
            team_memory_redacted_session_count
        )
    };

    let mut attention_labels = Vec::new();
    if retained_session_count > 0 && compacted_session_count == 0 {
        attention_labels.push(
            "No retained sessions have compaction records yet, so replay-safe continuity has not been captured."
                .to_string(),
        );
    }
    if uncompacted_session_count > 0 && compacted_session_count > 0 {
        attention_labels.push(format!(
            "{} retained session(s) still have no compaction record.",
            uncompacted_session_count
        ));
    }
    if recommended_compaction_count > 0 {
        attention_labels.push(format!(
            "{} retained session(s) should be compacted again before the next replay or handoff.",
            recommended_compaction_count
        ));
    }
    if stale_compaction_count > 0 {
        attention_labels.push(format!(
            "{} retained session(s) have new activity since the latest compaction record.",
            stale_compaction_count
        ));
    }
    if degraded_compaction_count > 0 {
        attention_labels.push(format!(
            "{} retained session(s) only have degraded resume-safety coverage.",
            degraded_compaction_count
        ));
    }
    if compacted_without_team_memory_count > 0 {
        attention_labels.push(format!(
            "{} compacted session(s) are not represented in team memory yet.",
            compacted_without_team_memory_count
        ));
    }
    if team_memory_review_required_session_count > 0 {
        attention_labels.push(format!(
            "{} team-memory session(s) still require governance review.",
            team_memory_review_required_session_count
        ));
    }

    let attention_summary = attention_labels
        .first()
        .cloned()
        .unwrap_or_else(|| {
            if retained_session_count == 0 {
                "Durability coverage will appear here once retained sessions and compaction records exist."
                    .to_string()
            } else {
                "Cross-session durability coverage is healthy across retained sessions."
                    .to_string()
            }
        });

    SessionDurabilityPortfolio {
        retained_session_count,
        compacted_session_count,
        replay_ready_session_count,
        uncompacted_session_count,
        stale_compaction_count,
        degraded_compaction_count,
        recommended_compaction_count,
        compacted_without_team_memory_count,
        team_memory_entry_count: team_memory_entries.len(),
        team_memory_covered_session_count,
        team_memory_redacted_session_count,
        team_memory_review_required_session_count,
        coverage_summary,
        team_memory_summary,
        attention_summary,
        attention_labels,
    }
}

fn build_session_compaction_snapshot(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    preview_policy: Option<SessionCompactionPolicy>,
    allow_auto_compaction: bool,
) -> SessionCompactionSnapshot {
    if allow_auto_compaction {
        maybe_auto_compact_active_session(memory_runtime, &sessions, active_session_id);
    }
    let preview_policy = preview_policy.unwrap_or_default();

    let active_session_title = active_session_id.and_then(|session_id| {
        sessions
            .iter()
            .find(|summary| summary.session_id == session_id)
            .map(title_for_session)
    });
    let records = collect_compaction_records(memory_runtime, &sessions);
    let latest_for_active = active_session_id.and_then(|session_id| {
        records
            .iter()
            .find(|record| record.session_id == session_id)
            .cloned()
    });
    let preview_for_active = active_session_id.and_then(|session_id| {
        let summary = sessions
            .iter()
            .find(|summary| summary.session_id == session_id)?;
        let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
        Some(build_compaction_preview_from_context(
            summary,
            local_task.as_ref(),
            &file_context,
            &preview_policy,
        ))
    });
    let recommendation_for_active = active_session_id.and_then(|session_id| {
        let summary = sessions
            .iter()
            .find(|summary| summary.session_id == session_id)?;
        let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
        Some(build_compaction_recommendation(
            summary,
            local_task.as_ref(),
            &file_context,
            latest_for_active.as_ref(),
        ))
    });
    let durability_portfolio =
        build_session_durability_portfolio(memory_runtime, sessions.as_slice());

    SessionCompactionSnapshot {
        generated_at_ms: crate::kernel::state::now(),
        active_session_id: active_session_id.map(ToOwned::to_owned),
        active_session_title,
        policy_for_active: preview_policy,
        record_count: records.len(),
        latest_for_active,
        preview_for_active,
        recommendation_for_active,
        durability_portfolio,
        records,
    }
}

fn selected_summary_for_compaction<'a>(
    sessions: &'a [SessionSummary],
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
) -> Result<&'a SessionSummary, String> {
    if sessions.is_empty() {
        return Err("No retained sessions are available for compaction.".to_string());
    }

    let selector = requested_session_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| !value.eq_ignore_ascii_case("latest"))
        .or(active_session_id);

    if let Some(selector) = selector {
        return sessions
            .iter()
            .find(|summary| summary.session_id == selector)
            .ok_or_else(|| format!("Session '{selector}' was not found for compaction."));
    }

    sessions
        .first()
        .ok_or_else(|| "No retained sessions are available for compaction.".to_string())
}

pub fn session_compaction_snapshot_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    preview_policy: Option<SessionCompactionPolicy>,
) -> SessionCompactionSnapshot {
    build_session_compaction_snapshot(
        memory_runtime,
        sessions,
        active_session_id,
        preview_policy,
        true,
    )
}

pub fn compact_retained_session_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
    policy: Option<SessionCompactionPolicy>,
) -> Result<SessionCompactionSnapshot, String> {
    let selected =
        selected_summary_for_compaction(&sessions, active_session_id, requested_session_id)?;
    let selected_session_id = selected.session_id.clone();
    let policy = policy.unwrap_or_default();
    let record = build_compaction_record(
        memory_runtime,
        selected,
        SessionCompactionMode::Manual,
        &policy,
    );
    orchestrator::append_session_compaction_record(
        memory_runtime,
        Some(selected_session_id.as_str()),
        record,
    );
    Ok(build_session_compaction_snapshot(
        memory_runtime,
        sessions,
        active_session_id.or(Some(selected_session_id.as_str())),
        Some(policy),
        false,
    ))
}

fn team_memory_scope_for_summary(
    summary: &SessionSummary,
    preview: &SessionCompactionPreview,
) -> (TeamMemoryScopeKind, String, String) {
    let workspace_root = preview
        .carried_forward_state
        .workspace_root
        .as_deref()
        .or(summary.workspace_root.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(workspace_root) = workspace_root {
        let scope_digest = sha256(workspace_root.as_bytes())
            .map(hex::encode)
            .unwrap_or_else(|_| workspace_root.to_string());
        let scope_label = Path::new(workspace_root)
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("Workspace {}", value))
            .unwrap_or_else(|| "Workspace".to_string());
        return (
            TeamMemoryScopeKind::Workspace,
            format!("workspace:{scope_digest}"),
            scope_label,
        );
    }

    let session_title = title_for_session(summary);
    (
        TeamMemoryScopeKind::Session,
        format!("session:{}", summary.session_id),
        format!("Session {session_title}"),
    )
}

fn normalized_team_memory_actor_component(raw: &str) -> String {
    let mut normalized = raw
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while normalized.contains("--") {
        normalized = normalized.replace("--", "-");
    }
    normalized.trim_matches('-').to_string()
}

fn team_memory_actor_id(actor_label: &str, actor_role: &str) -> String {
    let label = normalized_team_memory_actor_component(actor_label);
    let role = normalized_team_memory_actor_component(actor_role);
    let label = if label.is_empty() {
        "autopilot".to_string()
    } else {
        label
    };
    let role = if role.is_empty() {
        "operator".to_string()
    } else {
        role
    };
    format!("autopilot://team-memory/{label}/{role}")
}

fn trim_token_edge_char(ch: char) -> bool {
    matches!(
        ch,
        '"' | '\''
            | '`'
            | ','
            | '.'
            | ';'
            | ':'
            | '!'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
    )
}

fn trim_token_bounds(input: &str, mut start: usize, mut end: usize) -> Option<(usize, usize)> {
    while start < end {
        let ch = input[start..].chars().next()?;
        if trim_token_edge_char(ch) {
            start += ch.len_utf8();
        } else {
            break;
        }
    }
    while start < end {
        let ch = input[..end].chars().next_back()?;
        if trim_token_edge_char(ch) {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }
    (start < end).then_some((start, end))
}

fn whitespace_token_spans(input: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut token_start = None;
    for (index, ch) in input.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                spans.push((start, index));
            }
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        spans.push((start, input.len()));
    }
    spans
}

fn team_memory_detection_spans(input: &str) -> Vec<(usize, usize, String)> {
    let mut spans = Vec::new();
    for (raw_start, raw_end) in whitespace_token_spans(input) {
        let Some((start, end)) = trim_token_bounds(input, raw_start, raw_end) else {
            continue;
        };
        let token = &input[start..end];
        if token.is_empty() {
            continue;
        }

        let lower = token.to_ascii_lowercase();
        if let Some(at_index) = token.find('@') {
            let domain = &token[at_index + 1..];
            if at_index > 0 && domain.contains('.') {
                spans.push((start, end, "EMAIL".to_string()));
                continue;
            }
        }

        if token.starts_with("/home/")
            || token.starts_with("/Users/")
            || token.contains("C:\\Users\\")
        {
            spans.push((start, end, "ADDRESS".to_string()));
            continue;
        }

        if lower.starts_with("sk-")
            || lower.starts_with("ghp_")
            || lower.starts_with("tok_")
            || lower.starts_with("xoxb-")
            || lower.starts_with("xoxp-")
        {
            spans.push((start, end, "SECRET_TOKEN".to_string()));
            continue;
        }

        for marker in ["api_key=", "apikey=", "token=", "secret=", "password="] {
            if let Some(offset) = lower.find(marker) {
                let value_start = start + offset + marker.len();
                if value_start < end {
                    let category = if marker.starts_with("api") {
                        "API_KEY"
                    } else {
                        "SECRET_TOKEN"
                    };
                    spans.push((value_start, end, category.to_string()));
                }
            }
        }
    }

    spans.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let mut merged = Vec::new();
    for (start, end, category) in spans {
        if start >= end || end > input.len() {
            continue;
        }
        if let Some((_, last_end, last_category)) = merged.last_mut() {
            if start <= *last_end {
                if end > *last_end {
                    *last_end = end;
                }
                if last_category != &category
                    && (last_category == "SECRET_TOKEN"
                        || last_category == "API_KEY"
                        || category == "SECRET_TOKEN"
                        || category == "API_KEY")
                {
                    *last_category = "SECRET_TOKEN".to_string();
                }
                continue;
            }
        }
        merged.push((start, end, category));
    }
    merged
}

fn team_memory_redacted_fields(map: &ioi_types::app::RedactionMap) -> Vec<String> {
    let mut fields = BTreeSet::new();
    for entry in &map.entries {
        let label = match &entry.redaction_type {
            RedactionType::Pii => "pii".to_string(),
            RedactionType::Secret => "secret".to_string(),
            RedactionType::Custom(custom) => format!("custom:{custom}"),
        };
        fields.insert(label);
    }
    fields.into_iter().collect()
}

fn scrub_team_memory_text(input: &str) -> (String, usize, Vec<String>) {
    let detections = team_memory_detection_spans(input);
    if detections.is_empty() {
        return (input.trim().to_string(), 0, Vec::new());
    }

    match scrub_text(input, &detections) {
        Ok((scrubbed, map)) => (
            scrubbed.trim().to_string(),
            map.entries.len(),
            team_memory_redacted_fields(&map),
        ),
        Err(_) => (
            "<REDACTED:custom>".to_string(),
            1,
            vec!["scrubber_failure".to_string()],
        ),
    }
}

fn shared_team_memory_items(
    preview: &SessionCompactionPreview,
    include_governance_critical: bool,
) -> (Vec<SessionCompactionMemoryItem>, usize, usize, Vec<String>) {
    let mut items = Vec::new();
    let mut omitted_governance_item_count = 0usize;
    let mut redaction_count = 0usize;
    let mut redacted_fields = BTreeSet::new();

    for item in &preview.carried_forward_state.memory_items {
        if item.values.is_empty() || matches!(item.memory_class, SessionMemoryClass::Ephemeral) {
            continue;
        }
        if matches!(item.memory_class, SessionMemoryClass::GovernanceCritical)
            && !include_governance_critical
        {
            omitted_governance_item_count += 1;
            continue;
        }

        let mut next = item.clone();
        next.values = next
            .values
            .iter()
            .filter_map(|value| compaction_excerpt(value, TEAM_MEMORY_SYNC_MAX_ITEM_VALUE_CHARS))
            .take(TEAM_MEMORY_SYNC_MAX_ITEM_VALUES)
            .map(|value| {
                let (scrubbed, count, fields) = scrub_team_memory_text(&value);
                redaction_count += count;
                redacted_fields.extend(fields);
                scrubbed
            })
            .collect();
        if !next.values.is_empty() {
            items.push(next);
        }
    }

    (
        items,
        omitted_governance_item_count,
        redaction_count,
        redacted_fields.into_iter().collect(),
    )
}

fn build_team_memory_summary(
    scope_label: &str,
    preview: &SessionCompactionPreview,
    shared_items: &[SessionCompactionMemoryItem],
    omitted_governance_item_count: usize,
) -> String {
    let mut lines = vec![
        format!("Scope: {scope_label}."),
        preview.summary.clone(),
        format!("Resume anchor: {}.", preview.resume_anchor),
    ];

    if !shared_items.is_empty() {
        let item_summary = shared_items
            .iter()
            .map(|item| format!("{}: {}", item.label, item.values.join(" | ")))
            .collect::<Vec<_>>()
            .join(" || ");
        lines.push(format!("Shared memory items: {item_summary}."));
    }

    if omitted_governance_item_count > 0 {
        lines.push(format!(
            "{omitted_governance_item_count} governance-critical memory item(s) stayed local."
        ));
    }

    lines.join(" ")
}

fn build_team_memory_review_summary(
    actor_label: &str,
    sync_status: &TeamMemorySyncStatus,
    omitted_governance_item_count: usize,
    redaction_count: usize,
) -> String {
    match sync_status {
        TeamMemorySyncStatus::ReviewRequired => format!(
            "Synced by {actor_label} with governance-critical context included. Review before wider promotion."
        ),
        TeamMemorySyncStatus::Redacted if omitted_governance_item_count > 0 => format!(
            "Synced by {actor_label} after local redaction; {omitted_governance_item_count} governance-critical item(s) stayed local."
        ),
        TeamMemorySyncStatus::Redacted => format!(
            "Synced by {actor_label} after local redaction ({redaction_count} redaction(s))."
        ),
        TeamMemorySyncStatus::Synced if omitted_governance_item_count > 0 => format!(
            "Synced by {actor_label}; {omitted_governance_item_count} governance-critical item(s) stayed local."
        ),
        TeamMemorySyncStatus::Synced => {
            format!("Synced by {actor_label} with no additional redaction required.")
        }
    }
}

fn build_team_memory_entry(
    summary: &SessionSummary,
    preview: &SessionCompactionPreview,
    actor_label: Option<String>,
    actor_role: Option<String>,
    include_governance_critical: bool,
) -> TeamMemorySyncEntry {
    let actor_label = actor_label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Autopilot".to_string());
    let actor_role = actor_role
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "operator".to_string());
    let actor_id = team_memory_actor_id(&actor_label, &actor_role);
    let (scope_kind, scope_id, scope_label) = team_memory_scope_for_summary(summary, preview);
    let (
        shared_memory_items,
        omitted_governance_item_count,
        item_redaction_count,
        item_redacted_fields,
    ) = shared_team_memory_items(preview, include_governance_critical);

    let raw_summary = build_team_memory_summary(
        &scope_label,
        preview,
        &shared_memory_items,
        omitted_governance_item_count,
    );
    let (summary_text, summary_redaction_count, summary_redacted_fields) =
        scrub_team_memory_text(&raw_summary);
    let (resume_anchor, resume_anchor_redaction_count, resume_anchor_redacted_fields) =
        scrub_team_memory_text(&preview.resume_anchor);
    let (
        pre_compaction_span,
        pre_compaction_span_redaction_count,
        pre_compaction_span_redacted_fields,
    ) = scrub_team_memory_text(&preview.pre_compaction_span);

    let mut redacted_fields = BTreeSet::new();
    redacted_fields.extend(item_redacted_fields);
    redacted_fields.extend(summary_redacted_fields);
    redacted_fields.extend(resume_anchor_redacted_fields);
    redacted_fields.extend(pre_compaction_span_redacted_fields);

    let redaction_count = item_redaction_count
        + summary_redaction_count
        + resume_anchor_redaction_count
        + pre_compaction_span_redaction_count;
    let governance_included = include_governance_critical
        && preview
            .carried_forward_state
            .memory_items
            .iter()
            .any(|item| matches!(item.memory_class, SessionMemoryClass::GovernanceCritical));
    let sync_status = if governance_included {
        TeamMemorySyncStatus::ReviewRequired
    } else if redaction_count > 0 {
        TeamMemorySyncStatus::Redacted
    } else {
        TeamMemorySyncStatus::Synced
    };
    let review_summary = build_team_memory_review_summary(
        &actor_label,
        &sync_status,
        omitted_governance_item_count,
        redaction_count,
    );

    TeamMemorySyncEntry {
        entry_id: Uuid::new_v4().to_string(),
        session_id: summary.session_id.clone(),
        session_title: preview.title.clone(),
        synced_at_ms: crate::kernel::state::now(),
        scope_kind,
        scope_id,
        scope_label,
        actor_id,
        actor_label,
        actor_role,
        sync_status,
        review_summary: compaction_excerpt(&review_summary, 180).unwrap_or(review_summary),
        omitted_governance_item_count,
        resume_anchor: compaction_excerpt(&resume_anchor, 180).unwrap_or(resume_anchor),
        pre_compaction_span: compaction_excerpt(&pre_compaction_span, 180)
            .unwrap_or(pre_compaction_span),
        summary: compaction_excerpt(&summary_text, 640).unwrap_or(summary_text),
        shared_memory_items,
        redaction: TeamMemoryRedactionSummary {
            redaction_count,
            redacted_fields: redacted_fields.into_iter().collect(),
            redaction_version: TEAM_MEMORY_SYNC_REDACTION_VERSION.to_string(),
        },
    }
}

fn build_team_memory_snapshot(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    selected_summary: Option<&SessionSummary>,
) -> TeamMemorySyncSnapshot {
    let stored_entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    let (active_scope_kind, active_scope_id, active_scope_label) = if let Some(summary) =
        selected_summary
    {
        let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
        let preview = build_compaction_preview_from_context(
            summary,
            local_task.as_ref(),
            &file_context,
            &SessionCompactionPolicy::default(),
        );
        let (scope_kind, scope_id, scope_label) = team_memory_scope_for_summary(summary, &preview);
        (Some(scope_kind), Some(scope_id), Some(scope_label))
    } else {
        (None, None, None)
    };

    let entries = if let Some(scope_id) = active_scope_id.as_deref() {
        stored_entries
            .into_iter()
            .filter(|entry| entry.scope_id == scope_id)
            .take(12)
            .collect::<Vec<_>>()
    } else {
        stored_entries.into_iter().take(12).collect::<Vec<_>>()
    };

    let redacted_entry_count = entries
        .iter()
        .filter(|entry| matches!(entry.sync_status, TeamMemorySyncStatus::Redacted))
        .count();
    let review_required_count = entries
        .iter()
        .filter(|entry| matches!(entry.sync_status, TeamMemorySyncStatus::ReviewRequired))
        .count();
    let actor_count = entries
        .iter()
        .map(|entry| entry.actor_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let summary = match (active_scope_label.as_deref(), entries.len()) {
        (Some(scope_label), 0) => {
            format!("No team memory entries are synced yet for {scope_label}.")
        }
        (Some(scope_label), count) => format!(
            "{scope_label} currently has {count} synced team-memory entr{} across {actor_count} actor(s).",
            if count == 1 { "y" } else { "ies" }
        ),
        (None, 0) => {
            "No retained team-memory entries exist yet. Sync a retained session to start the shared ledger."
                .to_string()
        }
        (None, count) => format!(
            "Showing {count} recent team-memory entr{} across {actor_count} actor(s).",
            if count == 1 { "y" } else { "ies" }
        ),
    };

    TeamMemorySyncSnapshot {
        generated_at_ms: crate::kernel::state::now(),
        active_session_id: selected_summary.map(|summary| summary.session_id.clone()),
        active_scope_id,
        active_scope_kind,
        active_scope_label,
        entry_count: entries.len(),
        redacted_entry_count,
        review_required_count,
        summary,
        entries,
    }
}

pub fn team_memory_snapshot_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let selected = if sessions.is_empty() {
        None
    } else {
        Some(selected_summary_for_compaction(
            &sessions,
            active_session_id,
            requested_session_id,
        )?)
    };
    Ok(build_team_memory_snapshot(memory_runtime, selected))
}

pub fn sync_team_memory_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
    actor_label: Option<String>,
    actor_role: Option<String>,
    include_governance_critical: bool,
) -> Result<TeamMemorySyncSnapshot, String> {
    let selected =
        selected_summary_for_compaction(&sessions, active_session_id, requested_session_id)?;
    let (local_task, file_context) = load_compaction_context(memory_runtime, selected);
    let preview = build_compaction_preview_from_context(
        selected,
        local_task.as_ref(),
        &file_context,
        &SessionCompactionPolicy::default(),
    );
    let entry = build_team_memory_entry(
        selected,
        &preview,
        actor_label,
        actor_role,
        include_governance_critical,
    );

    let mut entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    entries.retain(|existing| {
        !(existing.session_id == entry.session_id
            && existing.scope_id == entry.scope_id
            && existing.actor_id == entry.actor_id)
    });
    entries.insert(0, entry);
    if entries.len() > TEAM_MEMORY_SYNC_MAX_ENTRIES {
        entries.truncate(TEAM_MEMORY_SYNC_MAX_ENTRIES);
    }
    orchestrator::save_team_memory_sync_entries(memory_runtime, &entries);
    Ok(build_team_memory_snapshot(memory_runtime, Some(selected)))
}

pub fn forget_team_memory_entry_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
    entry_id: &str,
) -> Result<TeamMemorySyncSnapshot, String> {
    let mut entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    entries.retain(|entry| entry.entry_id != entry_id.trim());
    orchestrator::save_team_memory_sync_entries(memory_runtime, &entries);

    let selected = if sessions.is_empty() {
        None
    } else {
        Some(selected_summary_for_compaction(
            &sessions,
            active_session_id,
            requested_session_id,
        )?)
    };
    Ok(build_team_memory_snapshot(memory_runtime, selected))
}

fn build_session_rewind_snapshot(
    sessions: Vec<SessionSummary>,
    current_task: Option<&crate::models::AgentTask>,
) -> SessionRewindSnapshot {
    let active_session_id =
        current_task.and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let active_session_title = active_session_id.as_ref().and_then(|session_id| {
        sessions
            .iter()
            .find(|summary| &summary.session_id == session_id)
            .map(title_for_session)
            .or_else(|| {
                current_task.and_then(|task| {
                    let title = task.intent.trim();
                    if title.is_empty() {
                        None
                    } else {
                        Some(title.to_string())
                    }
                })
            })
    });

    let last_stable_session_id = sessions
        .iter()
        .find(|summary| stable_session(summary, active_session_id.as_deref()))
        .map(|summary| summary.session_id.clone());

    let candidates = sessions
        .into_iter()
        .take(12)
        .map(|summary| {
            let is_current = active_session_id.as_deref() == Some(summary.session_id.as_str());
            let is_last_stable =
                last_stable_session_id.as_deref() == Some(summary.session_id.as_str());
            let summary_title = title_for_session(&summary);
            let preview_detail = session_preview_detail(&summary);
            let preview_headline = if is_current {
                "Reload the current retained session.".to_string()
            } else if is_last_stable {
                "Rewind shell focus to the last stable retained session.".to_string()
            } else {
                "Reattach this retained session in Spotlight.".to_string()
            };
            let discard_summary = match active_session_title.as_ref() {
                Some(active_title) if !is_current => format!(
                    "Replaces the active Spotlight session focus from \"{active_title}\" with this retained session. Retained evidence and other sessions stay stored."
                ),
                _ => "Refreshes this retained session without deleting evidence or other session history.".to_string(),
            };
            let action_label = if is_current {
                "Reload current session".to_string()
            } else if is_last_stable {
                "Rewind to this session".to_string()
            } else {
                "Open retained session".to_string()
            };

            SessionRewindCandidate {
                session_id: summary.session_id,
                title: summary_title,
                timestamp: summary.timestamp,
                phase: summary.phase,
                current_step: summary.current_step,
                resume_hint: summary.resume_hint,
                workspace_root: summary.workspace_root,
                is_current,
                is_last_stable,
                action_label,
                preview_headline,
                preview_detail,
                discard_summary,
            }
        })
        .collect();

    SessionRewindSnapshot {
        active_session_id,
        active_session_title,
        last_stable_session_id,
        candidates,
    }
}

async fn refresh_cached_session_history(state: &State<'_, Mutex<AppState>>) -> Vec<SessionSummary> {
    let mut all_sessions = {
        let memory_runtime = state
            .lock()
            .ok()
            .and_then(|guard| guard.memory_runtime.clone());
        local_session_history_snapshot(memory_runtime.as_ref())
    };

    match fetch_remote_session_history(state).await {
        Ok(remote_sessions) => {
            merge_remote_session_history(&mut all_sessions, remote_sessions);
        }
        Err(error) => {
            eprintln!("[Kernel] {}", error);
        }
    }

    all_sessions.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    if let Ok(mut guard) = state.lock() {
        guard.session_history_projection = all_sessions.clone();
    }
    all_sessions
}

async fn refresh_cached_session_history_with_change(
    state: &State<'_, Mutex<AppState>>,
) -> (Vec<SessionSummary>, bool) {
    let previous_sessions = cached_session_history_snapshot(state);
    let refreshed_sessions = refresh_cached_session_history(state).await;
    let changed = refreshed_sessions != previous_sessions;
    (refreshed_sessions, changed)
}

pub async fn emit_session_projection_update(app: &AppHandle, refresh_history: bool) {
    let state = app.state::<Mutex<AppState>>();
    let sessions = if refresh_history {
        refresh_cached_session_history(&state).await
    } else {
        projected_cached_session_history(&state)
    };

    let projection = SessionProjection {
        task: current_task_snapshot(&state),
        sessions,
    };
    let _ = app.emit("session-projection-updated", &projection);
}

pub async fn emit_session_projection_update_if_history_changed(
    app: &AppHandle,
    reason: &str,
) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let should_refresh = match state.lock() {
        Ok(mut guard) => {
            if guard.session_projection_refresh_in_flight {
                false
            } else {
                guard.session_projection_refresh_in_flight = true;
                true
            }
        }
        Err(_) => false,
    };

    if !should_refresh {
        return false;
    }

    let (sessions, changed) = refresh_cached_session_history_with_change(&state).await;
    if let Ok(mut guard) = state.lock() {
        guard.session_projection_refresh_in_flight = false;
    }

    if !changed {
        return false;
    }

    println!(
        "[Kernel] Session projection refreshed via {} ({} sessions)",
        reason,
        sessions.len()
    );
    let projection = SessionProjection {
        task: current_task_snapshot(&state),
        sessions,
    };
    let _ = app.emit("session-projection-updated", &projection);
    true
}

pub async fn spawn_session_projection_monitor(app: AppHandle) {
    loop {
        tokio::time::sleep(Duration::from_millis(SESSION_HISTORY_MONITOR_INTERVAL_MS)).await;
        let _ = emit_session_projection_update_if_history_changed(&app, "monitor").await;
    }
}

#[tauri::command]
pub async fn get_session_history(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    Ok(refresh_cached_session_history(&state).await)
}

#[tauri::command]
pub async fn get_session_projection(
    state: State<'_, Mutex<AppState>>,
) -> Result<SessionProjection, String> {
    Ok(SessionProjection {
        task: current_task_snapshot(&state),
        sessions: refresh_cached_session_history(&state).await,
    })
}

#[tauri::command]
pub async fn get_session_rewind_snapshot(
    state: State<'_, Mutex<AppState>>,
) -> Result<SessionRewindSnapshot, String> {
    let current_task = current_task_snapshot(&state);
    let sessions = refresh_cached_session_history(&state).await;
    Ok(build_session_rewind_snapshot(
        sessions,
        current_task.as_ref(),
    ))
}

#[tauri::command]
pub async fn get_session_compaction_snapshot(
    state: State<'_, Mutex<AppState>>,
    policy: Option<SessionCompactionPolicy>,
) -> Result<SessionCompactionSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for compaction.".to_string())?;
    Ok(session_compaction_snapshot_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        policy,
    ))
}

#[tauri::command]
pub async fn compact_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: Option<String>,
    policy: Option<SessionCompactionPolicy>,
) -> Result<SessionCompactionSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for compaction.".to_string())?;
    let snapshot = compact_retained_session_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
        policy,
    )?;
    let _ = app.emit("session-compaction-updated", &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn get_team_memory_snapshot(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for team memory sync.".to_string())?;
    team_memory_snapshot_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
    )
}

#[tauri::command]
pub async fn sync_team_memory(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: Option<String>,
    actor_label: Option<String>,
    actor_role: Option<String>,
    include_governance_critical: Option<bool>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for team memory sync.".to_string())?;
    let snapshot = sync_team_memory_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
        actor_label,
        actor_role,
        include_governance_critical.unwrap_or(false),
    )?;
    let _ = app.emit("team-memory-updated", &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn forget_team_memory_entry(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    entry_id: String,
    session_id: Option<String>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for team memory sync.".to_string())?;
    let snapshot = forget_team_memory_entry_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
        &entry_id,
    )?;
    let _ = app.emit("team-memory-updated", &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn load_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<crate::models::AgentTask, String> {
    use crate::kernel::state::hydrate_session_history;
    use crate::models::{AgentPhase, AgentTask};
    use std::collections::HashSet;
    use tauri::Emitter;

    let mut loaded_task = {
        let guard = state.lock().map_err(|_| "Lock fail")?;
        guard
            .memory_runtime
            .as_ref()
            .and_then(|memory_runtime| orchestrator::load_local_task(memory_runtime, &session_id))
    };

    if loaded_task.is_none() {
        println!(
            "[Kernel] Session {} not found locally, attempting remote hydrate...",
            session_id
        );
        if let Ok(mut client) = get_rpc_client(&state).await {
            let history = hydrate_session_history(&mut client, &session_id)
                .await
                .unwrap_or_default();
            if !history.is_empty() {
                let mut task = AgentTask {
                    id: session_id.clone(),
                    intent: history
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or("Restored Session".into()),
                    agent: "Restored".into(),
                    phase: AgentPhase::Complete,
                    progress: history.len() as u32,
                    total_steps: history.len() as u32,
                    current_step: "Session loaded from Kernel.".into(),
                    gate_info: None,
                    receipt: None,
                    visual_hash: None,
                    pending_request_hash: None,
                    session_id: Some(session_id.clone()),
                    credential_request: None,
                    clarification_request: None,
                    session_checklist: Vec::new(),
                    background_tasks: Vec::new(),
                    history,
                    events: Vec::new(),
                    artifacts: Vec::new(),
                    chat_session: None,
                    chat_outcome: None,
                    renderer_session: None,
                    build_session: None,
                    run_bundle_id: None,
                    processed_steps: HashSet::new(),
                    swarm_tree: Vec::new(),
                    generation: 0,
                    lineage_id: "unknown-remote".to_string(),
                    fitness_score: 0.0,
                };
                task.sync_runtime_views();
                loaded_task = Some(task);
            }
        }
    }

    if let Some(mut task) = loaded_task {
        task.sync_runtime_views();
        {
            let mut app_state = state.lock().map_err(|_| "Lock fail")?;
            app_state.current_task = Some(task.clone());
        }
        let _ = app.emit("task-started", &task);
        emit_session_projection_update(&app, true).await;
        return Ok(task);
    }

    Err(format!(
        "Session {} not found locally or remotely",
        session_id
    ))
}

#[tauri::command]
pub async fn delete_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<(), String> {
    if let Ok(guard) = state.lock() {
        if let Some(memory_runtime) = guard.memory_runtime.as_ref() {
            orchestrator::delete_local_session_summary(memory_runtime, &session_id);
        }
    }

    if let Ok(mut client) = get_rpc_client(&state).await {
        let session_bytes = hex::decode(&session_id).unwrap_or_default();
        if !session_bytes.is_empty() {
            let keypair = identity::load_identity_keypair_for_app(&app)?;
            let pk_bytes = keypair.public().encode_protobuf();
            let account_id = ioi_types::app::AccountId(
                account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
                    .map_err(|e| e.to_string())?,
            );

            let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
            let nonce = match client
                .query_raw_state(tonic::Request::new(QueryRawStateRequest { key: nonce_key }))
                .await
            {
                Ok(resp) => {
                    let val = resp.into_inner().value;
                    if val.is_empty() {
                        0
                    } else {
                        codec::from_bytes_canonical::<u64>(&val).unwrap_or(0)
                    }
                }
                Err(_) => 0,
            };

            let payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "delete_session@v1".to_string(),
                params: session_bytes,
            };

            let mut sys_tx = SystemTransaction {
                header: SignHeader {
                    account_id,
                    nonce,
                    chain_id: ChainId(0),
                    tx_version: 1,
                    session_auth: None,
                },
                payload,
                signature_proof: SignatureProof::default(),
            };

            let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| e.to_string())?;
            let sig = keypair.sign(&sign_bytes).map_err(|e| e.to_string())?;

            sys_tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: pk_bytes,
                signature: sig,
            };

            let tx = ChainTransaction::System(Box::new(sys_tx));
            let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())?;

            client
                .submit_transaction(tonic::Request::new(
                    ioi_ipc::public::SubmitTransactionRequest {
                        transaction_bytes: tx_bytes,
                    },
                ))
                .await
                .map_err(|e| e.to_string())?;

            println!(
                "[Kernel] Remote delete transaction submitted for session {}",
                session_id
            );
        }
    }

    emit_session_projection_update(&app, true).await;
    Ok(())
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;
