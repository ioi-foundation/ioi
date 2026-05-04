use ioi_types::app::agentic::PiiTarget;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use ts_rs::TS;

use super::chat::{BuildArtifactSession, ChatArtifactSession, ChatRendererSession};
use super::events::{AgentEvent, Artifact, Receipt};
use crate::models::{ChatMessage, ChatOutcomeRequest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub enum AgentPhase {
    Idle,
    Running,
    Gate,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInfo {
    pub title: String,
    pub description: String,
    pub risk: String,
    #[serde(default)]
    pub approve_label: Option<String>,
    #[serde(default)]
    pub deny_label: Option<String>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub surface_label: Option<String>,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub operation_label: Option<String>,
    #[serde(default)]
    pub target_label: Option<String>,
    #[serde(default)]
    pub operator_note: Option<String>,
    #[serde(default)]
    pub pii: Option<PiiReviewInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiReviewInfo {
    pub decision_hash: String,
    pub target_label: String,
    pub span_summary: String,
    #[serde(default)]
    pub class_counts: std::collections::BTreeMap<String, u32>,
    #[serde(default)]
    pub severity_counts: std::collections::BTreeMap<String, u32>,
    pub stage2_prompt: String,
    pub deadline_ms: u64,
    #[serde(default)]
    pub target_id: Option<PiiTarget>,
}

// Represents a node in the hierarchical work graph visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkGraphAgent {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub role: String,
    pub status: String, // "running", "completed", "failed", "requisition"
    pub budget_used: f64,
    pub budget_cap: f64,
    pub current_thought: Option<String>,
    #[serde(default)]
    pub artifacts_produced: u32,
    #[serde(default)]
    pub estimated_cost: f64,
    #[serde(default)]
    pub policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub kind: String,
    pub prompt: String,
    #[serde(default)]
    pub one_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationOption {
    pub id: String,
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub recommended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationRequest {
    pub kind: String,
    pub question: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub failure_class: Option<String>,
    #[serde(default)]
    pub evidence_snippet: Option<String>,
    #[serde(default)]
    pub context_hint: Option<String>,
    #[serde(default)]
    pub options: Vec<ClarificationOption>,
    #[serde(default)]
    pub allow_other: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionChecklistItem {
    pub item_id: String,
    pub label: String,
    pub status: String,
    #[serde(default)]
    pub detail: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionBackgroundTaskRecord {
    pub task_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub label: String,
    pub status: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub latest_output: Option<String>,
    #[serde(default)]
    pub can_stop: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionFileContext {
    #[serde(default)]
    pub session_id: Option<String>,
    pub workspace_root: String,
    #[serde(default)]
    pub pinned_files: Vec<String>,
    #[serde(default)]
    pub recent_files: Vec<String>,
    #[serde(default)]
    pub explicit_includes: Vec<String>,
    #[serde(default)]
    pub explicit_excludes: Vec<String>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub intent: String,
    pub agent: String,
    pub phase: AgentPhase,
    pub progress: u32,
    pub total_steps: u32,
    pub current_step: String,
    pub gate_info: Option<GateInfo>,
    pub receipt: Option<Receipt>,
    pub visual_hash: Option<String>,
    pub pending_request_hash: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub credential_request: Option<CredentialRequest>,
    #[serde(default)]
    pub clarification_request: Option<ClarificationRequest>,

    #[serde(default)]
    pub session_checklist: Vec<SessionChecklistItem>,

    #[serde(default)]
    pub background_tasks: Vec<SessionBackgroundTaskRecord>,

    // History source of truth.
    // This is populated by hydrating from the blockchain state (Audit Log).
    #[serde(default)]
    pub history: Vec<ChatMessage>,

    // New immutable event stream (canonical for new runs).
    #[serde(default)]
    pub events: Vec<AgentEvent>,

    // Macro artifacts for this thread.
    #[serde(default)]
    pub artifacts: Vec<Artifact>,

    #[serde(default)]
    pub chat_session: Option<ChatArtifactSession>,

    #[serde(default)]
    pub chat_outcome: Option<ChatOutcomeRequest>,

    #[serde(default)]
    pub renderer_session: Option<ChatRendererSession>,

    #[serde(default)]
    pub build_session: Option<BuildArtifactSession>,

    // Run bundle artifact pointer (if created).
    #[serde(default)]
    pub run_bundle_id: Option<String>,

    // Track processed steps using a composite key "{step}:{tool}"
    #[serde(skip, default)]
    pub processed_steps: HashSet<String>,

    // The hierarchical work graph state for WorkGraphViz.
    #[serde(default, alias = "swarm_tree")]
    pub work_graph_tree: Vec<WorkGraphAgent>,

    // Evolutionary Metadata (Genetics)
    #[serde(default)]
    pub generation: u64,

    #[serde(default = "default_lineage")]
    pub lineage_id: String,

    #[serde(default)]
    pub fitness_score: f32,
}

fn runtime_view_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn install_summary_from_runtime_detail(value: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(first_json_object_slice(value)?).ok()?;
    if parsed.get("install_event").is_none() && parsed.get("install_final_receipt").is_none() {
        return None;
    }
    parsed
        .get("summary")
        .and_then(|summary| summary.as_str())
        .map(|summary| format!("Install blocked: {summary}"))
}

fn first_json_object_slice(value: &str) -> Option<&str> {
    let start = value.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in value[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = start + offset + ch.len_utf8();
                    return Some(&value[start..end]);
                }
            }
            _ => {}
        }
    }
    None
}

fn truncate_detail_value(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}...", shortened)
    } else {
        value.to_string()
    }
}

fn truncated_runtime_detail(value: &str, max_chars: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let display_value =
        install_summary_from_runtime_detail(trimmed).unwrap_or_else(|| trimmed.to_string());
    Some(truncate_detail_value(&display_value, max_chars))
}

fn latest_task_output_excerpt(task: &AgentTask) -> Option<String> {
    task.history
        .iter()
        .rev()
        .find(|message| {
            !message.text.trim().is_empty()
                && matches!(message.role.as_str(), "assistant" | "agent" | "system")
        })
        .and_then(|message| truncated_runtime_detail(&message.text, 120))
        .or_else(|| truncated_runtime_detail(&task.current_step, 120))
}

fn checklist_request_item(task: &AgentTask, updated_at_ms: u64) -> SessionChecklistItem {
    SessionChecklistItem {
        item_id: "request".to_string(),
        label: "Request captured".to_string(),
        status: "completed".to_string(),
        detail: truncated_runtime_detail(&task.intent, 96),
        updated_at_ms,
    }
}

fn checklist_execution_item(task: &AgentTask, updated_at_ms: u64) -> SessionChecklistItem {
    let is_blocked = task.clarification_request.is_some()
        || task.credential_request.is_some()
        || task.phase == AgentPhase::Gate
        || task.pending_request_hash.is_some();
    let status = if is_blocked {
        "blocked"
    } else {
        match task.phase {
            AgentPhase::Idle => "pending",
            AgentPhase::Running => "in_progress",
            AgentPhase::Gate => "blocked",
            AgentPhase::Complete => "completed",
            AgentPhase::Failed => "failed",
        }
    };

    let detail = if matches!(task.phase, AgentPhase::Complete | AgentPhase::Failed) {
        truncated_runtime_detail(&task.current_step, 120)
            .or_else(|| latest_task_output_excerpt(task))
    } else {
        truncated_runtime_detail(&task.current_step, 120)
    };

    SessionChecklistItem {
        item_id: "execution".to_string(),
        label: if is_blocked {
            "Resolve blocker".to_string()
        } else {
            match task.phase {
                AgentPhase::Failed => "Execution failed".to_string(),
                AgentPhase::Complete => "Execution complete".to_string(),
                _ => "Continue execution".to_string(),
            }
        },
        status: status.to_string(),
        detail,
        updated_at_ms,
    }
}

fn checklist_interruption_item(
    task: &AgentTask,
    updated_at_ms: u64,
) -> Option<SessionChecklistItem> {
    if let Some(request) = task.clarification_request.as_ref() {
        return Some(SessionChecklistItem {
            item_id: "clarification".to_string(),
            label: "Resolve clarification".to_string(),
            status: "blocked".to_string(),
            detail: truncated_runtime_detail(&request.question, 120),
            updated_at_ms,
        });
    }

    if let Some(request) = task.credential_request.as_ref() {
        return Some(SessionChecklistItem {
            item_id: "credential".to_string(),
            label: "Provide runtime credential".to_string(),
            status: "blocked".to_string(),
            detail: truncated_runtime_detail(&request.prompt, 120)
                .or_else(|| truncated_runtime_detail(&request.kind, 80)),
            updated_at_ms,
        });
    }

    if task.phase == AgentPhase::Gate || task.pending_request_hash.is_some() {
        return Some(SessionChecklistItem {
            item_id: "approval".to_string(),
            label: "Review approval".to_string(),
            status: "blocked".to_string(),
            detail: task
                .gate_info
                .as_ref()
                .and_then(|gate| {
                    truncated_runtime_detail(&gate.description, 120)
                        .or_else(|| truncated_runtime_detail(&gate.title, 80))
                })
                .or_else(|| Some("Execution is waiting on operator approval.".to_string())),
            updated_at_ms,
        });
    }

    None
}

fn checklist_review_item(task: &AgentTask, updated_at_ms: u64) -> SessionChecklistItem {
    let latest_output = latest_task_output_excerpt(task);
    let is_blocked = task.clarification_request.is_some()
        || task.credential_request.is_some()
        || task.phase == AgentPhase::Gate
        || task.pending_request_hash.is_some();
    let (label, status, detail) = match task.phase {
        AgentPhase::Complete => (
            "Review latest output",
            "completed",
            latest_output
                .or_else(|| Some("Run finished without a retained output excerpt.".to_string())),
        ),
        AgentPhase::Failed => (
            "Decide next step",
            "blocked",
            Some("Retry the run or start a new session once the blocker is addressed.".to_string()),
        ),
        AgentPhase::Running | AgentPhase::Gate => (
            if is_blocked {
                "Resume execution"
            } else {
                "Review emerging output"
            },
            if is_blocked { "blocked" } else { "pending" },
            if is_blocked {
                checklist_interruption_item(task, updated_at_ms)
                    .and_then(|item| item.detail)
                    .or_else(|| Some("Answer the blocker so the runtime can continue.".to_string()))
            } else {
                latest_output.or_else(|| {
                    Some("Waiting for the next retained output from the runtime.".to_string())
                })
            },
        ),
        AgentPhase::Idle => (
            "Await next request",
            "pending",
            Some("Start or resume a session to produce output.".to_string()),
        ),
    };

    SessionChecklistItem {
        item_id: "review".to_string(),
        label: label.to_string(),
        status: status.to_string(),
        detail,
        updated_at_ms,
    }
}

fn build_session_checklist(task: &AgentTask, updated_at_ms: u64) -> Vec<SessionChecklistItem> {
    let mut items = vec![checklist_request_item(task, updated_at_ms)];

    if let Some(interruption) = checklist_interruption_item(task, updated_at_ms) {
        items.push(interruption);
    }

    items.push(checklist_execution_item(task, updated_at_ms));
    items.push(checklist_review_item(task, updated_at_ms));
    items
}

fn build_background_tasks(
    task: &AgentTask,
    updated_at_ms: u64,
) -> Vec<SessionBackgroundTaskRecord> {
    let session_id = task.session_id.clone().or_else(|| Some(task.id.clone()));
    let is_blocked = task.clarification_request.is_some()
        || task.credential_request.is_some()
        || task.phase == AgentPhase::Gate
        || task.pending_request_hash.is_some();

    let status = if is_blocked {
        "blocked"
    } else {
        match task.phase {
            AgentPhase::Idle => "pending",
            AgentPhase::Running => "running",
            AgentPhase::Gate => "blocked",
            AgentPhase::Complete => "completed",
            AgentPhase::Failed => "failed",
        }
    };

    let detail = if is_blocked {
        checklist_interruption_item(task, updated_at_ms).and_then(|item| item.detail)
    } else {
        truncated_runtime_detail(&task.current_step, 120)
    };

    vec![SessionBackgroundTaskRecord {
        task_id: task.id.clone(),
        session_id,
        label: truncated_runtime_detail(&task.intent, 72)
            .unwrap_or_else(|| "Session run".to_string()),
        status: status.to_string(),
        detail,
        latest_output: latest_task_output_excerpt(task),
        can_stop: matches!(task.phase, AgentPhase::Running | AgentPhase::Gate) || is_blocked,
        updated_at_ms,
    }]
}

impl AgentTask {
    pub fn sync_runtime_views(&mut self) {
        let updated_at_ms = runtime_view_now_ms();
        self.session_checklist = build_session_checklist(self, updated_at_ms);
        self.background_tasks = build_background_tasks(self, updated_at_ms);
    }
}

#[cfg(test)]
#[path = "runtime_view_tests.rs"]
mod runtime_view_tests;

fn default_lineage() -> String {
    "genesis".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResponse {
    pub responded: bool,
    pub approved: bool,
}
