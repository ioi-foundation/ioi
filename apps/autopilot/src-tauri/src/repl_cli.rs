use crate::kernel::connectors::{
    policy_state_path_for, AutomationPolicyMode, ConnectorPolicyOverride, DataHandlingMode,
    GlobalPolicyDefaults, PolicyDecisionMode, ShieldPolicyManager, ShieldPolicyState,
    ShieldRememberedApprovalSnapshot,
};
use crate::kernel::data::{
    build_local_engine_activity_record, default_agent_playbooks,
    load_or_initialize_effective_local_engine_control_plane_state,
    load_or_initialize_local_engine_control_plane_state, visible_parent_playbook_runs,
};
use crate::kernel::hooks::build_session_hook_snapshot_from_parts;
use crate::kernel::session::{
    compact_retained_session_for_sessions, forget_team_memory_entry_for_sessions,
    session_compaction_snapshot_for_sessions, sync_team_memory_for_sessions,
    team_memory_snapshot_for_sessions,
};
use crate::kernel::skill_sources::load_extension_manifests_for_sources;
use crate::models::{
    AgentTask, LocalEngineAgentPlaybookRecord, LocalEngineParentPlaybookReceiptRecord,
    LocalEngineParentPlaybookRunRecord, SessionCompactionPolicy, SessionHookSnapshot,
    SessionSummary,
};
use crate::open_or_create_memory_runtime;
use crate::orchestrator::{
    clear_local_task_state, get_local_sessions_with_live_tasks, load_events, load_local_task,
    load_skill_sources, persisted_workspace_root_for_session,
};
use crate::workspace::WorkspaceTerminalBridge;
use ioi_memory::MemoryRuntime;
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const ATTACH_DEFAULT_COLS: u16 = 120;
const ATTACH_DEFAULT_ROWS: u16 = 32;
const WRITE_IDLE_TIMEOUT: Duration = Duration::from_millis(350);
const WRITE_MAX_WAIT: Duration = Duration::from_secs(6);

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bool_env(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn compaction_policy_from_flags(
    flags: &[String],
) -> Result<Option<SessionCompactionPolicy>, String> {
    if flags.is_empty() {
        return Ok(None);
    }

    let mut policy = SessionCompactionPolicy::default();
    let mut changed = false;
    for flag in flags {
        match flag.as_str() {
            "--pinned-only" => {
                policy.carry_pinned_only = true;
                changed = true;
            }
            "--drop-checklist" => {
                policy.preserve_checklist_state = false;
                changed = true;
            }
            "--drop-background" => {
                policy.preserve_background_tasks = false;
                changed = true;
            }
            "--drop-output" => {
                policy.preserve_latest_output_excerpt = false;
                changed = true;
            }
            "--drop-blockers" => {
                policy.preserve_governance_blockers = false;
                changed = true;
            }
            "--aggressive-pruning" => {
                policy.aggressive_transcript_pruning = true;
                changed = true;
            }
            other => return Err(format!("Unknown compaction flag '{}'.", other)),
        }
    }

    Ok(changed.then_some(policy))
}

fn selector_and_compaction_policy(
    raw_args: Vec<String>,
    targets: &[ReplSessionTarget],
) -> Result<(Option<String>, Option<SessionCompactionPolicy>), String> {
    let (selector, flag_args) = match raw_args.first() {
        Some(first)
            if !first.starts_with('-')
                && (first.eq_ignore_ascii_case("latest")
                    || targets.iter().any(|target| target.session_id == *first)) =>
        {
            (Some(first.clone()), raw_args.into_iter().skip(1).collect())
        }
        _ => (None, raw_args),
    };

    let policy = compaction_policy_from_flags(&flag_args)?;
    Ok((selector, policy))
}

fn cli_data_dir() -> Result<PathBuf, String> {
    if let Some(override_path) = env_text("AUTOPILOT_DATA_DIR") {
        return Ok(PathBuf::from(override_path));
    }

    let home = env_text("HOME").ok_or_else(|| "HOME is not set.".to_string())?;
    let mut base = PathBuf::from(home);
    base.push(".local/share/ai.ioi.autopilot");

    let profile = env_text("AUTOPILOT_DATA_PROFILE").or_else(|| {
        if bool_env("AUTOPILOT_LOCAL_GPU_DEV") {
            Some("desktop-localgpu".to_string())
        } else {
            None
        }
    });

    if let Some(profile) = profile {
        Ok(base.join("profiles").join(profile))
    } else {
        Ok(base)
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
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ReplSessionTarget {
    session_id: String,
    title: String,
    timestamp: u64,
    phase: Option<crate::models::AgentPhase>,
    current_step: Option<String>,
    resume_hint: Option<String>,
    workspace_root: Option<String>,
    has_local_task: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplManagedSettingsView {
    control_plane_schema_version: u32,
    control_plane_profile_id: String,
    effective_control_plane: crate::models::LocalEngineControlPlane,
    managed_settings: crate::models::LocalEngineManagedSettingsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplAuthorityProfileSummary {
    id: String,
    label: String,
    summary: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplAuthorityAutomationPlan {
    tone: String,
    status_label: String,
    detail: String,
    action_kind: String,
    recommended_profile_id: Option<String>,
    primary_action_label: Option<String>,
    checklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplAuthorityView {
    session: ReplSessionTarget,
    current_profile_id: Option<String>,
    active_override_count: usize,
    available_profiles: Vec<ReplAuthorityProfileSummary>,
    policy_state: ShieldPolicyState,
    remembered_approvals: ShieldRememberedApprovalSnapshot,
    hook_snapshot: SessionHookSnapshot,
    recommendation: ReplAuthorityAutomationPlan,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplTaskOutputView {
    role: String,
    timestamp: u64,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplDelegatedStepView {
    step_id: String,
    label: String,
    status: String,
    dependency_status: String,
    depends_on_labels: Vec<String>,
    unmet_dependency_labels: Vec<String>,
    child_session_id: Option<String>,
    template_id: Option<String>,
    workflow_id: Option<String>,
    latest_receipt_summary: Option<String>,
    artifact_ids: Vec<String>,
    can_start: bool,
    can_resume: bool,
    can_message_worker: bool,
    can_promote: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplDelegatedRunView {
    run_id: String,
    playbook_id: String,
    playbook_label: String,
    status: String,
    summary: String,
    current_step_id: Option<String>,
    current_step_label: Option<String>,
    latest_receipt_summary: Option<String>,
    ready_step_count: usize,
    blocked_step_count: usize,
    active_worker_count: usize,
    promotable_step_count: usize,
    steps: Vec<ReplDelegatedStepView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplDelegatedTaskSummary {
    status_label: String,
    detail: String,
    run_count: usize,
    step_count: usize,
    ready_step_count: usize,
    blocked_step_count: usize,
    active_worker_count: usize,
    promotable_step_count: usize,
    artifact_backed_step_count: usize,
    dependency_edge_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplTasksView {
    session: ReplSessionTarget,
    has_local_task: bool,
    intent: Option<String>,
    phase: Option<String>,
    current_step: Option<String>,
    checklist: Vec<crate::models::SessionChecklistItem>,
    background_tasks: Vec<crate::models::SessionBackgroundTaskRecord>,
    recent_outputs: Vec<ReplTaskOutputView>,
    delegation: ReplDelegatedTaskSummary,
    delegated_runs: Vec<ReplDelegatedRunView>,
}

fn truncate_repl_text(value: &str, max_chars: usize) -> Option<String> {
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

fn recent_task_outputs(task: &AgentTask) -> Vec<ReplTaskOutputView> {
    task.history
        .iter()
        .rev()
        .filter(|message| {
            !message.text.trim().is_empty()
                && matches!(message.role.as_str(), "assistant" | "agent" | "system")
        })
        .filter_map(|message| {
            truncate_repl_text(&message.text, 200).map(|text| ReplTaskOutputView {
                role: message.role.clone(),
                timestamp: message.timestamp,
                text,
            })
        })
        .take(5)
        .collect()
}

fn run_belongs_to_session(run: &LocalEngineParentPlaybookRunRecord, session_id: &str) -> bool {
    if run.parent_session_id == session_id
        || run.active_child_session_id.as_deref() == Some(session_id)
    {
        return true;
    }

    run.steps
        .iter()
        .any(|step| step.child_session_id.as_deref() == Some(session_id))
}

fn normalized_run_status(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_completed_run_status(value: &str) -> bool {
    normalized_run_status(value) == "completed"
}

fn is_blocked_run_status(value: &str) -> bool {
    matches!(normalized_run_status(value).as_str(), "blocked" | "failed")
}

fn is_active_run_status(value: &str) -> bool {
    matches!(
        normalized_run_status(value).as_str(),
        "running" | "active" | "in_progress"
    )
}

fn latest_successful_receipt(
    receipts: &[LocalEngineParentPlaybookReceiptRecord],
) -> Option<&LocalEngineParentPlaybookReceiptRecord> {
    receipts
        .iter()
        .filter(|receipt| receipt.success)
        .max_by_key(|receipt| receipt.timestamp_ms)
}

fn latest_receipt(
    receipts: &[LocalEngineParentPlaybookReceiptRecord],
) -> Option<&LocalEngineParentPlaybookReceiptRecord> {
    receipts.iter().max_by_key(|receipt| receipt.timestamp_ms)
}

fn dependency_labels_for_step(
    run: &LocalEngineParentPlaybookRunRecord,
    playbook_by_id: &BTreeMap<String, LocalEngineAgentPlaybookRecord>,
    step_id: &str,
) -> Vec<String> {
    let Some(playbook) = playbook_by_id.get(&run.playbook_id) else {
        return Vec::new();
    };
    let Some(definition) = playbook.steps.iter().find(|step| step.step_id == step_id) else {
        return Vec::new();
    };

    definition
        .depends_on
        .iter()
        .map(|dependency_id| {
            playbook
                .steps
                .iter()
                .find(|candidate| candidate.step_id == *dependency_id)
                .map(|candidate| candidate.label.clone())
                .unwrap_or_else(|| dependency_id.clone())
        })
        .collect()
}

fn build_repl_delegated_runs(
    runs: &[LocalEngineParentPlaybookRunRecord],
    playbook_by_id: &BTreeMap<String, LocalEngineAgentPlaybookRecord>,
) -> (ReplDelegatedTaskSummary, Vec<ReplDelegatedRunView>) {
    if runs.is_empty() {
        return (
            ReplDelegatedTaskSummary {
                status_label: "No delegated graph yet".to_string(),
                detail:
                    "The runtime has not attached a retained parent playbook graph to this session yet."
                        .to_string(),
                run_count: 0,
                step_count: 0,
                ready_step_count: 0,
                blocked_step_count: 0,
                active_worker_count: 0,
                promotable_step_count: 0,
                artifact_backed_step_count: 0,
                dependency_edge_count: 0,
            },
            Vec::new(),
        );
    }

    let mut run_views = Vec::new();
    let mut step_count = 0;
    let mut ready_step_count = 0;
    let mut blocked_step_count = 0;
    let mut active_worker_count = 0;
    let mut promotable_step_count = 0;
    let mut artifact_backed_step_count = 0;
    let mut dependency_edge_count = 0;
    let mut first_blocked_label: Option<String> = None;

    for run in runs {
        let step_by_id = run
            .steps
            .iter()
            .map(|step| (step.step_id.as_str(), step))
            .collect::<BTreeMap<_, _>>();

        let mut run_ready_step_count = 0;
        let mut run_blocked_step_count = 0;
        let mut run_active_worker_count = 0;
        let mut run_promotable_step_count = 0;

        let steps = run
            .steps
            .iter()
            .map(|step| {
                let depends_on_labels =
                    dependency_labels_for_step(run, playbook_by_id, &step.step_id);
                let unmet_dependency_labels = playbook_by_id
                    .get(&run.playbook_id)
                    .and_then(|playbook| {
                        playbook
                            .steps
                            .iter()
                            .find(|entry| entry.step_id == step.step_id)
                    })
                    .map(|definition| {
                        definition
                            .depends_on
                            .iter()
                            .filter_map(|dependency_id| step_by_id.get(dependency_id.as_str()))
                            .filter(|dependency| !is_completed_run_status(&dependency.status))
                            .map(|dependency| dependency.label.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let can_start = normalized_run_status(&step.status) == "pending"
                    && unmet_dependency_labels.is_empty();
                let can_resume = normalized_run_status(&step.status) != "pending";
                let can_message_worker = step.child_session_id.is_some();
                let successful_receipt = latest_successful_receipt(&step.receipts);
                let latest_receipt = latest_receipt(&step.receipts);
                let can_promote = successful_receipt.is_some();
                let dependency_status = if is_blocked_run_status(&step.status) {
                    if normalized_run_status(&step.status) == "failed" {
                        "Failed".to_string()
                    } else {
                        "Blocked".to_string()
                    }
                } else if is_active_run_status(&step.status) {
                    "In progress".to_string()
                } else if is_completed_run_status(&step.status) {
                    "Completed".to_string()
                } else if depends_on_labels.is_empty() || unmet_dependency_labels.is_empty() {
                    "Ready now".to_string()
                } else if unmet_dependency_labels.len() == 1 {
                    format!("Waiting on {}", unmet_dependency_labels[0])
                } else {
                    format!("Waiting on {} dependencies", unmet_dependency_labels.len())
                };

                step_count += 1;
                dependency_edge_count += depends_on_labels.len();
                if can_start {
                    ready_step_count += 1;
                    run_ready_step_count += 1;
                }
                if is_blocked_run_status(&step.status) {
                    blocked_step_count += 1;
                    run_blocked_step_count += 1;
                    if first_blocked_label.is_none() {
                        first_blocked_label = Some(step.label.clone());
                    }
                }
                if step.child_session_id.is_some() && is_active_run_status(&step.status) {
                    active_worker_count += 1;
                    run_active_worker_count += 1;
                }
                if can_promote {
                    promotable_step_count += 1;
                    run_promotable_step_count += 1;
                }
                if step
                    .receipts
                    .iter()
                    .any(|receipt| !receipt.artifact_ids.is_empty())
                {
                    artifact_backed_step_count += 1;
                }

                ReplDelegatedStepView {
                    step_id: step.step_id.clone(),
                    label: step.label.clone(),
                    status: step.status.clone(),
                    dependency_status,
                    depends_on_labels,
                    unmet_dependency_labels,
                    child_session_id: step.child_session_id.clone(),
                    template_id: step.template_id.clone(),
                    workflow_id: step.workflow_id.clone(),
                    latest_receipt_summary: latest_receipt.map(|receipt| receipt.summary.clone()),
                    artifact_ids: latest_receipt
                        .map(|receipt| receipt.artifact_ids.clone())
                        .unwrap_or_default(),
                    can_start,
                    can_resume,
                    can_message_worker,
                    can_promote,
                }
            })
            .collect::<Vec<_>>();

        let latest_run_receipt = run
            .steps
            .iter()
            .flat_map(|step| step.receipts.iter())
            .max_by_key(|receipt| receipt.timestamp_ms);

        run_views.push(ReplDelegatedRunView {
            run_id: run.run_id.clone(),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.clone(),
            summary: run.summary.clone(),
            current_step_id: run.current_step_id.clone(),
            current_step_label: run.current_step_label.clone(),
            latest_receipt_summary: latest_run_receipt.map(|receipt| receipt.summary.clone()),
            ready_step_count: run_ready_step_count,
            blocked_step_count: run_blocked_step_count,
            active_worker_count: run_active_worker_count,
            promotable_step_count: run_promotable_step_count,
            steps,
        });
    }

    let summary = if blocked_step_count > 0 {
        ReplDelegatedTaskSummary {
            status_label: "Delegated work needs review".to_string(),
            detail: first_blocked_label
                .map(|label| {
                    format!(
                        "{blocked_step_count} delegated steps are blocked or failed, including {label}."
                    )
                })
                .unwrap_or_else(|| {
                    format!("{blocked_step_count} delegated steps are blocked or failed.")
                }),
            run_count: runs.len(),
            step_count,
            ready_step_count,
            blocked_step_count,
            active_worker_count,
            promotable_step_count,
            artifact_backed_step_count,
            dependency_edge_count,
        }
    } else if ready_step_count > 0 {
        ReplDelegatedTaskSummary {
            status_label: "Delegated work is ready to advance".to_string(),
            detail: if ready_step_count == 1 {
                "1 pending delegated step now has all dependencies satisfied.".to_string()
            } else {
                format!(
                    "{ready_step_count} pending delegated steps now have all dependencies satisfied."
                )
            },
            run_count: runs.len(),
            step_count,
            ready_step_count,
            blocked_step_count,
            active_worker_count,
            promotable_step_count,
            artifact_backed_step_count,
            dependency_edge_count,
        }
    } else if active_worker_count > 0 {
        ReplDelegatedTaskSummary {
            status_label: "Delegated work is in flight".to_string(),
            detail: if active_worker_count == 1 {
                "1 delegated worker session is currently active.".to_string()
            } else {
                format!("{active_worker_count} delegated worker sessions are currently active.")
            },
            run_count: runs.len(),
            step_count,
            ready_step_count,
            blocked_step_count,
            active_worker_count,
            promotable_step_count,
            artifact_backed_step_count,
            dependency_edge_count,
        }
    } else if promotable_step_count > 0 {
        ReplDelegatedTaskSummary {
            status_label: "Worker outputs are ready for parent review".to_string(),
            detail: if promotable_step_count == 1 {
                "1 delegated step has a successful retained receipt ready for promotion."
                    .to_string()
            } else {
                format!(
                    "{promotable_step_count} delegated steps have successful retained receipts ready for promotion."
                )
            },
            run_count: runs.len(),
            step_count,
            ready_step_count,
            blocked_step_count,
            active_worker_count,
            promotable_step_count,
            artifact_backed_step_count,
            dependency_edge_count,
        }
    } else {
        ReplDelegatedTaskSummary {
            status_label: "Delegated graph retained".to_string(),
            detail: if step_count == 1 {
                "1 delegated step is retained in the runtime graph for this session.".to_string()
            } else {
                format!("{step_count} delegated steps are retained in the runtime graph for this session.")
            },
            run_count: runs.len(),
            step_count,
            ready_step_count,
            blocked_step_count,
            active_worker_count,
            promotable_step_count,
            artifact_backed_step_count,
            dependency_edge_count,
        }
    };

    (summary, run_views)
}

fn tasks_view(memory_runtime: &Arc<MemoryRuntime>, target: &ReplSessionTarget) -> ReplTasksView {
    let local_task = load_local_task(memory_runtime, &target.session_id);
    let sessions = get_local_sessions_with_live_tasks(memory_runtime);
    let playbooks = default_agent_playbooks();
    let playbook_by_id = playbooks
        .iter()
        .map(|playbook| (playbook.playbook_id.clone(), playbook.clone()))
        .collect::<BTreeMap<_, _>>();
    let runs = visible_parent_playbook_runs(memory_runtime, &sessions, &playbooks)
        .into_iter()
        .filter(|run| run_belongs_to_session(run, &target.session_id))
        .collect::<Vec<_>>();
    let (delegation, delegated_runs) = build_repl_delegated_runs(&runs, &playbook_by_id);

    ReplTasksView {
        session: target.clone(),
        has_local_task: local_task.is_some(),
        intent: local_task.as_ref().map(|task| task.intent.clone()),
        phase: local_task.as_ref().map(|_| phase_label(target).to_string()),
        current_step: local_task.as_ref().map(|task| task.current_step.clone()),
        checklist: local_task
            .as_ref()
            .map(|task| task.session_checklist.clone())
            .unwrap_or_default(),
        background_tasks: local_task
            .as_ref()
            .map(|task| task.background_tasks.clone())
            .unwrap_or_default(),
        recent_outputs: local_task
            .as_ref()
            .map(recent_task_outputs)
            .unwrap_or_default(),
        delegation,
        delegated_runs,
    }
}

fn repl_target_from_summary(
    memory_runtime: &Arc<MemoryRuntime>,
    summary: SessionSummary,
) -> ReplSessionTarget {
    let local_task = load_local_task(memory_runtime, &summary.session_id);
    let workspace_root = summary
        .workspace_root
        .clone()
        .or_else(|| {
            local_task
                .as_ref()
                .and_then(workspace_root_from_task)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            persisted_workspace_root_for_session(memory_runtime, Some(summary.session_id.as_str()))
        });

    ReplSessionTarget {
        session_id: summary.session_id,
        title: summary.title,
        timestamp: summary.timestamp,
        phase: summary.phase,
        current_step: summary.current_step,
        resume_hint: summary.resume_hint,
        workspace_root,
        has_local_task: local_task.is_some(),
    }
}

fn load_repl_targets(memory_runtime: &Arc<MemoryRuntime>) -> Vec<ReplSessionTarget> {
    get_local_sessions_with_live_tasks(memory_runtime)
        .into_iter()
        .map(|summary| repl_target_from_summary(memory_runtime, summary))
        .collect()
}

fn requested_selector(value: Option<&str>) -> &str {
    match value.map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => "latest",
    }
}

fn select_target<'a>(
    targets: &'a [ReplSessionTarget],
    requested: Option<&str>,
) -> Result<&'a ReplSessionTarget, String> {
    if targets.is_empty() {
        return Err("No local sessions were found.".to_string());
    }

    let selector = requested_selector(requested);
    if selector.eq_ignore_ascii_case("latest") {
        return targets
            .first()
            .ok_or_else(|| "No local sessions were found.".to_string());
    }

    targets
        .iter()
        .find(|target| target.session_id == selector)
        .ok_or_else(|| format!("Session '{}' was not found.", selector))
}

fn select_attachable_target<'a>(
    targets: &'a [ReplSessionTarget],
    requested: Option<&str>,
) -> Result<&'a ReplSessionTarget, String> {
    let selector = requested_selector(requested);
    if selector.eq_ignore_ascii_case("latest") {
        return targets
            .iter()
            .find(|target| {
                target
                    .workspace_root
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
            })
            .ok_or_else(|| {
                "No local session with a workspace root was found for REPL attach.".to_string()
            });
    }

    let target = select_target(targets, Some(selector))?;
    if target
        .workspace_root
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(format!(
            "Session '{}' does not retain a workspace root for REPL attach.",
            target.session_id
        ));
    }
    Ok(target)
}

fn phase_label(target: &ReplSessionTarget) -> &'static str {
    match target.phase.as_ref() {
        Some(crate::models::AgentPhase::Idle) => "idle",
        Some(crate::models::AgentPhase::Running) => "running",
        Some(crate::models::AgentPhase::Gate) => "gate",
        Some(crate::models::AgentPhase::Complete) => "complete",
        Some(crate::models::AgentPhase::Failed) => "failed",
        None => "unknown",
    }
}

fn print_list(targets: &[ReplSessionTarget]) {
    if targets.is_empty() {
        println!("No local sessions were found.");
        return;
    }

    for (index, target) in targets.iter().enumerate() {
        let selector = if index == 0 { "latest" } else { "      " };
        let workspace = target
            .workspace_root
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("(no workspace root)");
        let hint = target
            .resume_hint
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("");
        println!(
            "{selector}  {}  {:<8}  {}  {}",
            target.session_id,
            phase_label(target),
            workspace,
            if hint.is_empty() {
                target.title.as_str()
            } else {
                hint
            }
        );
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("JSON encode failed: {error}"))?;
    println!("{text}");
    Ok(())
}

fn attach_terminal(target: &ReplSessionTarget) -> Result<(), String> {
    let workspace_root = target
        .workspace_root
        .as_deref()
        .ok_or_else(|| "The selected session does not have a workspace root.".to_string())?;
    let bridge =
        WorkspaceTerminalBridge::open(workspace_root, ATTACH_DEFAULT_COLS, ATTACH_DEFAULT_ROWS)?;
    let descriptor = bridge.session();

    eprintln!(
        "[autopilot-repl] attached to {} ({}) at {}",
        target.title, target.session_id, descriptor.root_path
    );
    eprintln!("[autopilot-repl] close stdin or run `exit` to stop the attached shell.");

    let stop = Arc::new(AtomicBool::new(false));
    let input_stop = Arc::clone(&stop);
    let input_bridge = bridge.clone();
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buffer = [0_u8; 4096];
        loop {
            if input_stop.load(Ordering::Relaxed) {
                break;
            }
            match stdin.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if input_bridge.write_bytes(&buffer[..count]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut cursor = 0;
    let mut stdout = io::stdout();
    let mut exit_seen_at = None;
    loop {
        let read = bridge.read(cursor)?;
        cursor = read.cursor;

        for chunk in read.chunks {
            stdout
                .write_all(chunk.text.as_bytes())
                .map_err(|error| format!("Failed to write terminal output: {}", error))?;
        }
        stdout
            .flush()
            .map_err(|error| format!("Failed to flush terminal output: {}", error))?;

        if !read.running {
            if exit_seen_at.is_none() {
                exit_seen_at = Some(Instant::now());
            }
            if exit_seen_at.is_some_and(|deadline| deadline.elapsed() >= WRITE_IDLE_TIMEOUT) {
                break;
            }
        } else {
            exit_seen_at = None;
        }

        thread::sleep(Duration::from_millis(50));
    }

    stop.store(true, Ordering::Relaxed);
    let _ = bridge.close();
    Ok(())
}

fn write_once(target: &ReplSessionTarget, payload: &str) -> Result<(), String> {
    let workspace_root = target
        .workspace_root
        .as_deref()
        .ok_or_else(|| "The selected session does not have a workspace root.".to_string())?;
    let bridge =
        WorkspaceTerminalBridge::open(workspace_root, ATTACH_DEFAULT_COLS, ATTACH_DEFAULT_ROWS)?;
    let mut rendered = payload.to_string();
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    bridge.write(&rendered)?;

    let started_at = Instant::now();
    let mut last_output_at = Instant::now();
    let mut cursor = 0;
    let mut stdout = io::stdout();
    loop {
        let read = bridge.read(cursor)?;
        cursor = read.cursor;
        if !read.chunks.is_empty() {
            last_output_at = Instant::now();
            for chunk in read.chunks {
                stdout
                    .write_all(chunk.text.as_bytes())
                    .map_err(|error| format!("Failed to write terminal output: {}", error))?;
            }
            stdout
                .flush()
                .map_err(|error| format!("Failed to flush terminal output: {}", error))?;
        }

        if !read.running {
            break;
        }
        if started_at.elapsed() >= WRITE_MAX_WAIT || last_output_at.elapsed() >= WRITE_IDLE_TIMEOUT
        {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = bridge.close();
    Ok(())
}

fn print_usage() {
    eprintln!(
        "Usage: autopilot_repl <list|inspect|read|review|tasks|continue|attach|resume|reply|write|stop|compact|compaction|team-memory|team-memory-sync|team-memory-forget|authority|authority-apply|authority-override|config|settings|settings-refresh|settings-clear-overrides> [args]"
    );
    eprintln!("  list");
    eprintln!("  inspect [session-id|latest]");
    eprintln!("    # alias for read; inspect the canonical session snapshot");
    eprintln!("  read [session-id|latest]");
    eprintln!("  review [session-id|latest]");
    eprintln!("    # alias for tasks; review checklist, blockers, and delegated work");
    eprintln!("  tasks [session-id|latest]");
    eprintln!("    # inspect runtime checklist, background tasks, recent output, and delegated playbook graph posture");
    eprintln!("  continue [session-id|latest]");
    eprintln!("    # alias for attach/resume; reopen the operator terminal on a session workspace");
    eprintln!("  attach [session-id|latest]");
    eprintln!("  resume [session-id|latest]");
    eprintln!("  reply [session-id|latest] <data>");
    eprintln!("    # alias for write; send one operator reply into the selected session shell");
    eprintln!("  write [session-id|latest] <data>");
    eprintln!("  stop [session-id|latest]");
    eprintln!(
        "  compact [session-id|latest] [--pinned-only] [--drop-checklist] [--drop-background] [--drop-output] [--drop-blockers] [--aggressive-pruning]"
    );
    eprintln!(
        "  compaction [session-id|latest] [--pinned-only] [--drop-checklist] [--drop-background] [--drop-output] [--drop-blockers] [--aggressive-pruning]"
    );
    eprintln!("    # show preview + retained records, optionally with a custom memory policy");
    eprintln!("  team-memory [session-id|latest]");
    eprintln!(
        "    # inspect scoped multi-actor team memory for the selected retained session scope"
    );
    eprintln!("  team-memory-sync [session-id|latest] [--include-governance]");
    eprintln!("    # sync the selected retained session into scoped team memory using REPL actor identity");
    eprintln!("  team-memory-forget <entry-id> [session-id|latest]");
    eprintln!("    # forget one retained team-memory entry and show the refreshed scoped snapshot");
    eprintln!("  authority [session-id|latest]");
    eprintln!(
        "    # inspect shared policy, hook posture, remembered approvals, and the recommended authority profile"
    );
    eprintln!(
        "  authority-apply [session-id|latest] <safer_review|guided_default|autonomous|expert>"
    );
    eprintln!(
        "    # apply a shared session permission profile, then show the refreshed authority posture"
    );
    eprintln!(
        "  authority-override [session-id|latest] <connector-id> <inherit|safer_review|guided_default|autonomous|expert>"
    );
    eprintln!(
        "    # set or clear one connector-scoped authority override, then show the refreshed authority posture"
    );
    eprintln!("  settings");
    eprintln!("    # inspect effective managed settings and local override posture");
    eprintln!("  config");
    eprintln!("    # alias for settings");
    eprintln!("  settings-refresh");
    eprintln!("    # refresh signed managed settings channels");
    eprintln!("  settings-clear-overrides");
    eprintln!("    # clear local overrides over the managed settings baseline");
}

fn managed_settings_view(memory_runtime: &Arc<MemoryRuntime>) -> ReplManagedSettingsView {
    let local_document = load_or_initialize_local_engine_control_plane_state(memory_runtime);
    let effective = load_or_initialize_effective_local_engine_control_plane_state(memory_runtime);
    ReplManagedSettingsView {
        control_plane_schema_version: local_document.schema_version,
        control_plane_profile_id: local_document.profile_id,
        effective_control_plane: effective.control_plane,
        managed_settings: effective.managed_settings,
    }
}

fn policy_defaults_equal(left: &GlobalPolicyDefaults, right: &GlobalPolicyDefaults) -> bool {
    left.reads == right.reads
        && left.writes == right.writes
        && left.admin == right.admin
        && left.expert == right.expert
        && left.automations == right.automations
        && left.data_handling == right.data_handling
}

fn authority_profile_defaults(profile_id: &str) -> Option<GlobalPolicyDefaults> {
    match profile_id {
        "safer_review" => Some(GlobalPolicyDefaults {
            reads: PolicyDecisionMode::Confirm,
            writes: PolicyDecisionMode::Confirm,
            admin: PolicyDecisionMode::Block,
            expert: PolicyDecisionMode::Block,
            automations: AutomationPolicyMode::ManualOnly,
            data_handling: DataHandlingMode::LocalOnly,
        }),
        "guided_default" => Some(GlobalPolicyDefaults::default()),
        "autonomous" => Some(GlobalPolicyDefaults {
            reads: PolicyDecisionMode::Auto,
            writes: PolicyDecisionMode::Auto,
            admin: PolicyDecisionMode::Confirm,
            expert: PolicyDecisionMode::Confirm,
            automations: AutomationPolicyMode::ConfirmOnCreate,
            data_handling: DataHandlingMode::LocalRedacted,
        }),
        "expert" => Some(GlobalPolicyDefaults {
            reads: PolicyDecisionMode::Auto,
            writes: PolicyDecisionMode::Auto,
            admin: PolicyDecisionMode::Auto,
            expert: PolicyDecisionMode::Auto,
            automations: AutomationPolicyMode::ConfirmOnCreate,
            data_handling: DataHandlingMode::LocalRedacted,
        }),
        _ => None,
    }
}

fn authority_profile_summaries() -> Vec<ReplAuthorityProfileSummary> {
    vec![
        ReplAuthorityProfileSummary {
            id: "safer_review".to_string(),
            label: "Safer review".to_string(),
            summary: "Keep risky actions approval-bound and durable automation disabled."
                .to_string(),
            detail: "Best for cautious repo work, approvals, and policy review where the shell should bias toward confirmation before acting.".to_string(),
        },
        ReplAuthorityProfileSummary {
            id: "guided_default".to_string(),
            label: "Guided default".to_string(),
            summary:
                "Match the shipped runtime posture with guarded writes and blocked expert actions."
                    .to_string(),
            detail: "Balanced day-to-day operator posture: reads may flow automatically, writes stay approval-bound, and expert actions remain blocked.".to_string(),
        },
        ReplAuthorityProfileSummary {
            id: "autonomous".to_string(),
            label: "Autonomous".to_string(),
            summary:
                "Reduce friction for routine reads and writes while keeping admin changes reviewable."
                    .to_string(),
            detail: "Useful when the operator wants more autonomous task execution without opening the shell all the way to unrestricted expert behavior.".to_string(),
        },
        ReplAuthorityProfileSummary {
            id: "expert".to_string(),
            label: "Expert".to_string(),
            summary:
                "Allow the broadest runtime posture, including expert actions and admin changes."
                    .to_string(),
            detail: "Closest to a bypass-style shell. Use only when the operator explicitly wants broad autonomous authority and redacted export handling.".to_string(),
        },
    ]
}

fn resolve_authority_profile_id(policy_state: &ShieldPolicyState) -> Option<String> {
    authority_profile_summaries()
        .into_iter()
        .find(|profile| {
            authority_profile_defaults(profile.id.as_str())
                .is_some_and(|defaults| policy_defaults_equal(&defaults, &policy_state.global))
        })
        .map(|profile| profile.id)
}

fn apply_authority_profile(
    policy_state: ShieldPolicyState,
    profile_id: &str,
) -> Result<ShieldPolicyState, String> {
    let Some(global) = authority_profile_defaults(profile_id) else {
        return Err(format!("Unknown authority profile '{}'.", profile_id));
    };
    Ok(ShieldPolicyState {
        version: policy_state.version,
        global,
        overrides: policy_state.overrides,
    })
}

fn apply_authority_override(
    mut policy_state: ShieldPolicyState,
    connector_id: &str,
    profile_id: &str,
) -> Result<ShieldPolicyState, String> {
    let connector_id = connector_id.trim();
    if connector_id.is_empty() {
        return Err("Connector id is required for authority overrides.".to_string());
    }

    if matches!(profile_id.trim(), "inherit" | "reset" | "baseline") {
        policy_state.overrides.remove(connector_id);
        return Ok(policy_state);
    }

    let Some(defaults) = authority_profile_defaults(profile_id) else {
        return Err(format!(
            "Unknown authority override profile '{}'.",
            profile_id
        ));
    };
    policy_state.overrides.insert(
        connector_id.to_string(),
        ConnectorPolicyOverride {
            inherit_global: false,
            reads: defaults.reads,
            writes: defaults.writes,
            admin: defaults.admin,
            expert: defaults.expert,
            automations: defaults.automations,
            data_handling: defaults.data_handling,
        },
    );
    Ok(policy_state)
}

fn count_active_overrides(policy_state: &ShieldPolicyState) -> usize {
    policy_state
        .overrides
        .values()
        .filter(|override_state| !override_state.inherit_global)
        .count()
}

fn collect_recent_local_engine_activity(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Vec<crate::models::LocalEngineActivityRecord> {
    let mut activity = get_local_sessions_with_live_tasks(memory_runtime)
        .into_iter()
        .take(12)
        .flat_map(|session| {
            load_events(memory_runtime, &session.session_id, None, None)
                .into_iter()
                .filter_map(|event| build_local_engine_activity_record(&session.session_id, &event))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    activity.sort_by(|left, right| {
        right
            .timestamp_ms
            .cmp(&left.timestamp_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    activity.truncate(12);
    activity
}

fn build_repl_hook_snapshot(
    memory_runtime: &Arc<MemoryRuntime>,
    target: &ReplSessionTarget,
    remembered_approvals: ShieldRememberedApprovalSnapshot,
) -> Result<SessionHookSnapshot, String> {
    let sources = load_skill_sources(memory_runtime);
    let manifests = load_extension_manifests_for_sources(&sources)?;
    let recent_activity = collect_recent_local_engine_activity(memory_runtime);
    let entries = Vec::new();
    Ok(build_session_hook_snapshot_from_parts(
        &entries,
        &manifests,
        &recent_activity,
        remembered_approvals,
        Some(target.session_id.clone()),
        target.workspace_root.clone(),
    ))
}

fn build_repl_authority_recommendation(
    current_profile_id: Option<&str>,
    hook_snapshot: &SessionHookSnapshot,
    remembered_approvals: &ShieldRememberedApprovalSnapshot,
    active_override_count: usize,
) -> ReplAuthorityAutomationPlan {
    let active_hook_count = hook_snapshot.active_hook_count;
    let disabled_hook_count = hook_snapshot.disabled_hook_count;
    let runtime_receipt_count = hook_snapshot.runtime_receipt_count;
    let approval_receipt_count = hook_snapshot.approval_receipt_count;
    let remembered_decision_count = remembered_approvals.active_decision_count;
    let recent_approval_receipt_count = remembered_approvals.recent_receipt_count;
    let checklist = vec![
        format!("{active_hook_count} active hooks"),
        format!("{approval_receipt_count} approval receipts"),
        format!("{remembered_decision_count} remembered approvals"),
        format!("{active_override_count} connector overrides"),
    ];

    if hook_snapshot.hooks.is_empty()
        && remembered_approvals.decisions.is_empty()
        && remembered_approvals.recent_receipts.is_empty()
    {
        return ReplAuthorityAutomationPlan {
            tone: "setup".to_string(),
            status_label: "Authority automation waiting on runtime posture".to_string(),
            detail: "Load hook and approval-memory posture before the shell can recommend a profile change or authority review path.".to_string(),
            action_kind: "none".to_string(),
            recommended_profile_id: None,
            primary_action_label: None,
            checklist,
        };
    }

    if approval_receipt_count > 0 {
        if current_profile_id != Some("safer_review") {
            return ReplAuthorityAutomationPlan {
                tone: "review".to_string(),
                status_label: "Safer review profile recommended".to_string(),
                detail: "Live approval-sensitive automation is active, so tightening the session baseline to Safer review is the safest next authority move before widening anything else.".to_string(),
                action_kind: "apply_profile".to_string(),
                recommended_profile_id: Some("safer_review".to_string()),
                primary_action_label: Some("Apply Safer review".to_string()),
                checklist,
            };
        }

        return ReplAuthorityAutomationPlan {
            tone: "review".to_string(),
            status_label: "Authority review should stay in focus".to_string(),
            detail: "The session is already on Safer review while approval-sensitive automation is active, so the next step is to inspect permissions rather than widen the baseline.".to_string(),
            action_kind: "review_permissions".to_string(),
            recommended_profile_id: None,
            primary_action_label: Some("Review session permissions".to_string()),
            checklist,
        };
    }

    if current_profile_id == Some("safer_review")
        && active_hook_count > 0
        && runtime_receipt_count > 0
        && remembered_decision_count > 0
    {
        return ReplAuthorityAutomationPlan {
            tone: "ready".to_string(),
            status_label: "Guided default can resume".to_string(),
            detail: "Hooks are active, runtime receipts are flowing, and remembered approvals already cover repeated work, so the session can move from Safer review back to Guided default without losing governance.".to_string(),
            action_kind: "apply_profile".to_string(),
            recommended_profile_id: Some("guided_default".to_string()),
            primary_action_label: Some("Apply Guided default".to_string()),
            checklist,
        };
    }

    if current_profile_id == Some("guided_default")
        && active_hook_count > 1
        && runtime_receipt_count > 1
        && remembered_decision_count > 2
        && recent_approval_receipt_count > 0
        && active_override_count == 0
        && disabled_hook_count == 0
    {
        return ReplAuthorityAutomationPlan {
            tone: "ready".to_string(),
            status_label: "Autonomous profile is now supportable".to_string(),
            detail: "Multiple live hooks, repeated runtime receipts, and remembered approvals are aligned without connector-specific widening, so Autonomous is now a supportable baseline if the operator wants faster execution.".to_string(),
            action_kind: "apply_profile".to_string(),
            recommended_profile_id: Some("autonomous".to_string()),
            primary_action_label: Some("Apply Autonomous".to_string()),
            checklist,
        };
    }

    if disabled_hook_count > 0 {
        return ReplAuthorityAutomationPlan {
            tone: "review".to_string(),
            status_label: "Hook coverage should be reviewed first".to_string(),
            detail: "Some tracked hooks are disabled, so authority changes should stay conservative until the live automation surface is fully understood.".to_string(),
            action_kind: "review_hooks".to_string(),
            recommended_profile_id: None,
            primary_action_label: Some("Review hooks".to_string()),
            checklist,
        };
    }

    ReplAuthorityAutomationPlan {
        tone: "ready".to_string(),
        status_label: "Authority automation has no pending change".to_string(),
        detail: "Current hooks, approvals, and profile posture are aligned well enough that the shell does not need to push a profile change right now.".to_string(),
        action_kind: "none".to_string(),
        recommended_profile_id: None,
        primary_action_label: None,
        checklist,
    }
}

fn authority_view(
    memory_runtime: &Arc<MemoryRuntime>,
    policy_manager: &ShieldPolicyManager,
    target: &ReplSessionTarget,
) -> Result<ReplAuthorityView, String> {
    let policy_state = policy_manager.current_state();
    let remembered_approvals = policy_manager.approval_snapshot();
    let hook_snapshot =
        build_repl_hook_snapshot(memory_runtime, target, remembered_approvals.clone())?;
    let current_profile_id = resolve_authority_profile_id(&policy_state);
    let active_override_count = count_active_overrides(&policy_state);
    let recommendation = build_repl_authority_recommendation(
        current_profile_id.as_deref(),
        &hook_snapshot,
        &remembered_approvals,
        active_override_count,
    );

    Ok(ReplAuthorityView {
        session: target.clone(),
        current_profile_id,
        active_override_count,
        available_profiles: authority_profile_summaries(),
        policy_state,
        remembered_approvals,
        hook_snapshot,
        recommendation,
    })
}

pub fn run_cli() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Err("A command is required.".to_string());
    };

    let data_dir = cli_data_dir()?;
    let memory_runtime = Arc::new(open_or_create_memory_runtime(Path::new(&data_dir))?);
    let policy_manager = ShieldPolicyManager::new(policy_state_path_for(Path::new(&data_dir)));
    let targets = load_repl_targets(&memory_runtime);

    match command.as_str() {
        "list" => {
            print_list(&targets);
            Ok(())
        }
        "inspect" | "read" => {
            let target = select_target(&targets, args.next().as_deref())?;
            print_json(target)
        }
        "review" | "tasks" => {
            let target = select_target(&targets, args.next().as_deref())?;
            print_json(&tasks_view(&memory_runtime, target))
        }
        "continue" | "attach" | "resume" => {
            let target = select_attachable_target(&targets, args.next().as_deref())?;
            attach_terminal(target)
        }
        "reply" | "write" => {
            let first = args.next();
            let (selector, payload_parts) = match first.as_deref() {
                Some("latest") => (Some("latest"), args.collect::<Vec<_>>()),
                Some(value) if targets.iter().any(|target| target.session_id == value) => {
                    (Some(value), args.collect::<Vec<_>>())
                }
                Some(value) => {
                    let mut parts = vec![value.to_string()];
                    parts.extend(args);
                    (Some("latest"), parts)
                }
                None => (Some("latest"), Vec::new()),
            };
            if payload_parts.is_empty() {
                print_usage();
                return Err("write requires shell input.".to_string());
            }
            let target = select_attachable_target(&targets, selector)?;
            write_once(target, &payload_parts.join(" "))
        }
        "stop" => {
            let selector = args.next();
            let target = select_target(&targets, selector.as_deref())?;
            clear_local_task_state(&memory_runtime, &target.session_id);
            let refreshed_targets = load_repl_targets(&memory_runtime);
            let refreshed = select_target(&refreshed_targets, Some(target.session_id.as_str()))
                .cloned()
                .unwrap_or_else(|_| target.clone());
            print_json(&refreshed)
        }
        "compact" => {
            let raw_args = args.collect::<Vec<_>>();
            let (selector, policy) = selector_and_compaction_policy(raw_args, &targets)?;
            let summaries = get_local_sessions_with_live_tasks(&memory_runtime);
            let active_session_id = targets.first().map(|target| target.session_id.as_str());
            let snapshot = compact_retained_session_for_sessions(
                &memory_runtime,
                summaries,
                active_session_id,
                selector.as_deref(),
                policy,
            )?;
            print_json(&snapshot)
        }
        "compaction" => {
            let raw_args = args.collect::<Vec<_>>();
            let (selector, policy) = selector_and_compaction_policy(raw_args, &targets)?;
            let summaries = get_local_sessions_with_live_tasks(&memory_runtime);
            let active_session_id = targets.first().map(|target| target.session_id.as_str());
            let snapshot = session_compaction_snapshot_for_sessions(
                &memory_runtime,
                summaries,
                selector
                    .as_deref()
                    .filter(|value| !value.eq_ignore_ascii_case("latest"))
                    .or(active_session_id),
                policy,
            );
            print_json(&snapshot)
        }
        "team-memory" => {
            let selector = args.next();
            let summaries = get_local_sessions_with_live_tasks(&memory_runtime);
            let active_session_id = targets.first().map(|target| target.session_id.as_str());
            let snapshot = team_memory_snapshot_for_sessions(
                &memory_runtime,
                summaries,
                active_session_id,
                selector.as_deref(),
            )?;
            print_json(&snapshot)
        }
        "team-memory-sync" => {
            let raw_args = args.collect::<Vec<_>>();
            let mut selector = None;
            let mut include_governance_critical = false;
            for value in raw_args {
                if value == "--include-governance" {
                    include_governance_critical = true;
                } else if selector.is_none()
                    && (value.eq_ignore_ascii_case("latest")
                        || targets.iter().any(|target| target.session_id == value))
                {
                    selector = Some(value);
                } else {
                    return Err(format!("Unknown team-memory-sync argument '{}'.", value));
                }
            }
            let summaries = get_local_sessions_with_live_tasks(&memory_runtime);
            let active_session_id = targets.first().map(|target| target.session_id.as_str());
            let snapshot = sync_team_memory_for_sessions(
                &memory_runtime,
                summaries,
                active_session_id,
                selector.as_deref(),
                Some("REPL".to_string()),
                Some("operator".to_string()),
                include_governance_critical,
            )?;
            print_json(&snapshot)
        }
        "team-memory-forget" => {
            let Some(entry_id) = args.next() else {
                print_usage();
                return Err("team-memory-forget requires an entry id.".to_string());
            };
            let selector = args.next();
            let summaries = get_local_sessions_with_live_tasks(&memory_runtime);
            let active_session_id = targets.first().map(|target| target.session_id.as_str());
            let snapshot = forget_team_memory_entry_for_sessions(
                &memory_runtime,
                summaries,
                active_session_id,
                selector.as_deref(),
                &entry_id,
            )?;
            print_json(&snapshot)
        }
        "authority" => {
            let target = select_target(&targets, args.next().as_deref())?;
            print_json(&authority_view(&memory_runtime, &policy_manager, target)?)
        }
        "authority-apply" => {
            let first = args.next();
            let (selector, profile_id) = match first.as_deref() {
                Some("latest") => (Some("latest"), args.next()),
                Some(value) if targets.iter().any(|target| target.session_id == value) => {
                    (Some(value), args.next())
                }
                Some(value) => (Some("latest"), Some(value.to_string())),
                None => (Some("latest"), None),
            };
            let Some(profile_id) = profile_id else {
                print_usage();
                return Err("authority-apply requires a profile id.".to_string());
            };
            let target = select_target(&targets, selector)?;
            let next_policy = apply_authority_profile(policy_manager.current_state(), &profile_id)?;
            policy_manager.replace_state(next_policy)?;
            print_json(&authority_view(&memory_runtime, &policy_manager, target)?)
        }
        "authority-override" => {
            let first = args.next();
            let (selector, connector_id, profile_id) = match first.as_deref() {
                Some("latest") => (Some("latest"), args.next(), args.next()),
                Some(value) if targets.iter().any(|target| target.session_id == value) => {
                    (Some(value), args.next(), args.next())
                }
                Some(value) => (Some("latest"), Some(value.to_string()), args.next()),
                None => (Some("latest"), None, None),
            };
            let Some(connector_id) = connector_id else {
                print_usage();
                return Err("authority-override requires a connector id.".to_string());
            };
            let Some(profile_id) = profile_id else {
                print_usage();
                return Err("authority-override requires a profile id.".to_string());
            };
            let target = select_target(&targets, selector)?;
            let next_policy = apply_authority_override(
                policy_manager.current_state(),
                &connector_id,
                &profile_id,
            )?;
            policy_manager.replace_state(next_policy)?;
            print_json(&authority_view(&memory_runtime, &policy_manager, target)?)
        }
        "config" | "settings" => print_json(&managed_settings_view(&memory_runtime)),
        "settings-refresh" => {
            let local_document =
                load_or_initialize_local_engine_control_plane_state(&memory_runtime);
            let _ = crate::kernel::local_engine::refresh_local_engine_managed_settings(
                &memory_runtime,
                &local_document,
            )?;
            print_json(&managed_settings_view(&memory_runtime))
        }
        "settings-clear-overrides" => {
            let local_document =
                load_or_initialize_local_engine_control_plane_state(&memory_runtime);
            let _ = crate::kernel::local_engine::clear_local_engine_managed_settings_overrides(
                &memory_runtime,
                &local_document,
            )?;
            print_json(&managed_settings_view(&memory_runtime))
        }
        _ => {
            print_usage();
            Err(format!("Unknown command '{}'.", command))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_authority_override, apply_authority_profile, build_repl_authority_recommendation,
        build_repl_delegated_runs, compaction_policy_from_flags, resolve_authority_profile_id,
        select_attachable_target, select_target, selector_and_compaction_policy, DataHandlingMode,
        LocalEngineAgentPlaybookRecord, LocalEngineParentPlaybookReceiptRecord,
        LocalEngineParentPlaybookRunRecord, PolicyDecisionMode, ReplSessionTarget,
    };
    use crate::models::{
        LocalEngineAgentPlaybookStepRecord, LocalEngineParentPlaybookStepRunRecord,
        LocalEngineWorkerCompletionContract, SessionHookReceiptSummary, SessionHookRecord,
        SessionHookSnapshot,
    };
    use std::collections::BTreeMap;

    fn target(session_id: &str, workspace_root: Option<&str>) -> ReplSessionTarget {
        ReplSessionTarget {
            session_id: session_id.to_string(),
            title: format!("Session {session_id}"),
            timestamp: 0,
            phase: None,
            current_step: None,
            resume_hint: None,
            workspace_root: workspace_root.map(ToOwned::to_owned),
            has_local_task: true,
        }
    }

    fn hook_snapshot(
        active_hook_count: usize,
        disabled_hook_count: usize,
        runtime_receipt_count: usize,
        approval_receipt_count: usize,
    ) -> SessionHookSnapshot {
        let mut hooks = Vec::new();
        for index in 0..active_hook_count {
            hooks.push(SessionHookRecord {
                hook_id: format!("active-hook-{index}"),
                entry_id: None,
                label: format!("Active hook {index}"),
                owner_label: "Owner".to_string(),
                source_label: "Source".to_string(),
                source_kind: "extension".to_string(),
                source_uri: None,
                contribution_path: None,
                trigger_label: "Trigger".to_string(),
                enabled: true,
                status_label: "Enabled".to_string(),
                trust_posture: "contained_local".to_string(),
                governed_profile: "automation_bridge".to_string(),
                authority_tier_label: "Automation bridge".to_string(),
                availability_label: "Ready".to_string(),
                session_scope_label: "Matches current workspace".to_string(),
                why_active: "Test hook".to_string(),
            });
        }
        for index in 0..disabled_hook_count {
            hooks.push(SessionHookRecord {
                hook_id: format!("disabled-hook-{index}"),
                entry_id: None,
                label: format!("Disabled hook {index}"),
                owner_label: "Owner".to_string(),
                source_label: "Source".to_string(),
                source_kind: "extension".to_string(),
                source_uri: None,
                contribution_path: None,
                trigger_label: "Trigger".to_string(),
                enabled: false,
                status_label: "Disabled".to_string(),
                trust_posture: "contained_local".to_string(),
                governed_profile: "automation_bridge".to_string(),
                authority_tier_label: "Automation bridge".to_string(),
                availability_label: "Disabled".to_string(),
                session_scope_label: "Matches current workspace".to_string(),
                why_active: "Test hook".to_string(),
            });
        }
        SessionHookSnapshot {
            generated_at_ms: 0,
            session_id: Some("session-a".to_string()),
            workspace_root: Some("/tmp/a".to_string()),
            active_hook_count,
            disabled_hook_count,
            runtime_receipt_count,
            approval_receipt_count,
            hooks,
            recent_receipts: Vec::new(),
        }
    }

    fn remembered_approvals(
        active_decision_count: usize,
        recent_receipt_count: usize,
    ) -> crate::kernel::connectors::ShieldRememberedApprovalSnapshot {
        crate::kernel::connectors::ShieldRememberedApprovalSnapshot {
            generated_at_ms: 0,
            active_decision_count,
            recent_receipt_count,
            decisions: Vec::new(),
            recent_receipts: Vec::new(),
        }
    }

    fn sample_playbook() -> LocalEngineAgentPlaybookRecord {
        LocalEngineAgentPlaybookRecord {
            playbook_id: "evidence_audited_patch".to_string(),
            label: "Evidence-Audited Patch".to_string(),
            summary: "Patch flow".to_string(),
            goal_template: "Close {topic}".to_string(),
            route_family: "coding".to_string(),
            topology: "planner_specialist_verifier".to_string(),
            trigger_intents: vec!["workspace.ops".to_string()],
            recommended_for: vec!["Patch work".to_string()],
            default_budget: 196,
            completion_contract: LocalEngineWorkerCompletionContract {
                success_criteria: "Return a verified patch summary.".to_string(),
                expected_output: "Patch handoff".to_string(),
                merge_mode: "append summary".to_string(),
                verification_hint: None,
            },
            steps: vec![
                LocalEngineAgentPlaybookStepRecord {
                    step_id: "context".to_string(),
                    label: "Capture repo context".to_string(),
                    summary: "Gather repo context.".to_string(),
                    worker_template_id: "context_worker".to_string(),
                    worker_workflow_id: "repo_context_brief".to_string(),
                    goal_template: "Gather context".to_string(),
                    depends_on: Vec::new(),
                },
                LocalEngineAgentPlaybookStepRecord {
                    step_id: "implement".to_string(),
                    label: "Patch the workspace".to_string(),
                    summary: "Apply the patch.".to_string(),
                    worker_template_id: "coder".to_string(),
                    worker_workflow_id: "patch_build_verify".to_string(),
                    goal_template: "Patch the repo".to_string(),
                    depends_on: vec!["context".to_string()],
                },
                LocalEngineAgentPlaybookStepRecord {
                    step_id: "verify".to_string(),
                    label: "Verify targeted tests".to_string(),
                    summary: "Run targeted verification.".to_string(),
                    worker_template_id: "verifier".to_string(),
                    worker_workflow_id: "targeted_test_audit".to_string(),
                    goal_template: "Verify the patch".to_string(),
                    depends_on: vec!["implement".to_string()],
                },
            ],
        }
    }

    fn sample_run() -> LocalEngineParentPlaybookRunRecord {
        LocalEngineParentPlaybookRunRecord {
            run_id: "run-1".to_string(),
            parent_session_id: "session-a".to_string(),
            playbook_id: "evidence_audited_patch".to_string(),
            playbook_label: "Evidence-Audited Patch".to_string(),
            status: "running".to_string(),
            latest_phase: "step_spawned".to_string(),
            summary: "Delegated patch flow is in flight.".to_string(),
            current_step_id: Some("implement".to_string()),
            current_step_label: Some("Patch the workspace".to_string()),
            active_child_session_id: Some("worker-2".to_string()),
            started_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: None,
            error_class: None,
            steps: vec![
                LocalEngineParentPlaybookStepRunRecord {
                    step_id: "context".to_string(),
                    label: "Capture repo context".to_string(),
                    summary: "Context brief captured.".to_string(),
                    status: "completed".to_string(),
                    child_session_id: Some("worker-1".to_string()),
                    template_id: Some("context_worker".to_string()),
                    workflow_id: Some("repo_context_brief".to_string()),
                    updated_at_ms: Some(1),
                    completed_at_ms: Some(1),
                    error_class: None,
                    receipts: vec![LocalEngineParentPlaybookReceiptRecord {
                        event_id: "event-1".to_string(),
                        timestamp_ms: 1,
                        phase: "step_completed".to_string(),
                        status: "completed".to_string(),
                        success: true,
                        summary: "Context brief captured.".to_string(),
                        receipt_ref: Some("receipt-1".to_string()),
                        child_session_id: Some("worker-1".to_string()),
                        template_id: Some("context_worker".to_string()),
                        workflow_id: Some("repo_context_brief".to_string()),
                        error_class: None,
                        artifact_ids: vec!["artifact-1".to_string()],
                    }],
                },
                LocalEngineParentPlaybookStepRunRecord {
                    step_id: "implement".to_string(),
                    label: "Patch the workspace".to_string(),
                    summary: "Patch worker is still running.".to_string(),
                    status: "running".to_string(),
                    child_session_id: Some("worker-2".to_string()),
                    template_id: Some("coder".to_string()),
                    workflow_id: Some("patch_build_verify".to_string()),
                    updated_at_ms: Some(2),
                    completed_at_ms: None,
                    error_class: None,
                    receipts: Vec::new(),
                },
                LocalEngineParentPlaybookStepRunRecord {
                    step_id: "verify".to_string(),
                    label: "Verify targeted tests".to_string(),
                    summary: "Verification is still pending.".to_string(),
                    status: "pending".to_string(),
                    child_session_id: None,
                    template_id: Some("verifier".to_string()),
                    workflow_id: Some("targeted_test_audit".to_string()),
                    updated_at_ms: None,
                    completed_at_ms: None,
                    error_class: None,
                    receipts: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn latest_attachable_target_prefers_first_target_with_workspace_root() {
        let targets = vec![
            target("session-a", None),
            target("session-b", Some("/tmp/repo")),
        ];
        let selected = select_attachable_target(&targets, Some("latest")).expect("attach target");
        assert_eq!(selected.session_id, "session-b");
    }

    #[test]
    fn explicit_target_selection_returns_exact_session() {
        let targets = vec![
            target("session-a", Some("/tmp/a")),
            target("session-b", Some("/tmp/b")),
        ];
        let selected = select_target(&targets, Some("session-b")).expect("selected target");
        assert_eq!(selected.session_id, "session-b");
    }

    #[test]
    fn explicit_attach_requires_workspace_root() {
        let targets = vec![target("session-a", None)];
        let error =
            select_attachable_target(&targets, Some("session-a")).expect_err("missing root");
        assert!(error.contains("workspace root"));
    }

    #[test]
    fn compaction_flags_parse_into_policy() {
        let policy = compaction_policy_from_flags(&[
            "--pinned-only".to_string(),
            "--drop-background".to_string(),
            "--aggressive-pruning".to_string(),
        ])
        .expect("policy parse")
        .expect("changed policy");

        assert!(policy.carry_pinned_only);
        assert!(!policy.preserve_background_tasks);
        assert!(policy.aggressive_transcript_pruning);
        assert!(policy.preserve_checklist_state);
    }

    #[test]
    fn selector_and_policy_parser_supports_selector_plus_flags() {
        let targets = vec![
            target("session-a", Some("/tmp/a")),
            target("session-b", Some("/tmp/b")),
        ];
        let (selector, policy) = selector_and_compaction_policy(
            vec![
                "session-b".to_string(),
                "--drop-output".to_string(),
                "--drop-blockers".to_string(),
            ],
            &targets,
        )
        .expect("selector and policy");

        let policy = policy.expect("changed policy");
        assert_eq!(selector.as_deref(), Some("session-b"));
        assert!(!policy.preserve_latest_output_excerpt);
        assert!(!policy.preserve_governance_blockers);
    }

    #[test]
    fn authority_profile_resolution_matches_guided_default() {
        let profile_id =
            resolve_authority_profile_id(&crate::kernel::connectors::ShieldPolicyState::default());
        assert_eq!(profile_id.as_deref(), Some("guided_default"));
    }

    #[test]
    fn authority_profile_apply_replaces_global_defaults() {
        let updated = apply_authority_profile(
            crate::kernel::connectors::ShieldPolicyState::default(),
            "safer_review",
        )
        .expect("profile apply");

        assert_eq!(
            resolve_authority_profile_id(&updated).as_deref(),
            Some("safer_review")
        );
    }

    #[test]
    fn authority_override_apply_sets_connector_specific_profile() {
        let updated = apply_authority_override(
            crate::kernel::connectors::ShieldPolicyState::default(),
            "gmail",
            "autonomous",
        )
        .expect("override apply");

        let override_state = updated.overrides.get("gmail").expect("gmail override");
        assert!(!override_state.inherit_global);
        assert_eq!(override_state.reads, PolicyDecisionMode::Auto);
        assert_eq!(override_state.writes, PolicyDecisionMode::Auto);
        assert_eq!(
            override_state.data_handling,
            DataHandlingMode::LocalRedacted
        );
    }

    #[test]
    fn authority_override_apply_can_reset_to_inherit() {
        let seeded = apply_authority_override(
            crate::kernel::connectors::ShieldPolicyState::default(),
            "gmail",
            "safer_review",
        )
        .expect("seeded override");
        let updated = apply_authority_override(seeded, "gmail", "inherit").expect("reset override");

        assert!(!updated.overrides.contains_key("gmail"));
    }

    #[test]
    fn authority_recommendation_tightens_when_approval_receipts_exist() {
        let plan = build_repl_authority_recommendation(
            Some("guided_default"),
            &hook_snapshot(1, 0, 0, 1),
            &remembered_approvals(1, 1),
            0,
        );

        assert_eq!(plan.recommended_profile_id.as_deref(), Some("safer_review"));
        assert_eq!(plan.action_kind, "apply_profile");
    }

    #[test]
    fn authority_recommendation_widens_back_to_guided_default_when_safe() {
        let mut snapshot = hook_snapshot(1, 0, 2, 0);
        snapshot.hooks.push(SessionHookRecord {
            hook_id: "hook-1".to_string(),
            entry_id: None,
            label: "Hook".to_string(),
            owner_label: "Owner".to_string(),
            source_label: "Source".to_string(),
            source_kind: "extension".to_string(),
            source_uri: None,
            contribution_path: None,
            trigger_label: "Trigger".to_string(),
            enabled: true,
            status_label: "Enabled".to_string(),
            trust_posture: "contained_local".to_string(),
            governed_profile: "automation_bridge".to_string(),
            authority_tier_label: "Automation bridge".to_string(),
            availability_label: "Ready".to_string(),
            session_scope_label: "Matches current workspace".to_string(),
            why_active: "Test hook".to_string(),
        });
        snapshot.recent_receipts.push(SessionHookReceiptSummary {
            title: "Hook".to_string(),
            timestamp_ms: 0,
            tool_name: "hook_worker".to_string(),
            status: "success".to_string(),
            summary: "Worker hook ran".to_string(),
        });

        let plan = build_repl_authority_recommendation(
            Some("safer_review"),
            &snapshot,
            &remembered_approvals(1, 1),
            0,
        );

        assert_eq!(
            plan.recommended_profile_id.as_deref(),
            Some("guided_default")
        );
        assert_eq!(plan.action_kind, "apply_profile");
    }

    #[test]
    fn delegated_run_view_marks_dependency_satisfied_pending_step_as_startable() {
        let playbook = sample_playbook();
        let playbooks = BTreeMap::from([(playbook.playbook_id.clone(), playbook)]);
        let mut run = sample_run();
        run.steps[1].status = "completed".to_string();
        run.steps[1]
            .receipts
            .push(LocalEngineParentPlaybookReceiptRecord {
                event_id: "event-2".to_string(),
                timestamp_ms: 2,
                phase: "step_completed".to_string(),
                status: "completed".to_string(),
                success: true,
                summary: "Patch landed.".to_string(),
                receipt_ref: Some("receipt-2".to_string()),
                child_session_id: Some("worker-2".to_string()),
                template_id: Some("coder".to_string()),
                workflow_id: Some("patch_build_verify".to_string()),
                error_class: None,
                artifact_ids: Vec::new(),
            });
        run.current_step_id = Some("verify".to_string());
        run.current_step_label = Some("Verify targeted tests".to_string());

        let (summary, runs) = build_repl_delegated_runs(&[run], &playbooks);
        let verify_step = runs[0]
            .steps
            .iter()
            .find(|step| step.step_id == "verify")
            .expect("verify step");

        assert_eq!(summary.status_label, "Delegated work is ready to advance");
        assert!(verify_step.can_start);
        assert_eq!(verify_step.dependency_status, "Ready now");
    }

    #[test]
    fn delegated_run_summary_prioritizes_blocked_steps() {
        let playbook = sample_playbook();
        let playbooks = BTreeMap::from([(playbook.playbook_id.clone(), playbook)]);
        let mut run = sample_run();
        run.status = "blocked".to_string();
        run.steps[1].status = "blocked".to_string();
        run.steps[1].error_class = Some("approval_required".to_string());

        let (summary, runs) = build_repl_delegated_runs(&[run], &playbooks);

        assert_eq!(summary.status_label, "Delegated work needs review");
        assert_eq!(summary.blocked_step_count, 1);
        assert!(summary.detail.contains("Patch the workspace"));
        assert_eq!(runs[0].blocked_step_count, 1);
    }
}
