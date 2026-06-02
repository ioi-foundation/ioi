use crate::agentic::runtime::agent_playbooks::builtin_agent_playbooks;
use crate::agentic::runtime::keys::{
    get_agent_brain_key, get_agent_trajectory_step_key, get_harness_worker_session_key,
    get_parent_playbook_run_key, get_session_result_key, get_state_key, get_worker_assignment_key,
};
use crate::agentic::runtime::types::{
    AgentState, AgentStatus, ParentPlaybookRun, WorkerAssignment, WorkerSessionResult,
};
use ioi_api::state::StateAccess;
use ioi_types::app::HarnessWorkerSessionRecord;
use ioi_types::codec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const RUNTIME_DELEGATION_SCHEMA_VERSION: &str = "ioi.runtime.delegation.v1";
const RUNS_TRACING_VISIBILITY: &str = "runs_tracing";
const PRODUCT_SUMMARY_MAX_CHARS: usize = 280;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDelegationSnapshot {
    pub schema_version: String,
    pub session_id: String,
    pub role: String,
    pub parent_session_id: Option<String>,
    pub child_count: usize,
    pub active_child_session_id: Option<String>,
    pub child_sessions: Vec<RuntimeDelegatedChildSnapshot>,
    pub parent_playbooks: Vec<RuntimeParentPlaybookSnapshot>,
    pub recovery: RuntimeDelegationRecoverySnapshot,
    pub product_lane: Vec<RuntimeDelegationProductLaneEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDelegatedChildSnapshot {
    pub child_session_id: String,
    pub parent_session_id: Option<String>,
    pub status: String,
    pub step_count: Option<u32>,
    pub max_steps: Option<u32>,
    pub has_state: bool,
    pub trajectory_present: bool,
    pub brain_present: bool,
    pub assignment: Option<RuntimeWorkerAssignmentSnapshot>,
    pub result: Option<RuntimeWorkerResultSnapshot>,
    pub harness_worker_session: Option<RuntimeHarnessWorkerSessionSnapshot>,
    pub recoverable: bool,
    pub product_summary: String,
    pub detail_visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeWorkerAssignmentSnapshot {
    pub role: String,
    pub status: String,
    pub playbook_id: Option<String>,
    pub template_id: Option<String>,
    pub workflow_id: Option<String>,
    pub allowed_tool_count: usize,
    pub completion_merge_mode: String,
    pub success_criteria_present: bool,
    pub expected_output_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeWorkerResultSnapshot {
    pub status: String,
    pub success: bool,
    pub error_class: Option<String>,
    pub merged: bool,
    pub handoff_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHarnessWorkerSessionSnapshot {
    pub session_record_id_present: bool,
    pub status: String,
    pub persisted_in_runtime_checkpoint: bool,
    pub restored_from_persisted_session: bool,
    pub launch_authority_ready: bool,
    pub rollback_handoff_ready: bool,
    pub blocker_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeParentPlaybookSnapshot {
    pub playbook_id: String,
    pub label: String,
    pub status: String,
    pub current_step_index: u32,
    pub active_child_session_id: Option<String>,
    pub steps: Vec<RuntimeParentPlaybookStepSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeParentPlaybookStepSnapshot {
    pub step_id: String,
    pub label: String,
    pub status: String,
    pub child_session_id: Option<String>,
    pub template_id: Option<String>,
    pub workflow_id: Option<String>,
    pub has_output_preview: bool,
    pub output_preview: Option<String>,
    pub error_class: Option<String>,
    pub detail_visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDelegationRecoverySnapshot {
    pub replay_cursor_step: u32,
    pub parent_has_child_links: bool,
    pub all_child_states_present: bool,
    pub missing_child_session_ids: Vec<String>,
    pub active_child_session_id: Option<String>,
    pub active_child_recoverable: bool,
    pub failed_child_feedback: Vec<RuntimeFailedChildFeedback>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeFailedChildFeedback {
    pub child_session_id: String,
    pub status: String,
    pub error_class: Option<String>,
    pub feedback_preview: String,
    pub detail_visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDelegationProductLaneEntry {
    pub kind: String,
    pub label: String,
    pub status: String,
    pub child_session_id: Option<String>,
    pub summary: String,
    pub detail_visibility: String,
}

pub fn delegation_snapshot_for_state(
    state: &dyn StateAccess,
    parent_state: &AgentState,
) -> Result<RuntimeDelegationSnapshot, String> {
    let session_id = parent_state.session_id;
    let session_hex = hex::encode(session_id);
    let parent_playbooks = load_parent_playbook_snapshots(state, session_id)?;
    let active_child_session_id = active_child_from_parent_playbooks(&parent_playbooks)
        .or_else(|| parent_state.child_session_ids.last().map(hex::encode));
    let child_ids = collect_child_session_ids(parent_state, &parent_playbooks);
    let mut child_sessions = Vec::with_capacity(child_ids.len());
    let mut missing_child_session_ids = Vec::new();
    let mut failed_child_feedback = Vec::new();
    let mut product_lane = Vec::new();

    for child_id in child_ids {
        let child_hex = hex::encode(child_id);
        let child = child_snapshot(state, child_id)?;
        if !child.has_state {
            missing_child_session_ids.push(child_hex.clone());
        }
        if let Some(feedback) = failed_feedback_for_child(&child) {
            failed_child_feedback.push(feedback);
        }
        product_lane.push(product_lane_entry_for_child(&child));
        child_sessions.push(child);
    }

    for playbook in &parent_playbooks {
        product_lane.push(RuntimeDelegationProductLaneEntry {
            kind: "parent_playbook".to_string(),
            label: playbook.label.clone(),
            status: playbook.status.clone(),
            child_session_id: playbook.active_child_session_id.clone(),
            summary: format!(
                "{} is {} at step {}.",
                playbook.label, playbook.status, playbook.current_step_index
            ),
            detail_visibility: RUNS_TRACING_VISIBILITY.to_string(),
        });
    }

    let active_child_recoverable = active_child_session_id
        .as_ref()
        .and_then(|active| {
            child_sessions
                .iter()
                .find(|child| child.child_session_id == *active)
        })
        .map(|child| child.recoverable)
        .unwrap_or(false);
    let child_count = child_sessions.len();

    Ok(RuntimeDelegationSnapshot {
        schema_version: RUNTIME_DELEGATION_SCHEMA_VERSION.to_string(),
        session_id: session_hex,
        role: if parent_state.parent_session_id.is_some() {
            "child".to_string()
        } else if child_count > 0 {
            "parent".to_string()
        } else {
            "standalone".to_string()
        },
        parent_session_id: parent_state.parent_session_id.map(hex::encode),
        child_count,
        active_child_session_id: active_child_session_id.clone(),
        child_sessions,
        parent_playbooks,
        recovery: RuntimeDelegationRecoverySnapshot {
            replay_cursor_step: parent_state.step_count,
            parent_has_child_links: child_count > 0,
            all_child_states_present: missing_child_session_ids.is_empty(),
            missing_child_session_ids,
            active_child_session_id,
            active_child_recoverable,
            failed_child_feedback,
        },
        product_lane,
    })
}

fn collect_child_session_ids(
    parent_state: &AgentState,
    parent_playbooks: &[RuntimeParentPlaybookSnapshot],
) -> Vec<[u8; 32]> {
    let mut seen = BTreeSet::new();
    let mut child_ids = Vec::new();
    for child_id in &parent_state.child_session_ids {
        let key = hex::encode(child_id);
        if seen.insert(key) {
            child_ids.push(*child_id);
        }
    }
    for playbook in parent_playbooks {
        for step in &playbook.steps {
            let Some(child_hex) = step.child_session_id.as_deref() else {
                continue;
            };
            let Some(child_id) = parse_session_hex(child_hex) else {
                continue;
            };
            if seen.insert(child_hex.to_string()) {
                child_ids.push(child_id);
            }
        }
    }
    child_ids
}

fn child_snapshot(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> Result<RuntimeDelegatedChildSnapshot, String> {
    let child_hex = hex::encode(child_session_id);
    let child_state = load_optional_state::<AgentState>(
        state,
        &get_state_key(&child_session_id),
        "child agent state",
    )?;
    let assignment = load_optional_state::<WorkerAssignment>(
        state,
        &get_worker_assignment_key(&child_session_id),
        "worker assignment",
    )?
    .map(worker_assignment_snapshot);
    let result = load_optional_state::<WorkerSessionResult>(
        state,
        &get_session_result_key(&child_session_id),
        "worker session result",
    )?
    .map(worker_result_snapshot);
    let harness_worker_session = load_optional_state::<HarnessWorkerSessionRecord>(
        state,
        &get_harness_worker_session_key(&child_session_id),
        "harness worker session",
    )?
    .map(harness_worker_session_snapshot);

    let (parent_session_id, status, step_count, max_steps, trajectory_present, brain_present) =
        if let Some(child_state) = child_state.as_ref() {
            (
                child_state.parent_session_id.map(hex::encode),
                agent_status_label(&child_state.status).to_string(),
                Some(child_state.step_count),
                Some(child_state.max_steps),
                state_has_key(
                    state,
                    &get_agent_trajectory_step_key(&child_session_id, child_state.step_count),
                )?,
                state_has_key(state, &get_agent_brain_key(&child_session_id))?,
            )
        } else {
            (None, "missing_state".to_string(), None, None, false, false)
        };
    let recoverable = child_state.is_some()
        && matches!(
            status.as_str(),
            "running" | "paused" | "failed" | "completed" | "idle" | "terminated"
        );
    let product_summary =
        product_summary_for_child(&child_hex, &status, assignment.as_ref(), result.as_ref());

    Ok(RuntimeDelegatedChildSnapshot {
        child_session_id: child_hex,
        parent_session_id,
        status,
        step_count,
        max_steps,
        has_state: child_state.is_some(),
        trajectory_present,
        brain_present,
        assignment,
        result,
        harness_worker_session,
        recoverable,
        product_summary,
        detail_visibility: RUNS_TRACING_VISIBILITY.to_string(),
    })
}

fn load_parent_playbook_snapshots(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
) -> Result<Vec<RuntimeParentPlaybookSnapshot>, String> {
    let mut snapshots = Vec::new();
    for playbook in builtin_agent_playbooks() {
        let Some(run) = load_optional_state::<ParentPlaybookRun>(
            state,
            &get_parent_playbook_run_key(&parent_session_id, &playbook.playbook_id),
            "parent playbook run",
        )?
        else {
            continue;
        };
        snapshots.push(RuntimeParentPlaybookSnapshot {
            playbook_id: run.playbook_id,
            label: run.playbook_label,
            status: run.status.as_label().to_string(),
            current_step_index: run.current_step_index,
            active_child_session_id: run.active_child_session_id.map(hex::encode),
            steps: run
                .steps
                .into_iter()
                .map(|step| RuntimeParentPlaybookStepSnapshot {
                    step_id: step.step_id,
                    label: step.label,
                    status: step.status.as_label().to_string(),
                    child_session_id: step.child_session_id.map(hex::encode),
                    template_id: step.template_id,
                    workflow_id: step.workflow_id,
                    has_output_preview: step
                        .output_preview
                        .as_deref()
                        .map(|value| !value.trim().is_empty())
                        .unwrap_or(false),
                    output_preview: step
                        .output_preview
                        .as_deref()
                        .map(|value| truncate_chars(value.trim(), PRODUCT_SUMMARY_MAX_CHARS)),
                    error_class: step.error.as_deref().and_then(extract_error_class),
                    detail_visibility: RUNS_TRACING_VISIBILITY.to_string(),
                })
                .collect(),
        });
    }
    Ok(snapshots)
}

fn active_child_from_parent_playbooks(
    parent_playbooks: &[RuntimeParentPlaybookSnapshot],
) -> Option<String> {
    parent_playbooks
        .iter()
        .find_map(|run| run.active_child_session_id.clone())
}

fn worker_assignment_snapshot(assignment: WorkerAssignment) -> RuntimeWorkerAssignmentSnapshot {
    RuntimeWorkerAssignmentSnapshot {
        role: assignment
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("delegated worker")
            .to_string(),
        status: assignment.status,
        playbook_id: assignment.playbook_id,
        template_id: assignment.template_id,
        workflow_id: assignment.workflow_id,
        allowed_tool_count: assignment.allowed_tools.len(),
        completion_merge_mode: assignment
            .completion_contract
            .merge_mode
            .as_label()
            .to_string(),
        success_criteria_present: !assignment
            .completion_contract
            .success_criteria
            .trim()
            .is_empty(),
        expected_output_present: !assignment
            .completion_contract
            .expected_output
            .trim()
            .is_empty(),
    }
}

fn worker_result_snapshot(result: WorkerSessionResult) -> RuntimeWorkerResultSnapshot {
    RuntimeWorkerResultSnapshot {
        status: result.status,
        success: result.success,
        error_class: result.error.as_deref().and_then(extract_error_class),
        merged: result.merged_at_ms.is_some(),
        handoff_preview: (!result.merged_output.trim().is_empty())
            .then(|| truncate_chars(result.merged_output.trim(), PRODUCT_SUMMARY_MAX_CHARS)),
    }
}

fn harness_worker_session_snapshot(
    record: HarnessWorkerSessionRecord,
) -> RuntimeHarnessWorkerSessionSnapshot {
    let blocker_count = record.blockers.len()
        + record.persistence_blockers.len()
        + record.launch_authority_blockers.len()
        + record.rollback_handoff_blockers.len();
    RuntimeHarnessWorkerSessionSnapshot {
        session_record_id_present: !record.session_record_id.trim().is_empty(),
        status: record.current_status.as_str().to_string(),
        persisted_in_runtime_checkpoint: record.persisted_in_runtime_checkpoint,
        restored_from_persisted_session: record.restored_from_persisted_session,
        launch_authority_ready: record.launch_authority_ready,
        rollback_handoff_ready: record.rollback_handoff_ready,
        blocker_count,
    }
}

fn product_summary_for_child(
    child_hex: &str,
    status: &str,
    assignment: Option<&RuntimeWorkerAssignmentSnapshot>,
    result: Option<&RuntimeWorkerResultSnapshot>,
) -> String {
    let role = assignment
        .map(|assignment| assignment.role.as_str())
        .unwrap_or("delegated worker");
    if let Some(preview) = result.and_then(|result| result.handoff_preview.as_deref()) {
        return truncate_chars(
            &format!("{role} {status}; handoff: {preview}"),
            PRODUCT_SUMMARY_MAX_CHARS,
        );
    }
    let short_child = child_hex.chars().take(8).collect::<String>();
    format!("{role} {status} (child {short_child}).")
}

fn product_lane_entry_for_child(
    child: &RuntimeDelegatedChildSnapshot,
) -> RuntimeDelegationProductLaneEntry {
    let label = child
        .assignment
        .as_ref()
        .map(|assignment| assignment.role.clone())
        .unwrap_or_else(|| "Delegated worker".to_string());
    RuntimeDelegationProductLaneEntry {
        kind: "delegated_child".to_string(),
        label,
        status: child.status.clone(),
        child_session_id: Some(child.child_session_id.clone()),
        summary: child.product_summary.clone(),
        detail_visibility: RUNS_TRACING_VISIBILITY.to_string(),
    }
}

fn failed_feedback_for_child(
    child: &RuntimeDelegatedChildSnapshot,
) -> Option<RuntimeFailedChildFeedback> {
    if !matches!(child.status.as_str(), "failed" | "paused" | "terminated")
        && !child
            .result
            .as_ref()
            .map(|result| !result.success)
            .unwrap_or(false)
    {
        return None;
    }
    let feedback_preview = child
        .result
        .as_ref()
        .and_then(|result| result.handoff_preview.clone())
        .unwrap_or_else(|| child.product_summary.clone());
    Some(RuntimeFailedChildFeedback {
        child_session_id: child.child_session_id.clone(),
        status: child.status.clone(),
        error_class: child
            .result
            .as_ref()
            .and_then(|result| result.error_class.clone()),
        feedback_preview,
        detail_visibility: RUNS_TRACING_VISIBILITY.to_string(),
    })
}

fn state_has_key(state: &dyn StateAccess, key: &[u8]) -> Result<bool, String> {
    state
        .get(key)
        .map(|value| value.is_some())
        .map_err(|error| format!("Failed to read runtime delegation key: {error}"))
}

fn load_optional_state<T: parity_scale_codec::Decode>(
    state: &dyn StateAccess,
    key: &[u8],
    label: &str,
) -> Result<Option<T>, String> {
    let Some(bytes) = state
        .get(key)
        .map_err(|error| format!("Failed to read {label}: {error}"))?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<T>(&bytes)
        .map(Some)
        .map_err(|error| format!("Failed to decode {label}: {error}"))
}

fn parse_session_hex(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn agent_status_label(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Idle => "idle",
        AgentStatus::Running => "running",
        AgentStatus::Completed(_) => "completed",
        AgentStatus::Failed(_) => "failed",
        AgentStatus::Paused(_) => "paused",
        AgentStatus::Terminated => "terminated",
    }
}

fn extract_error_class(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    value
        .split_whitespace()
        .find_map(|part| part.strip_prefix("ERROR_CLASS="))
        .map(|class| {
            class
                .trim_matches(|ch| matches!(ch, ':' | ',' | ';'))
                .to_string()
        })
        .filter(|class| !class.is_empty())
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::keys::{
        get_agent_brain_key, get_agent_trajectory_step_key, get_parent_playbook_run_key,
    };
    use crate::agentic::runtime::trajectory::{AgentBrainRecord, AgentTrajectoryStepRecord};
    use crate::agentic::runtime::types::{
        AgentMode, ExecutionTier, ParentPlaybookStatus, ParentPlaybookStepRun,
        ParentPlaybookStepStatus, ToolCallStatus, WorkerCompletionContract, WorkerMergeMode,
    };
    use ioi_api::state::StateScanIter;
    use ioi_types::error::StateError;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    fn agent_state(session_id: [u8; 32], status: AgentStatus) -> AgentState {
        AgentState {
            session_id,
            goal: "fix a failing disposable test".to_string(),
            runtime_route_frame: None,
            transcript_root: [0u8; 32],
            status,
            step_count: 3,
            max_steps: 12,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 100,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::<String, ToolCallStatus>::new(),
            execution_ledger: Default::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn put<T: parity_scale_codec::Encode>(state: &mut MockState, key: Vec<u8>, value: &T) {
        state
            .insert(&key, &codec::to_bytes_canonical(value).unwrap())
            .unwrap();
    }

    fn worker_assignment(child_session_id: [u8; 32]) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:3:22222222".to_string(),
            budget: 16,
            goal: "Verify the focused patch and return evidence.".to_string(),
            success_criteria: "focused verification passes".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(child_session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("verifier".to_string()),
            workflow_id: Some("targeted_test_audit".to_string()),
            role: Some("Verifier".to_string()),
            allowed_tools: vec!["file__read".to_string(), "shell__start".to_string()],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Run focused validation.".to_string(),
                expected_output: "Verifier handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }
    }

    #[test]
    fn delegation_snapshot_reports_parent_child_linkage_and_safe_product_lane() {
        let mut state = MockState::default();
        let parent_id = [0x11; 32];
        let child_id = [0x22; 32];
        let mut parent = agent_state(parent_id, AgentStatus::Running);
        parent.child_session_ids.push(child_id);
        let mut child = agent_state(
            child_id,
            AgentStatus::Failed("ERROR_CLASS=StopHookBlocked test failed".to_string()),
        );
        child.parent_session_id = Some(parent_id);
        put(&mut state, get_state_key(&child_id), &child);
        put(
            &mut state,
            get_worker_assignment_key(&child_id),
            &worker_assignment(child_id),
        );
        put(
            &mut state,
            get_session_result_key(&child_id),
            &WorkerSessionResult {
                child_session_id: child_id,
                parent_session_id: parent_id,
                budget: 16,
                playbook_id: Some("evidence_audited_patch".to_string()),
                template_id: Some("verifier".to_string()),
                workflow_id: Some("targeted_test_audit".to_string()),
                role: "Verifier".to_string(),
                goal: "Verify the focused patch.".to_string(),
                status: "failed".to_string(),
                success: false,
                error: Some("ERROR_CLASS=StopHookBlocked npm test failed".to_string()),
                raw_output: Some("raw child details stay in tracing".to_string()),
                merged_output:
                    "Focused validation failed; parent should repair and rerun the target test."
                        .to_string(),
                completion_contract: WorkerCompletionContract::default(),
                completed_at_ms: 1,
                merged_at_ms: Some(2),
                merged_step_index: Some(3),
            },
        );
        put(
            &mut state,
            get_agent_trajectory_step_key(&child_id, child.step_count),
            &AgentTrajectoryStepRecord {
                session_id: hex::encode(child_id),
                step_index: child.step_count,
                status: "failed".to_string(),
                ..Default::default()
            },
        );
        put(
            &mut state,
            get_agent_brain_key(&child_id),
            &AgentBrainRecord {
                session_id: hex::encode(child_id),
                status: "failed".to_string(),
                ..Default::default()
            },
        );

        let snapshot = delegation_snapshot_for_state(&state, &parent).unwrap();

        assert_eq!(snapshot.schema_version, RUNTIME_DELEGATION_SCHEMA_VERSION);
        assert_eq!(snapshot.role, "parent");
        assert_eq!(snapshot.child_count, 1);
        assert!(snapshot.recovery.parent_has_child_links);
        assert!(snapshot.recovery.all_child_states_present);
        assert_eq!(snapshot.recovery.failed_child_feedback.len(), 1);
        let child_snapshot = &snapshot.child_sessions[0];
        assert_eq!(child_snapshot.status, "failed");
        assert!(child_snapshot.trajectory_present);
        assert!(child_snapshot.brain_present);
        assert_eq!(
            child_snapshot
                .result
                .as_ref()
                .unwrap()
                .error_class
                .as_deref(),
            Some("StopHookBlocked")
        );
        assert_eq!(
            snapshot.product_lane[0].detail_visibility,
            RUNS_TRACING_VISIBILITY
        );
        assert!(!snapshot.product_lane[0]
            .summary
            .contains("raw child details"));
    }

    #[test]
    fn delegation_snapshot_includes_parent_playbook_steps() {
        let mut state = MockState::default();
        let parent_id = [0x33; 32];
        let child_id = [0x44; 32];
        let parent = agent_state(parent_id, AgentStatus::Running);
        let run = ParentPlaybookRun {
            parent_session_id: parent_id,
            playbook_id: "evidence_audited_patch".to_string(),
            playbook_label: "Evidence-Audited Patch".to_string(),
            topic: "fix a failing disposable test".to_string(),
            status: ParentPlaybookStatus::Running,
            current_step_index: 2,
            active_child_session_id: Some(child_id),
            started_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: None,
            steps: vec![ParentPlaybookStepRun {
                step_id: "verify".to_string(),
                label: "Verify targeted tests".to_string(),
                summary: "Run focused checks.".to_string(),
                status: ParentPlaybookStepStatus::Running,
                child_session_id: Some(child_id),
                template_id: Some("verifier".to_string()),
                workflow_id: Some("targeted_test_audit".to_string()),
                output_preview: Some("Verifier is running focused checks.".to_string()),
                ..Default::default()
            }],
        };
        put(
            &mut state,
            get_parent_playbook_run_key(&parent_id, "evidence_audited_patch"),
            &run,
        );

        let snapshot = delegation_snapshot_for_state(&state, &parent).unwrap();

        assert_eq!(
            snapshot.active_child_session_id,
            Some(hex::encode(child_id))
        );
        assert_eq!(snapshot.parent_playbooks.len(), 1);
        assert_eq!(snapshot.parent_playbooks[0].steps.len(), 1);
        assert_eq!(
            snapshot.parent_playbooks[0].steps[0].detail_visibility,
            RUNS_TRACING_VISIBILITY
        );
        assert_eq!(
            snapshot.recovery.missing_child_session_ids,
            vec![hex::encode(child_id)]
        );
    }
}
