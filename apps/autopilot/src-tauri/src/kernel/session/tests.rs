use super::{
    build_session_rewind_snapshot, compact_retained_session_for_sessions,
    forget_team_memory_entry_for_sessions, session_compaction_snapshot_for_sessions,
    sync_team_memory_for_sessions, team_memory_snapshot_for_sessions,
};
use crate::models::{
    AgentPhase, AgentTask, ChatMessage, GateInfo, SessionBackgroundTaskRecord,
    SessionChecklistItem, SessionCompactionDisposition, SessionCompactionMode,
    SessionCompactionPolicy, SessionCompactionResumeSafetyStatus, SessionFileContext,
    SessionMemoryClass, SessionSummary,
};
use crate::open_or_create_memory_runtime;
use crate::orchestrator::{
    save_local_session_summary, save_local_task_state, save_session_file_context,
};
use std::collections::HashSet;
use std::sync::Arc;

fn summary(
    session_id: &str,
    title: &str,
    timestamp: u64,
    phase: Option<AgentPhase>,
    current_step: Option<&str>,
) -> SessionSummary {
    SessionSummary {
        session_id: session_id.to_string(),
        title: title.to_string(),
        timestamp,
        phase,
        current_step: current_step.map(str::to_string),
        resume_hint: None,
        workspace_root: Some("/tmp/repo".to_string()),
    }
}

fn task(session_id: &str, intent: &str) -> AgentTask {
    AgentTask {
        id: session_id.to_string(),
        intent: intent.to_string(),
        agent: "Test".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 0,
        current_step: "Routing the request...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some(session_id.to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: Vec::new(),
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
        lineage_id: "lineage".to_string(),
        fitness_score: 0.0,
    }
}

fn temp_memory_runtime() -> Arc<ioi_memory::MemoryRuntime> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "autopilot-session-compaction-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&path).expect("temp memory runtime dir");
    Arc::new(open_or_create_memory_runtime(path.as_path()).expect("memory runtime"))
}

#[test]
fn rewind_snapshot_marks_current_and_last_stable_sessions() {
    let current = summary(
        "aaaabbbb",
        "Current",
        300,
        Some(AgentPhase::Running),
        Some("Waiting for intent clarification."),
    );
    let stable = summary(
        "ccccdddd",
        "Stable",
        200,
        Some(AgentPhase::Complete),
        Some("Reply delivered."),
    );
    let older = summary("eeeeffff", "Older", 100, None, None);

    let snapshot = build_session_rewind_snapshot(
        vec![current, stable.clone(), older],
        Some(&task("aaaabbbb", "Current intent")),
    );

    assert_eq!(snapshot.active_session_id.as_deref(), Some("aaaabbbb"));
    assert_eq!(snapshot.last_stable_session_id.as_deref(), Some("ccccdddd"));
    assert_eq!(snapshot.candidates.len(), 3);
    assert!(snapshot.candidates[0].is_current);
    assert!(snapshot.candidates[1].is_last_stable);
    assert_eq!(
        snapshot.candidates[1].action_label,
        "Rewind to this session"
    );
}

#[test]
fn rewind_snapshot_keeps_non_destructive_discard_summary() {
    let first = summary(
        "11112222",
        "Current",
        200,
        Some(AgentPhase::Running),
        Some("Sending message..."),
    );
    let second = summary(
        "33334444",
        "Previous",
        100,
        Some(AgentPhase::Failed),
        Some("Needs review"),
    );

    let snapshot = build_session_rewind_snapshot(
        vec![first, second],
        Some(&task("11112222", "Current intent")),
    );

    assert!(snapshot.candidates[1]
        .discard_summary
        .contains("Retained evidence and other sessions stay stored"));
}

#[test]
fn compact_session_records_resume_anchor_and_workspace_root() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-compaction",
        "Compaction target",
        1_234,
        Some(AgentPhase::Running),
        Some("Waiting for approval."),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut running_task = task("session-compaction", "run pwd via bash");
    running_task.phase = AgentPhase::Gate;
    running_task.current_step = "Waiting for approval.".to_string();
    running_task.pending_request_hash = Some("gate-hash".to_string());
    running_task.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Latest retained output excerpt".to_string(),
        timestamp: 1_700_000_000_000,
    });
    save_local_task_state(&memory_runtime, &running_task);

    let snapshot = compact_retained_session_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-compaction"),
        Some("session-compaction"),
        None,
    )
    .expect("compaction snapshot");

    let latest = snapshot
        .latest_for_active
        .expect("latest compaction for active session");
    assert_eq!(latest.session_id, "session-compaction");
    assert_eq!(latest.mode, SessionCompactionMode::Manual);
    assert_eq!(latest.policy, SessionCompactionPolicy::default());
    assert_eq!(
        latest
            .carried_forward_state
            .workspace_root
            .as_deref()
            .expect("workspace root"),
        "/tmp/repo"
    );
    assert!(
        latest.resume_anchor.contains("Approval"),
        "resume anchor should carry the retained step"
    );
    assert!(latest
        .carried_forward_state
        .memory_items
        .iter()
        .any(|item| item.memory_class == SessionMemoryClass::GovernanceCritical));
    assert!(latest
        .prune_decisions
        .iter()
        .any(|decision| decision.key == "history_transcript"
            && decision.disposition == SessionCompactionDisposition::RetainedSummary));
    assert_eq!(snapshot.record_count, 1);
    assert_eq!(
        snapshot
            .preview_for_active
            .as_ref()
            .expect("preview")
            .resume_anchor,
        latest.resume_anchor
    );
}

#[test]
fn compaction_snapshot_auto_compacts_eligible_session_once() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-auto-compaction",
        "Auto compaction target",
        1_234,
        Some(AgentPhase::Running),
        Some("Drafting a long response."),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut running_task = task("session-auto-compaction", "summarize this repo");
    running_task.current_step = "Drafting a long response.".to_string();
    for index in 0..super::AUTO_COMPACTION_HISTORY_THRESHOLD {
        running_task.history.push(ChatMessage {
            role: if index % 2 == 0 {
                "assistant".to_string()
            } else {
                "user".to_string()
            },
            text: format!("history message {index}"),
            timestamp: 1_700_000_000_000 + index as u64,
        });
    }
    save_local_task_state(&memory_runtime, &running_task);

    let first_snapshot = session_compaction_snapshot_for_sessions(
        &memory_runtime,
        vec![session.clone()],
        Some("session-auto-compaction"),
        None,
    );
    let latest = first_snapshot
        .latest_for_active
        .as_ref()
        .expect("auto compaction record");
    assert_eq!(latest.mode, SessionCompactionMode::Auto);
    assert_eq!(first_snapshot.record_count, 1);
    assert_eq!(
        first_snapshot
            .recommendation_for_active
            .as_ref()
            .expect("recommendation")
            .should_compact,
        false
    );

    let second_snapshot = session_compaction_snapshot_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-auto-compaction"),
        None,
    );
    assert_eq!(second_snapshot.record_count, 1);
    assert_eq!(
        second_snapshot
            .latest_for_active
            .as_ref()
            .expect("latest compaction")
            .mode,
        SessionCompactionMode::Auto
    );
    assert!(second_snapshot
        .preview_for_active
        .as_ref()
        .expect("preview")
        .prune_decisions
        .iter()
        .any(|decision| decision.key == "history_transcript"
            && decision.detail_count == super::AUTO_COMPACTION_HISTORY_THRESHOLD));
}

#[test]
fn compaction_preview_policy_changes_carried_forward_state() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-policy-preview",
        "Policy preview target",
        1_234,
        Some(AgentPhase::Running),
        Some("Waiting for follow-up."),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut running_task = task("session-policy-preview", "collect the latest repo notes");
    running_task.current_step = "Waiting for follow-up.".to_string();
    running_task.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Latest retained output excerpt".to_string(),
        timestamp: 1_700_000_000_000,
    });
    running_task.session_checklist.push(SessionChecklistItem {
        item_id: "checklist-1".to_string(),
        label: "Update release note".to_string(),
        status: "open".to_string(),
        detail: None,
        updated_at_ms: 1_700_000_000_100,
    });
    running_task
        .background_tasks
        .push(SessionBackgroundTaskRecord {
            task_id: "background-1".to_string(),
            session_id: Some("session-policy-preview".to_string()),
            label: "Watch CI".to_string(),
            status: "running".to_string(),
            detail: None,
            latest_output: None,
            can_stop: true,
            updated_at_ms: 1_700_000_000_200,
        });
    save_local_task_state(&memory_runtime, &running_task);

    save_session_file_context(
        &memory_runtime,
        Some("session-policy-preview"),
        &SessionFileContext {
            session_id: Some("session-policy-preview".to_string()),
            workspace_root: "/tmp/repo".to_string(),
            pinned_files: vec!["/tmp/repo/src/main.rs".to_string()],
            recent_files: Vec::new(),
            explicit_includes: vec!["/tmp/repo/docs".to_string()],
            explicit_excludes: vec!["/tmp/repo/target".to_string()],
            updated_at_ms: 1_700_000_000_300,
        },
    );

    let policy = SessionCompactionPolicy {
        carry_pinned_only: true,
        preserve_checklist_state: false,
        preserve_background_tasks: false,
        preserve_latest_output_excerpt: false,
        preserve_governance_blockers: false,
        aggressive_transcript_pruning: true,
    };

    let snapshot = session_compaction_snapshot_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-policy-preview"),
        Some(policy.clone()),
    );
    let preview = snapshot.preview_for_active.expect("preview");

    assert_eq!(snapshot.policy_for_active, policy);
    assert_eq!(preview.policy, snapshot.policy_for_active);
    assert!(preview.carried_forward_state.explicit_includes.is_empty());
    assert!(preview.carried_forward_state.explicit_excludes.is_empty());
    assert!(preview.carried_forward_state.checklist_labels.is_empty());
    assert!(preview
        .carried_forward_state
        .background_task_labels
        .is_empty());
    assert!(preview
        .carried_forward_state
        .latest_output_excerpt
        .is_none());
    assert!(preview
        .prune_decisions
        .iter()
        .any(|decision| decision.key == "explicit_includes"
            && decision.disposition == SessionCompactionDisposition::Pruned
            && decision.detail_count == 1));
    assert!(preview
        .prune_decisions
        .iter()
        .any(|decision| decision.key == "history_transcript"
            && decision.disposition == SessionCompactionDisposition::Pruned));
}

#[test]
fn compaction_recommendation_preserves_active_resume_context() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-recommendation-active",
        "Recommendation target",
        1_234,
        Some(AgentPhase::Running),
        Some("Reviewing the latest output."),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut running_task = task(
        "session-recommendation-active",
        "collect the latest repo notes",
    );
    running_task.current_step = "Reviewing the latest output.".to_string();
    running_task.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Latest retained output excerpt".to_string(),
        timestamp: 1_700_000_000_000,
    });
    running_task.sync_runtime_views();
    save_local_task_state(&memory_runtime, &running_task);

    save_session_file_context(
        &memory_runtime,
        Some("session-recommendation-active"),
        &SessionFileContext {
            session_id: Some("session-recommendation-active".to_string()),
            workspace_root: "/tmp/repo".to_string(),
            pinned_files: vec!["/tmp/repo/README.md".to_string()],
            recent_files: Vec::new(),
            explicit_includes: vec!["/tmp/repo/docs".to_string()],
            explicit_excludes: Vec::new(),
            updated_at_ms: 1_700_000_000_100,
        },
    );

    let snapshot = session_compaction_snapshot_for_sessions(
        &memory_runtime,
        vec![session.clone()],
        Some("session-recommendation-active"),
        None,
    );
    let recommendation = snapshot
        .recommendation_for_active
        .expect("recommendation for active session");

    assert_eq!(
        recommendation.recommended_policy,
        SessionCompactionPolicy::default()
    );
    assert!(recommendation
        .resume_safeguard_labels
        .iter()
        .any(|label| label.contains("checklist")));
    assert!(recommendation
        .resume_safeguard_labels
        .iter()
        .any(|label| label.contains("background task")));
    assert!(recommendation
        .resume_safeguard_labels
        .iter()
        .any(|label| label.contains("latest output excerpt")));

    let compacted = compact_retained_session_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-recommendation-active"),
        Some("session-recommendation-active"),
        Some(recommendation.recommended_policy.clone()),
    )
    .expect("compacted snapshot");
    let latest = compacted.latest_for_active.expect("latest compaction");

    assert!(!latest.carried_forward_state.checklist_labels.is_empty());
    assert!(!latest
        .carried_forward_state
        .background_task_labels
        .is_empty());
    assert!(latest.carried_forward_state.latest_output_excerpt.is_some());
}

#[test]
fn compaction_recommendation_prefers_lean_policy_for_large_stable_session() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-recommendation-lean",
        "Lean recommendation target",
        1_234,
        Some(AgentPhase::Complete),
        Some("Final report ready."),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut completed_task = task(
        "session-recommendation-lean",
        "summarize the repo and produce a final report",
    );
    completed_task.phase = AgentPhase::Complete;
    completed_task.current_step = "Final report ready.".to_string();
    for index in 0..(super::AUTO_COMPACTION_HISTORY_THRESHOLD * 2) {
        completed_task.history.push(ChatMessage {
            role: if index % 2 == 0 {
                "assistant".to_string()
            } else {
                "user".to_string()
            },
            text: format!("history message {index}"),
            timestamp: 1_700_000_100_000 + index as u64,
        });
    }
    completed_task.sync_runtime_views();
    save_local_task_state(&memory_runtime, &completed_task);

    save_session_file_context(
        &memory_runtime,
        Some("session-recommendation-lean"),
        &SessionFileContext {
            session_id: Some("session-recommendation-lean".to_string()),
            workspace_root: "/tmp/repo".to_string(),
            pinned_files: vec!["/tmp/repo/README.md".to_string()],
            recent_files: Vec::new(),
            explicit_includes: vec!["/tmp/repo/docs".to_string()],
            explicit_excludes: vec!["/tmp/repo/target".to_string()],
            updated_at_ms: 1_700_000_100_200,
        },
    );

    let snapshot = session_compaction_snapshot_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-recommendation-lean"),
        None,
    );
    let recommendation = snapshot
        .recommendation_for_active
        .expect("recommendation for active session");
    let auto_latest = snapshot
        .latest_for_active
        .as_ref()
        .expect("auto compaction record");

    assert!(
        recommendation
            .recommended_policy
            .aggressive_transcript_pruning
    );
    assert!(recommendation.recommended_policy.carry_pinned_only);
    assert!(!recommendation.recommended_policy.preserve_checklist_state);
    assert!(!recommendation.recommended_policy.preserve_background_tasks);
    assert!(
        !recommendation
            .recommended_policy
            .preserve_latest_output_excerpt
    );
    assert!(
        !recommendation
            .recommended_policy
            .preserve_governance_blockers
    );
    assert_eq!(
        recommendation.recommended_policy_label,
        "Focused pinned-context policy"
    );
    assert!(recommendation
        .resume_safeguard_labels
        .iter()
        .all(|label| !label.contains("checklist")
            && !label.contains("background task")
            && !label.contains("latest output excerpt")));
    assert!(recommendation
        .resume_safeguard_labels
        .iter()
        .any(|label| label.contains("artifact outcome") || label.contains("execution target")));
    assert!(recommendation
        .recommended_policy_reason_labels
        .iter()
        .any(|label| label.contains("Transcript pressure")));
    assert!(recommendation
        .recommended_policy_reason_labels
        .iter()
        .any(|label| label.contains("Pinned files")));
    assert_eq!(auto_latest.mode, SessionCompactionMode::Auto);
    assert_eq!(auto_latest.policy, recommendation.recommended_policy);
    assert!(auto_latest
        .carried_forward_state
        .explicit_includes
        .is_empty());
    assert!(auto_latest
        .carried_forward_state
        .checklist_labels
        .is_empty());
    assert!(auto_latest
        .carried_forward_state
        .background_task_labels
        .is_empty());
    assert!(auto_latest
        .carried_forward_state
        .latest_output_excerpt
        .is_none());

    let compacted = compact_retained_session_for_sessions(
        &memory_runtime,
        vec![summary(
            "session-recommendation-lean",
            "Lean recommendation target",
            1_234,
            Some(AgentPhase::Complete),
            Some("Final report ready."),
        )],
        Some("session-recommendation-lean"),
        Some("session-recommendation-lean"),
        Some(recommendation.recommended_policy.clone()),
    )
    .expect("compacted lean snapshot");
    let latest = compacted.latest_for_active.expect("latest lean compaction");

    assert_eq!(latest.mode, SessionCompactionMode::Manual);
    assert!(latest.carried_forward_state.explicit_includes.is_empty());
    assert!(latest.carried_forward_state.checklist_labels.is_empty());
    assert!(latest
        .carried_forward_state
        .background_task_labels
        .is_empty());
    assert!(latest.carried_forward_state.latest_output_excerpt.is_none());
    assert!(latest
        .carried_forward_state
        .latest_artifact_outcome
        .is_none());
    assert_eq!(
        latest.carried_forward_state.execution_targets,
        vec!["/tmp/repo/README.md".to_string()]
    );
    assert!(matches!(
        latest.resume_safety.status,
        SessionCompactionResumeSafetyStatus::Protected
    ));
}

#[test]
fn compaction_snapshot_reports_cross_session_durability_portfolio() {
    let memory_runtime = temp_memory_runtime();

    let ready_session = summary(
        "session-durability-ready",
        "Replay ready",
        1_234,
        Some(AgentPhase::Complete),
        Some("Final replay-safe report ready."),
    );
    save_local_session_summary(&memory_runtime, ready_session.clone());
    let mut ready_task = task(
        "session-durability-ready",
        "Summarize the repo and retain a clean replay-safe checkpoint",
    );
    ready_task.phase = AgentPhase::Complete;
    ready_task.current_step = "Final replay-safe report ready.".to_string();
    ready_task.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Replay-safe report prepared.".to_string(),
        timestamp: 1_700_000_100_000,
    });
    save_local_task_state(&memory_runtime, &ready_task);
    compact_retained_session_for_sessions(
        &memory_runtime,
        vec![ready_session.clone()],
        Some("session-durability-ready"),
        Some("session-durability-ready"),
        None,
    )
    .expect("ready compaction");
    sync_team_memory_for_sessions(
        &memory_runtime,
        vec![ready_session.clone()],
        Some("session-durability-ready"),
        Some("session-durability-ready"),
        Some("Chat".to_string()),
        Some("operator".to_string()),
        false,
    )
    .expect("ready team memory");

    let stale_session = summary(
        "session-durability-stale",
        "Needs refresh",
        2_345,
        Some(AgentPhase::Complete),
        Some("The retained summary needs a refresh."),
    );
    save_local_session_summary(&memory_runtime, stale_session.clone());
    let mut stale_task = task(
        "session-durability-stale",
        "Capture a stale long-session checkpoint",
    );
    stale_task.phase = AgentPhase::Complete;
    stale_task.current_step = "Old retained summary.".to_string();
    for index in 0..super::AUTO_COMPACTION_HISTORY_THRESHOLD {
        stale_task.history.push(ChatMessage {
            role: if index % 2 == 0 {
                "assistant".to_string()
            } else {
                "user".to_string()
            },
            text: format!("stale history message {index}"),
            timestamp: 1_700_000_200_000 + index as u64,
        });
    }
    save_local_task_state(&memory_runtime, &stale_task);
    compact_retained_session_for_sessions(
        &memory_runtime,
        vec![stale_session.clone()],
        Some("session-durability-stale"),
        Some("session-durability-stale"),
        None,
    )
    .expect("stale compaction");
    let mut stale_task_after_compaction = stale_task.clone();
    stale_task_after_compaction.current_step =
        "New post-compaction finding for ops@example.com token=sk-test-1234567890".to_string();
    stale_task_after_compaction.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Post-compaction follow-up for ops@example.com token=sk-test-1234567890".to_string(),
        timestamp: crate::kernel::state::now() + 60_000,
    });
    save_local_task_state(&memory_runtime, &stale_task_after_compaction);
    let stale_summary_after_compaction = summary(
        "session-durability-stale",
        "Needs refresh",
        crate::kernel::state::now() + 60_000,
        Some(AgentPhase::Complete),
        Some("Fresh work happened after the retained checkpoint."),
    );
    save_local_session_summary(&memory_runtime, stale_summary_after_compaction.clone());
    sync_team_memory_for_sessions(
        &memory_runtime,
        vec![stale_summary_after_compaction.clone()],
        Some("session-durability-stale"),
        Some("session-durability-stale"),
        Some("REPL".to_string()),
        Some("operator".to_string()),
        false,
    )
    .expect("stale team memory");

    let degraded_session = summary(
        "session-durability-degraded",
        "Degraded resume",
        3_456,
        Some(AgentPhase::Running),
        Some("Waiting on protected deploy approval."),
    );
    save_local_session_summary(&memory_runtime, degraded_session.clone());
    let mut degraded_task = task(
        "session-durability-degraded",
        "Approve protected deployment for production",
    );
    degraded_task.phase = AgentPhase::Gate;
    degraded_task.current_step = "Waiting on protected deploy approval.".to_string();
    degraded_task.pending_request_hash = Some("durability-gate".to_string());
    degraded_task.gate_info = Some(GateInfo {
        title: "Approval required".to_string(),
        description: "Approve protected deployment".to_string(),
        risk: "high".to_string(),
        approve_label: Some("Approve".to_string()),
        deny_label: Some("Deny".to_string()),
        deadline_ms: None,
        surface_label: Some("Chat".to_string()),
        scope_label: Some("workspace".to_string()),
        operation_label: Some("deploy".to_string()),
        target_label: Some("production".to_string()),
        operator_note: None,
        pii: None,
    });
    degraded_task.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Protected deploy remains blocked pending approval.".to_string(),
        timestamp: 1_700_000_300_000,
    });
    degraded_task.session_checklist.push(SessionChecklistItem {
        item_id: "deploy-review".to_string(),
        label: "Review protected deploy plan".to_string(),
        status: "open".to_string(),
        detail: None,
        updated_at_ms: 1_700_000_300_100,
    });
    degraded_task
        .background_tasks
        .push(SessionBackgroundTaskRecord {
            task_id: "deploy-watch".to_string(),
            session_id: Some("session-durability-degraded".to_string()),
            label: "Watch deploy health".to_string(),
            status: "running".to_string(),
            detail: None,
            latest_output: None,
            can_stop: true,
            updated_at_ms: 1_700_000_300_200,
        });
    save_local_task_state(&memory_runtime, &degraded_task);
    let degraded_policy = SessionCompactionPolicy {
        carry_pinned_only: false,
        preserve_checklist_state: false,
        preserve_background_tasks: false,
        preserve_latest_output_excerpt: false,
        preserve_governance_blockers: false,
        aggressive_transcript_pruning: true,
    };
    compact_retained_session_for_sessions(
        &memory_runtime,
        vec![degraded_session.clone()],
        Some("session-durability-degraded"),
        Some("session-durability-degraded"),
        Some(degraded_policy),
    )
    .expect("degraded compaction");
    sync_team_memory_for_sessions(
        &memory_runtime,
        vec![degraded_session.clone()],
        Some("session-durability-degraded"),
        Some("session-durability-degraded"),
        Some("Chat".to_string()),
        Some("operator".to_string()),
        true,
    )
    .expect("degraded team memory");

    let snapshot = session_compaction_snapshot_for_sessions(
        &memory_runtime,
        vec![
            ready_session,
            stale_summary_after_compaction,
            degraded_session,
        ],
        Some("session-durability-ready"),
        None,
    );
    let portfolio = snapshot.durability_portfolio;

    assert_eq!(portfolio.retained_session_count, 3);
    assert_eq!(portfolio.compacted_session_count, 3);
    assert_eq!(portfolio.replay_ready_session_count, 1);
    assert_eq!(portfolio.uncompacted_session_count, 0);
    assert_eq!(portfolio.stale_compaction_count, 1);
    assert_eq!(portfolio.degraded_compaction_count, 1);
    assert!(portfolio.recommended_compaction_count >= 1);
    assert_eq!(portfolio.compacted_without_team_memory_count, 0);
    assert_eq!(portfolio.team_memory_entry_count, 3);
    assert_eq!(portfolio.team_memory_covered_session_count, 3);
    assert_eq!(portfolio.team_memory_redacted_session_count, 1);
    assert_eq!(portfolio.team_memory_review_required_session_count, 1);
    assert!(portfolio.coverage_summary.contains("replay-ready"));
    assert!(portfolio.team_memory_summary.contains("team-memory"));
    assert!(portfolio
        .attention_labels
        .iter()
        .any(|label| label.contains("new activity since the latest compaction")));
    assert!(portfolio
        .attention_labels
        .iter()
        .any(|label| label.contains("degraded resume-safety")));
    assert!(portfolio
        .attention_labels
        .iter()
        .any(|label| label.contains("require governance review")));
}

#[test]
fn team_memory_sync_redacts_sensitive_values_and_keeps_governance_local_by_default() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-team-memory-redacted",
        "Team memory target",
        1_234,
        Some(AgentPhase::Gate),
        Some("Share status with ops@example.com token=sk-test-1234567890"),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut running_task = task(
        "session-team-memory-redacted",
        "Share status with ops@example.com token=sk-test-1234567890",
    );
    running_task.phase = AgentPhase::Gate;
    running_task.pending_request_hash = Some("gate-hash".to_string());
    running_task.current_step =
        "Waiting for approval before messaging ops@example.com.".to_string();
    running_task.gate_info = Some(GateInfo {
        title: "Approval required".to_string(),
        description: "Send a sync note to ops@example.com".to_string(),
        risk: "medium".to_string(),
        approve_label: Some("Approve".to_string()),
        deny_label: Some("Deny".to_string()),
        deadline_ms: None,
        surface_label: Some("Chat".to_string()),
        scope_label: Some("repo".to_string()),
        operation_label: Some("message".to_string()),
        target_label: Some("ops@example.com".to_string()),
        operator_note: None,
        pii: None,
    });
    running_task.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Drafted note for ops@example.com with token=sk-test-1234567890".to_string(),
        timestamp: 1_700_000_000_000,
    });
    save_local_task_state(&memory_runtime, &running_task);

    let snapshot = sync_team_memory_for_sessions(
        &memory_runtime,
        vec![session.clone()],
        Some("session-team-memory-redacted"),
        Some("session-team-memory-redacted"),
        Some("REPL".to_string()),
        Some("operator".to_string()),
        false,
    )
    .expect("team memory snapshot");

    assert_eq!(snapshot.entry_count, 1);
    let entry = snapshot.entries.first().expect("team memory entry");
    assert_eq!(entry.omitted_governance_item_count, 2);
    assert_eq!(
        entry.sync_status,
        crate::models::TeamMemorySyncStatus::Redacted
    );
    assert!(entry.summary.contains("<REDACTED:email>"));
    assert!(entry.summary.contains("<REDACTED:secret_token>"));
    assert!(entry
        .shared_memory_items
        .iter()
        .all(|item| item.memory_class != SessionMemoryClass::GovernanceCritical));
    assert!(entry.redaction.redaction_count >= 2);

    let refreshed = team_memory_snapshot_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-team-memory-redacted"),
        Some("session-team-memory-redacted"),
    )
    .expect("refreshed team memory snapshot");
    assert_eq!(refreshed.entry_count, 1);
    assert_eq!(
        refreshed.active_scope_label.as_deref(),
        Some("Workspace repo")
    );
}

#[test]
fn team_memory_sync_can_include_governance_and_mark_review_required() {
    let memory_runtime = temp_memory_runtime();
    let session = summary(
        "session-team-memory-review",
        "Review target",
        1_234,
        Some(AgentPhase::Gate),
        Some("Approval required for protected change."),
    );
    save_local_session_summary(&memory_runtime, session.clone());

    let mut running_task = task("session-team-memory-review", "Approve protected deployment");
    running_task.phase = AgentPhase::Gate;
    running_task.pending_request_hash = Some("gate-hash".to_string());
    running_task.gate_info = Some(GateInfo {
        title: "Approval required".to_string(),
        description: "Approve protected deployment".to_string(),
        risk: "high".to_string(),
        approve_label: Some("Approve".to_string()),
        deny_label: Some("Deny".to_string()),
        deadline_ms: None,
        surface_label: Some("Chat".to_string()),
        scope_label: Some("workspace".to_string()),
        operation_label: Some("deploy".to_string()),
        target_label: Some("production".to_string()),
        operator_note: None,
        pii: None,
    });
    save_local_task_state(&memory_runtime, &running_task);

    let snapshot = sync_team_memory_for_sessions(
        &memory_runtime,
        vec![session.clone()],
        Some("session-team-memory-review"),
        Some("session-team-memory-review"),
        Some("Chat".to_string()),
        Some("operator".to_string()),
        true,
    )
    .expect("team memory snapshot");

    let entry = snapshot.entries.first().expect("team memory entry");
    assert_eq!(
        entry.sync_status,
        crate::models::TeamMemorySyncStatus::ReviewRequired
    );
    assert!(entry
        .shared_memory_items
        .iter()
        .any(|item| item.memory_class == SessionMemoryClass::GovernanceCritical));
    assert!(entry.review_summary.contains("Review"));
    assert_eq!(snapshot.review_required_count, 1);

    let after_forget = forget_team_memory_entry_for_sessions(
        &memory_runtime,
        vec![session],
        Some("session-team-memory-review"),
        Some("session-team-memory-review"),
        &entry.entry_id,
    )
    .expect("forgotten snapshot");
    assert_eq!(after_forget.entry_count, 0);
}
