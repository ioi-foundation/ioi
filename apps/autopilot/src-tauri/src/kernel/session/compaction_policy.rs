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
