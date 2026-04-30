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
                .map(|summary| format!("Chat artifact: {summary}"))
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
        "The workspace root stays explicit so Chat, retained sessions, and the standalone REPL can reopen the same repo.",
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
