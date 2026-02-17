use super::support::{collect_urls, now_iso, snippet};
use crate::kernel::state::update_task_state;
use crate::kernel::{artifacts as artifact_store, thresholds};
use crate::models::{
    AgentEvent, AppState, Artifact, ArtifactRef, ArtifactType, EventStatus, EventType,
};
use crate::orchestrator;
use serde_json::{json, Value};
use std::sync::Mutex;
use tauri::{Emitter, Manager};
use uuid::Uuid;

pub(super) fn register_event(app: &tauri::AppHandle, mut event: AgentEvent) {
    let mut scs_handle = None;

    {
        let state = app.state::<Mutex<AppState>>();
        if let Ok(mut s) = state.lock() {
            let refs = s.event_index.entry(event.thread_id.clone()).or_default();
            if event.input_refs.is_empty() {
                if let Some(prev_id) = refs.last() {
                    event.input_refs.push(prev_id.clone());
                }
            }
            refs.push(event.event_id.clone());
            scs_handle = s.studio_scs.clone();
        };
    }

    update_task_state(app, |t| {
        let thread = t.session_id.clone().unwrap_or_else(|| t.id.clone());
        if thread == event.thread_id {
            t.events.push(event.clone());
        }
    });

    if let Some(scs) = scs_handle {
        orchestrator::append_event(&scs, &event);
    }

    let _ = app.emit("agent-event", &event);
}

pub(super) fn register_artifact(app: &tauri::AppHandle, artifact: Artifact) {
    let thread_id = artifact.thread_id.clone();
    let mut run_bundle_id = None;
    let mut scs_handle = None;

    {
        let state = app.state::<Mutex<AppState>>();
        if let Ok(mut s) = state.lock() {
            let refs = s.artifact_index.entry(thread_id.clone()).or_default();
            if !refs.iter().any(|id| id == &artifact.artifact_id) {
                refs.push(artifact.artifact_id.clone());
            }
            if let Some(task) = &s.current_task {
                let task_thread = task.session_id.clone().unwrap_or_else(|| task.id.clone());
                if task_thread == thread_id {
                    run_bundle_id = task.run_bundle_id.clone();
                }
            }
            scs_handle = s.studio_scs.clone();
        };
    }

    update_task_state(app, |t| {
        let task_thread = t.session_id.clone().unwrap_or_else(|| t.id.clone());
        if task_thread == thread_id
            && !t
                .artifacts
                .iter()
                .any(|existing| existing.artifact_id == artifact.artifact_id)
        {
            t.artifacts.push(artifact.clone());
        }
    });

    let _ = app.emit("artifact-created", &artifact);

    if artifact.artifact_type != ArtifactType::RunBundle {
        if let (Some(bundle_id), Some(scs)) = (run_bundle_id, scs_handle) {
            if let Some(updated_bundle) = artifact_store::append_run_bundle_ref(
                &scs,
                &thread_id,
                &bundle_id,
                &artifact.artifact_id,
            ) {
                update_task_state(app, |t| {
                    let task_thread = t.session_id.clone().unwrap_or_else(|| t.id.clone());
                    if task_thread == thread_id
                        && !t
                            .artifacts
                            .iter()
                            .any(|a| a.artifact_id == updated_bundle.artifact_id)
                    {
                        t.artifacts.push(updated_bundle.clone());
                    }
                });
                let _ = app.emit("artifact-created", &updated_bundle);
            }
        }
    }
}

pub(super) fn planned_artifact_types(event_type: &EventType, output: &str) -> Vec<ArtifactType> {
    if matches!(
        event_type,
        EventType::BrowserNavigate | EventType::BrowserSnapshot
    ) {
        return vec![ArtifactType::Web];
    }

    let (diff_lines, diff_files) = thresholds::estimate_diff_stats(output);
    if diff_lines > 0 && thresholds::should_spill_diff(diff_lines, diff_files) {
        return vec![ArtifactType::Diff];
    }

    if thresholds::should_spill_command_output(output) {
        return vec![ArtifactType::Log];
    }

    Vec::new()
}

pub(super) fn create_macro_artifacts_for_action(
    app: &tauri::AppHandle,
    thread_id: &str,
    event_type: &EventType,
    tool_name: &str,
    output: &str,
) -> Vec<ArtifactRef> {
    let scs = {
        let state = app.state::<Mutex<AppState>>();
        state.lock().ok().and_then(|s| s.studio_scs.clone())
    };
    let Some(scs) = scs else {
        return Vec::new();
    };

    let mut refs = Vec::new();

    for artifact_type in planned_artifact_types(event_type, output) {
        match artifact_type {
            ArtifactType::Web => {
                let urls = collect_urls(output, 5);
                let primary_url = urls
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("tool://{}", tool_name));
                let artifact = artifact_store::create_web_artifact(
                    &scs,
                    thread_id,
                    &primary_url,
                    output,
                    urls,
                );
                refs.push(ArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: ArtifactType::Web,
                });
                register_artifact(app, artifact);
            }
            ArtifactType::Diff => {
                let (diff_lines, diff_files) = thresholds::estimate_diff_stats(output);
                let metadata = json!({
                    "tool_name": tool_name,
                    "line_changes": diff_lines,
                    "files_touched": diff_files,
                });
                let artifact = artifact_store::create_diff_artifact(
                    &scs,
                    thread_id,
                    "Large Diff",
                    "Diff exceeded inline thresholds",
                    output,
                    metadata,
                );
                refs.push(ArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: ArtifactType::Diff,
                });
                register_artifact(app, artifact);
            }
            ArtifactType::Log => {
                let metadata = json!({
                    "tool_name": tool_name,
                    "line_count": thresholds::line_count(output),
                });
                let artifact = artifact_store::create_log_artifact(
                    &scs,
                    thread_id,
                    &format!("{} output", tool_name),
                    "Command output spilled due to threshold",
                    output,
                    metadata,
                );
                refs.push(ArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: ArtifactType::Log,
                });
                register_artifact(app, artifact);
            }
            _ => {}
        }
    }

    refs
}

pub(super) fn build_event(
    thread_id: &str,
    step_index: u32,
    event_type: EventType,
    title: String,
    digest: Value,
    details: Value,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    receipt_ref: Option<String>,
    input_refs: Vec<String>,
    duration_ms: Option<u64>,
) -> AgentEvent {
    AgentEvent {
        event_id: Uuid::new_v4().to_string(),
        timestamp: now_iso(),
        thread_id: thread_id.to_string(),
        step_index,
        event_type,
        title,
        digest,
        details,
        artifact_refs,
        receipt_ref,
        input_refs,
        status,
        duration_ms,
    }
}

pub(super) fn emit_command_run(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let digest = json!({
        "tool_name": tool_name,
        "output_snippet": snippet(output),
        "line_count": thresholds::line_count(output),
    });
    let details = json!({
        "output": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::CommandRun,
        format!("Ran {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub(super) fn emit_command_stream(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    stream_id: &str,
    channel: &str,
    chunk: &str,
    seq: u64,
    is_final: bool,
    exit_code: Option<i32>,
    command_preview: &str,
) -> AgentEvent {
    let status = if is_final {
        if exit_code.unwrap_or(0) == 0 {
            EventStatus::Success
        } else {
            EventStatus::Failure
        }
    } else {
        EventStatus::Partial
    };

    let digest = json!({
        "tool_name": tool_name,
        "stream_id": stream_id,
        "channel": channel,
        "seq": seq,
        "is_final": is_final,
        "exit_code": exit_code,
        "command_preview": command_preview,
    });
    let details = json!({
        "chunk": thresholds::trim_for_expanded_view(chunk),
    });

    build_event(
        thread_id,
        step_index,
        EventType::CommandStream,
        format!("Streaming {} ({})", tool_name, channel),
        digest,
        details,
        status,
        Vec::new(),
        None,
        Vec::new(),
        None,
    )
}

pub(super) fn emit_file_edit(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    diff_text: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let (line_changes, files_touched) = thresholds::estimate_diff_stats(diff_text);
    let digest = json!({
        "tool_name": tool_name,
        "line_changes": line_changes,
        "files_touched": files_touched,
        "excerpt": thresholds::trim_edit_excerpt(diff_text),
    });
    let details = json!({
        "diff_excerpt": thresholds::trim_for_expanded_view(diff_text),
    });

    build_event(
        thread_id,
        step_index,
        EventType::FileEdit,
        format!("Edited files via {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub(super) fn emit_code_search(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let digest = json!({
        "query": tool_name,
        "result_lines": thresholds::line_count(output),
        "snippet": snippet(output),
    });
    let details = json!({
        "results": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::CodeSearch,
        format!("Searched code with {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub(super) fn emit_browser_navigate(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let urls = collect_urls(output, 5);
    let digest = json!({
        "tool_name": tool_name,
        "url": urls.first().cloned().unwrap_or_else(|| "unknown".to_string()),
        "snippet": snippet(output),
        "citations": urls,
    });
    let details = json!({
        "output": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::BrowserNavigate,
        "Navigated browser".to_string(),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub(super) fn emit_browser_snapshot(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let urls = collect_urls(output, 5);
    let digest = json!({
        "tool_name": tool_name,
        "snapshot_length": output.len(),
        "top_links": urls,
        "snippet": snippet(output),
    });
    let details = json!({
        "snapshot": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::BrowserSnapshot,
        "Snapshotted browser page".to_string(),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub(super) fn emit_test_run(
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    output: &str,
    status: EventStatus,
    artifact_refs: Vec<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let digest = json!({
        "command": tool_name,
        "summary": snippet(output),
    });
    let details = json!({
        "output": thresholds::trim_for_expanded_view(output),
    });

    build_event(
        thread_id,
        step_index,
        EventType::TestRun,
        format!("Ran tests via {}", tool_name),
        digest,
        details,
        status,
        artifact_refs,
        None,
        input_refs,
        None,
    )
}

pub(super) fn emit_receipt_digest(
    thread_id: &str,
    step_index: u32,
    receipt_id: String,
    tool_name: &str,
    tier: &str,
    decision: &str,
    intent_class: &str,
    incident_stage: &str,
    strategy_node: &str,
    gate_state: &str,
    resolution_action: &str,
    summary: &str,
    report_ref: Option<ArtifactRef>,
    input_refs: Vec<String>,
) -> AgentEvent {
    let mut artifact_refs = Vec::new();
    if let Some(r) = report_ref {
        artifact_refs.push(r);
    }

    let digest = json!({
        "intent_class": intent_class,
        "incident_stage": incident_stage,
        "strategy_node": strategy_node,
        "gate_state": gate_state,
        "resolution_action": resolution_action,
        "tool_name": tool_name,
        "tier": tier,
        "decision": decision,
        "summary": snippet(summary),
    });
    let details = json!({
        "receipt_summary": thresholds::trim_for_expanded_view(summary),
    });

    build_event(
        thread_id,
        step_index,
        EventType::Receipt,
        format!("Receipt: {} ({})", tool_name, decision),
        digest,
        details,
        EventStatus::Success,
        artifact_refs,
        Some(receipt_id),
        input_refs,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_output(lines: usize) -> String {
        (0..lines)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn search_flow_events_link_to_web_artifact_and_prior_step() {
        let web_ref = ArtifactRef {
            artifact_id: "web-1".to_string(),
            artifact_type: ArtifactType::Web,
        };

        let navigate = emit_browser_navigate(
            "thread-1",
            1,
            "browser__navigate",
            "https://example.com?q=rust",
            EventStatus::Success,
            vec![web_ref.clone()],
            vec![],
        );
        assert_eq!(navigate.event_type, EventType::BrowserNavigate);
        assert_eq!(navigate.artifact_refs.len(), 1);
        assert_eq!(navigate.artifact_refs[0].artifact_type, ArtifactType::Web);

        let snapshot = emit_browser_snapshot(
            "thread-1",
            2,
            "browser__snapshot",
            "Top links https://example.com/a https://example.com/b",
            EventStatus::Success,
            vec![web_ref],
            vec![navigate.event_id.clone()],
        );
        assert_eq!(snapshot.event_type, EventType::BrowserSnapshot);
        assert_eq!(snapshot.input_refs[0], navigate.event_id);

        let completion = emit_command_run(
            "thread-1",
            3,
            "agent__complete",
            "Completed web synthesis",
            EventStatus::Success,
            snapshot.artifact_refs.clone(),
            vec![snapshot.event_id.clone()],
        );
        assert_eq!(completion.input_refs[0], snapshot.event_id);
        assert_eq!(completion.artifact_refs[0].artifact_type, ArtifactType::Web);
    }

    #[test]
    fn large_command_output_plans_log_artifact() {
        let output = long_output(210);
        let planned = planned_artifact_types(&EventType::CommandRun, &output);
        assert_eq!(planned, vec![ArtifactType::Log]);
    }

    #[test]
    fn large_diff_plans_diff_artifact() {
        let mut diff = String::new();
        for file in 0..4 {
            diff.push_str(&format!("diff --git a/f{file}.rs b/f{file}.rs\n"));
            diff.push_str("--- a/file\n+++ b/file\n");
            diff.push_str("-old\n+new\n");
        }
        let planned = planned_artifact_types(&EventType::FileEdit, &diff);
        assert_eq!(planned, vec![ArtifactType::Diff]);
    }
}
