// Path: crates/cli/src/commands/agent_tui_loop.rs

use super::agent_event_stream::{format_runtime_event_line, json_path_string};
use super::agent_tui::{
    add_tui_mcp_server, apply_tui_workspace_restore, assign_tui_subagent, cancel_tui_job,
    cancel_tui_run, cancel_tui_subagent, cancel_tui_task, decide_tui_approval, delete_tui_memory,
    edit_tui_memory, evaluate_tui_compaction_policy, evaluate_tui_context_budget,
    execute_tui_diagnostics_repair_decision, execute_tui_run_coding_tool_budget_recovery,
    fetch_tui_event_batch, fetch_tui_job, fetch_tui_mcp_tool, fetch_tui_run, fetch_tui_run_trace,
    fetch_tui_subagent_result, fetch_tui_task, fetch_tui_thread, fetch_tui_thread_usage,
    import_tui_mcp, inspect_tui_mcp_status, inspect_tui_memory_path, inspect_tui_memory_policy,
    inspect_tui_memory_status, inspect_tui_run, interrupt_tui_turn, invoke_tui_coding_tool,
    invoke_tui_mcp_tool, latest_event_seq, latest_usage_delta_status, list_tui_jobs_for_thread,
    list_tui_memory_records, list_tui_subagents, list_tui_tasks_for_thread,
    list_tui_workspace_snapshots, preview_tui_workspace_restore,
    propagate_tui_subagent_cancellation, remember_tui_memory, remove_tui_mcp_server,
    replay_tui_run_events, resume_tui_subagent, resume_tui_thread, search_tui_mcp_tools,
    selected_run_id_from_thread, selected_turn_id_from_values, send_tui_subagent_input,
    set_tui_mcp_server_enabled, spawn_tui_subagent, steer_tui_turn, thread_id_from_value,
    tui_approval_decisions, tui_approval_rows, tui_coding_tool_rows, tui_context_pressure_rows,
    tui_context_rows, tui_cost_rows, tui_job_rows, tui_mcp_rows, tui_memory_rows, tui_mode_status,
    tui_run_lifecycle_rows, tui_subagent_rows, tui_task_rows, tui_usage_delta_rows,
    tui_usage_status, tui_workspace_trust_rows, update_tui_memory_policy, update_tui_thread_mode,
    update_tui_thread_model, update_tui_thread_thinking, validate_tui_mcp, validate_tui_memory,
    wait_tui_subagent,
};
use anyhow::{anyhow, Result};
use serde_json::{Map, Value};
use std::io::{self, Write};

const DEFAULT_INTERRUPT_REASON: &str = "operator requested interrupt from TUI";
const TUI_CONTROL_STATE_SCHEMA_VERSION: &str = "ioi.agent-cli.tui-control-state.v1";

pub(crate) struct TuiInteractiveSession {
    pub(crate) endpoint: String,
    pub(crate) token: Option<String>,
    pub(crate) thread: Value,
    pub(crate) next_since_seq: Option<u64>,
    pub(crate) follow: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TuiLineCommand {
    Noop,
    Help,
    Resume,
    Events {
        since_seq: Option<u64>,
    },
    Approvals,
    Approve {
        approval_id: Option<String>,
        reason: Option<String>,
    },
    Reject {
        approval_id: Option<String>,
        reason: Option<String>,
    },
    Interrupt {
        reason: Option<String>,
    },
    Steer {
        guidance: String,
    },
    Mode {
        mode: Option<String>,
    },
    Model {
        model_id: Option<String>,
        route_id: Option<String>,
    },
    Thinking {
        reasoning_effort: Option<String>,
    },
    Cost,
    Context,
    BrowserDiscovery,
    NativeBrowser {
        prompt: Option<String>,
        session_mode: Option<String>,
        approval_ref: Option<String>,
        controlled_relaunch_approval_ref: Option<String>,
        controlled_relaunch_executable_path: Option<String>,
        controlled_relaunch_headless: bool,
        target_ref: Option<String>,
        selector: Option<String>,
        text: Option<String>,
        key: Option<String>,
        scroll_x: Option<i64>,
        scroll_y: Option<i64>,
        file_path: Option<String>,
        cdp_endpoint_url: Option<String>,
        cdp_websocket_url: Option<String>,
        cdp_timeout_ms: Option<u64>,
    },
    VisualGui {
        prompt: Option<String>,
        session_mode: Option<String>,
        screenshot_ref: Option<String>,
        screenshot_path: Option<String>,
        som_ref: Option<String>,
        som_path: Option<String>,
        ax_ref: Option<String>,
        ax_path: Option<String>,
        app_name: Option<String>,
        window_title: Option<String>,
        coordinate_space_id: Option<String>,
        viewport_width: Option<u64>,
        viewport_height: Option<u64>,
    },
    ComputerUseControl {
        action: String,
        lease_id: String,
        handoff_ref: Option<String>,
        reason: Option<String>,
        resume_observation_ref: Option<String>,
        cdp_endpoint_url: Option<String>,
    },
    Mcp {
        action: Option<String>,
    },
    Memory {
        action: Option<String>,
    },
    Subagent {
        action: Option<String>,
    },
    WorkspaceStatus,
    Diff {
        path: Option<String>,
    },
    Inspect {
        path: String,
    },
    ApplyPatch {
        path: String,
        old_text: String,
        new_text: String,
        dry_run: bool,
    },
    Test {
        path: Option<String>,
    },
    Diagnostics {
        path: String,
    },
    DiagnosticsRepair {
        action: String,
        decision_id: String,
        message: Option<String>,
        approved: bool,
        allow_conflicts: bool,
    },
    ArtifactRead {
        artifact_id: String,
    },
    RetrieveResult {
        target: String,
    },
    Tasks,
    TaskInspect {
        task_id: Option<String>,
    },
    TaskCancel {
        task_id: String,
    },
    Jobs,
    JobInspect {
        job_id: Option<String>,
    },
    JobCancel {
        job_id: String,
    },
    Run {
        run_id: Option<String>,
    },
    RunTrace {
        run_id: Option<String>,
    },
    RunInspect {
        run_id: Option<String>,
    },
    RunReplay {
        run_id: Option<String>,
    },
    RunCancel {
        run_id: String,
    },
    RunRecovery {
        action: String,
        run_id: Option<String>,
        approval_id: Option<String>,
    },
    RestoreList,
    RestorePreview {
        snapshot_id: String,
    },
    RestoreApply {
        snapshot_id: String,
        allow_conflicts: bool,
    },
    Quit,
}

pub(crate) async fn run_tui_interactive_loop(mut session: TuiInteractiveSession) -> Result<()> {
    print_tui_help();
    let mut control_state = TuiControlState::from_session(&session);
    print_tui_control_state(&control_state)?;
    let stdin = io::stdin();
    loop {
        print!("ioi:tui> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            println!("line_mode_command=quit reason=eof");
            break;
        }
        match parse_tui_line_command(&line) {
            Ok(TuiLineCommand::Noop) => {}
            Ok(TuiLineCommand::Help) => {
                print_tui_help();
                control_state.record_command(
                    "help",
                    line.trim(),
                    "accepted",
                    Some("help displayed"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Resume) => {
                handle_resume_command(&mut session).await?;
                control_state.record_command(
                    "resume",
                    line.trim(),
                    "applied",
                    Some("thread resumed"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Events { since_seq }) => {
                let events = handle_events_command(&mut session, since_seq).await?;
                control_state.record_command(
                    "events",
                    line.trim(),
                    "applied",
                    Some("events replayed"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Approvals) => {
                let events = handle_approvals_command(&mut session).await?;
                control_state.record_command(
                    "approvals",
                    line.trim(),
                    "applied",
                    Some("approval rows replayed"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Approve {
                approval_id,
                reason,
            }) => {
                let events = handle_approval_decision_command(
                    &mut session,
                    &control_state,
                    approval_id,
                    "approve",
                    reason,
                )
                .await?;
                control_state.record_command(
                    "approve",
                    line.trim(),
                    "applied",
                    Some("approval accepted"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Reject {
                approval_id,
                reason,
            }) => {
                let events = handle_approval_decision_command(
                    &mut session,
                    &control_state,
                    approval_id,
                    "reject",
                    reason,
                )
                .await?;
                control_state.record_command(
                    "reject",
                    line.trim(),
                    "applied",
                    Some("approval rejected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Interrupt { reason }) => {
                let events = handle_interrupt_command(&mut session, reason).await?;
                control_state.record_command(
                    "interrupt",
                    line.trim(),
                    "applied",
                    Some("turn interrupted"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Steer { guidance }) => {
                let events = handle_steer_command(&mut session, &guidance).await?;
                control_state.record_command(
                    "steer",
                    line.trim(),
                    "applied",
                    Some("turn steered"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Mode { mode }) => {
                let events = handle_mode_command(&mut session, mode).await?;
                control_state.record_command(
                    "mode",
                    line.trim(),
                    "applied",
                    Some("mode inspected or updated"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Model { model_id, route_id }) => {
                let events = handle_model_command(&mut session, model_id, route_id).await?;
                control_state.record_command(
                    "model",
                    line.trim(),
                    "applied",
                    Some("model route inspected or updated"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Thinking { reasoning_effort }) => {
                let events = handle_thinking_command(&mut session, reasoning_effort).await?;
                control_state.record_command(
                    "thinking",
                    line.trim(),
                    "applied",
                    Some("thinking effort inspected or updated"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Cost) => {
                let usage = handle_cost_command(&mut session).await?;
                control_state
                    .set_usage_status(tui_usage_status(&usage, control_state.thread_id.as_deref()));
                control_state
                    .merge_cost_rows(tui_cost_rows(&usage, control_state.thread_id.as_deref()));
                control_state.record_command(
                    "cost",
                    line.trim(),
                    "applied",
                    Some("usage cost inspected"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Context) => {
                let (events, usage, context_budget, compaction_policy) =
                    handle_context_command(&mut session).await?;
                control_state
                    .set_usage_status(tui_usage_status(&usage, control_state.thread_id.as_deref()));
                control_state
                    .merge_cost_rows(tui_cost_rows(&usage, control_state.thread_id.as_deref()));
                control_state.merge_context_rows(tui_context_rows(
                    &usage,
                    &context_budget,
                    &compaction_policy,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "context",
                    line.trim(),
                    "applied",
                    Some("context budget and compaction policy inspected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::BrowserDiscovery) => {
                let events = handle_browser_discovery_command(&mut session).await?;
                control_state.record_command(
                    "browser-discovery",
                    line.trim(),
                    "applied",
                    Some("browser discovery receipt emitted"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::NativeBrowser {
                prompt,
                session_mode,
                approval_ref,
                controlled_relaunch_approval_ref,
                controlled_relaunch_executable_path,
                controlled_relaunch_headless,
                target_ref,
                selector,
                text,
                key,
                scroll_x,
                scroll_y,
                file_path,
                cdp_endpoint_url,
                cdp_websocket_url,
                cdp_timeout_ms,
            }) => {
                let events = handle_native_browser_command(
                    &mut session,
                    NativeBrowserLineArgs {
                        prompt,
                        session_mode,
                        approval_ref,
                        controlled_relaunch_approval_ref,
                        controlled_relaunch_executable_path,
                        controlled_relaunch_headless,
                        target_ref,
                        selector,
                        text,
                        key,
                        scroll_x,
                        scroll_y,
                        file_path,
                        cdp_endpoint_url,
                        cdp_websocket_url,
                        cdp_timeout_ms,
                    },
                )
                .await?;
                control_state.record_command(
                    "native-browser",
                    line.trim(),
                    "applied",
                    Some("native-browser computer-use trace emitted"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::VisualGui {
                prompt,
                session_mode,
                screenshot_ref,
                screenshot_path,
                som_ref,
                som_path,
                ax_ref,
                ax_path,
                app_name,
                window_title,
                coordinate_space_id,
                viewport_width,
                viewport_height,
            }) => {
                let events = handle_visual_gui_command(
                    &mut session,
                    VisualGuiLineArgs {
                        prompt,
                        session_mode,
                        screenshot_ref,
                        screenshot_path,
                        som_ref,
                        som_path,
                        ax_ref,
                        ax_path,
                        app_name,
                        window_title,
                        coordinate_space_id,
                        viewport_width,
                        viewport_height,
                    },
                )
                .await?;
                control_state.record_command(
                    "visual-gui",
                    line.trim(),
                    "applied",
                    Some("visual-GUI computer-use trace emitted"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::ComputerUseControl {
                action,
                lease_id,
                handoff_ref,
                reason,
                resume_observation_ref,
                cdp_endpoint_url,
            }) => {
                let events = handle_computer_use_control_command(
                    &mut session,
                    ComputerUseControlLineArgs {
                        action,
                        lease_id,
                        handoff_ref,
                        reason,
                        resume_observation_ref,
                        cdp_endpoint_url,
                    },
                )
                .await?;
                control_state.record_command(
                    "computer-use-control",
                    line.trim(),
                    "applied",
                    Some("computer-use control receipt emitted"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Mcp { action }) => {
                let (events, mcp_status) = handle_mcp_command(&mut session, action).await?;
                control_state.merge_mcp_rows(tui_mcp_rows(
                    &mcp_status,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "mcp",
                    line.trim(),
                    "applied",
                    Some("MCP catalog inspected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Memory { action }) => {
                let (events, memory_status) = handle_memory_command(&mut session, action).await?;
                control_state.merge_memory_rows(tui_memory_rows(
                    &memory_status,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "memory",
                    line.trim(),
                    "applied",
                    Some("memory status inspected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Subagent { action }) => {
                let (events, subagent_status) =
                    handle_subagent_command(&mut session, &control_state, action).await?;
                control_state.merge_subagent_rows(tui_subagent_rows(
                    &subagent_status,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "subagent",
                    line.trim(),
                    "applied",
                    Some("subagent controls inspected or updated"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::WorkspaceStatus) => {
                let events =
                    handle_coding_tool_command(&mut session, "workspace.status", None).await?;
                control_state.record_command(
                    "status",
                    line.trim(),
                    "applied",
                    Some("workspace status inspected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Diff { path }) => {
                let events = handle_coding_tool_command(&mut session, "git.diff", path).await?;
                control_state.record_command(
                    "diff",
                    line.trim(),
                    "applied",
                    Some("git diff inspected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Inspect { path }) => {
                let events =
                    handle_coding_tool_command(&mut session, "file.inspect", Some(path)).await?;
                control_state.record_command(
                    "inspect",
                    line.trim(),
                    "applied",
                    Some("file inspected"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::ApplyPatch {
                path,
                old_text,
                new_text,
                dry_run,
            }) => {
                let mut input = serde_json::Map::new();
                input.insert("path".to_string(), Value::String(path));
                input.insert("oldText".to_string(), Value::String(old_text));
                input.insert("newText".to_string(), Value::String(new_text));
                if dry_run {
                    input.insert("dryRun".to_string(), Value::Bool(true));
                }
                let events =
                    handle_coding_tool_input_command(&mut session, "file.apply_patch", input)
                        .await?;
                control_state.record_command(
                    if dry_run { "patch-dry-run" } else { "patch" },
                    line.trim(),
                    "applied",
                    Some(if dry_run {
                        "file patch previewed"
                    } else {
                        "file patch applied"
                    }),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Test { path }) => {
                let mut input = serde_json::Map::new();
                input.insert(
                    "commandId".to_string(),
                    Value::String("node.test".to_string()),
                );
                if let Some(path) = path.as_deref().filter(|value| !value.trim().is_empty()) {
                    input.insert("path".to_string(), Value::String(path.to_string()));
                }
                let events =
                    handle_coding_tool_input_command(&mut session, "test.run", input).await?;
                control_state.record_command(
                    "test",
                    line.trim(),
                    "applied",
                    Some("tests run"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Diagnostics { path }) => {
                let mut input = serde_json::Map::new();
                input.insert("commandId".to_string(), Value::String("auto".to_string()));
                input.insert("path".to_string(), Value::String(path));
                let events =
                    handle_coding_tool_input_command(&mut session, "lsp.diagnostics", input)
                        .await?;
                control_state.record_command(
                    "diagnostics",
                    line.trim(),
                    "applied",
                    Some("diagnostics run"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::DiagnosticsRepair {
                action,
                decision_id,
                message,
                approved,
                allow_conflicts,
            }) => {
                let events = handle_diagnostics_repair_command(
                    &mut session,
                    &action,
                    &decision_id,
                    message.as_deref(),
                    approved,
                    allow_conflicts,
                )
                .await?;
                control_state.record_command(
                    "diagnostics",
                    line.trim(),
                    "applied",
                    Some("diagnostics repair decision executed"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::ArtifactRead { artifact_id }) => {
                let mut input = serde_json::Map::new();
                input.insert("artifactId".to_string(), Value::String(artifact_id));
                let events =
                    handle_coding_tool_input_command(&mut session, "artifact.read", input).await?;
                control_state.record_command(
                    "artifact",
                    line.trim(),
                    "applied",
                    Some("artifact read"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RetrieveResult { target }) => {
                let mut input = serde_json::Map::new();
                if target.starts_with("artifact_") {
                    input.insert("artifactId".to_string(), Value::String(target));
                } else {
                    input.insert("toolCallId".to_string(), Value::String(target));
                }
                let events =
                    handle_coding_tool_input_command(&mut session, "tool.retrieve_result", input)
                        .await?;
                control_state.record_command(
                    "retrieve",
                    line.trim(),
                    "applied",
                    Some("tool result retrieved"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Tasks) => {
                let tasks = handle_tasks_command(&mut session).await?;
                control_state
                    .merge_task_rows(tui_task_rows(&tasks, control_state.thread_id.as_deref()));
                control_state.record_command(
                    "tasks",
                    line.trim(),
                    "applied",
                    Some("tasks listed"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::TaskInspect { task_id }) => {
                let task =
                    handle_task_inspect_command(&mut session, &control_state, task_id).await?;
                let tasks = vec![task];
                control_state
                    .merge_task_rows(tui_task_rows(&tasks, control_state.thread_id.as_deref()));
                control_state.record_command(
                    "task",
                    line.trim(),
                    "applied",
                    Some("task inspected"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::TaskCancel { task_id }) => {
                let task = handle_task_cancel_command(&mut session, &task_id).await?;
                let tasks = vec![task];
                control_state
                    .merge_task_rows(tui_task_rows(&tasks, control_state.thread_id.as_deref()));
                control_state.record_command(
                    "task",
                    line.trim(),
                    "applied",
                    Some("task canceled"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Jobs) => {
                let jobs = handle_jobs_command(&mut session).await?;
                control_state
                    .merge_job_rows(tui_job_rows(&jobs, control_state.thread_id.as_deref()));
                control_state.merge_run_lifecycle_rows(tui_run_lifecycle_rows(
                    &jobs,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "jobs",
                    line.trim(),
                    "applied",
                    Some("jobs listed"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::JobInspect { job_id }) => {
                let job = handle_job_inspect_command(&mut session, &control_state, job_id).await?;
                let jobs = vec![job];
                control_state
                    .merge_job_rows(tui_job_rows(&jobs, control_state.thread_id.as_deref()));
                control_state.merge_run_lifecycle_rows(tui_run_lifecycle_rows(
                    &jobs,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "job",
                    line.trim(),
                    "applied",
                    Some("job inspected"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::JobCancel { job_id }) => {
                let job = handle_job_cancel_command(&mut session, &job_id).await?;
                let jobs = vec![job];
                control_state
                    .merge_job_rows(tui_job_rows(&jobs, control_state.thread_id.as_deref()));
                control_state.merge_run_lifecycle_rows(tui_run_lifecycle_rows(
                    &jobs,
                    control_state.thread_id.as_deref(),
                ));
                control_state.record_command(
                    "job",
                    line.trim(),
                    "applied",
                    Some("job canceled"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Run { run_id }) => {
                handle_run_command(&mut session, &control_state, run_id).await?;
                control_state.record_command(
                    "run",
                    line.trim(),
                    "applied",
                    Some("run inspected"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RunTrace { run_id }) => {
                handle_run_trace_command(&mut session, &control_state, run_id, false).await?;
                control_state.record_command(
                    "run",
                    line.trim(),
                    "applied",
                    Some("run trace fetched"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RunInspect { run_id }) => {
                handle_run_trace_command(&mut session, &control_state, run_id, true).await?;
                control_state.record_command(
                    "run",
                    line.trim(),
                    "applied",
                    Some("run inspection fetched"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RunReplay { run_id }) => {
                let events =
                    handle_run_replay_command(&mut session, &control_state, run_id).await?;
                control_state.record_command(
                    "run",
                    line.trim(),
                    "applied",
                    Some("run replayed"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RunCancel { run_id }) => {
                let run = handle_run_cancel_command(&mut session, &run_id).await?;
                let status =
                    json_path_string(&run, "/status").unwrap_or_else(|| "run canceled".to_string());
                control_state.record_command(
                    "run",
                    line.trim(),
                    "applied",
                    Some(status.as_str()),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RunRecovery {
                action,
                run_id,
                approval_id,
            }) => {
                let events = handle_run_recovery_command(
                    &mut session,
                    &control_state,
                    &action,
                    run_id,
                    approval_id,
                )
                .await?;
                control_state.record_command(
                    "run",
                    line.trim(),
                    "applied",
                    Some("coding-tool budget recovery applied"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RestoreList) => {
                let events = handle_restore_list_command(&mut session).await?;
                control_state.record_command(
                    "restore",
                    line.trim(),
                    "applied",
                    Some("workspace snapshots listed"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RestorePreview { snapshot_id }) => {
                let events = handle_restore_preview_command(&mut session, &snapshot_id).await?;
                control_state.record_command(
                    "restore",
                    line.trim(),
                    "applied",
                    Some("restore previewed"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::RestoreApply {
                snapshot_id,
                allow_conflicts,
            }) => {
                let events =
                    handle_restore_apply_command(&mut session, &snapshot_id, allow_conflicts)
                        .await?;
                control_state.record_command(
                    "restore",
                    line.trim(),
                    "applied",
                    Some("restore apply requested"),
                    &session,
                    &events,
                );
                print_tui_control_state(&control_state)?;
            }
            Ok(TuiLineCommand::Quit) => {
                println!("line_mode_command=quit");
                control_state.record_command(
                    "quit",
                    line.trim(),
                    "accepted",
                    Some("session closed"),
                    &session,
                    &[],
                );
                print_tui_control_state(&control_state)?;
                break;
            }
            Err(error) => {
                println!("line_mode_error={error}");
                control_state.record_validation_error(line.trim(), &error.to_string(), &session);
                print_tui_control_state(&control_state)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_tui_line_command(line: &str) -> Result<TuiLineCommand> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(TuiLineCommand::Noop);
    }
    if !trimmed.starts_with('/') {
        return Err(anyhow!(
            "line-mode TUI accepts slash commands; use /help for available commands"
        ));
    }
    let body = &trimmed[1..];
    let command_end = body.find(char::is_whitespace).unwrap_or(body.len());
    let command = body[..command_end].to_ascii_lowercase();
    let rest = body[command_end..].trim();
    match command.as_str() {
        "help" | "h" => Ok(TuiLineCommand::Help),
        "resume" => Ok(TuiLineCommand::Resume),
        "events" => {
            let since_seq =
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.parse::<u64>().map_err(|_| {
                        anyhow!("/events accepts an optional numeric since_seq cursor")
                    })?)
                };
            Ok(TuiLineCommand::Events { since_seq })
        }
        "approvals" => Ok(TuiLineCommand::Approvals),
        "approve" => {
            let (approval_id, reason) = parse_approval_decision_args(rest);
            Ok(TuiLineCommand::Approve {
                approval_id,
                reason,
            })
        }
        "reject" => {
            let (approval_id, reason) = parse_approval_decision_args(rest);
            Ok(TuiLineCommand::Reject {
                approval_id,
                reason,
            })
        }
        "interrupt" => Ok(TuiLineCommand::Interrupt {
            reason: non_empty_string(rest),
        }),
        "steer" => {
            let guidance =
                non_empty_string(rest).ok_or_else(|| anyhow!("/steer requires guidance text"))?;
            Ok(TuiLineCommand::Steer { guidance })
        }
        "mode" => Ok(TuiLineCommand::Mode {
            mode: non_empty_string(rest),
        }),
        "model" => parse_model_args(rest),
        "thinking" => Ok(TuiLineCommand::Thinking {
            reasoning_effort: non_empty_string(rest),
        }),
        "cost" | "usage" => {
            if !rest.is_empty() {
                return Err(anyhow!("/{command} does not accept extra arguments"));
            }
            Ok(TuiLineCommand::Cost)
        }
        "context" => {
            if !rest.is_empty() {
                return Err(anyhow!("/context does not accept extra arguments"));
            }
            Ok(TuiLineCommand::Context)
        }
        "browser-discovery" | "browser-discover" | "discover-browsers" => {
            if !rest.is_empty() {
                return Err(anyhow!("/{command} does not accept extra arguments"));
            }
            Ok(TuiLineCommand::BrowserDiscovery)
        }
        "native-browser" | "browser-use" => {
            let args = parse_native_browser_args(rest)?;
            Ok(TuiLineCommand::NativeBrowser {
                prompt: args.prompt,
                session_mode: args.session_mode,
                approval_ref: args.approval_ref,
                controlled_relaunch_approval_ref: args.controlled_relaunch_approval_ref,
                controlled_relaunch_executable_path: args.controlled_relaunch_executable_path,
                controlled_relaunch_headless: args.controlled_relaunch_headless,
                target_ref: args.target_ref,
                selector: args.selector,
                text: args.text,
                key: args.key,
                scroll_x: args.scroll_x,
                scroll_y: args.scroll_y,
                file_path: args.file_path,
                cdp_endpoint_url: args.cdp_endpoint_url,
                cdp_websocket_url: args.cdp_websocket_url,
                cdp_timeout_ms: args.cdp_timeout_ms,
            })
        }
        "visual-gui" | "computer-vision" | "desktop-gui" => {
            let args = parse_visual_gui_args(rest)?;
            Ok(TuiLineCommand::VisualGui {
                prompt: args.prompt,
                session_mode: args.session_mode,
                screenshot_ref: args.screenshot_ref,
                screenshot_path: args.screenshot_path,
                som_ref: args.som_ref,
                som_path: args.som_path,
                ax_ref: args.ax_ref,
                ax_path: args.ax_path,
                app_name: args.app_name,
                window_title: args.window_title,
                coordinate_space_id: args.coordinate_space_id,
                viewport_width: args.viewport_width,
                viewport_height: args.viewport_height,
            })
        }
        "computer-use-control" => {
            let args = parse_computer_use_control_args(rest)?;
            Ok(TuiLineCommand::ComputerUseControl {
                action: args.action,
                lease_id: args.lease_id,
                handoff_ref: args.handoff_ref,
                reason: args.reason,
                resume_observation_ref: args.resume_observation_ref,
                cdp_endpoint_url: args.cdp_endpoint_url,
            })
        }
        "computer-use" => {
            if matches!(
                rest,
                "browser-discovery" | "browser-discover" | "discover-browsers"
            ) {
                Ok(TuiLineCommand::BrowserDiscovery)
            } else if computer_use_control_prefix(rest).is_some() {
                let args = parse_computer_use_control_args(rest)?;
                Ok(TuiLineCommand::ComputerUseControl {
                    action: args.action,
                    lease_id: args.lease_id,
                    handoff_ref: args.handoff_ref,
                    reason: args.reason,
                    resume_observation_ref: args.resume_observation_ref,
                    cdp_endpoint_url: args.cdp_endpoint_url,
                })
            } else if let Some(prompt) = rest
                .strip_prefix("native-browser ")
                .or_else(|| (rest == "native-browser").then_some(""))
                .or_else(|| rest.strip_prefix("browser-use "))
                .or_else(|| (rest == "browser-use").then_some(""))
            {
                let args = parse_native_browser_args(prompt)?;
                Ok(TuiLineCommand::NativeBrowser {
                    prompt: args.prompt,
                    session_mode: args.session_mode,
                    approval_ref: args.approval_ref,
                    controlled_relaunch_approval_ref: args.controlled_relaunch_approval_ref,
                    controlled_relaunch_executable_path: args.controlled_relaunch_executable_path,
                    controlled_relaunch_headless: args.controlled_relaunch_headless,
                    target_ref: args.target_ref,
                    selector: args.selector,
                    text: args.text,
                    key: args.key,
                    scroll_x: args.scroll_x,
                    scroll_y: args.scroll_y,
                    file_path: args.file_path,
                    cdp_endpoint_url: args.cdp_endpoint_url,
                    cdp_websocket_url: args.cdp_websocket_url,
                    cdp_timeout_ms: args.cdp_timeout_ms,
                })
            } else if let Some(prompt) = rest
                .strip_prefix("visual-gui ")
                .or_else(|| (rest == "visual-gui").then_some(""))
                .or_else(|| rest.strip_prefix("desktop-gui "))
                .or_else(|| (rest == "desktop-gui").then_some(""))
            {
                let args = parse_visual_gui_args(prompt)?;
                Ok(TuiLineCommand::VisualGui {
                    prompt: args.prompt,
                    session_mode: args.session_mode,
                    screenshot_ref: args.screenshot_ref,
                    screenshot_path: args.screenshot_path,
                    som_ref: args.som_ref,
                    som_path: args.som_path,
                    ax_ref: args.ax_ref,
                    ax_path: args.ax_path,
                    app_name: args.app_name,
                    window_title: args.window_title,
                    coordinate_space_id: args.coordinate_space_id,
                    viewport_width: args.viewport_width,
                    viewport_height: args.viewport_height,
                })
            } else {
                Err(anyhow!(
                    "/computer-use accepts browser-discovery, native-browser <prompt>, visual-gui <prompt>, or pause|resume|abort|cleanup --lease-id <id>; use /help"
                ))
            }
        }
        "mcp" => Ok(TuiLineCommand::Mcp {
            action: non_empty_string(rest),
        }),
        "memory" => Ok(TuiLineCommand::Memory {
            action: non_empty_string(rest),
        }),
        "subagent" | "subagents" => Ok(TuiLineCommand::Subagent {
            action: non_empty_string(rest),
        }),
        "status" | "workspace-status" => Ok(TuiLineCommand::WorkspaceStatus),
        "diff" => Ok(TuiLineCommand::Diff {
            path: non_empty_string(rest),
        }),
        "inspect" => {
            let path = non_empty_string(rest)
                .ok_or_else(|| anyhow!("/inspect requires a workspace-relative path"))?;
            Ok(TuiLineCommand::Inspect { path })
        }
        "patch" | "apply-patch" | "apply" => {
            let (path, old_text, new_text) = parse_patch_args(rest)?;
            Ok(TuiLineCommand::ApplyPatch {
                path,
                old_text,
                new_text,
                dry_run: false,
            })
        }
        "patch-dry-run" | "apply-patch-dry-run" => {
            let (path, old_text, new_text) = parse_patch_args(rest)?;
            Ok(TuiLineCommand::ApplyPatch {
                path,
                old_text,
                new_text,
                dry_run: true,
            })
        }
        "test" | "test-run" => Ok(TuiLineCommand::Test {
            path: non_empty_string(rest),
        }),
        "diagnostics" | "diag" | "lsp-diagnostics" => {
            if line_command_head(rest).as_deref() == Some("repair") {
                return parse_diagnostics_repair_args(rest);
            }
            let path =
                non_empty_string(rest).ok_or_else(|| anyhow!("/diagnostics requires a path"))?;
            Ok(TuiLineCommand::Diagnostics { path })
        }
        "artifact" | "artifact-read" => {
            let artifact_id = non_empty_string(rest)
                .ok_or_else(|| anyhow!("/artifact requires an artifact id"))?;
            Ok(TuiLineCommand::ArtifactRead { artifact_id })
        }
        "retrieve" | "retrieve-result" => {
            let target = non_empty_string(rest)
                .ok_or_else(|| anyhow!("/retrieve requires a tool call id or artifact id"))?;
            Ok(TuiLineCommand::RetrieveResult { target })
        }
        "tasks" => {
            if !rest.is_empty() {
                return Err(anyhow!("/{command} does not accept extra arguments"));
            }
            Ok(TuiLineCommand::Tasks)
        }
        "task" => parse_task_args(rest),
        "jobs" | "runs" => {
            if !rest.is_empty() {
                return Err(anyhow!("/{command} does not accept extra arguments"));
            }
            Ok(TuiLineCommand::Jobs)
        }
        "job" => parse_job_args(rest),
        "run" => parse_run_args(rest),
        "restore" => parse_restore_args(rest),
        "quit" | "exit" | "q" => Ok(TuiLineCommand::Quit),
        _ => Err(anyhow!("unknown TUI command /{command}; use /help")),
    }
}

async fn handle_resume_command(session: &mut TuiInteractiveSession) -> Result<()> {
    let thread_id = thread_id_from_value(&session.thread)?;
    session.thread =
        resume_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=resume thread={} latest_seq={}",
        thread_id_from_value(&session.thread)?,
        json_path_string(&session.thread, "/latest_seq").unwrap_or_else(|| "0".to_string())
    );
    Ok(())
}

async fn handle_events_command(
    session: &mut TuiInteractiveSession,
    explicit_since_seq: Option<u64>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let since_seq = explicit_since_seq.or(session.next_since_seq);
    let batch = fetch_tui_event_batch(
        &thread_id,
        &session.endpoint,
        session.token.as_deref(),
        session.follow,
        since_seq,
        None,
    )
    .await?;
    if let Some(seq) = latest_event_seq(&batch.events) {
        session.next_since_seq = Some(seq);
    }
    println!(
        "line_mode_command=events route={} count={}",
        batch.event_route,
        batch.events.len()
    );
    print_events(&batch.events);
    print_streaming_telemetry_rows(&batch.events, Some(&thread_id));
    Ok(batch.events)
}

fn print_streaming_telemetry_rows(events: &[Value], fallback_thread_id: Option<&str>) {
    for row in tui_usage_delta_rows(events, fallback_thread_id) {
        println!(
            "usage_delta_row stage={} tokens={} cost_usd={} context={} status={} node={}",
            json_path_string(&row, "/usage_delta_stage").unwrap_or_else(|| "delta".to_string()),
            json_path_string(&row, "/usage_total_tokens").unwrap_or_else(|| "0".to_string()),
            json_path_string(&row, "/usage_cost_estimate_usd").unwrap_or_else(|| "0".to_string()),
            json_path_string(&row, "/usage_context_pressure").unwrap_or_else(|| "0".to_string()),
            json_path_string(&row, "/usage_context_pressure_status")
                .unwrap_or_else(|| "nominal".to_string()),
            json_path_string(&row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.usage-telemetry".to_string())
        );
    }
    for row in tui_context_pressure_rows(events, fallback_thread_id) {
        println!(
            "context_pressure_row pressure={} status={} node={} event={}",
            json_path_string(&row, "/usage_context_pressure").unwrap_or_else(|| "0".to_string()),
            json_path_string(&row, "/usage_context_pressure_status")
                .unwrap_or_else(|| "nominal".to_string()),
            json_path_string(&row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.context-budget".to_string()),
            json_path_string(&row, "/event_id").unwrap_or_else(|| "none".to_string())
        );
    }
}

async fn handle_approvals_command(session: &mut TuiInteractiveSession) -> Result<Vec<Value>> {
    let events = handle_events_command(session, Some(0)).await?;
    let thread_id = thread_id_from_value(&session.thread).ok();
    let rows = tui_approval_rows(&events, thread_id.as_deref());
    println!("line_mode_command=approvals count={}", rows.len());
    for row in &rows {
        println!(
            "  approval={} status={} node={}",
            json_path_string(row, "/approval_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/status").unwrap_or_else(|| "pending".to_string()),
            json_path_string(row, "/workflow_node_id").unwrap_or_else(|| "none".to_string())
        );
    }
    Ok(events)
}

async fn handle_approval_decision_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    approval_id: Option<String>,
    decision: &str,
    reason: Option<String>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let turn_id = selected_turn_id_from_values(None, None, &session.thread).ok();
    let approval_id = approval_id
        .or_else(|| control_state.default_pending_approval_id())
        .ok_or_else(|| {
            anyhow!(
                "/{decision} requires approval_id when no pending approval row is loaded; use /approvals first"
            )
        })?;
    let control = decide_tui_approval(
        &thread_id,
        turn_id.as_deref(),
        &approval_id,
        decision,
        reason.as_deref(),
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command={decision} approval={approval_id} status={} receipts={} policies={}",
        json_path_string(&control, "/status").unwrap_or_else(|| "unknown".to_string()),
        control
            .pointer("/receipt_refs")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        control
            .pointer("/policy_decision_refs")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    );
    handle_events_command(session, None).await
}

async fn handle_interrupt_command(
    session: &mut TuiInteractiveSession,
    reason: Option<String>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let turn_id = selected_turn_id_from_values(None, None, &session.thread)?;
    let reason = reason.unwrap_or_else(|| DEFAULT_INTERRUPT_REASON.to_string());
    let control = interrupt_tui_turn(
        &thread_id,
        &turn_id,
        &reason,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=interrupt thread={thread_id} turn={turn_id} status={} stop_reason={}",
        json_path_string(&control, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&control, "/stop_reason").unwrap_or_else(|| "n/a".to_string())
    );
    handle_events_command(session, None).await
}

async fn handle_steer_command(
    session: &mut TuiInteractiveSession,
    guidance: &str,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let turn_id = selected_turn_id_from_values(None, None, &session.thread)?;
    let control = steer_tui_turn(
        &thread_id,
        &turn_id,
        guidance,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=steer thread={thread_id} turn={turn_id} status={} stop_reason={}",
        json_path_string(&control, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&control, "/stop_reason").unwrap_or_else(|| "n/a".to_string())
    );
    handle_events_command(session, None).await
}

async fn handle_mode_command(
    session: &mut TuiInteractiveSession,
    mode: Option<String>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    if let Some(mode) = mode.as_deref().filter(|value| !value.trim().is_empty()) {
        let result = update_tui_thread_mode(
            &thread_id,
            mode,
            &session.endpoint,
            session.token.as_deref(),
        )
        .await?;
        session.thread =
            fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
        println!(
            "line_mode_command=mode thread={thread_id} mode={} approval_mode={} event={}",
            json_path_string(&result, "/mode").unwrap_or_else(|| mode.to_string()),
            json_path_string(&result, "/approval_mode")
                .or_else(|| json_path_string(&result, "/control/approval_mode"))
                .unwrap_or_else(|| "suggest".to_string()),
            json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
        );
        return handle_events_command(session, None).await;
    }
    let status = tui_mode_status(&session.thread, None);
    println!(
        "line_mode_command=mode thread={thread_id} mode={} approval_mode={}",
        json_path_string(&status, "/mode").unwrap_or_else(|| "agent".to_string()),
        json_path_string(&status, "/approval_mode").unwrap_or_else(|| "suggest".to_string())
    );
    Ok(Vec::new())
}

async fn handle_model_command(
    session: &mut TuiInteractiveSession,
    model_id: Option<String>,
    route_id: Option<String>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    if let Some(model_id) = model_id.as_deref().filter(|value| !value.trim().is_empty()) {
        let result = update_tui_thread_model(
            &thread_id,
            model_id,
            route_id.as_deref(),
            &session.endpoint,
            session.token.as_deref(),
        )
        .await?;
        session.thread =
            fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
        println!(
            "line_mode_command=model thread={thread_id} requested_model={} selected_model={} route={} event={}",
            json_path_string(&result, "/requested_model").unwrap_or_else(|| model_id.to_string()),
            json_path_string(&result, "/selected_model")
                .or_else(|| json_path_string(&result, "/model_route"))
                .unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&result, "/model_route_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
        );
        return handle_events_command(session, None).await;
    }
    let status = tui_mode_status(&session.thread, None);
    println!(
        "line_mode_command=model thread={thread_id} requested_model={} selected_model={} route={}",
        json_path_string(&status, "/requested_model").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&status, "/selected_model").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&status, "/model_route_id").unwrap_or_else(|| "unknown".to_string())
    );
    Ok(Vec::new())
}

async fn handle_thinking_command(
    session: &mut TuiInteractiveSession,
    reasoning_effort: Option<String>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    if let Some(reasoning_effort) = reasoning_effort
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let result = update_tui_thread_thinking(
            &thread_id,
            reasoning_effort,
            &session.endpoint,
            session.token.as_deref(),
        )
        .await?;
        session.thread =
            fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
        println!(
            "line_mode_command=thinking thread={thread_id} reasoning_effort={} route={} event={}",
            json_path_string(&result, "/reasoning_effort")
                .or_else(|| json_path_string(&result, "/control/model/reasoningEffort"))
                .unwrap_or_else(|| reasoning_effort.to_string()),
            json_path_string(&result, "/model_route_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
        );
        return handle_events_command(session, None).await;
    }
    let status = tui_mode_status(&session.thread, None);
    println!(
        "line_mode_command=thinking thread={thread_id} reasoning_effort={}",
        json_path_string(&status, "/reasoning_effort").unwrap_or_else(|| "default".to_string())
    );
    Ok(Vec::new())
}

async fn handle_cost_command(session: &mut TuiInteractiveSession) -> Result<Value> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let usage =
        fetch_tui_thread_usage(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    attach_tui_thread_usage(&mut session.thread, &usage);
    let rows = tui_cost_rows(&usage, Some(&thread_id));
    println!(
        "line_mode_command=cost thread={thread_id} count={}",
        rows.len()
    );
    for row in &rows {
        println!(
            "cost_row kind={} scope={} tokens={} input={} output={} cost_usd={} context={} status={} node={}",
            json_path_string(row, "/row_kind").unwrap_or_else(|| "cost_status".to_string()),
            json_path_string(row, "/scope").unwrap_or_else(|| "thread".to_string()),
            json_path_string(row, "/usage_total_tokens").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/usage_input_tokens").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/usage_output_tokens").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/usage_cost_estimate_usd").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/usage_context_pressure").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/usage_context_pressure_status")
                .unwrap_or_else(|| "nominal".to_string()),
            json_path_string(row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.usage-telemetry".to_string())
        );
    }
    Ok(usage)
}

async fn handle_context_command(
    session: &mut TuiInteractiveSession,
) -> Result<(Vec<Value>, Value, Value, Value)> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let usage =
        fetch_tui_thread_usage(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    let context_budget = evaluate_tui_context_budget(
        &thread_id,
        &usage,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    let turn_id = selected_turn_id_from_values(None, None, &session.thread).ok();
    let compaction_policy = evaluate_tui_compaction_policy(
        &thread_id,
        turn_id.as_deref(),
        &context_budget,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    attach_tui_thread_usage(&mut session.thread, &usage);
    let rows = tui_context_rows(
        &usage,
        &context_budget,
        &compaction_policy,
        Some(&thread_id),
    );
    println!(
        "line_mode_command=context thread={thread_id} budget_status={} compaction_status={} rows={}",
        json_path_string(&context_budget, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&compaction_policy, "/status").unwrap_or_else(|| "unknown".to_string()),
        rows.len()
    );
    for row in &rows {
        println!(
            "context_row kind={} status={} pressure={} pressure_status={} budget_status={} action={} node={} receipts={} policies={}",
            json_path_string(row, "/row_kind").unwrap_or_else(|| "context".to_string()),
            json_path_string(row, "/status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/usage_context_pressure").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/usage_context_pressure_status")
                .unwrap_or_else(|| "nominal".to_string()),
            json_path_string(row, "/context_budget_status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/compaction_policy_action")
                .unwrap_or_else(|| "n/a".to_string()),
            json_path_string(row, "/workflow_node_id").unwrap_or_else(|| "unknown".to_string()),
            row.pointer("/receipt_refs")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
            row.pointer("/policy_decision_refs")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        );
    }
    let events = handle_events_command(session, None).await?;
    Ok((events, usage, context_budget, compaction_policy))
}

fn attach_tui_thread_usage(thread: &mut Value, usage: &Value) {
    if let Some(object) = thread.as_object_mut() {
        object.insert("usage_telemetry".to_string(), usage.clone());
    }
}

async fn handle_mcp_command(
    session: &mut TuiInteractiveSession,
    action: Option<String>,
) -> Result<(Vec<Value>, Value)> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let action_text = action.unwrap_or_else(|| "status".to_string());
    let mut parts = action_text.split_whitespace();
    let action = parts.next().unwrap_or("status").trim().to_ascii_lowercase();
    let remaining = parts.collect::<Vec<_>>();
    let mut source_mode_for_print = "workspace_and_global".to_string();
    let result = match action.as_str() {
        "status" | "list" | "servers" | "tools" => {
            let (positionals, options) = parse_mcp_catalog_option_tokens(&remaining)?;
            if !positionals.is_empty() {
                return Err(anyhow!("/mcp {} accepts only source/catalog flags", action));
            }
            if let Some(source_mode) = options.source_mode.clone() {
                source_mode_for_print = source_mode;
            }
            inspect_tui_mcp_status(
                &thread_id,
                options.source_mode.as_deref(),
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "validate" | "doctor" => {
            let (positionals, options) = parse_mcp_catalog_option_tokens(&remaining)?;
            if !positionals.is_empty() {
                return Err(anyhow!("/mcp {} accepts only source/catalog flags", action));
            }
            if let Some(source_mode) = options.source_mode.clone() {
                source_mode_for_print = source_mode;
            }
            validate_tui_mcp(
                &thread_id,
                options.source_mode.as_deref(),
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "search" | "find" => {
            let (positionals, options) = parse_mcp_catalog_option_tokens(&remaining)?;
            let query = positionals.join(" ");
            if query.trim().is_empty() {
                return Err(anyhow!("/mcp search requires <query>"));
            }
            if let Some(source_mode) = options.source_mode.clone() {
                source_mode_for_print = source_mode;
            }
            search_tui_mcp_tools(
                &thread_id,
                &query,
                options.server_id.as_deref(),
                options.source_mode.as_deref(),
                options.limit,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "fetch" | "get" => {
            let (positionals, options) = parse_mcp_catalog_option_tokens(&remaining)?;
            let raw_tool_id = positionals.first().ok_or_else(|| {
                anyhow!("/mcp fetch requires <tool_id> or <server_id>/<tool_name>")
            })?;
            if positionals.len() > 1 {
                return Err(anyhow!(
                    "/mcp fetch accepts exactly one <tool_id> or <server_id>/<tool_name>"
                ));
            }
            let (tool_id, inferred_server_id) = normalize_mcp_fetch_tool_id(raw_tool_id);
            if let Some(source_mode) = options.source_mode.clone() {
                source_mode_for_print = source_mode;
            }
            fetch_tui_mcp_tool(
                &thread_id,
                &tool_id,
                options
                    .server_id
                    .as_deref()
                    .or(inferred_server_id.as_deref()),
                options.source_mode.as_deref(),
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "import" => {
            let json_tail = remaining.join(" ");
            if json_tail.trim().is_empty() {
                return Err(anyhow!("/mcp import requires <mcp_json>"));
            }
            let mcp_json = serde_json::from_str::<Value>(json_tail.trim())
                .map_err(|error| anyhow!("/mcp import input must be JSON: {error}"))?;
            import_tui_mcp(
                &thread_id,
                mcp_json,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "add" => {
            let mut parts = remaining.iter().copied();
            let label = parts
                .next()
                .ok_or_else(|| anyhow!("/mcp add requires <label> <json_config>"))?;
            let json_tail = parts.collect::<Vec<_>>().join(" ");
            if json_tail.trim().is_empty() {
                return Err(anyhow!("/mcp add requires <label> <json_config>"));
            }
            let config = serde_json::from_str::<Value>(json_tail.trim())
                .map_err(|error| anyhow!("/mcp add config must be JSON: {error}"))?;
            add_tui_mcp_server(
                &thread_id,
                label,
                config,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "remove" | "rm" => {
            let mut parts = remaining.iter().copied();
            let server_id = parts
                .next()
                .ok_or_else(|| anyhow!("/mcp remove requires <server_id>"))?;
            remove_tui_mcp_server(
                &thread_id,
                server_id,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "enable" | "disable" => {
            let mut parts = remaining.iter().copied();
            let server_id = parts
                .next()
                .ok_or_else(|| anyhow!("/mcp {} requires <server_id>", action))?;
            set_tui_mcp_server_enabled(
                &thread_id,
                server_id,
                action == "enable",
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "invoke" | "call" => {
            let mut parts = remaining.iter().copied();
            let server_id = parts
                .next()
                .ok_or_else(|| anyhow!("/mcp invoke requires <server_id> <tool_name> [json]"))?;
            let tool_name = parts
                .next()
                .ok_or_else(|| anyhow!("/mcp invoke requires <server_id> <tool_name> [json]"))?;
            let json_tail = parts.collect::<Vec<_>>().join(" ");
            let input = if json_tail.trim().is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str::<Value>(json_tail.trim()).map_err(|error| {
                    anyhow!("/mcp invoke input must be JSON when provided: {error}")
                })?
            };
            invoke_tui_mcp_tool(
                &thread_id,
                server_id,
                tool_name,
                input,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        _ => {
            return Err(anyhow!(
                "/mcp accepts status, tools, servers, search, fetch, validate, import, add, remove, enable, disable, or invoke"
            ));
        }
    };
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    let server_count = json_path_string(&result, "/server_count")
        .or_else(|| json_path_string(&result, "/serverCount"))
        .unwrap_or_else(|| "0".to_string());
    let tool_count = json_path_string(&result, "/tool_count")
        .or_else(|| json_path_string(&result, "/toolCount"))
        .unwrap_or_else(|| "0".to_string());
    let resource_count = json_path_string(&result, "/resource_count")
        .or_else(|| json_path_string(&result, "/resourceCount"))
        .unwrap_or_else(|| "0".to_string());
    let prompt_count = json_path_string(&result, "/prompt_count")
        .or_else(|| json_path_string(&result, "/promptCount"))
        .unwrap_or_else(|| "0".to_string());
    let issue_count = json_path_string(&result, "/issue_count")
        .or_else(|| json_path_string(&result, "/issueCount"))
        .unwrap_or_else(|| "0".to_string());
    println!(
        "line_mode_command=mcp action={} source_mode={} status={} servers={} tools={} resources={} prompts={} issues={} event={}",
        action,
        source_mode_for_print,
        json_path_string(&result, "/status").unwrap_or_else(|| "unknown".to_string()),
        server_count,
        tool_count,
        resource_count,
        prompt_count,
        issue_count,
        json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
    );
    for row in tui_mcp_rows(&result, Some(&thread_id)) {
        println!(
            "  mcp_row kind={} server={} tool={} operation={} status={} node={}",
            json_path_string(&row, "/row_kind").unwrap_or_else(|| "mcp".to_string()),
            json_path_string(&row, "/mcp_server_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&row, "/mcp_tool_name").unwrap_or_else(|| "n/a".to_string()),
            json_path_string(&row, "/mcp_operation").unwrap_or_else(|| "status".to_string()),
            json_path_string(&row, "/status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.mcp-manager".to_string())
        );
    }
    let events = handle_events_command(session, None).await?;
    Ok((events, result))
}

#[derive(Debug, Default)]
struct McpCatalogCommandOptions {
    source_mode: Option<String>,
    server_id: Option<String>,
    limit: Option<u64>,
}

fn parse_mcp_catalog_option_tokens(
    tokens: &[&str],
) -> Result<(Vec<String>, McpCatalogCommandOptions)> {
    let mut positionals = Vec::new();
    let mut options = McpCatalogCommandOptions::default();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        match token {
            "--global" => options.source_mode = Some("global".to_string()),
            "--workspace" | "--local" => options.source_mode = Some("workspace".to_string()),
            "--all" | "--workspace-and-global" => {
                options.source_mode = Some("workspace_and_global".to_string())
            }
            "--source-mode" | "--source" | "--config-source" => {
                index += 1;
                let value = tokens
                    .get(index)
                    .ok_or_else(|| anyhow!("{token} requires a value"))?;
                options.source_mode = Some(normalize_mcp_source_mode_arg(value)?);
            }
            "--server" | "--server-id" => {
                index += 1;
                let value = tokens
                    .get(index)
                    .ok_or_else(|| anyhow!("{token} requires a value"))?;
                options.server_id = Some((*value).to_string());
            }
            "--limit" => {
                index += 1;
                let value = tokens
                    .get(index)
                    .ok_or_else(|| anyhow!("{token} requires a numeric value"))?;
                options.limit = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| anyhow!("{token} requires a numeric value"))?,
                );
            }
            _ if token.starts_with("--source-mode=") => {
                options.source_mode = Some(normalize_mcp_source_mode_arg(
                    token.trim_start_matches("--source-mode="),
                )?);
            }
            _ if token.starts_with("--source=") => {
                options.source_mode = Some(normalize_mcp_source_mode_arg(
                    token.trim_start_matches("--source="),
                )?);
            }
            _ if token.starts_with("--config-source=") => {
                options.source_mode = Some(normalize_mcp_source_mode_arg(
                    token.trim_start_matches("--config-source="),
                )?);
            }
            _ if token.starts_with("--server=") => {
                options.server_id = Some(token.trim_start_matches("--server=").to_string());
            }
            _ if token.starts_with("--server-id=") => {
                options.server_id = Some(token.trim_start_matches("--server-id=").to_string());
            }
            _ if token.starts_with("--limit=") => {
                let value = token.trim_start_matches("--limit=");
                options.limit = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| anyhow!("--limit requires a numeric value"))?,
                );
            }
            _ if token.starts_with("--") => {
                return Err(anyhow!("unknown /mcp catalog flag {token}"))
            }
            _ => positionals.push(token.to_string()),
        }
        index += 1;
    }
    Ok((positionals, options))
}

fn normalize_mcp_source_mode_arg(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "global" | "global_only" | "global_ioi" | "ioi_global" => Ok("global".to_string()),
        "workspace" | "workspace_only" | "local" | "local_only" => Ok("workspace".to_string()),
        "all" | "workspace_and_global" | "workspace_global" | "workspace_plus_global" => {
            Ok("workspace_and_global".to_string())
        }
        _ => Err(anyhow!(
            "--source-mode accepts workspace, global, or workspace_and_global"
        )),
    }
}

fn normalize_mcp_fetch_tool_id(value: &str) -> (String, Option<String>) {
    if let Some((server_id, tool_name)) = value.split_once('/') {
        if !server_id.trim().is_empty() && !tool_name.trim().is_empty() {
            return (
                format!("{}.{}", server_id.trim(), tool_name.trim()),
                Some(server_id.trim().to_string()),
            );
        }
    }
    (value.to_string(), None)
}

async fn handle_memory_command(
    session: &mut TuiInteractiveSession,
    action: Option<String>,
) -> Result<(Vec<Value>, Value)> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let action_text = action.unwrap_or_else(|| "status".to_string());
    let mut parts = action_text.split_whitespace();
    let action = parts.next().unwrap_or("status").trim().to_ascii_lowercase();
    let result = match action.as_str() {
        "status" => {
            inspect_tui_memory_status(&thread_id, &session.endpoint, session.token.as_deref())
                .await?
        }
        "validate" | "doctor" => {
            validate_tui_memory(&thread_id, &session.endpoint, session.token.as_deref()).await?
        }
        "show" | "records" | "list" => {
            let projection =
                list_tui_memory_records(&thread_id, &session.endpoint, session.token.as_deref())
                    .await?;
            let mut status =
                inspect_tui_memory_status(&thread_id, &session.endpoint, session.token.as_deref())
                    .await?;
            if let Some(records) = projection.pointer("/records").cloned() {
                status["records"] = records;
            }
            status
        }
        "policy" => {
            let policy =
                inspect_tui_memory_policy(&thread_id, &session.endpoint, session.token.as_deref())
                    .await?;
            let mut status =
                inspect_tui_memory_status(&thread_id, &session.endpoint, session.token.as_deref())
                    .await?;
            status["policy"] = policy;
            status
        }
        "path" => {
            let paths =
                inspect_tui_memory_path(&thread_id, &session.endpoint, session.token.as_deref())
                    .await?;
            let mut status =
                inspect_tui_memory_status(&thread_id, &session.endpoint, session.token.as_deref())
                    .await?;
            status["paths"] = paths;
            status
        }
        "disable" | "enable" => {
            update_tui_memory_policy(
                &thread_id,
                action == "disable",
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "remember" | "write" => {
            let text = parts.collect::<Vec<_>>().join(" ");
            if text.trim().is_empty() {
                return Err(anyhow!("/memory remember requires text"));
            }
            remember_tui_memory(
                &thread_id,
                text.trim(),
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "edit" => {
            let memory_id = parts
                .next()
                .ok_or_else(|| anyhow!("/memory edit requires <memory_id> <text>"))?;
            let text = parts.collect::<Vec<_>>().join(" ");
            if text.trim().is_empty() {
                return Err(anyhow!("/memory edit requires <memory_id> <text>"));
            }
            edit_tui_memory(
                &thread_id,
                memory_id,
                text.trim(),
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "delete" | "remove" | "forget" => {
            let memory_id = parts
                .next()
                .ok_or_else(|| anyhow!("/memory delete requires <memory_id>"))?;
            delete_tui_memory(
                &thread_id,
                memory_id,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        _ => {
            return Err(anyhow!(
                "/memory accepts status, show, policy, path, validate, enable, disable, remember, edit, or delete"
            ));
        }
    };
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=memory action={} status={} records={} issues={} event={}",
        action,
        json_path_string(&result, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&result, "/record_count")
            .or_else(|| json_path_string(&result, "/recordCount"))
            .unwrap_or_else(|| "0".to_string()),
        json_path_string(&result, "/issue_count")
            .or_else(|| json_path_string(&result, "/validation/issue_count"))
            .unwrap_or_else(|| "0".to_string()),
        json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
    );
    for row in tui_memory_rows(&result, Some(&thread_id)) {
        println!(
            "  memory_row kind={} record={} scope={} key={} status={} node={}",
            json_path_string(&row, "/row_kind").unwrap_or_else(|| "memory".to_string()),
            json_path_string(&row, "/memory_record_id").unwrap_or_else(|| "n/a".to_string()),
            json_path_string(&row, "/memory_scope").unwrap_or_else(|| "n/a".to_string()),
            json_path_string(&row, "/memory_key").unwrap_or_else(|| "n/a".to_string()),
            json_path_string(&row, "/status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.memory-manager".to_string())
        );
    }
    let events = handle_events_command(session, None).await?;
    Ok((events, result))
}

async fn handle_subagent_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    action: Option<String>,
) -> Result<(Vec<Value>, Value)> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let action_text = action.unwrap_or_else(|| "list".to_string());
    let parts = action_text.split_whitespace().collect::<Vec<_>>();
    let action = parts
        .first()
        .copied()
        .unwrap_or("list")
        .trim()
        .to_ascii_lowercase();
    let remaining = parts.iter().skip(1).copied().collect::<Vec<_>>();
    let result = match action.as_str() {
        "status" | "list" | "ls" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            if !positionals.is_empty() {
                return Err(anyhow!("/subagent list accepts only --role"));
            }
            list_tui_subagents(
                &thread_id,
                options.role.as_deref(),
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "spawn" | "start" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            let (role, prompt_parts) = if let Some(role) = options.role.clone() {
                (role, positionals)
            } else {
                let role = positionals
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "general".to_string());
                let prompt_parts = if positionals.is_empty() {
                    Vec::new()
                } else {
                    positionals[1..].to_vec()
                };
                (role, prompt_parts)
            };
            let prompt = prompt_parts.join(" ");
            if prompt.trim().is_empty() {
                return Err(anyhow!(
                    "/subagent spawn requires <role> <prompt> or --role <role> <prompt>"
                ));
            }
            let mut body = subagent_body_from_options(
                &options,
                &format!("runtime.subagent.spawn.{}", tui_safe_id(&role)),
            );
            body.insert("role".to_string(), Value::String(role));
            body.insert("prompt".to_string(), Value::String(prompt));
            spawn_tui_subagent(
                &thread_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "wait" | "join" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            let (subagent_id, tail) =
                split_subagent_target(control_state, &positionals, "/subagent wait")?;
            if !tail.is_empty() {
                return Err(anyhow!("/subagent wait accepts at most one <subagent_id>"));
            }
            let body = subagent_body_from_options(
                &options,
                &format!("runtime.subagent.join.{}", tui_safe_id(&subagent_id)),
            );
            wait_tui_subagent(
                &thread_id,
                &subagent_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "result" | "get" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            if options.has_control_values() {
                return Err(anyhow!(
                    "/subagent result accepts only an optional <subagent_id>"
                ));
            }
            let (subagent_id, tail) =
                split_subagent_target(control_state, &positionals, "/subagent result")?;
            if !tail.is_empty() {
                return Err(anyhow!(
                    "/subagent result accepts at most one <subagent_id>"
                ));
            }
            fetch_tui_subagent_result(
                &thread_id,
                &subagent_id,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "input" | "send" | "send-input" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            let (subagent_id, tail) =
                split_subagent_target(control_state, &positionals, "/subagent input")?;
            let message = tail.join(" ");
            if message.trim().is_empty() {
                return Err(anyhow!(
                    "/subagent input requires <message> when a default subagent is loaded, or <subagent_id> <message>"
                ));
            }
            let mut body = subagent_body_from_options(
                &options,
                &format!("runtime.subagent.input.{}", tui_safe_id(&subagent_id)),
            );
            body.insert("message".to_string(), Value::String(message));
            send_tui_subagent_input(
                &thread_id,
                &subagent_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "cancel" | "stop" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            let (subagent_id, tail) =
                split_subagent_target(control_state, &positionals, "/subagent cancel")?;
            let reason = tail.join(" ");
            let mut body = subagent_body_from_options(
                &options,
                &format!("runtime.subagent.cancel.{}", tui_safe_id(&subagent_id)),
            );
            if !reason.trim().is_empty() {
                body.insert("reason".to_string(), Value::String(reason));
            }
            cancel_tui_subagent(
                &thread_id,
                &subagent_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "resume" | "restart" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            let (subagent_id, tail) =
                split_subagent_target(control_state, &positionals, "/subagent resume")?;
            let mut body = subagent_body_from_options(
                &options,
                &format!("runtime.subagent.resume.{}", tui_safe_id(&subagent_id)),
            );
            let message = tail.join(" ");
            if !message.trim().is_empty() {
                body.insert("message".to_string(), Value::String(message));
            }
            resume_tui_subagent(
                &thread_id,
                &subagent_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "assign" => {
            let (positionals, mut options) = parse_subagent_option_tokens(&remaining)?;
            let (subagent_id, tail) =
                split_subagent_target(control_state, &positionals, "/subagent assign")?;
            let role_from_option = options.role.take();
            let role = role_from_option
                .clone()
                .or_else(|| tail.first().cloned())
                .ok_or_else(|| {
                    anyhow!(
                        "/subagent assign requires <role> when a default subagent is loaded, or <subagent_id> <role>"
                    )
                })?;
            if (role_from_option.is_some() && !tail.is_empty())
                || (role_from_option.is_none() && tail.len() > 1)
            {
                return Err(anyhow!(
                    "/subagent assign accepts exactly one role argument"
                ));
            }
            let mut body = subagent_body_from_options(
                &options,
                &format!("runtime.subagent.assign.{}", tui_safe_id(&role)),
            );
            body.insert("role".to_string(), Value::String(role));
            assign_tui_subagent(
                &thread_id,
                &subagent_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        "propagate" | "cancel-all" | "parent-cancel" => {
            let (positionals, options) = parse_subagent_option_tokens(&remaining)?;
            let reason = positionals.join(" ");
            let mut body = subagent_body_from_options(&options, "runtime.subagent.cancel.parent");
            if !reason.trim().is_empty() {
                body.insert("reason".to_string(), Value::String(reason));
            }
            propagate_tui_subagent_cancellation(
                &thread_id,
                body,
                &session.endpoint,
                session.token.as_deref(),
            )
            .await?
        }
        _ => {
            return Err(anyhow!(
                "/subagent accepts list, spawn, wait, result, input, cancel, resume, assign, or propagate"
            ));
        }
    };
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    let rows = tui_subagent_rows(&result, Some(&thread_id));
    let count = json_path_string(&result, "/count").unwrap_or_else(|| rows.len().to_string());
    let active_count = json_path_string(&result, "/active_count")
        .or_else(|| json_path_string(&result, "/activeCount"))
        .unwrap_or_else(|| {
            rows.iter()
                .filter(|row| {
                    let status = json_path_string(row, "/status")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    matches!(
                        status.as_str(),
                        "queued" | "running" | "waiting_for_input" | "interrupted"
                    )
                })
                .count()
                .to_string()
        });
    let selected_row = rows.last();
    println!(
        "line_mode_command=subagent action={} thread={} status={} count={} active={} subagent={} lifecycle={} output_contract={} event={}",
        action,
        thread_id,
        json_path_string(&result, "/status").unwrap_or_else(|| "unknown".to_string()),
        count,
        active_count,
        selected_row
            .and_then(|row| json_path_string(row, "/subagent_id"))
            .unwrap_or_else(|| "none".to_string()),
        selected_row
            .and_then(|row| json_path_string(row, "/subagent_lifecycle_status"))
            .or_else(|| json_path_string(&result, "/lifecycle_status"))
            .unwrap_or_else(|| "unknown".to_string()),
        selected_row
            .and_then(|row| json_path_string(row, "/subagent_output_contract_status"))
            .or_else(|| json_path_string(&result, "/output_contract_status"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
    );
    for row in &rows {
        println!(
            "  subagent_row subagent={} role={} status={} operation={} run={} contract={} restart={} inputs={} assignments={} cancel_inheritance={} node={}",
            json_path_string(row, "/subagent_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/subagent_role").unwrap_or_else(|| "general".to_string()),
            json_path_string(row, "/subagent_lifecycle_status")
                .or_else(|| json_path_string(row, "/status"))
                .unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/subagent_operation").unwrap_or_else(|| action.clone()),
            json_path_string(row, "/subagent_run_id").unwrap_or_else(|| "none".to_string()),
            json_path_string(row, "/subagent_output_contract_status")
                .unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/subagent_restart_count").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/subagent_input_count").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/subagent_assignment_count").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/subagent_cancellation_inheritance")
                .unwrap_or_else(|| "propagate".to_string()),
            json_path_string(row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.subagent".to_string())
        );
    }
    let events = handle_events_command(session, None).await?;
    Ok((events, result))
}

#[derive(Debug, Default)]
struct SubagentCommandOptions {
    role: Option<String>,
    tool_pack: Option<String>,
    model_route_id: Option<String>,
    max_concurrency: Option<u64>,
    output_contract: Vec<String>,
    merge_policy: Option<String>,
    cancellation_inheritance: Option<String>,
    fork_context: Option<bool>,
    workflow_graph_id: Option<String>,
    workflow_node_id: Option<String>,
    target_agent_id: Option<String>,
}

impl SubagentCommandOptions {
    fn has_control_values(&self) -> bool {
        self.role.is_some()
            || self.tool_pack.is_some()
            || self.model_route_id.is_some()
            || self.max_concurrency.is_some()
            || !self.output_contract.is_empty()
            || self.merge_policy.is_some()
            || self.cancellation_inheritance.is_some()
            || self.fork_context.is_some()
            || self.workflow_graph_id.is_some()
            || self.workflow_node_id.is_some()
            || self.target_agent_id.is_some()
    }
}

fn parse_subagent_option_tokens(tokens: &[&str]) -> Result<(Vec<String>, SubagentCommandOptions)> {
    let mut positionals = Vec::new();
    let mut options = SubagentCommandOptions::default();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        match token {
            "--role" => {
                options.role = Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--tool-pack" | "--toolpack" => {
                options.tool_pack = Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--route" | "--model-route" | "--model-route-id" => {
                options.model_route_id =
                    Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--max-concurrency" => {
                let value = required_subagent_option_value(tokens, &mut index, token)?;
                options.max_concurrency = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| anyhow!("{token} requires a numeric value"))?,
                );
            }
            "--output-contract" => {
                options.output_contract = parse_subagent_output_contract(
                    &required_subagent_option_value(tokens, &mut index, token)?,
                );
            }
            "--merge-policy" => {
                options.merge_policy =
                    Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--cancel-inheritance" | "--cancellation-inheritance" => {
                options.cancellation_inheritance =
                    Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--fork-context" => options.fork_context = Some(true),
            "--fresh-context" => options.fork_context = Some(false),
            "--workflow-graph" | "--workflow-graph-id" => {
                options.workflow_graph_id =
                    Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--workflow-node" | "--workflow-node-id" => {
                options.workflow_node_id =
                    Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            "--target-agent" | "--target-agent-id" => {
                options.target_agent_id =
                    Some(required_subagent_option_value(tokens, &mut index, token)?)
            }
            _ if token.starts_with("--role=") => {
                options.role = Some(token.trim_start_matches("--role=").to_string())
            }
            _ if token.starts_with("--tool-pack=") => {
                options.tool_pack = Some(token.trim_start_matches("--tool-pack=").to_string())
            }
            _ if token.starts_with("--toolpack=") => {
                options.tool_pack = Some(token.trim_start_matches("--toolpack=").to_string())
            }
            _ if token.starts_with("--route=") => {
                options.model_route_id = Some(token.trim_start_matches("--route=").to_string())
            }
            _ if token.starts_with("--model-route=") => {
                options.model_route_id =
                    Some(token.trim_start_matches("--model-route=").to_string())
            }
            _ if token.starts_with("--model-route-id=") => {
                options.model_route_id =
                    Some(token.trim_start_matches("--model-route-id=").to_string())
            }
            _ if token.starts_with("--max-concurrency=") => {
                let value = token.trim_start_matches("--max-concurrency=");
                options.max_concurrency = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| anyhow!("--max-concurrency requires a numeric value"))?,
                );
            }
            _ if token.starts_with("--output-contract=") => {
                options.output_contract =
                    parse_subagent_output_contract(token.trim_start_matches("--output-contract="));
            }
            _ if token.starts_with("--merge-policy=") => {
                options.merge_policy = Some(token.trim_start_matches("--merge-policy=").to_string())
            }
            _ if token.starts_with("--cancel-inheritance=") => {
                options.cancellation_inheritance = Some(
                    token
                        .trim_start_matches("--cancel-inheritance=")
                        .to_string(),
                )
            }
            _ if token.starts_with("--cancellation-inheritance=") => {
                options.cancellation_inheritance = Some(
                    token
                        .trim_start_matches("--cancellation-inheritance=")
                        .to_string(),
                )
            }
            _ if token.starts_with("--workflow-graph=") => {
                options.workflow_graph_id =
                    Some(token.trim_start_matches("--workflow-graph=").to_string())
            }
            _ if token.starts_with("--workflow-graph-id=") => {
                options.workflow_graph_id =
                    Some(token.trim_start_matches("--workflow-graph-id=").to_string())
            }
            _ if token.starts_with("--workflow-node=") => {
                options.workflow_node_id =
                    Some(token.trim_start_matches("--workflow-node=").to_string())
            }
            _ if token.starts_with("--workflow-node-id=") => {
                options.workflow_node_id =
                    Some(token.trim_start_matches("--workflow-node-id=").to_string())
            }
            _ if token.starts_with("--target-agent=") => {
                options.target_agent_id =
                    Some(token.trim_start_matches("--target-agent=").to_string())
            }
            _ if token.starts_with("--target-agent-id=") => {
                options.target_agent_id =
                    Some(token.trim_start_matches("--target-agent-id=").to_string())
            }
            _ if token.starts_with("--") => return Err(anyhow!("unknown /subagent flag {token}")),
            _ => positionals.push(token.to_string()),
        }
        index += 1;
    }
    Ok((positionals, options))
}

fn required_subagent_option_value(
    tokens: &[&str],
    index: &mut usize,
    flag: &str,
) -> Result<String> {
    *index += 1;
    tokens
        .get(*index)
        .map(|value| (*value).to_string())
        .ok_or_else(|| anyhow!("{flag} requires a value"))
}

fn parse_subagent_output_contract(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|section| !section.is_empty())
        .map(|section| section.to_ascii_uppercase())
        .collect()
}

fn subagent_body_from_options(
    options: &SubagentCommandOptions,
    default_workflow_node_id: &str,
) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("source".to_string(), Value::String("cli_tui".to_string()));
    body.insert("actor".to_string(), Value::String("operator".to_string()));
    body.insert(
        "workflowNodeId".to_string(),
        Value::String(
            options
                .workflow_node_id
                .clone()
                .unwrap_or_else(|| default_workflow_node_id.to_string()),
        ),
    );
    if let Some(workflow_graph_id) = options.workflow_graph_id.as_ref() {
        body.insert(
            "workflowGraphId".to_string(),
            Value::String(workflow_graph_id.clone()),
        );
    }
    if let Some(tool_pack) = options.tool_pack.as_ref() {
        body.insert("toolPack".to_string(), Value::String(tool_pack.clone()));
    }
    if let Some(model_route_id) = options.model_route_id.as_ref() {
        body.insert(
            "modelRouteId".to_string(),
            Value::String(model_route_id.clone()),
        );
    }
    if let Some(max_concurrency) = options.max_concurrency {
        body.insert(
            "maxConcurrency".to_string(),
            Value::Number(serde_json::Number::from(max_concurrency)),
        );
    }
    if !options.output_contract.is_empty() {
        body.insert(
            "outputContract".to_string(),
            Value::Array(
                options
                    .output_contract
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(merge_policy) = options.merge_policy.as_ref() {
        body.insert(
            "mergePolicy".to_string(),
            Value::String(merge_policy.clone()),
        );
    }
    if let Some(cancellation_inheritance) = options.cancellation_inheritance.as_ref() {
        body.insert(
            "cancellationInheritance".to_string(),
            Value::String(cancellation_inheritance.clone()),
        );
    }
    if let Some(fork_context) = options.fork_context {
        body.insert("forkContext".to_string(), Value::Bool(fork_context));
    }
    if let Some(target_agent_id) = options.target_agent_id.as_ref() {
        body.insert(
            "targetAgentId".to_string(),
            Value::String(target_agent_id.clone()),
        );
    }
    body
}

fn split_subagent_target(
    control_state: &TuiControlState,
    positionals: &[String],
    command_name: &str,
) -> Result<(String, Vec<String>)> {
    let default_id = control_state.default_subagent_id();
    if let Some(first) = positionals.first() {
        if looks_like_subagent_id(first) || default_id.is_none() {
            return Ok((first.clone(), positionals[1..].to_vec()));
        }
        return Ok((
            default_id.expect("checked default subagent"),
            positionals.to_vec(),
        ));
    }
    default_id
        .map(|subagent_id| (subagent_id, Vec::new()))
        .ok_or_else(|| {
            anyhow!(
                "{command_name} requires <subagent_id> when no subagent row is loaded; use /subagents first"
            )
        })
}

fn looks_like_subagent_id(value: &str) -> bool {
    value.starts_with("agent_") || value.starts_with("subagent_")
}

fn tui_safe_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

async fn handle_coding_tool_command(
    session: &mut TuiInteractiveSession,
    tool_id: &str,
    path: Option<String>,
) -> Result<Vec<Value>> {
    let mut input = serde_json::Map::new();
    if let Some(path) = path.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert("path".to_string(), Value::String(path.to_string()));
    }
    handle_coding_tool_input_command(session, tool_id, input).await
}

async fn handle_browser_discovery_command(
    session: &mut TuiInteractiveSession,
) -> Result<Vec<Value>> {
    let mut input = serde_json::Map::new();
    input.insert("includeTabs".to_string(), Value::Bool(false));
    input.insert("revealTabTitles".to_string(), Value::Bool(false));
    handle_coding_tool_input_command(session, "ioi.computer_use.browser_discovery", input).await
}

async fn handle_native_browser_command(
    session: &mut TuiInteractiveSession,
    args: NativeBrowserLineArgs,
) -> Result<Vec<Value>> {
    let prompt = args.prompt;
    let approval_ref = args.approval_ref;
    let mut input = serde_json::Map::new();
    if let Some(prompt) = prompt.as_deref().filter(|value| !value.trim().is_empty()) {
        if let Some(action_kind) = native_browser_action_kind_from_prompt(prompt) {
            input.insert(
                "actionKind".to_string(),
                Value::String(action_kind.to_string()),
            );
        }
        input.insert(
            "prompt".to_string(),
            Value::String(prompt.trim().to_string()),
        );
        if prompt.trim().starts_with("http://") || prompt.trim().starts_with("https://") {
            input.insert("url".to_string(), Value::String(prompt.trim().to_string()));
        }
    }
    input.insert(
        "observationRetentionMode".to_string(),
        Value::String("prompt_visible_summary_only".to_string()),
    );
    if let Some(session_mode) = args
        .session_mode
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "sessionMode".to_string(),
            Value::String(session_mode.trim().to_string()),
        );
    }
    if let Some(approval_ref) = approval_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "approvalRef".to_string(),
            Value::String(approval_ref.trim().to_string()),
        );
    }
    if let Some(controlled_relaunch_approval_ref) = args
        .controlled_relaunch_approval_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "controlledRelaunchApprovalRef".to_string(),
            Value::String(controlled_relaunch_approval_ref.trim().to_string()),
        );
    }
    if let Some(controlled_relaunch_executable_path) = args
        .controlled_relaunch_executable_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "controlledRelaunchExecutablePath".to_string(),
            Value::String(controlled_relaunch_executable_path.trim().to_string()),
        );
    }
    if args.controlled_relaunch_headless {
        input.insert("controlledRelaunchHeadless".to_string(), Value::Bool(true));
    }
    if let Some(target_ref) = args
        .target_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "targetRef".to_string(),
            Value::String(target_ref.trim().to_string()),
        );
    }
    if let Some(selector) = args
        .selector
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "selector".to_string(),
            Value::String(selector.trim().to_string()),
        );
    }
    if let Some(text) = args
        .text
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert("text".to_string(), Value::String(text.trim().to_string()));
    }
    if let Some(key) = args.key.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert("key".to_string(), Value::String(key.trim().to_string()));
    }
    if let Some(scroll_x) = args.scroll_x {
        input.insert("scrollX".to_string(), Value::from(scroll_x));
    }
    if let Some(scroll_y) = args.scroll_y {
        input.insert("scrollY".to_string(), Value::from(scroll_y));
    }
    if let Some(file_path) = args
        .file_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "filePath".to_string(),
            Value::String(file_path.trim().to_string()),
        );
    }
    if let Some(cdp_endpoint_url) = args
        .cdp_endpoint_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "cdpEndpointUrl".to_string(),
            Value::String(cdp_endpoint_url.trim().to_string()),
        );
    }
    if let Some(cdp_websocket_url) = args
        .cdp_websocket_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "cdpWebSocketUrl".to_string(),
            Value::String(cdp_websocket_url.trim().to_string()),
        );
    }
    if let Some(cdp_timeout_ms) = args.cdp_timeout_ms {
        input.insert("cdpTimeoutMs".to_string(), Value::from(cdp_timeout_ms));
    }
    handle_coding_tool_input_command(session, "ioi.computer_use.native_browser", input).await
}

async fn handle_visual_gui_command(
    session: &mut TuiInteractiveSession,
    args: VisualGuiLineArgs,
) -> Result<Vec<Value>> {
    let mut input = serde_json::Map::new();
    if let Some(prompt) = args
        .prompt
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "prompt".to_string(),
            Value::String(prompt.trim().to_string()),
        );
    }
    input.insert(
        "observationRetentionMode".to_string(),
        Value::String("local_redacted_artifacts".to_string()),
    );
    if let Some(session_mode) = args
        .session_mode
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "sessionMode".to_string(),
            Value::String(session_mode.trim().to_string()),
        );
    }
    if let Some(screenshot_ref) = args
        .screenshot_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "screenshotRef".to_string(),
            Value::String(screenshot_ref.trim().to_string()),
        );
    }
    if let Some(screenshot_path) = args
        .screenshot_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "screenshotPath".to_string(),
            Value::String(screenshot_path.trim().to_string()),
        );
    }
    if let Some(som_ref) = args
        .som_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "somRef".to_string(),
            Value::String(som_ref.trim().to_string()),
        );
    }
    if let Some(som_path) = args
        .som_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "somPath".to_string(),
            Value::String(som_path.trim().to_string()),
        );
    }
    if let Some(ax_ref) = args
        .ax_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "axRef".to_string(),
            Value::String(ax_ref.trim().to_string()),
        );
    }
    if let Some(ax_path) = args
        .ax_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "axPath".to_string(),
            Value::String(ax_path.trim().to_string()),
        );
    }
    if let Some(app_name) = args
        .app_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "appName".to_string(),
            Value::String(app_name.trim().to_string()),
        );
    }
    if let Some(window_title) = args
        .window_title
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "windowTitle".to_string(),
            Value::String(window_title.trim().to_string()),
        );
    }
    if let Some(coordinate_space_id) = args
        .coordinate_space_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "coordinateSpaceId".to_string(),
            Value::String(coordinate_space_id.trim().to_string()),
        );
    }
    if let Some(viewport_width) = args.viewport_width {
        input.insert("viewportWidth".to_string(), Value::from(viewport_width));
    }
    if let Some(viewport_height) = args.viewport_height {
        input.insert("viewportHeight".to_string(), Value::from(viewport_height));
    }
    handle_coding_tool_input_command(session, "ioi.computer_use.visual_gui", input).await
}

async fn handle_computer_use_control_command(
    session: &mut TuiInteractiveSession,
    args: ComputerUseControlLineArgs,
) -> Result<Vec<Value>> {
    let mut input = serde_json::Map::new();
    input.insert("controlAction".to_string(), Value::String(args.action));
    input.insert("leaseId".to_string(), Value::String(args.lease_id));
    if let Some(handoff_ref) = args.handoff_ref {
        input.insert("handoffRef".to_string(), Value::String(handoff_ref));
    }
    if let Some(reason) = args.reason {
        input.insert("reason".to_string(), Value::String(reason));
    }
    if let Some(resume_observation_ref) = args.resume_observation_ref {
        input.insert(
            "resumeObservationRef".to_string(),
            Value::String(resume_observation_ref),
        );
    }
    if let Some(cdp_endpoint_url) = args.cdp_endpoint_url {
        input.insert(
            "cdpEndpointUrl".to_string(),
            Value::String(cdp_endpoint_url),
        );
    }
    handle_coding_tool_input_command(session, "ioi.computer_use.control", input).await
}

fn native_browser_action_kind_from_prompt(prompt: &str) -> Option<&'static str> {
    let first = prompt.split_whitespace().next()?.to_ascii_lowercase();
    match first.as_str() {
        "click" => Some("click"),
        "type" | "type_text" | "input" => Some("type_text"),
        "key" | "key_press" | "keypress" | "press" => Some("key_press"),
        "navigate" | "open" => Some("navigate"),
        "select" => Some("select"),
        "upload" => Some("upload"),
        "scroll" => Some("scroll"),
        "hover" => Some("hover"),
        "wait" => Some("wait"),
        "inspect" => Some("inspect"),
        _ => None,
    }
}

async fn handle_coding_tool_input_command(
    session: &mut TuiInteractiveSession,
    tool_id: &str,
    input: serde_json::Map<String, Value>,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let result = invoke_tui_coding_tool(
        &thread_id,
        tool_id,
        Value::Object(input),
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command={} tool={} status={} receipts={}",
        coding_tool_line_command(tool_id),
        tool_id,
        json_path_string(&result, "/status").unwrap_or_else(|| "unknown".to_string()),
        result
            .pointer("/receipt_refs")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    );
    handle_events_command(session, None).await
}

async fn handle_restore_list_command(session: &mut TuiInteractiveSession) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let result =
        list_tui_workspace_snapshots(&thread_id, &session.endpoint, session.token.as_deref())
            .await?;
    let snapshots = result
        .pointer("/snapshots")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    println!(
        "line_mode_command=restore action=list count={}",
        snapshots.len()
    );
    for snapshot in snapshots {
        println!(
            "  snapshot={} changed_files={} restore={} receipts={} artifacts={}",
            json_path_string(&snapshot, "/snapshotId")
                .or_else(|| json_path_string(&snapshot, "/snapshot_id"))
                .unwrap_or_else(|| "unknown".to_string()),
            json_path_string(&snapshot, "/changedFileCount")
                .or_else(|| json_path_string(&snapshot, "/changed_file_count"))
                .or_else(|| json_path_string(&snapshot, "/fileCount"))
                .unwrap_or_else(|| "0".to_string()),
            json_path_string(&snapshot, "/restore/status").unwrap_or_else(|| "unknown".to_string()),
            snapshot
                .pointer("/receiptRefs")
                .or_else(|| snapshot.pointer("/receipt_refs"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
            snapshot
                .pointer("/artifactRefs")
                .or_else(|| snapshot.pointer("/artifact_refs"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        );
    }
    Ok(Vec::new())
}

async fn handle_restore_preview_command(
    session: &mut TuiInteractiveSession,
    snapshot_id: &str,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let result = preview_tui_workspace_restore(
        &thread_id,
        snapshot_id,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=restore action=preview snapshot={} status={} apply_supported={} receipts={} artifacts={}",
        snapshot_id,
        json_path_string(&result, "/preview_status")
            .or_else(|| json_path_string(&result, "/previewStatus"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&result, "/apply_supported")
            .or_else(|| json_path_string(&result, "/applySupported"))
            .unwrap_or_else(|| "false".to_string()),
        result
            .pointer("/receipt_refs")
            .or_else(|| result.pointer("/receiptRefs"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        result
            .pointer("/artifact_refs")
            .or_else(|| result.pointer("/artifactRefs"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    );
    handle_events_command(session, None).await
}

async fn handle_restore_apply_command(
    session: &mut TuiInteractiveSession,
    snapshot_id: &str,
    allow_conflicts: bool,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let result = apply_tui_workspace_restore(
        &thread_id,
        snapshot_id,
        allow_conflicts,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=restore action=apply snapshot={} status={} approval_satisfied={} allow_conflicts={} receipts={} policies={}",
        snapshot_id,
        json_path_string(&result, "/apply_status")
            .or_else(|| json_path_string(&result, "/applyStatus"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&result, "/approval_satisfied")
            .or_else(|| json_path_string(&result, "/approvalSatisfied"))
            .unwrap_or_else(|| "false".to_string()),
        allow_conflicts,
        result
            .pointer("/receipt_refs")
            .or_else(|| result.pointer("/receiptRefs"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        result
            .pointer("/policy_decision_refs")
            .or_else(|| result.pointer("/policyDecisionRefs"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    );
    handle_events_command(session, None).await
}

async fn handle_diagnostics_repair_command(
    session: &mut TuiInteractiveSession,
    action: &str,
    decision_id: &str,
    message: Option<&str>,
    approved: bool,
    allow_conflicts: bool,
) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let result = execute_tui_diagnostics_repair_decision(
        &thread_id,
        decision_id,
        action,
        message,
        approved,
        allow_conflicts,
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    session.thread =
        fetch_tui_thread(&thread_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=diagnostics action=repair repair_action={} decision={} status={} snapshot={} approved={} allow_conflicts={} receipts={} policies={} event={}",
        action,
        decision_id,
        json_path_string(&result, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&result, "/snapshotId")
            .or_else(|| json_path_string(&result, "/snapshot_id"))
            .unwrap_or_else(|| "none".to_string()),
        approved,
        allow_conflicts,
        result
            .pointer("/receipt_refs")
            .or_else(|| result.pointer("/receiptRefs"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        result
            .pointer("/policy_decision_refs")
            .or_else(|| result.pointer("/policyDecisionRefs"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        json_path_string(&result, "/event/event_id").unwrap_or_else(|| "none".to_string())
    );
    if let Some(turn_id) = json_path_string(&result, "/repairTurn/turn_id")
        .or_else(|| json_path_string(&result, "/repair_turn/turn_id"))
    {
        println!("  repair_turn={turn_id}");
    }
    if let Some(preview_status) = json_path_string(&result, "/restorePreview/previewStatus")
        .or_else(|| json_path_string(&result, "/restore_preview/preview_status"))
    {
        println!("  restore_preview_status={preview_status}");
    }
    if let Some(apply_status) = json_path_string(&result, "/restoreApply/applyStatus")
        .or_else(|| json_path_string(&result, "/restore_apply/apply_status"))
    {
        println!("  restore_apply_status={apply_status}");
    }
    if let Some(continuation_allowed) =
        json_path_string(&result, "/operatorOverride/continuationAllowed")
            .or_else(|| json_path_string(&result, "/operator_override/continuation_allowed"))
    {
        println!("  operator_override_continuation_allowed={continuation_allowed}");
    }
    handle_events_command(session, None).await
}

async fn handle_jobs_command(session: &mut TuiInteractiveSession) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let jobs =
        list_tui_jobs_for_thread(&session.thread, &session.endpoint, session.token.as_deref())
            .await?;
    let rows = tui_job_rows(&jobs, Some(&thread_id));
    println!("line_mode_command=jobs count={}", rows.len());
    for row in &rows {
        println!(
            "  job={} run={} status={} progress={} cancelable={} node={}",
            json_path_string(row, "/job_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/run_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/progress_percent").unwrap_or_else(|| "0".to_string()),
            json_path_string(row, "/cancelable").unwrap_or_else(|| "false".to_string()),
            json_path_string(row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.runtime-job".to_string())
        );
    }
    Ok(jobs)
}

async fn handle_tasks_command(session: &mut TuiInteractiveSession) -> Result<Vec<Value>> {
    let thread_id = thread_id_from_value(&session.thread)?;
    let tasks =
        list_tui_tasks_for_thread(&session.thread, &session.endpoint, session.token.as_deref())
            .await?;
    let rows = tui_task_rows(&tasks, Some(&thread_id));
    println!("line_mode_command=tasks count={}", rows.len());
    for row in &rows {
        println!(
            "  task={} run={} status={} family={} node={}",
            json_path_string(row, "/task_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/run_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/task_family").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(row, "/workflow_node_id")
                .unwrap_or_else(|| "runtime.runtime-task".to_string())
        );
    }
    Ok(tasks)
}

async fn handle_task_inspect_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    task_id: Option<String>,
) -> Result<Value> {
    let task_id = select_task_id(session, control_state, task_id).await?;
    let task = fetch_tui_task(&task_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=task action=inspect task={} run={} status={} family={} cancelable={}",
        json_path_string(&task, "/taskId")
            .or_else(|| json_path_string(&task, "/task_id"))
            .unwrap_or_else(|| task_id.clone()),
        json_path_string(&task, "/runId")
            .or_else(|| json_path_string(&task, "/run_id"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&task, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&task, "/taskFamily")
            .or_else(|| json_path_string(&task, "/task_family"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&task, "/cancelable").unwrap_or_else(|| "false".to_string())
    );
    Ok(task)
}

async fn handle_task_cancel_command(
    session: &mut TuiInteractiveSession,
    task_id: &str,
) -> Result<Value> {
    let task = cancel_tui_task(task_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=task action=cancel task={} run={} status={}",
        json_path_string(&task, "/taskId")
            .or_else(|| json_path_string(&task, "/task_id"))
            .unwrap_or_else(|| task_id.to_string()),
        json_path_string(&task, "/runId")
            .or_else(|| json_path_string(&task, "/run_id"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&task, "/status").unwrap_or_else(|| "unknown".to_string())
    );
    Ok(task)
}

async fn handle_job_inspect_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    job_id: Option<String>,
) -> Result<Value> {
    let job_id = select_job_id(session, control_state, job_id).await?;
    let job = fetch_tui_job(&job_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=job action=inspect job={} run={} status={} lifecycle={} cancelable={}",
        json_path_string(&job, "/jobId")
            .or_else(|| json_path_string(&job, "/job_id"))
            .unwrap_or_else(|| job_id.clone()),
        json_path_string(&job, "/runId")
            .or_else(|| json_path_string(&job, "/run_id"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&job, "/status").unwrap_or_else(|| "unknown".to_string()),
        job.pointer("/lifecycle")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(">")
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&job, "/cancelable").unwrap_or_else(|| "false".to_string())
    );
    Ok(job)
}

async fn handle_job_cancel_command(
    session: &mut TuiInteractiveSession,
    job_id: &str,
) -> Result<Value> {
    let job = cancel_tui_job(job_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=job action=cancel job={} run={} status={} cancellation={}",
        json_path_string(&job, "/jobId")
            .or_else(|| json_path_string(&job, "/job_id"))
            .unwrap_or_else(|| job_id.to_string()),
        json_path_string(&job, "/runId")
            .or_else(|| json_path_string(&job, "/run_id"))
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&job, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&job, "/cancellation/reason")
            .unwrap_or_else(|| "operator_cancel".to_string())
    );
    Ok(job)
}

async fn handle_run_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    run_id: Option<String>,
) -> Result<Value> {
    let run_id = select_run_id(session, control_state, run_id).await?;
    let run = fetch_tui_run(&run_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=run action=inspect run={} status={} mode={} events={} artifacts={}",
        json_path_string(&run, "/id").unwrap_or_else(|| run_id.clone()),
        json_path_string(&run, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&run, "/mode").unwrap_or_else(|| "unknown".to_string()),
        run.pointer("/events")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        run.pointer("/artifacts")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    );
    Ok(run)
}

async fn handle_run_trace_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    run_id: Option<String>,
    inspect: bool,
) -> Result<Value> {
    let run_id = select_run_id(session, control_state, run_id).await?;
    let trace = if inspect {
        inspect_tui_run(&run_id, &session.endpoint, session.token.as_deref()).await?
    } else {
        fetch_tui_run_trace(&run_id, &session.endpoint, session.token.as_deref()).await?
    };
    println!(
        "line_mode_command=run action={} run={} status={} events={} receipts={} canonical_state={}",
        if inspect { "inspect" } else { "trace" },
        run_id,
        json_path_string(&trace, "/runtimeTask/status")
            .or_else(|| json_path_string(&trace, "/runtime_task/status"))
            .or_else(|| json_path_string(&trace, "/taskState/status"))
            .unwrap_or_else(|| "unknown".to_string()),
        trace
            .pointer("/events")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        trace
            .pointer("/receipts")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        trace.pointer("/canonicalState").is_some()
    );
    Ok(trace)
}

async fn handle_run_replay_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    run_id: Option<String>,
) -> Result<Vec<Value>> {
    let run_id = select_run_id(session, control_state, run_id).await?;
    let batch =
        replay_tui_run_events(&run_id, &session.endpoint, session.token.as_deref(), None).await?;
    println!(
        "line_mode_command=run action=replay route={} count={}",
        batch.event_route,
        batch.events.len()
    );
    print_events(&batch.events);
    Ok(batch.events)
}

async fn handle_run_cancel_command(
    session: &mut TuiInteractiveSession,
    run_id: &str,
) -> Result<Value> {
    let run = cancel_tui_run(run_id, &session.endpoint, session.token.as_deref()).await?;
    println!(
        "line_mode_command=run action=cancel run={} status={} events={}",
        json_path_string(&run, "/id").unwrap_or_else(|| run_id.to_string()),
        json_path_string(&run, "/status").unwrap_or_else(|| "unknown".to_string()),
        run.pointer("/events")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    );
    Ok(run)
}

async fn handle_run_recovery_command(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    action: &str,
    run_id: Option<String>,
    approval_id: Option<String>,
) -> Result<Vec<Value>> {
    let run_id = select_run_id(session, control_state, run_id).await?;
    let approval_id = if action == "request_approval" {
        approval_id
    } else {
        approval_id.or_else(|| control_state.default_pending_approval_id())
    };
    let thread_id = thread_id_from_value(&session.thread).ok();
    let result = execute_tui_run_coding_tool_budget_recovery(
        &run_id,
        action,
        thread_id.as_deref(),
        approval_id.as_deref(),
        &session.endpoint,
        session.token.as_deref(),
    )
    .await?;
    println!(
        "line_mode_command=run action=recovery recovery_action={} run={} status={} approval={} event={}",
        json_path_string(&result, "/recovery_action")
            .or_else(|| json_path_string(&result, "/recoveryAction"))
            .unwrap_or_else(|| action.to_string()),
        json_path_string(&result, "/run_id")
            .or_else(|| json_path_string(&result, "/runId"))
            .unwrap_or_else(|| run_id.clone()),
        json_path_string(&result, "/status").unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&result, "/approval_id")
            .or_else(|| json_path_string(&result, "/approvalId"))
            .unwrap_or_else(|| approval_id.unwrap_or_else(|| "none".to_string())),
        json_path_string(&result, "/event_id")
            .or_else(|| json_path_string(&result, "/eventId"))
            .unwrap_or_else(|| "none".to_string())
    );
    let batch =
        replay_tui_run_events(&run_id, &session.endpoint, session.token.as_deref(), None).await?;
    print_events(&batch.events);
    Ok(batch.events)
}

async fn select_job_id(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    explicit_job_id: Option<String>,
) -> Result<String> {
    if let Some(job_id) = explicit_job_id.filter(|value| !value.trim().is_empty()) {
        return Ok(job_id);
    }
    if let Some(job_id) = control_state.default_job_id() {
        return Ok(job_id);
    }
    let jobs =
        list_tui_jobs_for_thread(&session.thread, &session.endpoint, session.token.as_deref())
            .await?;
    jobs.iter()
        .rev()
        .find_map(|job| {
            json_path_string(job, "/jobId").or_else(|| json_path_string(job, "/job_id"))
        })
        .ok_or_else(|| {
            anyhow!("/job requires a job id when no job rows are loaded; use /jobs first")
        })
}

async fn select_task_id(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    explicit_task_id: Option<String>,
) -> Result<String> {
    if let Some(task_id) = explicit_task_id.filter(|value| !value.trim().is_empty()) {
        return Ok(task_id);
    }
    if let Some(task_id) = control_state.default_task_id() {
        return Ok(task_id);
    }
    let tasks =
        list_tui_tasks_for_thread(&session.thread, &session.endpoint, session.token.as_deref())
            .await?;
    tasks
        .iter()
        .rev()
        .find_map(|task| {
            json_path_string(task, "/taskId").or_else(|| json_path_string(task, "/task_id"))
        })
        .ok_or_else(|| {
            anyhow!("/task requires a task id when no task rows are loaded; use /tasks first")
        })
}

async fn select_run_id(
    session: &mut TuiInteractiveSession,
    control_state: &TuiControlState,
    explicit_run_id: Option<String>,
) -> Result<String> {
    if let Some(run_id) = explicit_run_id.filter(|value| !value.trim().is_empty()) {
        return Ok(run_id);
    }
    if let Some(run_id) = control_state.default_run_id() {
        return Ok(run_id);
    }
    if let Some(run_id) = selected_run_id_from_thread(&session.thread) {
        return Ok(run_id);
    }
    let jobs =
        list_tui_jobs_for_thread(&session.thread, &session.endpoint, session.token.as_deref())
            .await?;
    jobs.iter()
        .rev()
        .find_map(|job| {
            json_path_string(job, "/runId").or_else(|| json_path_string(job, "/run_id"))
        })
        .ok_or_else(|| {
            anyhow!(
                "/run requires a run id when no thread run or job rows are loaded; use /jobs first"
            )
        })
}

fn coding_tool_line_command(tool_id: &str) -> &'static str {
    match tool_id {
        "workspace.status" => "status",
        "git.diff" => "diff",
        "file.inspect" => "inspect",
        "file.apply_patch" => "patch",
        "test.run" => "test",
        "lsp.diagnostics" => "diagnostics",
        "artifact.read" => "artifact",
        "tool.retrieve_result" => "retrieve",
        "ioi.computer_use.browser_discovery" => "browser-discovery",
        "ioi.computer_use.native_browser" => "native-browser",
        "ioi.computer_use.visual_gui" => "visual-gui",
        "ioi.computer_use.control" => "computer-use-control",
        _ => "tool",
    }
}

fn print_tui_help() {
    println!("Line-mode commands: /resume /events [since_seq] /mode [plan|agent|yolo] /model [model_id] [route_id|--route route_id] /thinking [low|medium|high|xhigh] /cost /context /browser-discovery /native-browser [prompt-or-url] [--session-mode owned_hermetic_browser|attached_cdp|controlled_relaunch] [--approval-ref approval_id] [--controlled-relaunch-approval-ref approval_id] [--controlled-relaunch-executable-path path] [--controlled-relaunch-headless] [--selector css] [--target-ref ref] [--text value] [--key value] [--scroll-x n] [--scroll-y n] [--file-path path] [--cdp-endpoint-url url] [--cdp-websocket-url ws] [--cdp-timeout-ms n] /visual-gui [prompt] [--session-mode visual_fallback|foreground_desktop|background_desktop|app_scoped_desktop] [--screenshot-ref ref|--screenshot-path path] [--som-ref ref|--som-path path] [--ax-ref ref|--ax-path path] [--app-name name] [--window-title title] [--coordinate-space-id id] [--viewport-width n] [--viewport-height n] /computer-use [pause|resume|abort|cleanup] --lease-id lease_id [--handoff-ref ref] [--reason text] [--resume-observation-ref ref] [--cdp-endpoint-url url] /mcp [status|tools|servers|search <query>|fetch <tool_id>|validate|enable <server_id>|disable <server_id>|invoke <server_id> <tool_name> [json]] [--source-mode workspace|global|workspace_and_global] /memory [status|show|policy|path|validate|enable|disable|remember <text>|edit <memory_id> <text>|delete <memory_id>] /subagents /subagent [list|spawn <role> <prompt>|wait [subagent_id]|result [subagent_id]|input [subagent_id] <message>|cancel [subagent_id] [reason]|resume [subagent_id] [message]|assign [subagent_id] <role>|propagate [reason]] [--role role] [--tool-pack pack] [--route route_id] [--max-concurrency n] [--output-contract A,B] [--merge-policy policy] [--cancel-inheritance propagate|isolate] /approvals /approve [approval_id] [reason] /reject [approval_id] [reason] /interrupt [reason] /steer <guidance> /status /diff [path] /inspect <path> /patch <path> <old> => <new> /patch-dry-run <path> <old> => <new> /test [path] /diagnostics <path> /diagnostics repair [retry|preview-restore|apply-restore|override] [decision_id] [--approve] [--allow-conflicts] [--message text] /artifact <artifact_id> /retrieve <tool_call_id_or_artifact_id> /tasks /task [inspect|cancel] [task_id] /jobs /job [inspect|cancel] [job_id] /run [run_id|trace|inspect|replay|cancel|recovery] [run_id] /run recovery [request|approve|reject|retry-approved] [run_id] [approval_id] /restore [list|preview <snapshot_id>|apply <snapshot_id> --approve] /quit");
}

fn print_events(events: &[Value]) {
    for event in events {
        println!("  {}", format_runtime_event_line(event));
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComputerUseControlLineArgs {
    action: String,
    lease_id: String,
    handoff_ref: Option<String>,
    reason: Option<String>,
    resume_observation_ref: Option<String>,
    cdp_endpoint_url: Option<String>,
}

fn computer_use_control_prefix(value: &str) -> Option<&str> {
    let first = value.split_whitespace().next()?;
    match first {
        "pause" | "resume" | "abort" | "cancel" | "cleanup" => Some(first),
        _ => None,
    }
}

fn parse_computer_use_control_args(value: &str) -> Result<ComputerUseControlLineArgs> {
    let mut parts = value.split_whitespace();
    let action = parts
        .next()
        .ok_or_else(|| anyhow!("computer-use control requires pause, resume, abort, or cleanup"))?;
    let action = match action {
        "pause" => "pause",
        "resume" => "resume",
        "abort" | "cancel" => "abort",
        "cleanup" => "cleanup",
        _ => {
            return Err(anyhow!(
                "computer-use control action must be pause, resume, abort, or cleanup"
            ))
        }
    }
    .to_string();
    let mut lease_id = None;
    let mut handoff_ref = None;
    let mut reason_parts = Vec::new();
    let mut resume_observation_ref = None;
    let mut cdp_endpoint_url = None;
    while let Some(part) = parts.next() {
        if let Some(inline) = part.strip_prefix("--lease-id=") {
            lease_id = Some(non_empty_flag_value("--lease-id", inline)?);
            continue;
        }
        if part == "--lease-id" {
            lease_id = Some(non_empty_flag_value(
                "--lease-id",
                required_flag_value("--lease-id", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--handoff-ref=") {
            handoff_ref = Some(non_empty_flag_value("--handoff-ref", inline)?);
            continue;
        }
        if part == "--handoff-ref" {
            handoff_ref = Some(non_empty_flag_value(
                "--handoff-ref",
                required_flag_value("--handoff-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--resume-observation-ref=") {
            resume_observation_ref =
                Some(non_empty_flag_value("--resume-observation-ref", inline)?);
            continue;
        }
        if part == "--resume-observation-ref" {
            resume_observation_ref = Some(non_empty_flag_value(
                "--resume-observation-ref",
                required_flag_value("--resume-observation-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--cdp-endpoint-url=") {
            cdp_endpoint_url = Some(non_empty_flag_value("--cdp-endpoint-url", inline)?);
            continue;
        }
        if part == "--cdp-endpoint-url" {
            cdp_endpoint_url = Some(non_empty_flag_value(
                "--cdp-endpoint-url",
                required_flag_value("--cdp-endpoint-url", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--reason=") {
            reason_parts.push(non_empty_flag_value("--reason", inline)?);
            reason_parts.extend(parts.map(ToString::to_string));
            break;
        }
        if part == "--reason" {
            reason_parts.push(non_empty_flag_value(
                "--reason",
                required_flag_value("--reason", &mut parts)?,
            )?);
            reason_parts.extend(parts.map(ToString::to_string));
            break;
        }
        reason_parts.push(part.to_string());
    }
    Ok(ComputerUseControlLineArgs {
        action,
        lease_id: lease_id.ok_or_else(|| anyhow!("computer-use control requires --lease-id"))?,
        handoff_ref,
        reason: non_empty_string(&reason_parts.join(" ")),
        resume_observation_ref,
        cdp_endpoint_url,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeBrowserLineArgs {
    prompt: Option<String>,
    session_mode: Option<String>,
    approval_ref: Option<String>,
    controlled_relaunch_approval_ref: Option<String>,
    controlled_relaunch_executable_path: Option<String>,
    controlled_relaunch_headless: bool,
    target_ref: Option<String>,
    selector: Option<String>,
    text: Option<String>,
    key: Option<String>,
    scroll_x: Option<i64>,
    scroll_y: Option<i64>,
    file_path: Option<String>,
    cdp_endpoint_url: Option<String>,
    cdp_websocket_url: Option<String>,
    cdp_timeout_ms: Option<u64>,
}

fn parse_native_browser_args(value: &str) -> Result<NativeBrowserLineArgs> {
    let mut prompt_parts = Vec::new();
    let mut session_mode = None;
    let mut approval_ref = None;
    let mut controlled_relaunch_approval_ref = None;
    let mut controlled_relaunch_executable_path = None;
    let mut controlled_relaunch_headless = false;
    let mut target_ref = None;
    let mut selector = None;
    let mut text = None;
    let mut key = None;
    let mut scroll_x = None;
    let mut scroll_y = None;
    let mut file_path = None;
    let mut cdp_endpoint_url = None;
    let mut cdp_websocket_url = None;
    let mut cdp_timeout_ms = None;
    let mut parts = value.split_whitespace();
    while let Some(part) = parts.next() {
        if let Some(inline) = part.strip_prefix("--approval-ref=") {
            if inline.trim().is_empty() {
                return Err(anyhow!("--approval-ref requires a non-empty value"));
            }
            approval_ref = Some(inline.trim().to_string());
            continue;
        }
        if part == "--approval-ref" {
            let Some(next) = parts.next() else {
                return Err(anyhow!("--approval-ref requires a value"));
            };
            approval_ref = Some(next.trim().to_string());
            continue;
        }
        if let Some(inline) = part.strip_prefix("--session-mode=") {
            session_mode = Some(non_empty_flag_value("--session-mode", inline)?);
            continue;
        }
        if part == "--session-mode" {
            session_mode = Some(non_empty_flag_value(
                "--session-mode",
                required_flag_value("--session-mode", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--controlled-relaunch-approval-ref=") {
            controlled_relaunch_approval_ref = Some(non_empty_flag_value(
                "--controlled-relaunch-approval-ref",
                inline,
            )?);
            continue;
        }
        if part == "--controlled-relaunch-approval-ref" {
            controlled_relaunch_approval_ref = Some(non_empty_flag_value(
                "--controlled-relaunch-approval-ref",
                required_flag_value("--controlled-relaunch-approval-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--controlled-relaunch-executable-path=") {
            controlled_relaunch_executable_path = Some(non_empty_flag_value(
                "--controlled-relaunch-executable-path",
                inline,
            )?);
            continue;
        }
        if part == "--controlled-relaunch-executable-path" {
            controlled_relaunch_executable_path = Some(non_empty_flag_value(
                "--controlled-relaunch-executable-path",
                required_flag_value("--controlled-relaunch-executable-path", &mut parts)?,
            )?);
            continue;
        }
        if part == "--controlled-relaunch-headless" {
            controlled_relaunch_headless = true;
            continue;
        }
        if let Some(inline) = part.strip_prefix("--target-ref=") {
            target_ref = Some(non_empty_flag_value("--target-ref", inline)?);
            continue;
        }
        if part == "--target-ref" {
            target_ref = Some(non_empty_flag_value(
                "--target-ref",
                required_flag_value("--target-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--selector=") {
            selector = Some(non_empty_flag_value("--selector", inline)?);
            continue;
        }
        if part == "--selector" {
            selector = Some(non_empty_flag_value(
                "--selector",
                required_flag_value("--selector", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--text=") {
            text = Some(non_empty_flag_value("--text", inline)?);
            continue;
        }
        if part == "--text" {
            text = Some(non_empty_flag_value(
                "--text",
                required_flag_value("--text", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--key=") {
            key = Some(non_empty_flag_value("--key", inline)?);
            continue;
        }
        if part == "--key" {
            key = Some(non_empty_flag_value(
                "--key",
                required_flag_value("--key", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--scroll-x=") {
            scroll_x = Some(parse_scroll_delta("--scroll-x", inline)?);
            continue;
        }
        if part == "--scroll-x" {
            scroll_x = Some(parse_scroll_delta(
                "--scroll-x",
                required_flag_value("--scroll-x", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--scroll-y=") {
            scroll_y = Some(parse_scroll_delta("--scroll-y", inline)?);
            continue;
        }
        if part == "--scroll-y" {
            scroll_y = Some(parse_scroll_delta(
                "--scroll-y",
                required_flag_value("--scroll-y", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--file-path=") {
            file_path = Some(non_empty_flag_value("--file-path", inline)?);
            continue;
        }
        if part == "--file-path" {
            file_path = Some(non_empty_flag_value(
                "--file-path",
                required_flag_value("--file-path", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--cdp-endpoint-url=") {
            cdp_endpoint_url = Some(non_empty_flag_value("--cdp-endpoint-url", inline)?);
            continue;
        }
        if part == "--cdp-endpoint-url" {
            cdp_endpoint_url = Some(non_empty_flag_value(
                "--cdp-endpoint-url",
                required_flag_value("--cdp-endpoint-url", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--cdp-websocket-url=") {
            cdp_websocket_url = Some(non_empty_flag_value("--cdp-websocket-url", inline)?);
            continue;
        }
        if part == "--cdp-websocket-url" {
            cdp_websocket_url = Some(non_empty_flag_value(
                "--cdp-websocket-url",
                required_flag_value("--cdp-websocket-url", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--cdp-timeout-ms=") {
            cdp_timeout_ms = Some(parse_cdp_timeout_ms(inline)?);
            continue;
        }
        if part == "--cdp-timeout-ms" {
            cdp_timeout_ms = Some(parse_cdp_timeout_ms(required_flag_value(
                "--cdp-timeout-ms",
                &mut parts,
            )?)?);
            continue;
        }
        prompt_parts.push(part);
    }
    Ok(NativeBrowserLineArgs {
        prompt: non_empty_string(&prompt_parts.join(" ")),
        session_mode,
        approval_ref,
        controlled_relaunch_approval_ref,
        controlled_relaunch_executable_path,
        controlled_relaunch_headless,
        target_ref,
        selector,
        text,
        key,
        scroll_x,
        scroll_y,
        file_path,
        cdp_endpoint_url,
        cdp_websocket_url,
        cdp_timeout_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VisualGuiLineArgs {
    prompt: Option<String>,
    session_mode: Option<String>,
    screenshot_ref: Option<String>,
    screenshot_path: Option<String>,
    som_ref: Option<String>,
    som_path: Option<String>,
    ax_ref: Option<String>,
    ax_path: Option<String>,
    app_name: Option<String>,
    window_title: Option<String>,
    coordinate_space_id: Option<String>,
    viewport_width: Option<u64>,
    viewport_height: Option<u64>,
}

fn parse_visual_gui_args(value: &str) -> Result<VisualGuiLineArgs> {
    let mut prompt_parts = Vec::new();
    let mut session_mode = None;
    let mut screenshot_ref = None;
    let mut screenshot_path = None;
    let mut som_ref = None;
    let mut som_path = None;
    let mut ax_ref = None;
    let mut ax_path = None;
    let mut app_name = None;
    let mut window_title = None;
    let mut coordinate_space_id = None;
    let mut viewport_width = None;
    let mut viewport_height = None;
    let mut parts = value.split_whitespace();
    while let Some(part) = parts.next() {
        if let Some(inline) = part.strip_prefix("--session-mode=") {
            session_mode = Some(non_empty_flag_value("--session-mode", inline)?);
            continue;
        }
        if part == "--session-mode" {
            session_mode = Some(non_empty_flag_value(
                "--session-mode",
                required_flag_value("--session-mode", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--screenshot-ref=") {
            screenshot_ref = Some(non_empty_flag_value("--screenshot-ref", inline)?);
            continue;
        }
        if part == "--screenshot-ref" {
            screenshot_ref = Some(non_empty_flag_value(
                "--screenshot-ref",
                required_flag_value("--screenshot-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--screenshot-path=") {
            screenshot_path = Some(non_empty_flag_value("--screenshot-path", inline)?);
            continue;
        }
        if part == "--screenshot-path" {
            screenshot_path = Some(non_empty_flag_value(
                "--screenshot-path",
                required_flag_value("--screenshot-path", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--som-ref=") {
            som_ref = Some(non_empty_flag_value("--som-ref", inline)?);
            continue;
        }
        if part == "--som-ref" {
            som_ref = Some(non_empty_flag_value(
                "--som-ref",
                required_flag_value("--som-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--som-path=") {
            som_path = Some(non_empty_flag_value("--som-path", inline)?);
            continue;
        }
        if part == "--som-path" {
            som_path = Some(non_empty_flag_value(
                "--som-path",
                required_flag_value("--som-path", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--ax-ref=") {
            ax_ref = Some(non_empty_flag_value("--ax-ref", inline)?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--ax-path=") {
            ax_path = Some(non_empty_flag_value("--ax-path", inline)?);
            continue;
        }
        if part == "--ax-path" {
            ax_path = Some(non_empty_flag_value(
                "--ax-path",
                required_flag_value("--ax-path", &mut parts)?,
            )?);
            continue;
        }
        if part == "--ax-ref" {
            ax_ref = Some(non_empty_flag_value(
                "--ax-ref",
                required_flag_value("--ax-ref", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--app-name=") {
            app_name = Some(non_empty_flag_value("--app-name", inline)?);
            continue;
        }
        if part == "--app-name" {
            app_name = Some(non_empty_flag_value(
                "--app-name",
                required_flag_value("--app-name", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--window-title=") {
            window_title = Some(non_empty_flag_value("--window-title", inline)?);
            continue;
        }
        if part == "--window-title" {
            window_title = Some(non_empty_flag_value(
                "--window-title",
                required_flag_value("--window-title", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--coordinate-space-id=") {
            coordinate_space_id = Some(non_empty_flag_value("--coordinate-space-id", inline)?);
            continue;
        }
        if part == "--coordinate-space-id" {
            coordinate_space_id = Some(non_empty_flag_value(
                "--coordinate-space-id",
                required_flag_value("--coordinate-space-id", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--viewport-width=") {
            viewport_width = Some(parse_positive_u64("--viewport-width", inline)?);
            continue;
        }
        if part == "--viewport-width" {
            viewport_width = Some(parse_positive_u64(
                "--viewport-width",
                required_flag_value("--viewport-width", &mut parts)?,
            )?);
            continue;
        }
        if let Some(inline) = part.strip_prefix("--viewport-height=") {
            viewport_height = Some(parse_positive_u64("--viewport-height", inline)?);
            continue;
        }
        if part == "--viewport-height" {
            viewport_height = Some(parse_positive_u64(
                "--viewport-height",
                required_flag_value("--viewport-height", &mut parts)?,
            )?);
            continue;
        }
        prompt_parts.push(part);
    }
    Ok(VisualGuiLineArgs {
        prompt: non_empty_string(&prompt_parts.join(" ")),
        session_mode,
        screenshot_ref,
        screenshot_path,
        som_ref,
        som_path,
        ax_ref,
        ax_path,
        app_name,
        window_title,
        coordinate_space_id,
        viewport_width,
        viewport_height,
    })
}

fn required_flag_value<'a>(
    flag: &str,
    parts: &mut std::str::SplitWhitespace<'a>,
) -> Result<&'a str> {
    parts
        .next()
        .ok_or_else(|| anyhow!("{flag} requires a value"))
}

fn non_empty_flag_value(flag: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{flag} requires a non-empty value"));
    }
    Ok(trimmed.to_string())
}

fn parse_cdp_timeout_ms(value: &str) -> Result<u64> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("--cdp-timeout-ms requires an integer millisecond value"))?;
    if parsed == 0 {
        return Err(anyhow!("--cdp-timeout-ms must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_positive_u64(flag: &str, value: &str) -> Result<u64> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("{flag} requires a positive integer value"))?;
    if parsed == 0 {
        return Err(anyhow!("{flag} must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_scroll_delta(flag: &str, value: &str) -> Result<i64> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| anyhow!("{flag} requires an integer pixel delta"))
}

fn line_command_head(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    Some(trimmed[..end].to_ascii_lowercase())
}

fn parse_patch_args(rest: &str) -> Result<(String, String, String)> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("/patch requires <path> <old> => <new>"));
    }
    let path_end = trimmed
        .find(char::is_whitespace)
        .ok_or_else(|| anyhow!("/patch requires <path> <old> => <new>"))?;
    let path = trimmed[..path_end].trim().to_string();
    let body = trimmed[path_end..].trim();
    let separator = body
        .find("=>")
        .ok_or_else(|| anyhow!("/patch separates old and new text with =>"))?;
    let old_text = body[..separator].trim().to_string();
    let new_text = body[separator + 2..].trim().to_string();
    if path.is_empty() || old_text.is_empty() {
        return Err(anyhow!("/patch requires a path and non-empty old text"));
    }
    Ok((path, old_text, new_text))
}

fn parse_model_args(rest: &str) -> Result<TuiLineCommand> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Ok(TuiLineCommand::Model {
            model_id: None,
            route_id: None,
        });
    }
    let mut parts = trimmed.split_whitespace();
    let model_id = parts
        .next()
        .ok_or_else(|| anyhow!("/model accepts [model_id] [route_id|--route route_id]"))?;
    let mut route_id = None;
    while let Some(part) = parts.next() {
        match part {
            "--route" | "--route-id" | "--route_id" => {
                let value = parts
                    .next()
                    .ok_or_else(|| anyhow!("/model --route requires a route id"))?;
                route_id = Some(value.to_string());
            }
            value if route_id.is_none() => {
                route_id = Some(value.to_string());
            }
            _ => {
                return Err(anyhow!(
                    "/model accepts [model_id] [route_id|--route route_id]"
                ));
            }
        }
    }
    Ok(TuiLineCommand::Model {
        model_id: Some(model_id.to_string()),
        route_id,
    })
}

fn parse_restore_args(rest: &str) -> Result<TuiLineCommand> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Ok(TuiLineCommand::RestoreList);
    }

    let mut parts = trimmed.split_whitespace();
    let action = parts
        .next()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| anyhow!("/restore accepts list, preview, or apply"))?;
    match action.as_str() {
        "list" | "snapshots" => {
            if parts.next().is_some() {
                return Err(anyhow!("/restore list does not accept extra arguments"));
            }
            Ok(TuiLineCommand::RestoreList)
        }
        "preview" => {
            let snapshot_id = parts
                .next()
                .ok_or_else(|| anyhow!("/restore preview requires a snapshot id"))?;
            if parts.next().is_some() {
                return Err(anyhow!("/restore preview accepts exactly one snapshot id"));
            }
            Ok(TuiLineCommand::RestorePreview {
                snapshot_id: snapshot_id.to_string(),
            })
        }
        "apply" => {
            let snapshot_id = parts
                .next()
                .ok_or_else(|| anyhow!("/restore apply requires a snapshot id"))?;
            let mut approved = false;
            let mut allow_conflicts = false;
            for flag in parts {
                match flag {
                    "--approve" | "--approved" | "--confirm" | "--confirmed" => {
                        approved = true;
                    }
                    "--allow-conflicts"
                    | "--allow_conflicts"
                    | "--override-conflicts"
                    | "--override_conflicts" => {
                        allow_conflicts = true;
                    }
                    _ => {
                        return Err(anyhow!(
                            "/restore apply unknown flag {flag}; use --approve [--allow-conflicts]"
                        ));
                    }
                }
            }
            if !approved {
                return Err(anyhow!(
                    "/restore apply requires --approve to apply a snapshot"
                ));
            }
            Ok(TuiLineCommand::RestoreApply {
                snapshot_id: snapshot_id.to_string(),
                allow_conflicts,
            })
        }
        _ => Err(anyhow!(
            "/restore accepts list, preview <snapshot_id>, or apply <snapshot_id> --approve"
        )),
    }
}

fn parse_diagnostics_repair_args(rest: &str) -> Result<TuiLineCommand> {
    let trimmed = rest.trim();
    let mut parts = trimmed.split_whitespace();
    let subcommand = parts
        .next()
        .ok_or_else(|| anyhow!("/diagnostics repair requires an action"))?;
    if subcommand.to_ascii_lowercase() != "repair" {
        return Err(anyhow!("/diagnostics repair requires an action"));
    }
    let action_token = parts.next().ok_or_else(|| {
        anyhow!("/diagnostics repair requires retry, preview-restore, apply-restore, or override")
    })?;
    let action = normalize_diagnostics_repair_action(action_token)?;
    let mut decision_id = None;
    let mut message = Vec::new();
    let mut approved = false;
    let mut allow_conflicts = false;
    let mut saw_flag = false;
    while let Some(part) = parts.next() {
        match part {
            "--approve" | "--approved" | "--confirm" | "--confirmed" => {
                approved = true;
                saw_flag = true;
            }
            "--allow-conflicts"
            | "--allow_conflicts"
            | "--override-conflicts"
            | "--override_conflicts" => {
                allow_conflicts = true;
                saw_flag = true;
            }
            "--decision" | "--decision-id" | "--decision_id" => {
                saw_flag = true;
                let value = parts.next().ok_or_else(|| {
                    anyhow!("/diagnostics repair --decision requires a decision id")
                })?;
                decision_id = Some(value.to_string());
            }
            "--message" | "-m" => {
                message.extend(parts.map(ToOwned::to_owned));
                if message.is_empty() {
                    return Err(anyhow!("/diagnostics repair --message requires text"));
                }
                break;
            }
            value if value.starts_with("--") => {
                return Err(anyhow!(
                    "/diagnostics repair unknown flag {value}; use --decision, --message, --approve, or --allow-conflicts"
                ));
            }
            value if decision_id.is_none() && !saw_flag => {
                decision_id = Some(value.to_string());
            }
            value => {
                message.push(value.to_string());
                message.extend(parts.map(ToOwned::to_owned));
                break;
            }
        }
    }
    if action == "restore_apply" && !approved {
        return Err(anyhow!(
            "/diagnostics repair apply-restore requires --approve"
        ));
    }
    Ok(TuiLineCommand::DiagnosticsRepair {
        decision_id: decision_id.unwrap_or_else(|| action.clone()),
        action,
        message: if message.is_empty() {
            None
        } else {
            Some(message.join(" "))
        },
        approved,
        allow_conflicts,
    })
}

fn normalize_diagnostics_repair_action(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', '.'], "_");
    match normalized.as_str() {
        "retry" | "repair" | "repair_retry" => Ok("repair_retry".to_string()),
        "preview" | "preview_restore" | "restore_preview" => Ok("restore_preview".to_string()),
        "apply" | "apply_restore" | "restore_apply" => Ok("restore_apply".to_string()),
        "override" | "operator_override" => Ok("operator_override".to_string()),
        _ => Err(anyhow!(
            "/diagnostics repair accepts retry, preview-restore, apply-restore, or override"
        )),
    }
}

fn parse_job_args(rest: &str) -> Result<TuiLineCommand> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Ok(TuiLineCommand::JobInspect { job_id: None });
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts
        .next()
        .ok_or_else(|| anyhow!("/job accepts [job_id] or cancel <job_id>"))?;
    match first.to_ascii_lowercase().as_str() {
        "cancel" => {
            let job_id = parts
                .next()
                .ok_or_else(|| anyhow!("/job cancel requires a job id"))?;
            if parts.next().is_some() {
                return Err(anyhow!("/job cancel accepts exactly one job id"));
            }
            Ok(TuiLineCommand::JobCancel {
                job_id: job_id.to_string(),
            })
        }
        "inspect" | "show" => {
            let job_id = parts.next().map(ToOwned::to_owned);
            if parts.next().is_some() {
                return Err(anyhow!("/job inspect accepts at most one job id"));
            }
            Ok(TuiLineCommand::JobInspect { job_id })
        }
        _ => {
            if parts.next().is_some() {
                return Err(anyhow!("/job accepts [job_id] or cancel <job_id>"));
            }
            Ok(TuiLineCommand::JobInspect {
                job_id: Some(first.to_string()),
            })
        }
    }
}

fn parse_task_args(rest: &str) -> Result<TuiLineCommand> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Ok(TuiLineCommand::TaskInspect { task_id: None });
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts
        .next()
        .ok_or_else(|| anyhow!("/task accepts [task_id] or cancel <task_id>"))?;
    match first.to_ascii_lowercase().as_str() {
        "cancel" => {
            let task_id = parts
                .next()
                .ok_or_else(|| anyhow!("/task cancel requires a task id"))?;
            if parts.next().is_some() {
                return Err(anyhow!("/task cancel accepts exactly one task id"));
            }
            Ok(TuiLineCommand::TaskCancel {
                task_id: task_id.to_string(),
            })
        }
        "inspect" | "show" => {
            let task_id = parts.next().map(ToOwned::to_owned);
            if parts.next().is_some() {
                return Err(anyhow!("/task inspect accepts at most one task id"));
            }
            Ok(TuiLineCommand::TaskInspect { task_id })
        }
        _ => {
            if parts.next().is_some() {
                return Err(anyhow!("/task accepts [task_id] or cancel <task_id>"));
            }
            Ok(TuiLineCommand::TaskInspect {
                task_id: Some(first.to_string()),
            })
        }
    }
}

fn parse_run_args(rest: &str) -> Result<TuiLineCommand> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Ok(TuiLineCommand::Run { run_id: None });
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts
        .next()
        .ok_or_else(|| anyhow!("/run accepts [run_id], trace, inspect, replay, or cancel"))?;
    match first.to_ascii_lowercase().as_str() {
        "trace" => {
            let run_id = parts.next().map(ToOwned::to_owned);
            if parts.next().is_some() {
                return Err(anyhow!("/run trace accepts at most one run id"));
            }
            Ok(TuiLineCommand::RunTrace { run_id })
        }
        "inspect" => {
            let run_id = parts.next().map(ToOwned::to_owned);
            if parts.next().is_some() {
                return Err(anyhow!("/run inspect accepts at most one run id"));
            }
            Ok(TuiLineCommand::RunInspect { run_id })
        }
        "replay" | "events" => {
            let run_id = parts.next().map(ToOwned::to_owned);
            if parts.next().is_some() {
                return Err(anyhow!("/run replay accepts at most one run id"));
            }
            Ok(TuiLineCommand::RunReplay { run_id })
        }
        "cancel" => {
            let run_id = parts
                .next()
                .ok_or_else(|| anyhow!("/run cancel requires a run id"))?;
            if parts.next().is_some() {
                return Err(anyhow!("/run cancel accepts exactly one run id"));
            }
            Ok(TuiLineCommand::RunCancel {
                run_id: run_id.to_string(),
            })
        }
        "recovery" | "recover" => parse_run_recovery_args(parts.collect()),
        _ => {
            if parts.next().is_some() {
                return Err(anyhow!(
                    "/run accepts [run_id], trace, inspect, replay, cancel, or recovery"
                ));
            }
            Ok(TuiLineCommand::Run {
                run_id: Some(first.to_string()),
            })
        }
    }
}

fn parse_run_recovery_args(args: Vec<&str>) -> Result<TuiLineCommand> {
    let mut tokens = args.into_iter();
    let first = tokens.next();
    let (action, first_value) = match first {
        None => ("request_approval".to_string(), None),
        Some(value) => match normalize_run_recovery_action(value) {
            Some(action) => (action, None),
            None => ("request_approval".to_string(), Some(value.to_string())),
        },
    };
    let remaining = tokens.map(ToOwned::to_owned).collect::<Vec<_>>();
    let mut values = Vec::new();
    if let Some(value) = first_value {
        values.push(value);
    }
    values.extend(remaining);
    if values.len() > 2 {
        return Err(anyhow!(
            "/run recovery accepts [request|approve|reject|retry-approved] [run_id] [approval_id]"
        ));
    }
    let (run_id, approval_id) = match values.as_slice() {
        [] => (None, None),
        [only] if action == "request_approval" => (Some(only.clone()), None),
        [only] if only.starts_with("run_") => (Some(only.clone()), None),
        [only] => (None, Some(only.clone())),
        [run_id, approval_id] => (Some(run_id.clone()), Some(approval_id.clone())),
        _ => unreachable!(),
    };
    Ok(TuiLineCommand::RunRecovery {
        action,
        run_id,
        approval_id,
    })
}

fn normalize_run_recovery_action(value: &str) -> Option<String> {
    match value.to_ascii_lowercase().replace('-', "_").as_str() {
        "request" | "request_approval" | "approval_request" => Some("request_approval".to_string()),
        "approve" | "approved" | "approve_override" | "allow" => {
            Some("approve_override".to_string())
        }
        "reject" | "rejected" | "reject_override" | "deny" => Some("reject_override".to_string()),
        "retry" | "retry_approved" | "approved_retry" => Some("retry_approved".to_string()),
        _ => None,
    }
}

fn parse_approval_decision_args(rest: &str) -> (Option<String>, Option<String>) {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return (None, None);
    }
    let split_at = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let approval_id = trimmed[..split_at].trim();
    let reason = trimmed[split_at..].trim();
    (
        non_empty_string(approval_id),
        if reason.is_empty() {
            None
        } else {
            Some(reason.to_string())
        },
    )
}

struct TuiControlState {
    thread_id: Option<String>,
    current_turn_id: Option<String>,
    last_cursor: Option<String>,
    last_event_id: Option<String>,
    mode_status: Value,
    usage_status: Value,
    approval_rows: Vec<Value>,
    approval_decisions: Vec<Value>,
    workspace_trust_rows: Vec<Value>,
    task_rows: Vec<Value>,
    job_rows: Vec<Value>,
    run_lifecycle_rows: Vec<Value>,
    cost_rows: Vec<Value>,
    context_rows: Vec<Value>,
    coding_tool_rows: Vec<Value>,
    mcp_rows: Vec<Value>,
    memory_rows: Vec<Value>,
    subagent_rows: Vec<Value>,
    command_history: Vec<Value>,
    validation_errors: Vec<Value>,
    sequence: u64,
}

impl TuiControlState {
    fn from_session(session: &TuiInteractiveSession) -> Self {
        let current_turn_id = selected_turn_id_from_values(None, None, &session.thread).ok();
        Self {
            thread_id: thread_id_from_value(&session.thread).ok(),
            current_turn_id: current_turn_id.clone(),
            last_cursor: None,
            last_event_id: None,
            mode_status: tui_mode_status(&session.thread, current_turn_id.as_deref()),
            usage_status: tui_usage_status(
                &session.thread,
                thread_id_from_value(&session.thread).ok().as_deref(),
            ),
            approval_rows: Vec::new(),
            approval_decisions: Vec::new(),
            workspace_trust_rows: Vec::new(),
            task_rows: Vec::new(),
            job_rows: Vec::new(),
            run_lifecycle_rows: Vec::new(),
            cost_rows: Vec::new(),
            context_rows: Vec::new(),
            coding_tool_rows: Vec::new(),
            mcp_rows: Vec::new(),
            memory_rows: Vec::new(),
            subagent_rows: Vec::new(),
            command_history: Vec::new(),
            validation_errors: Vec::new(),
            sequence: 0,
        }
    }

    fn record_command(
        &mut self,
        command: &str,
        raw_input: &str,
        status: &str,
        message: Option<&str>,
        session: &TuiInteractiveSession,
        events: &[Value],
    ) {
        self.update_from_session(session);
        self.update_from_events(events);
        self.sequence += 1;
        self.command_history.push(serde_json::json!({
            "id": format!("tui-command-{}", self.sequence),
            "sequence": self.sequence,
            "command": command,
            "raw_input": raw_input,
            "status": status,
            "message": message,
            "thread_id": self.thread_id.clone(),
            "turn_id": self.current_turn_id.clone(),
            "cursor": self.last_cursor.clone(),
            "event_id": self.last_event_id.clone(),
        }));
    }

    fn record_validation_error(
        &mut self,
        raw_input: &str,
        message: &str,
        session: &TuiInteractiveSession,
    ) {
        self.update_from_session(session);
        self.sequence += 1;
        self.validation_errors.push(serde_json::json!({
            "id": format!("tui-validation-error-{}", self.sequence),
            "sequence": self.sequence,
            "command": raw_command_name(raw_input),
            "raw_input": raw_input,
            "status": "validation_error",
            "message": message,
            "thread_id": self.thread_id.clone(),
            "turn_id": self.current_turn_id.clone(),
            "cursor": self.last_cursor.clone(),
            "event_id": self.last_event_id.clone(),
        }));
    }

    fn update_from_session(&mut self, session: &TuiInteractiveSession) {
        self.thread_id = thread_id_from_value(&session.thread).ok();
        self.current_turn_id = selected_turn_id_from_values(None, None, &session.thread).ok();
        self.mode_status = tui_mode_status(&session.thread, self.current_turn_id.as_deref());
        self.usage_status = tui_usage_status(&session.thread, self.thread_id.as_deref());
    }

    fn set_usage_status(&mut self, usage_status: Value) {
        self.usage_status = usage_status;
    }

    fn update_from_events(&mut self, events: &[Value]) {
        if let Some(event) = events
            .iter()
            .max_by_key(|event| event.pointer("/seq").and_then(Value::as_u64).unwrap_or(0))
        {
            let seq = event.pointer("/seq").and_then(Value::as_u64);
            self.last_event_id = json_path_string(event, "/event_id");
            self.last_cursor = json_path_string(event, "/cursor").or_else(|| {
                let stream = json_path_string(event, "/event_stream_id")?;
                Some(format!("{stream}:{}", seq?))
            });
        }
        self.merge_approval_rows(tui_approval_rows(events, self.thread_id.as_deref()));
        self.merge_approval_decisions(tui_approval_decisions(events, self.thread_id.as_deref()));
        self.merge_workspace_trust_rows(tui_workspace_trust_rows(
            events,
            self.thread_id.as_deref(),
        ));
        if let Some(usage_status) = latest_usage_delta_status(events, self.thread_id.as_deref()) {
            self.usage_status = tui_usage_status(&usage_status, self.thread_id.as_deref());
        }
        self.merge_cost_rows(tui_usage_delta_rows(events, self.thread_id.as_deref()));
        self.merge_context_rows(tui_context_pressure_rows(events, self.thread_id.as_deref()));
        self.merge_coding_tool_rows(tui_coding_tool_rows(events, self.thread_id.as_deref()));
    }

    fn merge_approval_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/approval_id")
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.approval_rows.push(row);
                continue;
            }
            if let Some(existing) = self.approval_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/approval_id")
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.approval_rows.push(row);
            }
        }
    }

    fn merge_approval_decisions(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/event_id")
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty()
                || !self.approval_decisions.iter().any(|existing| {
                    json_path_string(existing, "/event_id")
                        .or_else(|| json_path_string(existing, "/id"))
                        .as_deref()
                        == Some(key.as_str())
                })
            {
                self.approval_decisions.push(row);
            }
        }
    }

    fn merge_workspace_trust_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/warning_id")
                .or_else(|| json_path_string(&row, "/event_id"))
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.workspace_trust_rows.push(row);
                continue;
            }
            if let Some(existing) = self.workspace_trust_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/warning_id")
                    .or_else(|| json_path_string(existing, "/event_id"))
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.workspace_trust_rows.push(row);
            }
        }
    }

    fn merge_job_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/job_id")
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.job_rows.push(row);
                continue;
            }
            if let Some(existing) = self.job_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/job_id")
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.job_rows.push(row);
            }
        }
    }

    fn merge_task_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/task_id")
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.task_rows.push(row);
                continue;
            }
            if let Some(existing) = self.task_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/task_id")
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.task_rows.push(row);
            }
        }
    }

    fn merge_run_lifecycle_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/run_id")
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.run_lifecycle_rows.push(row);
                continue;
            }
            if let Some(existing) = self.run_lifecycle_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/run_id")
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.run_lifecycle_rows.push(row);
            }
        }
    }

    fn merge_cost_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/id")
                .or_else(|| json_path_string(&row, "/thread_id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.cost_rows.push(row);
                continue;
            }
            if let Some(existing) = self.cost_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/id")
                    .or_else(|| json_path_string(existing, "/thread_id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.cost_rows.push(row);
            }
        }
    }

    fn merge_context_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/id")
                .or_else(|| json_path_string(&row, "/workflow_node_id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.context_rows.push(row);
                continue;
            }
            if let Some(existing) = self.context_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/id")
                    .or_else(|| json_path_string(existing, "/workflow_node_id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.context_rows.push(row);
            }
        }
    }

    fn merge_coding_tool_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/event_id")
                .or_else(|| json_path_string(&row, "/tool_call_id"))
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.coding_tool_rows.push(row);
                continue;
            }
            if let Some(existing) = self.coding_tool_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/event_id")
                    .or_else(|| json_path_string(existing, "/tool_call_id"))
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.coding_tool_rows.push(row);
            }
        }
    }

    fn merge_mcp_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/id")
                .or_else(|| json_path_string(&row, "/mcp_server_id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.mcp_rows.push(row);
                continue;
            }
            if let Some(existing) = self.mcp_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/id")
                    .or_else(|| json_path_string(existing, "/mcp_server_id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.mcp_rows.push(row);
            }
        }
    }

    fn merge_memory_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/id")
                .or_else(|| json_path_string(&row, "/memory_record_id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.memory_rows.push(row);
                continue;
            }
            if let Some(existing) = self.memory_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/id")
                    .or_else(|| json_path_string(existing, "/memory_record_id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.memory_rows.push(row);
            }
        }
    }

    fn merge_subagent_rows(&mut self, rows: Vec<Value>) {
        for row in rows {
            let key = json_path_string(&row, "/subagent_id")
                .or_else(|| json_path_string(&row, "/id"))
                .unwrap_or_default();
            if key.is_empty() {
                self.subagent_rows.push(row);
                continue;
            }
            if let Some(existing) = self.subagent_rows.iter_mut().find(|existing| {
                json_path_string(existing, "/subagent_id")
                    .or_else(|| json_path_string(existing, "/id"))
                    .as_deref()
                    == Some(key.as_str())
            }) {
                *existing = row;
            } else {
                self.subagent_rows.push(row);
            }
        }
    }

    fn default_pending_approval_id(&self) -> Option<String> {
        self.approval_rows.iter().find_map(|row| {
            let status = json_path_string(row, "/status")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if status == "pending" || status.contains("waiting") {
                json_path_string(row, "/approval_id")
            } else {
                None
            }
        })
    }

    fn default_job_id(&self) -> Option<String> {
        self.job_rows
            .iter()
            .rev()
            .find_map(|row| json_path_string(row, "/job_id"))
    }

    fn default_task_id(&self) -> Option<String> {
        self.task_rows
            .iter()
            .rev()
            .find_map(|row| json_path_string(row, "/task_id"))
    }

    fn default_run_id(&self) -> Option<String> {
        self.run_lifecycle_rows
            .iter()
            .rev()
            .find_map(|row| json_path_string(row, "/run_id"))
            .or_else(|| {
                self.job_rows
                    .iter()
                    .rev()
                    .find_map(|row| json_path_string(row, "/run_id"))
            })
    }

    fn default_subagent_id(&self) -> Option<String> {
        self.subagent_rows
            .iter()
            .rev()
            .find_map(|row| json_path_string(row, "/subagent_id"))
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "schema_version": TUI_CONTROL_STATE_SCHEMA_VERSION,
            "surface": "tui",
            "thread_id": self.thread_id.clone(),
            "current_turn_id": self.current_turn_id.clone(),
            "last_cursor": self.last_cursor.clone(),
            "last_event_id": self.last_event_id.clone(),
            "mode_status": self.mode_status.clone(),
            "usage_status": self.usage_status.clone(),
            "approval_rows": self.approval_rows.clone(),
            "approval_decisions": self.approval_decisions.clone(),
            "workspace_trust_rows": self.workspace_trust_rows.clone(),
            "task_rows": self.task_rows.clone(),
            "job_rows": self.job_rows.clone(),
            "run_lifecycle_rows": self.run_lifecycle_rows.clone(),
            "cost_rows": self.cost_rows.clone(),
            "context_rows": self.context_rows.clone(),
            "coding_tool_rows": self.coding_tool_rows.clone(),
            "mcp_rows": self.mcp_rows.clone(),
            "memory_rows": self.memory_rows.clone(),
            "subagent_rows": self.subagent_rows.clone(),
            "command_history": self.command_history.clone(),
            "validation_errors": self.validation_errors.clone(),
        })
    }
}

fn print_tui_control_state(control_state: &TuiControlState) -> Result<()> {
    println!(
        "tui_control_state={}",
        serde_json::to_string(&control_state.to_json())?
    );
    Ok(())
}

fn raw_command_name(raw_input: &str) -> Option<String> {
    let trimmed = raw_input.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let body = &trimmed[1..];
    let command_end = body.find(char::is_whitespace).unwrap_or(body.len());
    let command = body[..command_end].trim();
    if command.is_empty() {
        None
    } else {
        Some(command.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_line_mode_slash_commands() {
        assert_eq!(parse_tui_line_command("").unwrap(), TuiLineCommand::Noop);
        assert_eq!(
            parse_tui_line_command("/events 12").unwrap(),
            TuiLineCommand::Events {
                since_seq: Some(12)
            }
        );
        assert_eq!(
            parse_tui_line_command("/approvals").unwrap(),
            TuiLineCommand::Approvals
        );
        assert_eq!(
            parse_tui_line_command("/approve approval-live looks good").unwrap(),
            TuiLineCommand::Approve {
                approval_id: Some("approval-live".to_string()),
                reason: Some("looks good".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/reject").unwrap(),
            TuiLineCommand::Reject {
                approval_id: None,
                reason: None
            }
        );
        assert_eq!(
            parse_tui_line_command("/interrupt pause live validation").unwrap(),
            TuiLineCommand::Interrupt {
                reason: Some("pause live validation".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/steer focus on receipts").unwrap(),
            TuiLineCommand::Steer {
                guidance: "focus on receipts".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/mode yolo").unwrap(),
            TuiLineCommand::Mode {
                mode: Some("yolo".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/model auto --route route.native-local").unwrap(),
            TuiLineCommand::Model {
                model_id: Some("auto".to_string()),
                route_id: Some("route.native-local".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/thinking high").unwrap(),
            TuiLineCommand::Thinking {
                reasoning_effort: Some("high".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/cost").unwrap(),
            TuiLineCommand::Cost
        );
        assert_eq!(
            parse_tui_line_command("/usage").unwrap(),
            TuiLineCommand::Cost
        );
        assert_eq!(
            parse_tui_line_command("/context").unwrap(),
            TuiLineCommand::Context
        );
        assert_eq!(
            parse_tui_line_command("/browser-discovery").unwrap(),
            TuiLineCommand::BrowserDiscovery
        );
        assert_eq!(
            parse_tui_line_command("/computer-use browser-discovery").unwrap(),
            TuiLineCommand::BrowserDiscovery
        );
        assert_eq!(
            parse_tui_line_command(
                "/computer-use resume --lease-id lease_controlled_relaunch --handoff-ref handoff_controlled_relaunch --resume-observation-ref observation_after_relaunch --cdp-endpoint-url http://127.0.0.1:9222"
            )
            .unwrap(),
            TuiLineCommand::ComputerUseControl {
                action: "resume".to_string(),
                lease_id: "lease_controlled_relaunch".to_string(),
                handoff_ref: Some("handoff_controlled_relaunch".to_string()),
                reason: None,
                resume_observation_ref: Some("observation_after_relaunch".to_string()),
                cdp_endpoint_url: Some("http://127.0.0.1:9222".to_string()),
            }
        );
        assert_eq!(
            parse_tui_line_command("/native-browser inspect https://example.com").unwrap(),
            TuiLineCommand::NativeBrowser {
                prompt: Some("inspect https://example.com".to_string()),
                session_mode: None,
                approval_ref: None,
                controlled_relaunch_approval_ref: None,
                controlled_relaunch_executable_path: None,
                controlled_relaunch_headless: false,
                target_ref: None,
                selector: None,
                text: None,
                key: None,
                scroll_x: None,
                scroll_y: None,
                file_path: None,
                cdp_endpoint_url: None,
                cdp_websocket_url: None,
                cdp_timeout_ms: None,
            }
        );
        assert_eq!(
            parse_tui_line_command("/computer-use native-browser https://example.com").unwrap(),
            TuiLineCommand::NativeBrowser {
                prompt: Some("https://example.com".to_string()),
                session_mode: None,
                approval_ref: None,
                controlled_relaunch_approval_ref: None,
                controlled_relaunch_executable_path: None,
                controlled_relaunch_headless: false,
                target_ref: None,
                selector: None,
                text: None,
                key: None,
                scroll_x: None,
                scroll_y: None,
                file_path: None,
                cdp_endpoint_url: None,
                cdp_websocket_url: None,
                cdp_timeout_ms: None,
            }
        );
        assert_eq!(
            parse_tui_line_command(
                "/visual-gui inspect local canvas --session-mode foreground_desktop --screenshot-ref artifact:visual:screenshot --som-ref artifact:visual:som --ax-ref artifact:visual:ax --app-name CanvasApp --window-title CanvasWindow --coordinate-space-id screen-visual-1 --viewport-width 1200 --viewport-height 800"
            )
            .unwrap(),
            TuiLineCommand::VisualGui {
                prompt: Some("inspect local canvas".to_string()),
                session_mode: Some("foreground_desktop".to_string()),
                screenshot_ref: Some("artifact:visual:screenshot".to_string()),
                screenshot_path: None,
                som_ref: Some("artifact:visual:som".to_string()),
                som_path: None,
                ax_ref: Some("artifact:visual:ax".to_string()),
                ax_path: None,
                app_name: Some("CanvasApp".to_string()),
                window_title: Some("CanvasWindow".to_string()),
                coordinate_space_id: Some("screen-visual-1".to_string()),
                viewport_width: Some(1200),
                viewport_height: Some(800),
            }
        );
        assert_eq!(
            parse_tui_line_command("/computer-use visual-gui inspect canvas --screenshot-ref artifact:visual:screenshot").unwrap(),
            TuiLineCommand::VisualGui {
                prompt: Some("inspect canvas".to_string()),
                session_mode: None,
                screenshot_ref: Some("artifact:visual:screenshot".to_string()),
                screenshot_path: None,
                som_ref: None,
                som_path: None,
                ax_ref: None,
                ax_path: None,
                app_name: None,
                window_title: None,
                coordinate_space_id: None,
                viewport_width: None,
                viewport_height: None,
            }
        );
        assert_eq!(
            parse_tui_line_command("/computer-use visual-gui inspect canvas --screenshot-path /tmp/visual.png --som-path /tmp/som.json --ax-path /tmp/ax.json").unwrap(),
            TuiLineCommand::VisualGui {
                prompt: Some("inspect canvas".to_string()),
                session_mode: None,
                screenshot_ref: None,
                screenshot_path: Some("/tmp/visual.png".to_string()),
                som_ref: None,
                som_path: Some("/tmp/som.json".to_string()),
                ax_ref: None,
                ax_path: Some("/tmp/ax.json".to_string()),
                app_name: None,
                window_title: None,
                coordinate_space_id: None,
                viewport_width: None,
                viewport_height: None,
            }
        );
        assert_eq!(
            parse_tui_line_command(
                "/native-browser click submit --session-mode controlled_relaunch --approval-ref approval-browser-click --controlled-relaunch-approval-ref approval-controlled-browser-launch --controlled-relaunch-executable-path /usr/bin/chromium --controlled-relaunch-headless --selector #submit --target-ref #submit --text hello --key Enter --scroll-y 420 --file-path /tmp/upload.txt --cdp-endpoint-url http://127.0.0.1:9222 --cdp-timeout-ms 5000"
            )
            .unwrap(),
            TuiLineCommand::NativeBrowser {
                prompt: Some("click submit".to_string()),
                session_mode: Some("controlled_relaunch".to_string()),
                approval_ref: Some("approval-browser-click".to_string()),
                controlled_relaunch_approval_ref: Some(
                    "approval-controlled-browser-launch".to_string()
                ),
                controlled_relaunch_executable_path: Some("/usr/bin/chromium".to_string()),
                controlled_relaunch_headless: true,
                target_ref: Some("#submit".to_string()),
                selector: Some("#submit".to_string()),
                text: Some("hello".to_string()),
                key: Some("Enter".to_string()),
                scroll_x: None,
                scroll_y: Some(420),
                file_path: Some("/tmp/upload.txt".to_string()),
                cdp_endpoint_url: Some("http://127.0.0.1:9222".to_string()),
                cdp_websocket_url: None,
                cdp_timeout_ms: Some(5000),
            }
        );
        assert_eq!(
            parse_tui_line_command("/mcp tools").unwrap(),
            TuiLineCommand::Mcp {
                action: Some("tools".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/mcp search query --source-mode global").unwrap(),
            TuiLineCommand::Mcp {
                action: Some("search query --source-mode global".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/mcp fetch mcp.search/query --source-mode workspace").unwrap(),
            TuiLineCommand::Mcp {
                action: Some("fetch mcp.search/query --source-mode workspace".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/memory validate").unwrap(),
            TuiLineCommand::Memory {
                action: Some("validate".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/subagents").unwrap(),
            TuiLineCommand::Subagent { action: None }
        );
        assert_eq!(
            parse_tui_line_command(
                "/subagent spawn explore Inspect daemon evidence --tool-pack coding --route route.native-local"
            )
            .unwrap(),
            TuiLineCommand::Subagent {
                action: Some(
                    "spawn explore Inspect daemon evidence --tool-pack coding --route route.native-local"
                        .to_string()
                )
            }
        );
        assert_eq!(
            parse_tui_line_command("/subagent input Follow up with route evidence").unwrap(),
            TuiLineCommand::Subagent {
                action: Some("input Follow up with route evidence".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/status").unwrap(),
            TuiLineCommand::WorkspaceStatus
        );
        assert_eq!(
            parse_tui_line_command("/diff README.md").unwrap(),
            TuiLineCommand::Diff {
                path: Some("README.md".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/inspect README.md").unwrap(),
            TuiLineCommand::Inspect {
                path: "README.md".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/patch README.md before => after").unwrap(),
            TuiLineCommand::ApplyPatch {
                path: "README.md".to_string(),
                old_text: "before".to_string(),
                new_text: "after".to_string(),
                dry_run: false,
            }
        );
        assert_eq!(
            parse_tui_line_command("/patch-dry-run README.md before => after").unwrap(),
            TuiLineCommand::ApplyPatch {
                path: "README.md".to_string(),
                old_text: "before".to_string(),
                new_text: "after".to_string(),
                dry_run: true,
            }
        );
        assert_eq!(
            parse_tui_line_command("/test sample.test.mjs").unwrap(),
            TuiLineCommand::Test {
                path: Some("sample.test.mjs".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/diagnostics src/main.mjs").unwrap(),
            TuiLineCommand::Diagnostics {
                path: "src/main.mjs".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/diagnostics repair retry").unwrap(),
            TuiLineCommand::DiagnosticsRepair {
                action: "repair_retry".to_string(),
                decision_id: "repair_retry".to_string(),
                message: None,
                approved: false,
                allow_conflicts: false,
            }
        );
        assert_eq!(
            parse_tui_line_command("/diagnostics repair preview-restore restore_preview").unwrap(),
            TuiLineCommand::DiagnosticsRepair {
                action: "restore_preview".to_string(),
                decision_id: "restore_preview".to_string(),
                message: None,
                approved: false,
                allow_conflicts: false,
            }
        );
        assert_eq!(
            parse_tui_line_command("/diagnostics repair apply-restore --approve --allow-conflicts")
                .unwrap(),
            TuiLineCommand::DiagnosticsRepair {
                action: "restore_apply".to_string(),
                decision_id: "restore_apply".to_string(),
                message: None,
                approved: true,
                allow_conflicts: true,
            }
        );
        assert_eq!(
            parse_tui_line_command(
                "/diagnostics repair override operator_override --approve Continue anyway"
            )
            .unwrap(),
            TuiLineCommand::DiagnosticsRepair {
                action: "operator_override".to_string(),
                decision_id: "operator_override".to_string(),
                message: Some("Continue anyway".to_string()),
                approved: true,
                allow_conflicts: false,
            }
        );
        assert_eq!(
            parse_tui_line_command(
                "/diagnostics repair retry --message Try a focused diagnostics repair"
            )
            .unwrap(),
            TuiLineCommand::DiagnosticsRepair {
                action: "repair_retry".to_string(),
                decision_id: "repair_retry".to_string(),
                message: Some("Try a focused diagnostics repair".to_string()),
                approved: false,
                allow_conflicts: false,
            }
        );
        assert_eq!(
            parse_tui_line_command("/artifact artifact_coding_tool_output").unwrap(),
            TuiLineCommand::ArtifactRead {
                artifact_id: "artifact_coding_tool_output".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/retrieve coding_tool_abc123").unwrap(),
            TuiLineCommand::RetrieveResult {
                target: "coding_tool_abc123".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/tasks").unwrap(),
            TuiLineCommand::Tasks
        );
        assert_eq!(
            parse_tui_line_command("/task").unwrap(),
            TuiLineCommand::TaskInspect { task_id: None }
        );
        assert_eq!(
            parse_tui_line_command("/task inspect task_run_live").unwrap(),
            TuiLineCommand::TaskInspect {
                task_id: Some("task_run_live".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/task cancel task_run_live").unwrap(),
            TuiLineCommand::TaskCancel {
                task_id: "task_run_live".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/jobs").unwrap(),
            TuiLineCommand::Jobs
        );
        assert_eq!(
            parse_tui_line_command("/runs").unwrap(),
            TuiLineCommand::Jobs
        );
        assert_eq!(
            parse_tui_line_command("/job").unwrap(),
            TuiLineCommand::JobInspect { job_id: None }
        );
        assert_eq!(
            parse_tui_line_command("/job inspect job_run_live").unwrap(),
            TuiLineCommand::JobInspect {
                job_id: Some("job_run_live".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/job cancel job_run_live").unwrap(),
            TuiLineCommand::JobCancel {
                job_id: "job_run_live".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/run run_live").unwrap(),
            TuiLineCommand::Run {
                run_id: Some("run_live".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/run trace").unwrap(),
            TuiLineCommand::RunTrace { run_id: None }
        );
        assert_eq!(
            parse_tui_line_command("/run inspect run_live").unwrap(),
            TuiLineCommand::RunInspect {
                run_id: Some("run_live".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/run replay run_live").unwrap(),
            TuiLineCommand::RunReplay {
                run_id: Some("run_live".to_string())
            }
        );
        assert_eq!(
            parse_tui_line_command("/run cancel run_live").unwrap(),
            TuiLineCommand::RunCancel {
                run_id: "run_live".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/run recovery request run_live approval_budget_live").unwrap(),
            TuiLineCommand::RunRecovery {
                action: "request_approval".to_string(),
                run_id: Some("run_live".to_string()),
                approval_id: Some("approval_budget_live".to_string()),
            }
        );
        assert_eq!(
            parse_tui_line_command("/run recovery approve approval_budget_live").unwrap(),
            TuiLineCommand::RunRecovery {
                action: "approve_override".to_string(),
                run_id: None,
                approval_id: Some("approval_budget_live".to_string()),
            }
        );
        assert_eq!(
            parse_tui_line_command("/run recovery retry-approved run_live approval_budget_live")
                .unwrap(),
            TuiLineCommand::RunRecovery {
                action: "retry_approved".to_string(),
                run_id: Some("run_live".to_string()),
                approval_id: Some("approval_budget_live".to_string()),
            }
        );
        assert_eq!(
            parse_tui_line_command("/restore").unwrap(),
            TuiLineCommand::RestoreList
        );
        assert_eq!(
            parse_tui_line_command("/restore list").unwrap(),
            TuiLineCommand::RestoreList
        );
        assert_eq!(
            parse_tui_line_command("/restore preview workspace_snapshot_abc123").unwrap(),
            TuiLineCommand::RestorePreview {
                snapshot_id: "workspace_snapshot_abc123".to_string()
            }
        );
        assert_eq!(
            parse_tui_line_command("/restore apply workspace_snapshot_abc123 --approve").unwrap(),
            TuiLineCommand::RestoreApply {
                snapshot_id: "workspace_snapshot_abc123".to_string(),
                allow_conflicts: false,
            }
        );
        assert_eq!(
            parse_tui_line_command(
                "/restore apply workspace_snapshot_abc123 --approve --allow-conflicts"
            )
            .unwrap(),
            TuiLineCommand::RestoreApply {
                snapshot_id: "workspace_snapshot_abc123".to_string(),
                allow_conflicts: true,
            }
        );
        assert_eq!(
            parse_tui_line_command("/quit").unwrap(),
            TuiLineCommand::Quit
        );
    }

    #[test]
    fn rejects_unknown_or_incomplete_line_mode_commands() {
        assert!(parse_tui_line_command("hello").is_err());
        assert!(parse_tui_line_command("/steer").is_err());
        assert!(parse_tui_line_command("/inspect").is_err());
        assert!(parse_tui_line_command("/patch README.md before after").is_err());
        assert!(parse_tui_line_command("/events latest").is_err());
        assert!(parse_tui_line_command("/model auto --route").is_err());
        assert!(parse_tui_line_command("/diagnostics repair").is_err());
        assert!(parse_tui_line_command("/diagnostics repair unknown").is_err());
        assert!(parse_tui_line_command("/diagnostics repair apply-restore").is_err());
        assert!(parse_tui_line_command("/tasks extra").is_err());
        assert!(parse_tui_line_command("/jobs extra").is_err());
        assert!(parse_tui_line_command("/cost extra").is_err());
        assert!(parse_tui_line_command("/context extra").is_err());
        assert!(parse_tui_line_command("/task cancel").is_err());
        assert!(parse_tui_line_command("/task cancel task extra").is_err());
        assert!(parse_tui_line_command("/job cancel").is_err());
        assert!(parse_tui_line_command("/job cancel job extra").is_err());
        assert!(parse_tui_line_command("/run cancel").is_err());
        assert!(parse_tui_line_command("/run trace run extra").is_err());
        assert!(parse_tui_line_command("/restore preview").is_err());
        assert!(parse_tui_line_command("/restore apply workspace_snapshot_abc123").is_err());
        assert!(parse_tui_line_command(
            "/restore apply workspace_snapshot_abc123 --approve --unknown"
        )
        .is_err());
        assert!(parse_tui_line_command("/unknown").is_err());
    }

    #[test]
    fn parses_subagent_line_mode_options() {
        let (positionals, options) = parse_subagent_option_tokens(&[
            "explore",
            "Inspect",
            "runtime",
            "--tool-pack",
            "coding",
            "--route=route.native-local",
            "--max-concurrency",
            "2",
            "--output-contract",
            "SUMMARY,EVIDENCE,RECEIPTS",
            "--merge-policy=manual_review",
            "--cancel-inheritance",
            "isolate",
            "--workflow-node",
            "runtime.subagent.spawn.explore",
        ])
        .unwrap();
        assert_eq!(positionals, vec!["explore", "Inspect", "runtime"]);
        assert_eq!(options.tool_pack.as_deref(), Some("coding"));
        assert_eq!(
            options.model_route_id.as_deref(),
            Some("route.native-local")
        );
        assert_eq!(options.max_concurrency, Some(2));
        assert_eq!(
            options.output_contract,
            vec!["SUMMARY", "EVIDENCE", "RECEIPTS"]
        );
        assert_eq!(options.merge_policy.as_deref(), Some("manual_review"));
        assert_eq!(options.cancellation_inheritance.as_deref(), Some("isolate"));
        assert_eq!(
            options.workflow_node_id.as_deref(),
            Some("runtime.subagent.spawn.explore")
        );
    }

    #[test]
    fn line_mode_control_state_records_history_cursor_and_validation_errors() {
        let session = TuiInteractiveSession {
            endpoint: "http://127.0.0.1:8765".to_string(),
            token: None,
            thread: serde_json::json!({
                "thread_id": "thread_live",
                "latest_turn_id": "turn_live",
                "mode": "agent",
                "approval_mode": "suggest",
                "trust_profile": "local_private",
            }),
            next_since_seq: Some(0),
            follow: false,
        };
        let mut state = TuiControlState::from_session(&session);
        state.record_command(
            "events",
            "/events 0",
            "applied",
            Some("events replayed"),
            &session,
            &[
                serde_json::json!({
                    "event_id": "event_live",
                    "event_stream_id": "events_thread_live",
                    "seq": 8,
                }),
                serde_json::json!({
                    "event_id": "event_approval",
                    "event_stream_id": "events_thread_live",
                    "seq": 9,
                    "event_kind": "approval.required",
                    "source_event_kind": "KernelEvent::ApprovalRequired",
                    "status": "waiting_for_approval",
                    "approval_id": "approval_live",
                    "workflow_node_id": "runtime.approval.approval_live",
                }),
                serde_json::json!({
                    "event_id": "event_coding_budget_blocked",
                    "event_stream_id": "events_thread_live",
                    "seq": 10,
                    "thread_id": "thread_live",
                    "turn_id": "turn_live",
                    "event_kind": "policy.blocked",
                    "source_event_kind": "CodingTool.FileApplyPatch",
                    "status": "blocked",
                    "component_kind": "coding_tool",
                    "workflow_graph_id": "workflow.react-flow.coding-tool-summary-budget",
                    "workflow_node_id": "workflow.coding.file.apply_patch.summary-budget",
                    "tool_call_id": "coding_tool_summary_budget_blocked",
                    "payload_summary": {
                        "tool_name": "file.apply_patch",
                        "tool_call_id": "coding_tool_summary_budget_blocked",
                        "budget_status": "exceeded",
                        "context_budget_status": "blocked",
                        "result_summary": {
                            "status": "blocked",
                            "reason": "coding_tool_budget_exceeded",
                        },
                        "context_budget": {
                            "status": "blocked",
                            "mode": "block",
                            "policy_decision_id": "policy_context_budget_thread_budget_blocked",
                            "violations": [
                                { "id": "total_tokens", "severity": "violation", "actual": 720, "limit": 100 },
                            ],
                            "usage_summary": {
                                "total_tokens": 720,
                                "estimated_cost_usd": 0.0042,
                                "context_pressure": 0.72,
                            },
                        },
                    },
                }),
            ],
        );
        let jobs = vec![serde_json::json!({
            "jobId": "job_run_live",
            "taskId": "task_live",
            "runId": "run_live",
            "threadId": "thread_live",
            "turnId": "turn_live",
            "status": "completed",
            "lifecycle": ["queued", "started", "completed"],
            "progress": { "percent": 100 },
            "workflowNodeId": "runtime.runtime-job",
            "cancelable": true,
        })];
        state.merge_job_rows(tui_job_rows(&jobs, Some("thread_live")));
        state.merge_run_lifecycle_rows(tui_run_lifecycle_rows(&jobs, Some("thread_live")));
        state.merge_subagent_rows(vec![serde_json::json!({
            "id": "tui-subagent-agent_live",
            "row_kind": "subagent",
            "subagent_id": "agent_live",
            "subagent_role": "explore",
            "status": "completed",
            "workflow_node_id": "runtime.subagent.spawn.explore",
        })]);
        state.record_validation_error("/steer", "/steer requires guidance text", &session);
        let json = state.to_json();

        assert_eq!(json["schema_version"], TUI_CONTROL_STATE_SCHEMA_VERSION);
        assert_eq!(json["thread_id"], "thread_live");
        assert_eq!(json["current_turn_id"], "turn_live");
        assert_eq!(json["last_cursor"], "events_thread_live:10");
        assert_eq!(json["last_event_id"], "event_coding_budget_blocked");
        assert_eq!(json["mode_status"]["approval_mode"], "suggest");
        assert_eq!(json["approval_rows"][0]["approval_id"], "approval_live");
        assert_eq!(
            json["coding_tool_rows"][0]["row_kind"],
            "coding_tool_budget"
        );
        assert_eq!(
            json["coding_tool_rows"][0]["tool_call_id"],
            "coding_tool_summary_budget_blocked"
        );
        assert_eq!(json["job_rows"][0]["job_id"], "job_run_live");
        assert_eq!(json["job_rows"][0]["run_id"], "run_live");
        assert_eq!(json["run_lifecycle_rows"][0]["run_id"], "run_live");
        assert_eq!(json["subagent_rows"][0]["subagent_id"], "agent_live");
        assert_eq!(
            json["run_lifecycle_rows"][0]["routes"]["trace"],
            "/v1/runs/run_live/trace"
        );
        assert_eq!(json["command_history"][0]["command"], "events");
        assert_eq!(
            json["validation_errors"][0]["message"],
            "/steer requires guidance text"
        );
    }
}
