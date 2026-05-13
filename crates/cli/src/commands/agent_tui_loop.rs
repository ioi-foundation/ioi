// Path: crates/cli/src/commands/agent_tui_loop.rs

use super::agent_event_stream::{format_runtime_event_line, json_path_string};
use super::agent_tui::{
    add_tui_mcp_server, apply_tui_workspace_restore, cancel_tui_job, cancel_tui_run,
    decide_tui_approval, delete_tui_memory, edit_tui_memory, fetch_tui_event_batch, fetch_tui_job,
    fetch_tui_mcp_tool, fetch_tui_run, fetch_tui_run_trace, fetch_tui_thread, import_tui_mcp,
    inspect_tui_mcp_status, inspect_tui_memory_path, inspect_tui_memory_policy,
    inspect_tui_memory_status, inspect_tui_run, interrupt_tui_turn, invoke_tui_coding_tool,
    invoke_tui_mcp_tool, latest_event_seq, list_tui_jobs_for_thread, list_tui_memory_records,
    list_tui_workspace_snapshots, preview_tui_workspace_restore, remember_tui_memory,
    remove_tui_mcp_server, replay_tui_run_events, resume_tui_thread, search_tui_mcp_tools,
    selected_run_id_from_thread, selected_turn_id_from_values, set_tui_mcp_server_enabled,
    steer_tui_turn, thread_id_from_value, tui_approval_decisions, tui_approval_rows, tui_job_rows,
    tui_mcp_rows, tui_memory_rows, tui_mode_status, tui_run_lifecycle_rows,
    update_tui_memory_policy, update_tui_thread_mode, update_tui_thread_model,
    update_tui_thread_thinking, validate_tui_mcp, validate_tui_memory,
};
use anyhow::{anyhow, Result};
use serde_json::Value;
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
    Mcp {
        action: Option<String>,
    },
    Memory {
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
    ArtifactRead {
        artifact_id: String,
    },
    RetrieveResult {
        target: String,
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
        "mcp" => Ok(TuiLineCommand::Mcp {
            action: non_empty_string(rest),
        }),
        "memory" => Ok(TuiLineCommand::Memory {
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
    Ok(batch.events)
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
        _ => "tool",
    }
}

fn print_tui_help() {
    println!("Line-mode commands: /resume /events [since_seq] /mode [plan|agent|yolo] /model [model_id] [route_id|--route route_id] /thinking [low|medium|high|xhigh] /mcp [status|tools|servers|search <query>|fetch <tool_id>|validate|enable <server_id>|disable <server_id>|invoke <server_id> <tool_name> [json]] [--source-mode workspace|global|workspace_and_global] /memory [status|show|policy|path|validate|enable|disable|remember <text>|edit <memory_id> <text>|delete <memory_id>] /approvals /approve [approval_id] [reason] /reject [approval_id] [reason] /interrupt [reason] /steer <guidance> /status /diff [path] /inspect <path> /patch <path> <old> => <new> /patch-dry-run <path> <old> => <new> /test [path] /diagnostics <path> /artifact <artifact_id> /retrieve <tool_call_id_or_artifact_id> /jobs /job [inspect|cancel] [job_id] /run [run_id|trace|inspect|replay|cancel] [run_id] /restore [list|preview <snapshot_id>|apply <snapshot_id> --approve] /quit");
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
        _ => {
            if parts.next().is_some() {
                return Err(anyhow!(
                    "/run accepts [run_id], trace, inspect, replay, or cancel"
                ));
            }
            Ok(TuiLineCommand::Run {
                run_id: Some(first.to_string()),
            })
        }
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
    approval_rows: Vec<Value>,
    approval_decisions: Vec<Value>,
    job_rows: Vec<Value>,
    run_lifecycle_rows: Vec<Value>,
    mcp_rows: Vec<Value>,
    memory_rows: Vec<Value>,
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
            approval_rows: Vec::new(),
            approval_decisions: Vec::new(),
            job_rows: Vec::new(),
            run_lifecycle_rows: Vec::new(),
            mcp_rows: Vec::new(),
            memory_rows: Vec::new(),
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

    fn to_json(&self) -> Value {
        serde_json::json!({
            "schema_version": TUI_CONTROL_STATE_SCHEMA_VERSION,
            "surface": "tui",
            "thread_id": self.thread_id.clone(),
            "current_turn_id": self.current_turn_id.clone(),
            "last_cursor": self.last_cursor.clone(),
            "last_event_id": self.last_event_id.clone(),
            "mode_status": self.mode_status.clone(),
            "approval_rows": self.approval_rows.clone(),
            "approval_decisions": self.approval_decisions.clone(),
            "job_rows": self.job_rows.clone(),
            "run_lifecycle_rows": self.run_lifecycle_rows.clone(),
            "mcp_rows": self.mcp_rows.clone(),
            "memory_rows": self.memory_rows.clone(),
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
        assert!(parse_tui_line_command("/jobs extra").is_err());
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
        state.record_validation_error("/steer", "/steer requires guidance text", &session);
        let json = state.to_json();

        assert_eq!(json["schema_version"], TUI_CONTROL_STATE_SCHEMA_VERSION);
        assert_eq!(json["thread_id"], "thread_live");
        assert_eq!(json["current_turn_id"], "turn_live");
        assert_eq!(json["last_cursor"], "events_thread_live:9");
        assert_eq!(json["last_event_id"], "event_approval");
        assert_eq!(json["mode_status"]["approval_mode"], "suggest");
        assert_eq!(json["approval_rows"][0]["approval_id"], "approval_live");
        assert_eq!(json["job_rows"][0]["job_id"], "job_run_live");
        assert_eq!(json["job_rows"][0]["run_id"], "run_live");
        assert_eq!(json["run_lifecycle_rows"][0]["run_id"], "run_live");
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
