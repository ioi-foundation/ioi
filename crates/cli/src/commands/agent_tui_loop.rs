// Path: crates/cli/src/commands/agent_tui_loop.rs

use super::agent_event_stream::{format_runtime_event_line, json_path_string};
use super::agent_tui::{
    decide_tui_approval, fetch_tui_event_batch, fetch_tui_thread, interrupt_tui_turn,
    invoke_tui_coding_tool, latest_event_seq, resume_tui_thread, selected_turn_id_from_values,
    steer_tui_turn, thread_id_from_value, tui_approval_decisions, tui_approval_rows,
    tui_mode_status,
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

fn coding_tool_line_command(tool_id: &str) -> &'static str {
    match tool_id {
        "workspace.status" => "status",
        "git.diff" => "diff",
        "file.inspect" => "inspect",
        "file.apply_patch" => "patch",
        "test.run" => "test",
        _ => "tool",
    }
}

fn print_tui_help() {
    println!("Line-mode commands: /resume /events [since_seq] /approvals /approve [approval_id] [reason] /reject [approval_id] [reason] /interrupt [reason] /steer <guidance> /status /diff [path] /inspect <path> /patch <path> <old> => <new> /patch-dry-run <path> <old> => <new> /test [path] /quit");
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
        state.record_validation_error("/steer", "/steer requires guidance text", &session);
        let json = state.to_json();

        assert_eq!(json["schema_version"], TUI_CONTROL_STATE_SCHEMA_VERSION);
        assert_eq!(json["thread_id"], "thread_live");
        assert_eq!(json["current_turn_id"], "turn_live");
        assert_eq!(json["last_cursor"], "events_thread_live:9");
        assert_eq!(json["last_event_id"], "event_approval");
        assert_eq!(json["mode_status"]["approval_mode"], "suggest");
        assert_eq!(json["approval_rows"][0]["approval_id"], "approval_live");
        assert_eq!(json["command_history"][0]["command"], "events");
        assert_eq!(
            json["validation_errors"][0]["message"],
            "/steer requires guidance text"
        );
    }
}
