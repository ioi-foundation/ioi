// Path: crates/cli/src/commands/agent_tui_loop.rs

use super::agent_event_stream::{format_runtime_event_line, json_path_string};
use super::agent_tui::{
    fetch_tui_event_batch, fetch_tui_thread, interrupt_tui_turn, latest_event_seq,
    resume_tui_thread, selected_turn_id_from_values, steer_tui_turn, thread_id_from_value,
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
    Events { since_seq: Option<u64> },
    Interrupt { reason: Option<String> },
    Steer { guidance: String },
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
        "interrupt" => Ok(TuiLineCommand::Interrupt {
            reason: non_empty_string(rest),
        }),
        "steer" => {
            let guidance =
                non_empty_string(rest).ok_or_else(|| anyhow!("/steer requires guidance text"))?;
            Ok(TuiLineCommand::Steer { guidance })
        }
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

fn print_tui_help() {
    println!("Line-mode commands: /resume /events [since_seq] /interrupt [reason] /steer <guidance> /quit");
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

struct TuiControlState {
    thread_id: Option<String>,
    current_turn_id: Option<String>,
    last_cursor: Option<String>,
    last_event_id: Option<String>,
    command_history: Vec<Value>,
    validation_errors: Vec<Value>,
    sequence: u64,
}

impl TuiControlState {
    fn from_session(session: &TuiInteractiveSession) -> Self {
        Self {
            thread_id: thread_id_from_value(&session.thread).ok(),
            current_turn_id: selected_turn_id_from_values(None, None, &session.thread).ok(),
            last_cursor: None,
            last_event_id: None,
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
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "schema_version": TUI_CONTROL_STATE_SCHEMA_VERSION,
            "surface": "tui",
            "thread_id": self.thread_id.clone(),
            "current_turn_id": self.current_turn_id.clone(),
            "last_cursor": self.last_cursor.clone(),
            "last_event_id": self.last_event_id.clone(),
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
            parse_tui_line_command("/quit").unwrap(),
            TuiLineCommand::Quit
        );
    }

    #[test]
    fn rejects_unknown_or_incomplete_line_mode_commands() {
        assert!(parse_tui_line_command("hello").is_err());
        assert!(parse_tui_line_command("/steer").is_err());
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
            &[serde_json::json!({
                "event_id": "event_live",
                "event_stream_id": "events_thread_live",
                "seq": 8,
            })],
        );
        state.record_validation_error("/steer", "/steer requires guidance text", &session);
        let json = state.to_json();

        assert_eq!(json["schema_version"], TUI_CONTROL_STATE_SCHEMA_VERSION);
        assert_eq!(json["thread_id"], "thread_live");
        assert_eq!(json["current_turn_id"], "turn_live");
        assert_eq!(json["last_cursor"], "events_thread_live:8");
        assert_eq!(json["last_event_id"], "event_live");
        assert_eq!(json["command_history"][0]["command"], "events");
        assert_eq!(
            json["validation_errors"][0]["message"],
            "/steer requires guidance text"
        );
    }
}
