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
            Ok(TuiLineCommand::Help) => print_tui_help(),
            Ok(TuiLineCommand::Resume) => {
                handle_resume_command(&mut session).await?;
            }
            Ok(TuiLineCommand::Events { since_seq }) => {
                handle_events_command(&mut session, since_seq).await?;
            }
            Ok(TuiLineCommand::Interrupt { reason }) => {
                handle_interrupt_command(&mut session, reason).await?;
            }
            Ok(TuiLineCommand::Steer { guidance }) => {
                handle_steer_command(&mut session, &guidance).await?;
            }
            Ok(TuiLineCommand::Quit) => {
                println!("line_mode_command=quit");
                break;
            }
            Err(error) => {
                println!("line_mode_error={error}");
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
) -> Result<()> {
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
    Ok(())
}

async fn handle_interrupt_command(
    session: &mut TuiInteractiveSession,
    reason: Option<String>,
) -> Result<()> {
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

async fn handle_steer_command(session: &mut TuiInteractiveSession, guidance: &str) -> Result<()> {
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
}
