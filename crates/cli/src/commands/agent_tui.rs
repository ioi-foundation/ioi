// Path: crates/cli/src/commands/agent_tui.rs

use super::agent_event_stream::{
    fetch_runtime_event_stream, format_runtime_event_line, json_path_string,
    resolve_daemon_endpoint, resolve_daemon_token, runtime_event_url,
};
use super::agent_tui_loop::{run_tui_interactive_loop, TuiInteractiveSession};
use super::model_mount_http::daemon_request;
use anyhow::{anyhow, Result};
use clap::Parser;
use reqwest::Method;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const TUI_SCHEMA_VERSION: &str = "ioi.agent-cli.tui.v1";
const TUI_CONTROL_STATE_SCHEMA_VERSION: &str = "ioi.agent-cli.tui-control-state.v1";
const TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION: &str = "ioi.workflow.runtime-tui-deeplink.v1";
const TUI_PRIVATE_RUNTIME_LOOP: bool = false;
const TUI_THREAD_CREATE_ROUTE: &str = "/v1/threads";
const TUI_THREAD_LIST_ROUTE: &str = "/v1/threads";
const TUI_THREAD_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}";
const TUI_THREAD_RESUME_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/resume";
const TUI_TURN_CREATE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns";
const TUI_EVENT_STREAM_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/events";
const TUI_INTERRUPT_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns/{turn_id}/interrupt";
const TUI_STEER_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns/{turn_id}/steer";
const TUI_APPROVAL_DECISION_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/approvals/{approval_id}/decision";

#[derive(Parser, Debug)]
pub struct AgentTuiArgs {
    /// Select an existing runtime thread id.
    #[clap(long = "thread-id")]
    pub thread_id: Option<String>,
    /// Start a new runtime thread with this goal when no thread id is supplied.
    #[clap(long)]
    pub goal: Option<String>,
    /// Submit one user message to the selected or newly started thread.
    #[clap(long)]
    pub message: Option<String>,
    /// Resume the selected thread before reading or sending.
    #[clap(long)]
    pub resume: bool,
    /// Turn id for interrupt/steer controls. Defaults to the submitted or latest turn.
    #[clap(long = "turn-id")]
    pub turn_id: Option<String>,
    /// Interrupt the selected turn through the daemon control endpoint.
    #[clap(long)]
    pub interrupt: bool,
    /// Add steering guidance to the selected turn through the daemon control endpoint.
    #[clap(long)]
    pub steer: Option<String>,
    /// Operator-visible interrupt reason.
    #[clap(long, default_value = "operator requested interrupt from TUI")]
    pub reason: String,
    /// Replay events after this monotonic sequence cursor.
    #[clap(long)]
    pub since_seq: Option<u64>,
    /// Replay events after this event id cursor via Last-Event-ID.
    #[clap(long)]
    pub last_event_id: Option<String>,
    /// Use the daemon stream alias where available.
    #[clap(long)]
    pub follow: bool,
    /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
    #[clap(long)]
    pub endpoint: Option<String>,
    /// Capability token. Defaults to IOI_DAEMON_TOKEN.
    #[clap(long)]
    pub token: Option<String>,
    /// Optional runtime profile for a newly started thread.
    #[clap(long = "runtime-profile")]
    pub runtime_profile: Option<String>,
    /// Optional model id for a newly started thread.
    #[clap(long)]
    pub model: Option<String>,
    /// Optional model route id for a newly started thread.
    #[clap(long = "route-id")]
    pub route_id: Option<String>,
    /// Optional workspace root for a newly started thread.
    #[clap(long)]
    pub cwd: Option<String>,
    /// Max steps hint for a newly started thread.
    #[clap(long, default_value = "20")]
    pub max_steps: u32,
    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,
    /// Enter the daemon-backed line-mode TUI loop after the initial render.
    #[clap(long)]
    pub interactive: bool,
}

pub async fn run_agent_tui(args: AgentTuiArgs) -> Result<()> {
    if args.interrupt && args.steer.is_some() {
        return Err(anyhow!(
            "agent tui accepts either --interrupt or --steer <guidance>, not both"
        ));
    }
    if args.interactive && args.json {
        return Err(anyhow!(
            "agent tui --interactive cannot be combined with --json"
        ));
    }

    let endpoint = resolve_daemon_endpoint(args.endpoint.as_deref());
    let token = resolve_daemon_token(args.token.as_deref());
    let mut thread = resolve_tui_thread(&args, &endpoint, token.as_deref()).await?;
    if args.resume {
        thread =
            resume_tui_thread(&thread_id_from_value(&thread)?, &endpoint, token.as_deref()).await?;
    }

    let submitted_turn = match args.message.as_deref() {
        Some(message) if !message.trim().is_empty() => Some(
            submit_tui_turn(
                &thread_id_from_value(&thread)?,
                message,
                &endpoint,
                token.as_deref(),
            )
            .await?,
        ),
        _ => None,
    };
    let control = run_tui_control(
        &args,
        &thread_id_from_value(&thread)?,
        submitted_turn.as_ref(),
        &thread,
        &endpoint,
        token.as_deref(),
    )
    .await?;
    thread = fetch_tui_thread(&thread_id_from_value(&thread)?, &endpoint, token.as_deref()).await?;
    let event_batch = fetch_tui_event_batch(
        &thread_id_from_value(&thread)?,
        &endpoint,
        token.as_deref(),
        args.follow,
        args.since_seq,
        args.last_event_id.as_deref(),
    )
    .await?;
    let latest_event_seq = latest_event_seq(&event_batch.events);
    let render = TuiRender {
        endpoint: endpoint.clone(),
        event_route: event_batch.event_route,
        thread,
        submitted_turn,
        control,
        events: event_batch.events,
        since_seq: args.since_seq,
        last_event_id: args.last_event_id,
        follow: args.follow,
    };

    if args.json {
        return print_tui_json(&render);
    }

    print_tui_screen(&render)?;
    if args.interactive {
        return run_tui_interactive_loop(TuiInteractiveSession {
            endpoint,
            token,
            thread: render.thread,
            next_since_seq: latest_event_seq.or(args.since_seq),
            follow: args.follow,
        })
        .await;
    }
    Ok(())
}

pub(crate) struct TuiEventBatch {
    pub(crate) event_route: String,
    pub(crate) events: Vec<Value>,
}

pub(crate) struct TuiRender {
    endpoint: String,
    event_route: String,
    thread: Value,
    submitted_turn: Option<Value>,
    control: Option<Value>,
    events: Vec<Value>,
    since_seq: Option<u64>,
    last_event_id: Option<String>,
    follow: bool,
}

fn print_tui_json(render: &TuiRender) -> Result<()> {
    let workflow_node_ids = workflow_node_ids(&render.events);
    let thread_id = json_path_string(&render.thread, "/thread_id");
    let event_rows = tui_event_rows(&render.events, thread_id.as_deref());
    let tui_control_state = tui_control_state_for_render(render, thread_id.as_deref());
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": TUI_SCHEMA_VERSION,
            "surface": "tui",
            "private_runtime_loop": TUI_PRIVATE_RUNTIME_LOOP,
            "daemon_endpoint": render.endpoint,
            "event_route": render.event_route,
            "thread": render.thread,
            "submitted_turn": render.submitted_turn,
            "control": render.control,
            "since_seq": render.since_seq,
            "last_event_id": render.last_event_id,
            "follow": render.follow,
            "event_count": render.events.len(),
            "workflow_node_ids": workflow_node_ids,
            "tui_control_state": tui_control_state,
            "event_rows": event_rows,
            "events": render.events,
            "deep_links": {
                "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
                "workflow_node_ids": workflow_node_ids,
                "thread_id": thread_id,
                "event_row_count": event_rows.len(),
            },
            "routes": {
                "thread_create": TUI_THREAD_CREATE_ROUTE,
                "thread_list": TUI_THREAD_LIST_ROUTE,
                "thread": TUI_THREAD_ROUTE_TEMPLATE,
                "thread_resume": TUI_THREAD_RESUME_ROUTE_TEMPLATE,
                "turn_create": TUI_TURN_CREATE_ROUTE_TEMPLATE,
                "event_stream": TUI_EVENT_STREAM_ROUTE_TEMPLATE,
                "interrupt": TUI_INTERRUPT_ROUTE_TEMPLATE,
                "steer": TUI_STEER_ROUTE_TEMPLATE,
                "approval_decision": TUI_APPROVAL_DECISION_ROUTE_TEMPLATE,
            }
        }))?
    );
    Ok(())
}

pub(crate) fn print_tui_screen(render: &TuiRender) -> Result<()> {
    let thread_id = thread_id_from_value(&render.thread)?;
    let latest_seq =
        json_path_string(&render.thread, "/latest_seq").unwrap_or_else(|| "0".to_string());
    println!("IOI Agent TUI");
    println!("  schema={TUI_SCHEMA_VERSION}");
    println!("  daemon={}", render.endpoint);
    println!("  thread={thread_id}");
    println!("  latest_seq={latest_seq}");
    println!("  private_runtime_loop={TUI_PRIVATE_RUNTIME_LOOP}");
    println!("  event_route={}", render.event_route);
    if let Some(turn) = render.submitted_turn.as_ref() {
        println!(
            "  submitted_turn={} status={}",
            json_path_string(turn, "/turn_id").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(turn, "/status").unwrap_or_else(|| "unknown".to_string())
        );
    }
    if let Some(control) = render.control.as_ref() {
        println!(
            "  control_status={} stop_reason={}",
            json_path_string(control, "/status").unwrap_or_else(|| "unknown".to_string()),
            json_path_string(control, "/stop_reason").unwrap_or_else(|| "n/a".to_string())
        );
    }
    let control_state = tui_control_state_for_render(render, Some(&thread_id));
    println!(
        "  control_state schema={} current_turn={} last_cursor={}",
        json_path_string(&control_state, "/schema_version")
            .unwrap_or_else(|| TUI_CONTROL_STATE_SCHEMA_VERSION.to_string()),
        json_path_string(&control_state, "/current_turn_id").unwrap_or_else(|| "none".to_string()),
        json_path_string(&control_state, "/last_cursor").unwrap_or_else(|| "none".to_string())
    );
    let approval_rows = tui_approval_rows(&render.events, Some(&thread_id));
    println!(
        "  mode={} approval_mode={} trust={}",
        json_path_string(&control_state, "/mode_status/mode")
            .unwrap_or_else(|| "agent".to_string()),
        json_path_string(&control_state, "/mode_status/approval_mode")
            .unwrap_or_else(|| "suggest".to_string()),
        json_path_string(&control_state, "/mode_status/trust_profile")
            .unwrap_or_else(|| "local_private".to_string())
    );
    println!(
        "  controls=/interrupt /steer /approvals /approve /reject /resume via daemon thread endpoints"
    );
    if !approval_rows.is_empty() {
        println!("Approvals: count={}", approval_rows.len());
        for row in approval_rows {
            println!(
                "  approval={} status={} node={} receipt_refs={} policy_refs={}",
                json_path_string(&row, "/approval_id").unwrap_or_else(|| "unknown".to_string()),
                json_path_string(&row, "/status").unwrap_or_else(|| "pending".to_string()),
                json_path_string(&row, "/workflow_node_id").unwrap_or_else(|| "none".to_string()),
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
    }
    println!("Events: count={}", render.events.len());
    for event in &render.events {
        println!("  {}", format_runtime_event_line(event));
    }
    Ok(())
}

async fn resolve_tui_thread(
    args: &AgentTuiArgs,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    match (args.thread_id.as_deref(), args.goal.as_deref()) {
        (Some(thread_id), None) if !thread_id.trim().is_empty() => {
            fetch_tui_thread(thread_id, endpoint, token).await
        }
        (None, Some(goal)) if !goal.trim().is_empty() => {
            start_tui_thread(args, goal, endpoint, token).await
        }
        (None, None) => select_latest_tui_thread(endpoint, token).await,
        (Some(_), Some(_)) => Err(anyhow!(
            "agent tui accepts either --thread-id or --goal, not both"
        )),
        _ => Err(anyhow!(
            "agent tui requires --thread-id <id>, --goal <goal>, or at least one existing daemon thread"
        )),
    }
}

async fn select_latest_tui_thread(endpoint: &str, token: Option<&str>) -> Result<Value> {
    let value = daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        TUI_THREAD_LIST_ROUTE,
        None,
    )
    .await?;
    let threads = value
        .as_array()
        .ok_or_else(|| anyhow!("daemon thread list did not return an array"))?;
    threads
        .iter()
        .max_by_key(|thread| {
            json_path_string(thread, "/updated_at")
                .or_else(|| json_path_string(thread, "/updatedAt"))
                .unwrap_or_default()
        })
        .cloned()
        .ok_or_else(|| anyhow!("agent tui found no daemon threads to select"))
}

async fn start_tui_thread(
    args: &AgentTuiArgs,
    goal: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut body = Map::new();
    body.insert("goal".to_string(), Value::String(goal.to_string()));
    body.insert("source".to_string(), Value::String("cli_tui".to_string()));
    body.insert(
        "max_steps".to_string(),
        Value::Number(serde_json::Number::from(args.max_steps)),
    );
    if let Some(runtime_profile) = args
        .runtime_profile
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "runtime_profile".to_string(),
            Value::String(runtime_profile.to_string()),
        );
    }
    let options = start_thread_options(args);
    if !options.is_empty() {
        body.insert("options".to_string(), Value::Object(options));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        TUI_THREAD_CREATE_ROUTE,
        Some(Value::Object(body)),
    )
    .await
}

fn start_thread_options(args: &AgentTuiArgs) -> Map<String, Value> {
    let mut options = Map::new();
    if let Some(cwd) = args.cwd.as_deref().filter(|value| !value.trim().is_empty()) {
        options.insert(
            "local".to_string(),
            serde_json::json!({
                "cwd": cwd,
            }),
        );
    }
    if args.model.is_some() || args.route_id.is_some() {
        let mut model = Map::new();
        if let Some(model_id) = args
            .model
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            model.insert("id".to_string(), Value::String(model_id.to_string()));
        }
        if let Some(route_id) = args
            .route_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            model.insert("routeId".to_string(), Value::String(route_id.to_string()));
        }
        options.insert("model".to_string(), Value::Object(model));
    }
    options
}

pub(crate) async fn fetch_tui_thread(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_for_thread(thread_id),
        None,
    )
    .await
}

pub(crate) async fn resume_tui_thread(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_RESUME_ROUTE_TEMPLATE, thread_id),
        None,
    )
    .await
}

async fn submit_tui_turn(
    thread_id: &str,
    message: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_TURN_CREATE_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "prompt": message,
            "source": "cli_tui",
            "mode": "tui",
        })),
    )
    .await
}

async fn run_tui_control(
    args: &AgentTuiArgs,
    thread_id: &str,
    submitted_turn: Option<&Value>,
    thread: &Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Option<Value>> {
    if args.interrupt {
        let turn_id = selected_turn_id(args, submitted_turn, thread)?;
        return interrupt_tui_turn(thread_id, &turn_id, &args.reason, endpoint, token)
            .await
            .map(Some);
    }
    if let Some(guidance) = args
        .steer
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let turn_id = selected_turn_id(args, submitted_turn, thread)?;
        return steer_tui_turn(thread_id, &turn_id, guidance, endpoint, token)
            .await
            .map(Some);
    }
    Ok(None)
}

pub(crate) async fn interrupt_tui_turn(
    thread_id: &str,
    turn_id: &str,
    reason: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_turn(TUI_INTERRUPT_ROUTE_TEMPLATE, thread_id, turn_id),
        Some(serde_json::json!({
            "reason": reason,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Interrupt",
            "component_kind": "operator_control",
            "workflow_node_id": "runtime.operator-interrupt",
        })),
    )
    .await
}

pub(crate) async fn steer_tui_turn(
    thread_id: &str,
    turn_id: &str,
    guidance: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_turn(TUI_STEER_ROUTE_TEMPLATE, thread_id, turn_id),
        Some(serde_json::json!({
            "guidance": guidance,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Steer",
            "component_kind": "operator_control",
            "workflow_node_id": "runtime.operator-steer",
        })),
    )
    .await
}

pub(crate) async fn decide_tui_approval(
    thread_id: &str,
    turn_id: Option<&str>,
    approval_id: &str,
    decision: &str,
    reason: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut body = Map::new();
    let event_kind = if decision == "approve" {
        "OperatorApproval.Approve"
    } else {
        "OperatorApproval.Reject"
    };
    body.insert("decision".to_string(), Value::String(decision.to_string()));
    body.insert("source".to_string(), Value::String("cli_tui".to_string()));
    body.insert("actor".to_string(), Value::String("operator".to_string()));
    body.insert(
        "event_kind".to_string(),
        Value::String(event_kind.to_string()),
    );
    body.insert(
        "component_kind".to_string(),
        Value::String("approval_gate".to_string()),
    );
    body.insert(
        "workflow_node_id".to_string(),
        Value::String(format!("runtime.approval.{}", safe_id(approval_id))),
    );
    if let Some(turn_id) = turn_id.filter(|value| !value.trim().is_empty()) {
        body.insert("turn_id".to_string(), Value::String(turn_id.to_string()));
    }
    if let Some(reason) = reason.filter(|value| !value.trim().is_empty()) {
        body.insert("reason".to_string(), Value::String(reason.to_string()));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_approval(
            TUI_APPROVAL_DECISION_ROUTE_TEMPLATE,
            thread_id,
            approval_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

fn selected_turn_id(
    args: &AgentTuiArgs,
    submitted_turn: Option<&Value>,
    thread: &Value,
) -> Result<String> {
    selected_turn_id_from_values(args.turn_id.as_deref(), submitted_turn, thread)
}

pub(crate) fn selected_turn_id_from_values(
    explicit_turn_id: Option<&str>,
    submitted_turn: Option<&Value>,
    thread: &Value,
) -> Result<String> {
    explicit_turn_id
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| submitted_turn.and_then(|turn| json_path_string(turn, "/turn_id")))
        .or_else(|| json_path_string(thread, "/latest_turn_id"))
        .or_else(|| {
            thread
                .get("turns")
                .and_then(Value::as_array)
                .and_then(|turns| turns.last())
                .and_then(|turn| json_path_string(turn, "/turn_id"))
        })
        .ok_or_else(|| anyhow!("agent tui control requires --turn-id or a thread latest turn"))
}

pub(crate) fn thread_id_from_value(thread: &Value) -> Result<String> {
    json_path_string(thread, "/thread_id")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("daemon thread record is missing thread_id"))
}

pub(crate) async fn fetch_tui_event_batch(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
    follow: bool,
    since_seq: Option<u64>,
    last_event_id: Option<&str>,
) -> Result<TuiEventBatch> {
    let event_route = thread_event_route(thread_id, follow, since_seq);
    let event_url = runtime_event_url(endpoint, &event_route);
    let events = fetch_runtime_event_stream(&event_url, token, last_event_id, follow).await?;
    Ok(TuiEventBatch {
        event_route,
        events,
    })
}

pub(crate) fn latest_event_seq(events: &[Value]) -> Option<u64> {
    events
        .iter()
        .filter_map(|event| event.pointer("/seq")?.as_u64())
        .max()
}

fn latest_tui_event(events: &[Value]) -> Option<&Value> {
    events
        .iter()
        .max_by_key(|event| event.pointer("/seq").and_then(Value::as_u64).unwrap_or(0))
}

fn tui_control_state_for_render(render: &TuiRender, fallback_thread_id: Option<&str>) -> Value {
    let thread_id = json_path_string(&render.thread, "/thread_id")
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let current_turn_id =
        selected_turn_id_from_values(None, render.submitted_turn.as_ref(), &render.thread).ok();
    let latest_event = latest_tui_event(&render.events);
    let last_seq = latest_event.and_then(|event| event.pointer("/seq").and_then(Value::as_u64));
    let last_cursor = latest_event.and_then(|event| tui_event_cursor(event, last_seq));
    let last_event_id = latest_event.and_then(|event| json_path_string(event, "/event_id"));
    let mut command_history = Vec::new();
    let approval_rows = tui_approval_rows(&render.events, thread_id.as_deref());
    let approval_decisions = tui_approval_decisions(&render.events, thread_id.as_deref());

    if let Some(turn) = render.submitted_turn.as_ref() {
        command_history.push(serde_json::json!({
            "id": "tui-command-message",
            "sequence": command_history.len() + 1,
            "command": "message",
            "raw_input": "--message",
            "status": "applied",
            "message": "submitted turn through daemon",
            "thread_id": thread_id.clone(),
            "turn_id": json_path_string(turn, "/turn_id"),
            "cursor": last_cursor.clone(),
            "event_id": last_event_id.clone(),
        }));
    }
    if let Some(control) = render.control.as_ref() {
        let source_event_kind = latest_event
            .and_then(|event| json_path_string(event, "/source_event_kind"))
            .unwrap_or_default();
        let command = if source_event_kind.contains("Steer") {
            "steer"
        } else {
            "interrupt"
        };
        command_history.push(serde_json::json!({
            "id": format!("tui-command-{command}"),
            "sequence": command_history.len() + 1,
            "command": command,
            "raw_input": format!("--{command}"),
            "status": "applied",
            "message": json_path_string(control, "/status"),
            "thread_id": thread_id.clone(),
            "turn_id": current_turn_id.clone(),
            "cursor": last_cursor.clone(),
            "event_id": last_event_id.clone(),
        }));
    }

    serde_json::json!({
        "schema_version": TUI_CONTROL_STATE_SCHEMA_VERSION,
        "surface": "tui",
        "thread_id": thread_id,
        "current_turn_id": current_turn_id,
        "last_cursor": last_cursor,
        "last_event_id": last_event_id,
        "mode_status": tui_mode_status(&render.thread, current_turn_id.as_deref()),
        "approval_rows": approval_rows,
        "approval_decisions": approval_decisions,
        "command_history": command_history,
        "validation_errors": [],
    })
}

pub(crate) fn tui_mode_status(thread: &Value, current_turn_id: Option<&str>) -> Value {
    let turn = selected_turn_value(thread, current_turn_id);
    serde_json::json!({
        "mode": json_path_string(turn.unwrap_or(thread), "/mode")
            .or_else(|| json_path_string(thread, "/mode"))
            .unwrap_or_else(|| "agent".to_string()),
        "approval_mode": json_path_string(turn.unwrap_or(thread), "/approval_mode")
            .or_else(|| json_path_string(thread, "/approval_mode"))
            .unwrap_or_else(|| "suggest".to_string()),
        "trust_profile": json_path_string(thread, "/trust_profile")
            .unwrap_or_else(|| "local_private".to_string()),
        "thread_status": json_path_string(thread, "/status"),
        "current_turn_status": turn.and_then(|value| json_path_string(value, "/status")),
        "current_turn_id": current_turn_id,
        "source": "daemon_thread",
    })
}

pub(crate) fn tui_approval_rows(events: &[Value], fallback_thread_id: Option<&str>) -> Vec<Value> {
    events
        .iter()
        .filter(|event| is_pending_approval_event(event))
        .map(|event| tui_approval_row(event, fallback_thread_id))
        .collect()
}

pub(crate) fn tui_approval_decisions(
    events: &[Value],
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    events
        .iter()
        .filter(|event| is_approval_decision_event(event))
        .map(|event| tui_approval_row(event, fallback_thread_id))
        .collect()
}

fn tui_approval_row(event: &Value, fallback_thread_id: Option<&str>) -> Value {
    let seq = event.pointer("/seq").and_then(Value::as_u64);
    let approval_id = approval_id_from_event(event)
        .or_else(|| json_path_string(event, "/event_id"))
        .unwrap_or_else(|| "approval".to_string());
    let status = approval_status_for_event(event);
    let workflow_node_id = json_path_string(event, "/workflow_node_id")
        .unwrap_or_else(|| format!("runtime.approval.{}", safe_id(&approval_id)));
    serde_json::json!({
        "id": format!("tui-approval-{approval_id}-{}", seq.unwrap_or(0)),
        "approval_id": approval_id.clone(),
        "status": status,
        "label": if is_approval_decision_event(event) {
            "Approval decision"
        } else {
            "Approval required"
        },
        "message": approval_message_for_event(event),
        "thread_id": json_path_string(event, "/thread_id").or_else(|| fallback_thread_id.map(ToOwned::to_owned)),
        "turn_id": json_path_string(event, "/turn_id"),
        "cursor": tui_event_cursor(event, seq),
        "event_id": json_path_string(event, "/event_id"),
        "sequence": seq,
        "workflow_node_id": workflow_node_id,
        "receipt_refs": event.pointer("/receipt_refs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "policy_decision_refs": event.pointer("/policy_decision_refs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "decision": json_path_string(event, "/payload/decision")
            .or_else(|| json_path_string(event, "/payload_summary/decision")),
    })
}

fn selected_turn_value<'a>(thread: &'a Value, current_turn_id: Option<&str>) -> Option<&'a Value> {
    let turns = thread.get("turns")?.as_array()?;
    if let Some(current_turn_id) = current_turn_id {
        if let Some(turn) = turns
            .iter()
            .find(|turn| json_path_string(turn, "/turn_id").as_deref() == Some(current_turn_id))
        {
            return Some(turn);
        }
    }
    turns.last()
}

pub(crate) fn approval_id_from_event(event: &Value) -> Option<String> {
    json_path_string(event, "/approval_id")
        .or_else(|| json_path_string(event, "/payload/approval_id"))
        .or_else(|| json_path_string(event, "/payload/approvalId"))
        .or_else(|| json_path_string(event, "/payload_summary/approval_id"))
        .or_else(|| json_path_string(event, "/payload_summary/approvalId"))
}

fn is_approval_event(event: &Value) -> bool {
    if approval_id_from_event(event).is_some() {
        return true;
    }
    let haystack = [
        json_path_string(event, "/event_kind"),
        json_path_string(event, "/source_event_kind"),
        json_path_string(event, "/component_kind"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    haystack.contains("approval")
        || event
            .pointer("/payload_summary/approval_required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || event
            .pointer("/payload/approval_required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn is_pending_approval_event(event: &Value) -> bool {
    is_approval_event(event)
        && !is_approval_decision_event(event)
        && approval_status_for_event(event) == "pending"
}

fn is_approval_decision_event(event: &Value) -> bool {
    let event_kind = json_path_string(event, "/event_kind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let source_event_kind = json_path_string(event, "/source_event_kind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let component_kind = json_path_string(event, "/component_kind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let approval_shaped = approval_id_from_event(event).is_some()
        || event_kind.contains("approval")
        || source_event_kind.contains("approval")
        || component_kind.contains("approval");
    if !approval_shaped {
        return false;
    }
    event_kind == "approval.approved"
        || event_kind == "approval.rejected"
        || source_event_kind.contains("operatorapproval.")
        || json_path_string(event, "/payload/decision").is_some()
        || json_path_string(event, "/payload_summary/decision").is_some()
}

fn approval_status_for_event(event: &Value) -> String {
    let status = json_path_string(event, "/status")
        .unwrap_or_else(|| "pending".to_string())
        .to_ascii_lowercase();
    let decision = json_path_string(event, "/payload/decision")
        .or_else(|| json_path_string(event, "/payload_summary/decision"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if status.contains("approved") || matches!(decision.as_str(), "approve" | "approved") {
        return "approved".to_string();
    }
    if status.contains("rejected") || matches!(decision.as_str(), "reject" | "rejected") {
        return "rejected".to_string();
    }
    if status.contains("waiting") || status.contains("pending") {
        return "pending".to_string();
    }
    status
}

fn approval_message_for_event(event: &Value) -> Option<String> {
    json_path_string(event, "/payload/message")
        .or_else(|| json_path_string(event, "/payload_summary/message"))
        .or_else(|| json_path_string(event, "/payload/reason"))
        .or_else(|| json_path_string(event, "/payload_summary/reason"))
        .or_else(|| json_path_string(event, "/payload/summary"))
        .or_else(|| json_path_string(event, "/payload_summary/summary"))
}

fn workflow_node_ids(events: &[Value]) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for event in events {
        if let Some(id) =
            json_path_string(event, "/workflow_node_id").filter(|value| !value.trim().is_empty())
        {
            ids.insert(id);
        }
    }
    ids.into_iter().collect()
}

fn tui_event_rows(events: &[Value], fallback_thread_id: Option<&str>) -> Vec<Value> {
    events
        .iter()
        .map(|event| tui_event_row(event, fallback_thread_id))
        .collect()
}

fn tui_event_row(event: &Value, fallback_thread_id: Option<&str>) -> Value {
    let thread_id =
        json_path_string(event, "/thread_id").or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let turn_id = json_path_string(event, "/turn_id");
    let workflow_graph_id = json_path_string(event, "/workflow_graph_id");
    let workflow_node_id = json_path_string(event, "/workflow_node_id");
    let event_id = json_path_string(event, "/event_id");
    let event_kind = json_path_string(event, "/event_kind");
    let source_event_kind = json_path_string(event, "/source_event_kind");
    let component_kind = json_path_string(event, "/component_kind");
    let seq = event.pointer("/seq").and_then(Value::as_u64);
    let cursor = tui_event_cursor(event, seq);
    let args = tui_reopen_args(thread_id.as_deref(), seq);
    serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "surface": "tui",
        "thread_id": thread_id,
        "turn_id": turn_id,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "event_id": event_id,
        "event_kind": event_kind,
        "source_event_kind": source_event_kind,
        "component_kind": component_kind,
        "seq": seq,
        "cursor": cursor,
        "tui_reopen": {
            "command": "ioi agent tui",
            "args": args,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "since_seq": seq,
            "last_event_id": event_id,
        },
        "react_flow": {
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "event_id": event_id,
            "cursor": cursor,
        }
    })
}

fn tui_event_cursor(event: &Value, seq: Option<u64>) -> Option<String> {
    json_path_string(event, "/cursor").or_else(|| {
        let stream = json_path_string(event, "/event_stream_id")?;
        Some(format!("{stream}:{}", seq?))
    })
}

fn tui_reopen_args(thread_id: Option<&str>, seq: Option<u64>) -> Vec<String> {
    let mut args = vec!["agent".to_string(), "tui".to_string()];
    if let Some(thread_id) = thread_id.filter(|value| !value.trim().is_empty()) {
        args.push("--thread-id".to_string());
        args.push(thread_id.to_string());
    }
    if let Some(seq) = seq {
        args.push("--since-seq".to_string());
        args.push(seq.to_string());
    }
    args
}

fn thread_event_route(thread_id: &str, follow: bool, since_seq: Option<u64>) -> String {
    let template = if follow {
        "/v1/threads/{thread_id}/events/stream"
    } else {
        TUI_EVENT_STREAM_ROUTE_TEMPLATE
    };
    let mut route = route_with_thread(template, thread_id);
    if let Some(since_seq) = since_seq {
        route.push_str(&format!("?since_seq={since_seq}"));
    }
    route
}

fn route_for_thread(thread_id: &str) -> String {
    route_with_thread(TUI_THREAD_ROUTE_TEMPLATE, thread_id)
}

fn route_with_thread(template: &str, thread_id: &str) -> String {
    template.replace("{thread_id}", thread_id)
}

fn route_with_thread_and_turn(template: &str, thread_id: &str, turn_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{turn_id}", turn_id)
}

fn route_with_thread_and_approval(template: &str, thread_id: &str, approval_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{approval_id}", approval_id)
}

fn safe_id(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tui_event_route_uses_canonical_thread_stream_cursor() {
        assert_eq!(
            thread_event_route("thread_live", false, Some(7)),
            "/v1/threads/thread_live/events?since_seq=7"
        );
        assert_eq!(
            thread_event_route("thread_live", true, None),
            "/v1/threads/thread_live/events/stream"
        );
        assert_eq!(
            route_with_thread_and_approval(
                TUI_APPROVAL_DECISION_ROUTE_TEMPLATE,
                "thread_live",
                "approval_live"
            ),
            "/v1/threads/thread_live/approvals/approval_live/decision"
        );
    }

    #[test]
    fn tui_control_selects_submitted_turn_before_thread_latest() {
        let args = AgentTuiArgs {
            thread_id: Some("thread_live".to_string()),
            goal: None,
            message: None,
            resume: false,
            turn_id: None,
            interrupt: true,
            steer: None,
            reason: "stop".to_string(),
            since_seq: None,
            last_event_id: None,
            follow: false,
            endpoint: None,
            token: None,
            runtime_profile: None,
            model: None,
            route_id: None,
            cwd: None,
            max_steps: 20,
            json: true,
            interactive: false,
        };
        let turn = serde_json::json!({ "turn_id": "turn_submitted" });
        let thread = serde_json::json!({ "latest_turn_id": "turn_latest" });
        assert_eq!(
            selected_turn_id(&args, Some(&turn), &thread).expect("selected turn"),
            "turn_submitted"
        );
    }

    #[test]
    fn tui_start_options_are_daemon_request_options() {
        let args = AgentTuiArgs {
            thread_id: None,
            goal: Some("Build TUI".to_string()),
            message: None,
            resume: false,
            turn_id: None,
            interrupt: false,
            steer: None,
            reason: "stop".to_string(),
            since_seq: None,
            last_event_id: None,
            follow: false,
            endpoint: None,
            token: None,
            runtime_profile: Some("runtime_service".to_string()),
            model: Some("auto".to_string()),
            route_id: Some("route.native-local".to_string()),
            cwd: Some("/tmp/workspace".to_string()),
            max_steps: 20,
            json: true,
            interactive: false,
        };
        let options = start_thread_options(&args);
        assert_eq!(options["local"]["cwd"], "/tmp/workspace");
        assert_eq!(options["model"]["id"], "auto");
        assert_eq!(options["model"]["routeId"], "route.native-local");
    }

    #[test]
    fn tui_event_rows_preserve_workflow_and_reopen_identity() {
        let rows = tui_event_rows(
            &[serde_json::json!({
                "event_id": "event_live",
                "event_stream_id": "events_thread_live",
                "seq": 7,
                "thread_id": "thread_live",
                "turn_id": "turn_live",
                "event_kind": "turn.interrupted",
                "source_event_kind": "OperatorControl.Interrupt",
                "component_kind": "operator_control",
                "workflow_graph_id": "graph_live",
                "workflow_node_id": "runtime.operator-interrupt",
            })],
            None,
        );
        assert_eq!(
            rows[0]["schema_version"],
            TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION
        );
        assert_eq!(rows[0]["thread_id"], "thread_live");
        assert_eq!(rows[0]["turn_id"], "turn_live");
        assert_eq!(rows[0]["workflow_graph_id"], "graph_live");
        assert_eq!(rows[0]["workflow_node_id"], "runtime.operator-interrupt");
        assert_eq!(rows[0]["event_id"], "event_live");
        assert_eq!(rows[0]["cursor"], "events_thread_live:7");
        assert_eq!(
            rows[0]["tui_reopen"]["args"],
            serde_json::json!([
                "agent",
                "tui",
                "--thread-id",
                "thread_live",
                "--since-seq",
                "7"
            ])
        );
        assert_eq!(
            rows[0]["react_flow"]["workflow_node_id"],
            "runtime.operator-interrupt"
        );
    }

    #[test]
    fn tui_control_state_preserves_turn_cursor_and_command_history() {
        let render = TuiRender {
            endpoint: "http://127.0.0.1:8765".to_string(),
            event_route: "/v1/threads/thread_live/events?since_seq=0".to_string(),
            thread: serde_json::json!({
                "thread_id": "thread_live",
                "latest_turn_id": "turn_live",
            }),
            submitted_turn: Some(serde_json::json!({ "turn_id": "turn_live" })),
            control: Some(serde_json::json!({
                "status": "interrupted",
                "stop_reason": "operator_interrupt",
            })),
            events: vec![serde_json::json!({
                "event_id": "event_live",
                "event_stream_id": "events_thread_live",
                "seq": 9,
                "thread_id": "thread_live",
                "turn_id": "turn_live",
                "source_event_kind": "OperatorControl.Interrupt",
            })],
            since_seq: Some(0),
            last_event_id: None,
            follow: false,
        };

        let state = tui_control_state_for_render(&render, Some("thread_live"));
        assert_eq!(state["schema_version"], TUI_CONTROL_STATE_SCHEMA_VERSION);
        assert_eq!(state["thread_id"], "thread_live");
        assert_eq!(state["current_turn_id"], "turn_live");
        assert_eq!(state["last_cursor"], "events_thread_live:9");
        assert_eq!(state["last_event_id"], "event_live");
        assert_eq!(state["command_history"][0]["command"], "message");
        assert_eq!(state["command_history"][1]["command"], "interrupt");
    }

    #[test]
    fn tui_control_state_projects_mode_status_and_approval_rows() {
        let render = TuiRender {
            endpoint: "http://127.0.0.1:8765".to_string(),
            event_route: "/v1/threads/thread_live/events?since_seq=0".to_string(),
            thread: serde_json::json!({
                "thread_id": "thread_live",
                "latest_turn_id": "turn_live",
                "mode": "agent",
                "approval_mode": "suggest",
                "trust_profile": "local_private",
                "status": "active",
                "turns": [{
                    "turn_id": "turn_live",
                    "status": "waiting_for_approval",
                    "mode": "agent",
                    "approval_mode": "suggest"
                }],
            }),
            submitted_turn: None,
            control: None,
            events: vec![
                serde_json::json!({
                    "event_id": "event_approval_required",
                    "event_stream_id": "events_thread_live",
                    "seq": 10,
                    "thread_id": "thread_live",
                    "turn_id": "turn_live",
                    "event_kind": "approval.required",
                    "source_event_kind": "KernelEvent::ApprovalRequired",
                    "status": "waiting_for_approval",
                    "approval_id": "approval_live",
                    "component_kind": "approval_gate",
                    "workflow_node_id": "runtime.approval.approval_live",
                    "payload": {
                        "message": "Approve shell execution"
                    }
                }),
                serde_json::json!({
                    "event_id": "event_approval_approved",
                    "event_stream_id": "events_thread_live",
                    "seq": 11,
                    "thread_id": "thread_live",
                    "turn_id": "turn_live",
                    "event_kind": "approval.approved",
                    "source_event_kind": "OperatorApproval.Approve",
                    "status": "approved",
                    "approval_id": "approval_live",
                    "component_kind": "approval_gate",
                    "workflow_node_id": "runtime.approval.approval_live",
                    "receipt_refs": ["receipt_approval"],
                    "policy_decision_refs": ["policy_approval_allow"],
                    "payload": {
                        "decision": "approve"
                    }
                }),
            ],
            since_seq: Some(0),
            last_event_id: None,
            follow: false,
        };

        let state = tui_control_state_for_render(&render, Some("thread_live"));
        assert_eq!(state["mode_status"]["approval_mode"], "suggest");
        assert_eq!(
            state["mode_status"]["current_turn_status"],
            "waiting_for_approval"
        );
        assert_eq!(state["approval_rows"][0]["approval_id"], "approval_live");
        assert_eq!(state["approval_rows"][0]["status"], "pending");
        assert_eq!(state["approval_decisions"][0]["decision"], "approve");
        assert_eq!(
            state["approval_decisions"][0]["receipt_refs"],
            serde_json::json!(["receipt_approval"])
        );
    }
}
