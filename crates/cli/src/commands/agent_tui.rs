// Path: crates/cli/src/commands/agent_tui.rs

use super::agent_event_stream::{
    fetch_runtime_event_stream, format_runtime_event_line, json_path_string,
    resolve_daemon_endpoint, resolve_daemon_token, runtime_event_url,
};
use super::model_mount_http::daemon_request;
use anyhow::{anyhow, Result};
use clap::Parser;
use reqwest::Method;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const TUI_SCHEMA_VERSION: &str = "ioi.agent-cli.tui.v1";
const TUI_PRIVATE_RUNTIME_LOOP: bool = false;
const TUI_THREAD_CREATE_ROUTE: &str = "/v1/threads";
const TUI_THREAD_LIST_ROUTE: &str = "/v1/threads";
const TUI_THREAD_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}";
const TUI_THREAD_RESUME_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/resume";
const TUI_TURN_CREATE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns";
const TUI_EVENT_STREAM_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/events";
const TUI_INTERRUPT_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns/{turn_id}/interrupt";
const TUI_STEER_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns/{turn_id}/steer";

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
}

pub async fn run_agent_tui(args: AgentTuiArgs) -> Result<()> {
    if args.interrupt && args.steer.is_some() {
        return Err(anyhow!(
            "agent tui accepts either --interrupt or --steer <guidance>, not both"
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
    let event_route =
        thread_event_route(&thread_id_from_value(&thread)?, args.follow, args.since_seq);
    let event_url = runtime_event_url(&endpoint, &event_route);
    let events = fetch_runtime_event_stream(
        &event_url,
        token.as_deref(),
        args.last_event_id.as_deref(),
        args.follow,
    )
    .await?;

    if args.json {
        return print_tui_json(TuiRender {
            endpoint,
            event_route,
            thread,
            submitted_turn,
            control,
            events,
            since_seq: args.since_seq,
            last_event_id: args.last_event_id,
            follow: args.follow,
        });
    }

    print_tui_screen(TuiRender {
        endpoint,
        event_route,
        thread,
        submitted_turn,
        control,
        events,
        since_seq: args.since_seq,
        last_event_id: args.last_event_id,
        follow: args.follow,
    })
}

struct TuiRender {
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

fn print_tui_json(render: TuiRender) -> Result<()> {
    let workflow_node_ids = workflow_node_ids(&render.events);
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
            "events": render.events,
            "deep_links": {
                "workflow_node_ids": workflow_node_ids,
                "thread_id": json_path_string(&render.thread, "/thread_id"),
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
            }
        }))?
    );
    Ok(())
}

fn print_tui_screen(render: TuiRender) -> Result<()> {
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
    println!("  controls=/interrupt /steer /resume via daemon thread endpoints");
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

async fn fetch_tui_thread(thread_id: &str, endpoint: &str, token: Option<&str>) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_for_thread(thread_id),
        None,
    )
    .await
}

async fn resume_tui_thread(thread_id: &str, endpoint: &str, token: Option<&str>) -> Result<Value> {
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
        return daemon_request(
            Some(endpoint),
            token,
            Method::POST,
            &route_with_thread_and_turn(TUI_INTERRUPT_ROUTE_TEMPLATE, thread_id, &turn_id),
            Some(serde_json::json!({
                "reason": args.reason,
                "source": "cli_tui",
                "actor": "operator",
                "event_kind": "OperatorControl.Interrupt",
                "component_kind": "operator_control",
                "workflow_node_id": "runtime.operator-interrupt",
            })),
        )
        .await
        .map(Some);
    }
    if let Some(guidance) = args
        .steer
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let turn_id = selected_turn_id(args, submitted_turn, thread)?;
        return daemon_request(
            Some(endpoint),
            token,
            Method::POST,
            &route_with_thread_and_turn(TUI_STEER_ROUTE_TEMPLATE, thread_id, &turn_id),
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
        .map(Some);
    }
    Ok(None)
}

fn selected_turn_id(
    args: &AgentTuiArgs,
    submitted_turn: Option<&Value>,
    thread: &Value,
) -> Result<String> {
    args.turn_id
        .as_deref()
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

fn thread_id_from_value(thread: &Value) -> Result<String> {
    json_path_string(thread, "/thread_id")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("daemon thread record is missing thread_id"))
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
        };
        let options = start_thread_options(&args);
        assert_eq!(options["local"]["cwd"], "/tmp/workspace");
        assert_eq!(options["model"]["id"], "auto");
        assert_eq!(options["model"]["routeId"], "route.native-local");
    }
}
