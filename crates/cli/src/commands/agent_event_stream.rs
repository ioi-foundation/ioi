// Path: crates/cli/src/commands/agent_event_stream.rs

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::time::Duration;

const DEFAULT_DAEMON_ENDPOINT: &str = "http://127.0.0.1:8765";
const THREAD_EVENT_STREAM_ROUTE_TEMPLATE: &str = "/v1/threads/{id}/events";
const THREAD_EVENT_STREAM_ALIAS_ROUTE_TEMPLATE: &str = "/v1/threads/{id}/events/stream";
const RUN_EVENT_STREAM_ROUTE_TEMPLATE: &str = "/v1/runs/{id}/events";

#[derive(Parser, Debug)]
pub struct AgentEventStreamArgs {
    /// Runtime thread id whose canonical event stream should be replayed.
    #[clap(long)]
    pub thread_id: Option<String>,
    /// Runtime run id whose owning turn events should be replayed.
    #[clap(long)]
    pub run_id: Option<String>,
    /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
    #[clap(long)]
    pub endpoint: Option<String>,
    /// Capability token. Defaults to IOI_DAEMON_TOKEN.
    #[clap(long)]
    pub token: Option<String>,
    /// Replay events after this monotonic sequence cursor.
    #[clap(long)]
    pub since_seq: Option<u64>,
    /// Replay events after this event id cursor via Last-Event-ID.
    #[clap(long)]
    pub last_event_id: Option<String>,
    /// Use the daemon stream alias where available.
    #[clap(long)]
    pub follow: bool,
    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentEventStreamTargetKind {
    Thread,
    Run,
}

impl AgentEventStreamTargetKind {
    fn as_str(self) -> &'static str {
        match self {
            AgentEventStreamTargetKind::Thread => "thread",
            AgentEventStreamTargetKind::Run => "run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentEventStreamTarget {
    kind: AgentEventStreamTargetKind,
    id: String,
}

pub async fn stream_agent_events(args: AgentEventStreamArgs) -> Result<()> {
    let target = agent_event_stream_target(&args)?;
    let endpoint = resolve_daemon_endpoint(args.endpoint.as_deref());
    let token = resolve_daemon_token(args.token.as_deref());
    let route = runtime_event_route_with_cursor(&target, args.follow, args.since_seq);
    let url = runtime_event_url(&endpoint, &route);
    let events = fetch_runtime_event_stream(
        &url,
        token.as_deref(),
        args.last_event_id.as_deref(),
        args.follow,
    )
    .await?;

    if args.json {
        return print_json(&serde_json::json!({
            "schema_version": "ioi.agent-cli.runtime-event-stream.v1",
            "surfaces": ["cli", "tui"],
            "source": target.kind.as_str(),
            "target_id": target.id,
            "endpoint": endpoint,
            "route": route,
            "since_seq": args.since_seq,
            "last_event_id": args.last_event_id,
            "follow": args.follow,
            "event_count": events.len(),
            "events": events,
        }));
    }

    println!(
        "Agent runtime event stream: {}={} events={}",
        target.kind.as_str(),
        target.id,
        events.len()
    );
    for event in &events {
        println!("  {}", format_runtime_event_line(event));
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn agent_event_stream_target(args: &AgentEventStreamArgs) -> Result<AgentEventStreamTarget> {
    match (args.thread_id.as_deref(), args.run_id.as_deref()) {
        (Some(thread_id), None) if !thread_id.trim().is_empty() => Ok(AgentEventStreamTarget {
            kind: AgentEventStreamTargetKind::Thread,
            id: thread_id.to_string(),
        }),
        (None, Some(run_id)) if !run_id.trim().is_empty() => Ok(AgentEventStreamTarget {
            kind: AgentEventStreamTargetKind::Run,
            id: run_id.to_string(),
        }),
        (Some(_), Some(_)) => Err(anyhow!(
            "agent stream accepts either --thread-id or --run-id, not both"
        )),
        _ => Err(anyhow!(
            "agent stream requires one target: --thread-id <id> or --run-id <id>"
        )),
    }
}

pub(crate) fn resolve_daemon_endpoint(endpoint: Option<&str>) -> String {
    endpoint
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("IOI_DAEMON_ENDPOINT").ok())
        .unwrap_or_else(|| DEFAULT_DAEMON_ENDPOINT.to_string())
}

pub(crate) fn resolve_daemon_token(token: Option<&str>) -> Option<String> {
    token
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("IOI_DAEMON_TOKEN").ok())
}

fn runtime_event_route_for_target(target: &AgentEventStreamTarget, follow: bool) -> String {
    let template = match (target.kind, follow) {
        (AgentEventStreamTargetKind::Thread, true) => THREAD_EVENT_STREAM_ALIAS_ROUTE_TEMPLATE,
        (AgentEventStreamTargetKind::Thread, false) => THREAD_EVENT_STREAM_ROUTE_TEMPLATE,
        (AgentEventStreamTargetKind::Run, _) => RUN_EVENT_STREAM_ROUTE_TEMPLATE,
    };
    template.replace("{id}", &target.id)
}

fn runtime_event_route_with_cursor(
    target: &AgentEventStreamTarget,
    follow: bool,
    since_seq: Option<u64>,
) -> String {
    let mut route = runtime_event_route_for_target(target, follow);
    if let Some(since_seq) = since_seq {
        route.push_str(&format!("?since_seq={since_seq}"));
    }
    route
}

pub(crate) fn runtime_event_url(endpoint: &str, route: &str) -> String {
    format!(
        "{}/{}",
        endpoint.trim_end_matches('/'),
        route.trim_start_matches('/')
    )
}

pub(crate) async fn fetch_runtime_event_stream(
    url: &str,
    token: Option<&str>,
    last_event_id: Option<&str>,
    follow: bool,
) -> Result<Vec<serde_json::Value>> {
    let mut builder = reqwest::Client::builder().no_proxy();
    if !follow {
        builder = builder.timeout(Duration::from_secs(10));
    }
    let client = builder
        .build()
        .context("failed to build local IOI daemon runtime event HTTP client")?;
    let mut request = client
        .get(url)
        .header("accept", "text/event-stream, application/json");
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(last_event_id) = last_event_id.filter(|value| !value.trim().is_empty()) {
        request = request.header("Last-Event-ID", last_event_id);
    }

    let response = request.send().await.with_context(|| {
        format!("failed to call local IOI daemon runtime event stream at {url}")
    })?;
    let status = response.status();
    let text = response.text().await.with_context(|| {
        format!("failed to read local IOI daemon runtime event stream from {url}")
    })?;
    if !status.is_success() {
        return Err(anyhow!(
            "local IOI daemon runtime event stream failed: {} {} -> {} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("error"),
            url,
            text
        ));
    }
    parse_runtime_event_response(&text)
}

fn parse_runtime_event_response(text: &str) -> Result<Vec<serde_json::Value>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let value: serde_json::Value =
            serde_json::from_str(trimmed).context("runtime event response is not valid JSON")?;
        return runtime_events_from_json_value(value);
    }
    parse_runtime_event_sse_blocks(trimmed)
}

fn runtime_events_from_json_value(value: serde_json::Value) -> Result<Vec<serde_json::Value>> {
    match value {
        serde_json::Value::Array(events) => Ok(events),
        serde_json::Value::Object(mut object) => {
            if let Some(serde_json::Value::Array(events)) = object.remove("events") {
                Ok(events)
            } else {
                Ok(vec![serde_json::Value::Object(object)])
            }
        }
        _ => Err(anyhow!(
            "runtime event JSON response must be an event, event array, or object with events"
        )),
    }
}

fn parse_runtime_event_sse_blocks(text: &str) -> Result<Vec<serde_json::Value>> {
    let normalized = text.replace("\r\n", "\n");
    normalized
        .split("\n\n")
        .filter_map(|block| {
            let data = block
                .lines()
                .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
                .collect::<Vec<_>>()
                .join("\n");
            if data.trim().is_empty() || data.trim() == "[DONE]" {
                None
            } else {
                Some(
                    serde_json::from_str::<serde_json::Value>(&data)
                        .with_context(|| format!("invalid runtime event SSE data frame: {data}")),
                )
            }
        })
        .collect()
}

pub(crate) fn json_scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(crate) fn json_path_string(value: &serde_json::Value, path: &str) -> Option<String> {
    value.pointer(path).and_then(json_scalar_string)
}

fn first_json_path_string(value: &serde_json::Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| json_path_string(value, path))
}

fn json_array_strings(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(|value| value.as_array())
        .map(|items| items.iter().filter_map(json_scalar_string).collect())
        .unwrap_or_default()
}

fn append_runtime_event_field(fields: &mut Vec<String>, label: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        fields.push(format!("{label}={value}"));
    }
}

fn append_runtime_event_refs(fields: &mut Vec<String>, label: &str, refs: Vec<String>) {
    if !refs.is_empty() {
        fields.push(format!("{label}=[{}]", refs.join(",")));
    }
}

pub(crate) fn format_runtime_event_line(event: &serde_json::Value) -> String {
    let seq = json_path_string(event, "/seq").unwrap_or_else(|| "?".to_string());
    let stream = json_path_string(event, "/event_stream_id").unwrap_or_else(|| "?".to_string());
    let cursor = if seq == "?" || stream == "?" {
        "?".to_string()
    } else {
        format!("{stream}:{seq}")
    };
    let event_kind = json_path_string(event, "/event_kind")
        .or_else(|| json_path_string(event, "/event"))
        .unwrap_or_else(|| "unknown".to_string());
    let mut fields = vec![
        format!("seq={seq}"),
        format!("cursor={cursor}"),
        format!("kind={event_kind}"),
    ];
    append_runtime_event_field(
        &mut fields,
        "source",
        json_path_string(event, "/source_event_kind"),
    );
    append_runtime_event_field(
        &mut fields,
        "component",
        json_path_string(event, "/component_kind"),
    );
    append_runtime_event_field(
        &mut fields,
        "node",
        json_path_string(event, "/workflow_node_id"),
    );
    append_runtime_event_field(
        &mut fields,
        "graph",
        json_path_string(event, "/workflow_graph_id"),
    );
    append_runtime_event_field(&mut fields, "status", json_path_string(event, "/status"));
    append_runtime_event_field(
        &mut fields,
        "payload",
        json_path_string(event, "/payload_schema_version"),
    );
    append_runtime_event_field(
        &mut fields,
        "payload_event",
        first_json_path_string(
            event,
            &["/payload/event_kind", "/payload_summary/event_kind"],
        ),
    );
    append_runtime_event_field(
        &mut fields,
        "tool",
        first_json_path_string(event, &["/payload/tool_name", "/payload_summary/tool_name"]),
    );
    append_runtime_event_field(
        &mut fields,
        "run",
        first_json_path_string(event, &["/payload/run_id", "/payload_summary/run_id"]),
    );
    append_runtime_event_refs(
        &mut fields,
        "receipts",
        json_array_strings(event, "receipt_refs"),
    );
    append_runtime_event_refs(
        &mut fields,
        "policies",
        json_array_strings(event, "policy_decision_refs"),
    );
    append_runtime_event_refs(
        &mut fields,
        "artifacts",
        json_array_strings(event, "artifact_refs"),
    );
    append_runtime_event_field(
        &mut fields,
        "event_id",
        json_path_string(event, "/event_id"),
    );
    fields.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_event_stream_target_and_route_are_canonical() {
        let thread_args = AgentEventStreamArgs {
            thread_id: Some("thread_live".to_string()),
            run_id: None,
            endpoint: None,
            token: None,
            since_seq: Some(5),
            last_event_id: None,
            follow: true,
            json: false,
        };
        let thread = agent_event_stream_target(&thread_args).expect("thread target");
        assert_eq!(thread.kind, AgentEventStreamTargetKind::Thread);
        assert_eq!(
            runtime_event_route_with_cursor(&thread, thread_args.follow, thread_args.since_seq),
            "/v1/threads/thread_live/events/stream?since_seq=5"
        );

        let run_args = AgentEventStreamArgs {
            thread_id: None,
            run_id: Some("run_live".to_string()),
            endpoint: None,
            token: None,
            since_seq: None,
            last_event_id: Some("event_live".to_string()),
            follow: true,
            json: true,
        };
        let run = agent_event_stream_target(&run_args).expect("run target");
        assert_eq!(run.kind, AgentEventStreamTargetKind::Run);
        assert_eq!(
            runtime_event_route_with_cursor(&run, run_args.follow, run_args.since_seq),
            "/v1/runs/run_live/events"
        );

        let invalid = AgentEventStreamArgs {
            thread_id: Some("thread_live".to_string()),
            run_id: Some("run_live".to_string()),
            endpoint: None,
            token: None,
            since_seq: None,
            last_event_id: None,
            follow: false,
            json: false,
        };
        assert!(agent_event_stream_target(&invalid).is_err());
    }

    #[test]
    fn parses_runtime_event_sse_blocks() {
        let events = parse_runtime_event_sse_blocks(
            "id: 1\nevent: runtime.event\ndata: {\"event_id\":\"e1\",\"event_stream_id\":\"thread_a:events\",\"seq\":1,\"event_kind\":\"thread.started\"}\n\n\
             id: 2\nevent: runtime.event\ndata: {\"event_id\":\"e2\",\"event_stream_id\":\"thread_a:events\",\"seq\":2,\"event_kind\":\"tool.completed\"}\n\n",
        )
        .expect("valid sse");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["event_kind"], "tool.completed");
    }

    #[test]
    fn formats_mapped_kernel_event_rows_for_compact_output() {
        let event = serde_json::json!({
            "event_id": "thread_a:events:seq:00000003",
            "event_stream_id": "thread_a:events",
            "seq": 3,
            "source_event_kind": "KernelEvent::AgentActionResult",
            "event_kind": "tool.completed",
            "status": "completed",
            "component_kind": "tool_result",
            "workflow_node_id": "runtime.tool-result",
            "workflow_graph_id": "graph_runtime",
            "payload_schema_version": "ioi.runtime.kernel-event.v1",
            "payload": {
                "event_kind": "KernelEvent::AgentActionResult",
                "tool_name": "system::intent_clarification",
                "run_id": "run_live"
            },
            "receipt_refs": ["receipt_tool"],
            "policy_decision_refs": ["policy_allow"],
            "artifact_refs": ["artifact_trace"]
        });
        let line = format_runtime_event_line(&event);
        assert!(line.contains("cursor=thread_a:events:3"));
        assert!(line.contains("kind=tool.completed"));
        assert!(line.contains("source=KernelEvent::AgentActionResult"));
        assert!(line.contains("component=tool_result"));
        assert!(line.contains("node=runtime.tool-result"));
        assert!(line.contains("payload_event=KernelEvent::AgentActionResult"));
        assert!(line.contains("tool=system::intent_clarification"));
        assert!(line.contains("receipts=[receipt_tool]"));
        assert!(line.contains("policies=[policy_allow]"));
        assert!(line.contains("artifacts=[artifact_trace]"));
    }
}
