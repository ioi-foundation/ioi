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
const TUI_THREAD_MODE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/mode";
const TUI_THREAD_MODEL_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/model";
const TUI_THREAD_THINKING_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/thinking";
const TUI_THREAD_USAGE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/usage";
const TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/context-budget";
const TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/compaction-policy";
const TUI_THREAD_MCP_STATUS_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/mcp/status";
const TUI_THREAD_MCP_VALIDATE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/mcp/validate";
const TUI_THREAD_MCP_IMPORT_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/mcp/import";
const TUI_THREAD_MCP_SERVER_ADD_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/mcp/servers";
const TUI_THREAD_MCP_SERVER_REMOVE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/mcp/servers/{server_id}";
const TUI_THREAD_MCP_SERVER_ENABLE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/mcp/servers/{server_id}/enable";
const TUI_THREAD_MCP_SERVER_DISABLE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/mcp/servers/{server_id}/disable";
const TUI_THREAD_MCP_TOOL_SEARCH_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/mcp/tools/search";
const TUI_THREAD_MCP_TOOL_FETCH_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/mcp/tools/{tool_id}";
const TUI_THREAD_MCP_TOOL_INVOKE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/mcp/tools/{tool_id}/invoke";
const TUI_THREAD_MEMORY_STATUS_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/memory/status";
const TUI_THREAD_MEMORY_VALIDATE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/memory/validate";
const TUI_THREAD_MEMORY_POLICY_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/memory/policy";
const TUI_THREAD_MEMORY_PATH_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/memory/path";
const TUI_THREAD_MEMORY_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/memory";
const TUI_THREAD_MEMORY_RECORD_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/memory/{memory_id}";
const TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/subagents";
const TUI_THREAD_SUBAGENT_WAIT_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/{subagent_id}/wait";
const TUI_THREAD_SUBAGENT_RESULT_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/{subagent_id}/result";
const TUI_THREAD_SUBAGENT_INPUT_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/{subagent_id}/input";
const TUI_THREAD_SUBAGENT_CANCEL_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/{subagent_id}/cancel";
const TUI_THREAD_SUBAGENT_RESUME_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/{subagent_id}/resume";
const TUI_THREAD_SUBAGENT_ASSIGN_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/{subagent_id}/assign";
const TUI_THREAD_SUBAGENT_CANCEL_PROPAGATE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/subagents/cancel";
const TUI_MEMORY_STATUS_ROUTE: &str = "/v1/memory";
const TUI_MEMORY_VALIDATE_ROUTE: &str = "/v1/memory/validate";
const TUI_MCP_STATUS_ROUTE: &str = "/v1/mcp";
const TUI_MCP_SERVER_LIST_ROUTE: &str = "/v1/mcp/servers";
const TUI_MCP_TOOL_LIST_ROUTE: &str = "/v1/mcp/tools";
const TUI_MCP_VALIDATE_ROUTE: &str = "/v1/mcp/validate";
const TUI_TURN_CREATE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns";
const TUI_EVENT_STREAM_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/events";
const TUI_INTERRUPT_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns/{turn_id}/interrupt";
const TUI_STEER_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/turns/{turn_id}/steer";
const TUI_APPROVAL_DECISION_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/approvals/{approval_id}/decision";
const TUI_CODING_TOOL_INVOKE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/tools/{tool_id}/invoke";
const TUI_SNAPSHOT_LIST_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/snapshots";
const TUI_RESTORE_PREVIEW_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-preview";
const TUI_RESTORE_APPLY_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-apply";
const TUI_THREAD_DIAGNOSTICS_REPAIR_DECISION_EXECUTE_ROUTE_TEMPLATE: &str =
    "/v1/threads/{thread_id}/diagnostics/repair-decisions/{decision_id}/execute";
const TUI_JOB_LIST_ROUTE: &str = "/v1/jobs";
const TUI_JOB_ROUTE_TEMPLATE: &str = "/v1/jobs/{job_id}";
const TUI_JOB_CANCEL_ROUTE_TEMPLATE: &str = "/v1/jobs/{job_id}/cancel";
const TUI_RUN_ROUTE_TEMPLATE: &str = "/v1/runs/{run_id}";
const TUI_RUN_CANCEL_ROUTE_TEMPLATE: &str = "/v1/runs/{run_id}/cancel";
const TUI_RUN_EVENTS_ROUTE_TEMPLATE: &str = "/v1/runs/{run_id}/events";
const TUI_RUN_REPLAY_ROUTE_TEMPLATE: &str = "/v1/runs/{run_id}/replay";
const TUI_RUN_TRACE_ROUTE_TEMPLATE: &str = "/v1/runs/{run_id}/trace";
const TUI_RUN_INSPECT_ROUTE_TEMPLATE: &str = "/v1/runs/{run_id}/inspect";
const TUI_RUN_CODING_TOOL_BUDGET_RECOVERY_ROUTE_TEMPLATE: &str =
    "/v1/runs/{run_id}/coding-tool-budget-recovery";

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
    let jobs = list_tui_jobs_for_thread(&thread, &endpoint, token.as_deref()).await?;
    let latest_event_seq = latest_event_seq(&event_batch.events);
    let render = TuiRender {
        endpoint: endpoint.clone(),
        event_route: event_batch.event_route,
        thread,
        submitted_turn,
        control,
        events: event_batch.events,
        jobs,
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
    jobs: Vec<Value>,
    since_seq: Option<u64>,
    last_event_id: Option<String>,
    follow: bool,
}

fn print_tui_json(render: &TuiRender) -> Result<()> {
    let workflow_node_ids = workflow_node_ids(&render.events);
    let thread_id = json_path_string(&render.thread, "/thread_id");
    let event_rows = tui_event_rows(&render.events, thread_id.as_deref());
    let job_rows = tui_job_rows(&render.jobs, thread_id.as_deref());
    let run_lifecycle_rows = tui_run_lifecycle_rows(&render.jobs, thread_id.as_deref());
    let tui_control_state = tui_control_state_for_render(render, thread_id.as_deref());
    let deep_links = serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "workflow_node_ids": workflow_node_ids.clone(),
        "thread_id": thread_id.clone(),
        "event_row_count": event_rows.len(),
        "job_row_count": job_rows.len(),
        "run_lifecycle_row_count": run_lifecycle_rows.len(),
    });
    let routes = serde_json::json!({
        "thread_create": TUI_THREAD_CREATE_ROUTE,
        "thread_list": TUI_THREAD_LIST_ROUTE,
        "thread": TUI_THREAD_ROUTE_TEMPLATE,
        "thread_resume": TUI_THREAD_RESUME_ROUTE_TEMPLATE,
        "thread_mode": TUI_THREAD_MODE_ROUTE_TEMPLATE,
        "thread_model": TUI_THREAD_MODEL_ROUTE_TEMPLATE,
        "thread_thinking": TUI_THREAD_THINKING_ROUTE_TEMPLATE,
        "thread_mcp_status": TUI_THREAD_MCP_STATUS_ROUTE_TEMPLATE,
        "thread_mcp_validate": TUI_THREAD_MCP_VALIDATE_ROUTE_TEMPLATE,
        "thread_memory_status": TUI_THREAD_MEMORY_STATUS_ROUTE_TEMPLATE,
        "thread_memory_validate": TUI_THREAD_MEMORY_VALIDATE_ROUTE_TEMPLATE,
        "thread_memory_policy": TUI_THREAD_MEMORY_POLICY_ROUTE_TEMPLATE,
        "thread_memory_path": TUI_THREAD_MEMORY_PATH_ROUTE_TEMPLATE,
        "thread_memory": TUI_THREAD_MEMORY_ROUTE_TEMPLATE,
        "thread_memory_record": TUI_THREAD_MEMORY_RECORD_ROUTE_TEMPLATE,
        "memory_status": TUI_MEMORY_STATUS_ROUTE,
        "memory_validate": TUI_MEMORY_VALIDATE_ROUTE,
        "mcp_status": TUI_MCP_STATUS_ROUTE,
        "mcp_servers": TUI_MCP_SERVER_LIST_ROUTE,
        "mcp_tools": TUI_MCP_TOOL_LIST_ROUTE,
        "mcp_validate": TUI_MCP_VALIDATE_ROUTE,
        "turn_create": TUI_TURN_CREATE_ROUTE_TEMPLATE,
        "event_stream": TUI_EVENT_STREAM_ROUTE_TEMPLATE,
        "interrupt": TUI_INTERRUPT_ROUTE_TEMPLATE,
        "steer": TUI_STEER_ROUTE_TEMPLATE,
        "approval_decision": TUI_APPROVAL_DECISION_ROUTE_TEMPLATE,
        "coding_tool_invoke": TUI_CODING_TOOL_INVOKE_ROUTE_TEMPLATE,
        "snapshot_list": TUI_SNAPSHOT_LIST_ROUTE_TEMPLATE,
        "restore_preview": TUI_RESTORE_PREVIEW_ROUTE_TEMPLATE,
        "restore_apply": TUI_RESTORE_APPLY_ROUTE_TEMPLATE,
        "diagnostics_repair_decision_execute": TUI_THREAD_DIAGNOSTICS_REPAIR_DECISION_EXECUTE_ROUTE_TEMPLATE,
        "job_list": TUI_JOB_LIST_ROUTE,
        "job": TUI_JOB_ROUTE_TEMPLATE,
        "job_cancel": TUI_JOB_CANCEL_ROUTE_TEMPLATE,
        "run": TUI_RUN_ROUTE_TEMPLATE,
        "run_cancel": TUI_RUN_CANCEL_ROUTE_TEMPLATE,
        "run_events": TUI_RUN_EVENTS_ROUTE_TEMPLATE,
        "run_replay": TUI_RUN_REPLAY_ROUTE_TEMPLATE,
        "run_trace": TUI_RUN_TRACE_ROUTE_TEMPLATE,
        "run_inspect": TUI_RUN_INSPECT_ROUTE_TEMPLATE,
        "run_coding_tool_budget_recovery": TUI_RUN_CODING_TOOL_BUDGET_RECOVERY_ROUTE_TEMPLATE,
    });
    let mut routes = routes;
    if let Some(routes_object) = routes.as_object_mut() {
        routes_object.insert(
            "thread_mcp_import".to_string(),
            Value::String(TUI_THREAD_MCP_IMPORT_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_mcp_server_add".to_string(),
            Value::String(TUI_THREAD_MCP_SERVER_ADD_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_mcp_server_remove".to_string(),
            Value::String(TUI_THREAD_MCP_SERVER_REMOVE_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagents".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_wait".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_WAIT_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_result".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_RESULT_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_input".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_INPUT_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_cancel".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_CANCEL_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_resume".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_RESUME_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_assign".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_ASSIGN_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_subagent_cancel_propagate".to_string(),
            Value::String(TUI_THREAD_SUBAGENT_CANCEL_PROPAGATE_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_usage".to_string(),
            Value::String(TUI_THREAD_USAGE_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_context_budget".to_string(),
            Value::String(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE.to_string()),
        );
        routes_object.insert(
            "thread_compaction_policy".to_string(),
            Value::String(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE.to_string()),
        );
    }
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
            "job_count": render.jobs.len(),
            "workflow_node_ids": workflow_node_ids,
            "tui_control_state": tui_control_state,
            "event_rows": event_rows,
            "job_rows": job_rows,
            "run_lifecycle_rows": run_lifecycle_rows,
            "events": render.events,
            "jobs": render.jobs,
            "deep_links": deep_links,
            "routes": routes,
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
        "  controls=/mode /model /thinking /cost /context /mcp /memory /interrupt /steer /approvals /approve /reject /restore /jobs /job /run /resume via daemon endpoints"
    );
    println!(
        "  model={} route={} thinking={}",
        json_path_string(&control_state, "/mode_status/requested_model")
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&control_state, "/mode_status/model_route_id")
            .unwrap_or_else(|| "unknown".to_string()),
        json_path_string(&control_state, "/mode_status/reasoning_effort")
            .unwrap_or_else(|| "default".to_string())
    );
    println!(
        "  usage tokens={} cost_usd={} context={} status={}",
        json_path_string(&control_state, "/usage_status/usage_total_tokens")
            .unwrap_or_else(|| "0".to_string()),
        json_path_string(&control_state, "/usage_status/usage_cost_estimate_usd")
            .unwrap_or_else(|| "0".to_string()),
        json_path_string(&control_state, "/usage_status/usage_context_pressure")
            .unwrap_or_else(|| "0".to_string()),
        json_path_string(
            &control_state,
            "/usage_status/usage_context_pressure_status"
        )
        .unwrap_or_else(|| "nominal".to_string())
    );
    let job_rows = tui_job_rows(&render.jobs, Some(&thread_id));
    if !job_rows.is_empty() {
        println!("Jobs: count={}", job_rows.len());
        for row in job_rows {
            println!(
                "  job={} run={} status={} progress={} cancelable={} node={}",
                json_path_string(&row, "/job_id").unwrap_or_else(|| "unknown".to_string()),
                json_path_string(&row, "/run_id").unwrap_or_else(|| "unknown".to_string()),
                json_path_string(&row, "/status").unwrap_or_else(|| "unknown".to_string()),
                json_path_string(&row, "/progress_percent").unwrap_or_else(|| "0".to_string()),
                json_path_string(&row, "/cancelable").unwrap_or_else(|| "false".to_string()),
                json_path_string(&row, "/workflow_node_id")
                    .unwrap_or_else(|| "runtime.runtime-job".to_string())
            );
        }
    }
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

pub(crate) async fn update_tui_thread_mode(
    thread_id: &str,
    mode: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MODE_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "mode": mode,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Mode",
            "component_kind": "runtime_mode",
            "workflow_node_id": "runtime.thread-mode",
        })),
    )
    .await
}

pub(crate) async fn update_tui_thread_model(
    thread_id: &str,
    model_id: &str,
    route_id: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut model = Map::new();
    model.insert("id".to_string(), Value::String(model_id.to_string()));
    if let Some(route_id) = route_id.filter(|value| !value.trim().is_empty()) {
        model.insert("routeId".to_string(), Value::String(route_id.to_string()));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MODEL_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "model": Value::Object(model),
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Model",
            "component_kind": "model_router",
            "workflow_node_id": "runtime.model-router",
        })),
    )
    .await
}

pub(crate) async fn update_tui_thread_thinking(
    thread_id: &str,
    reasoning_effort: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_THINKING_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "reasoningEffort": reasoning_effort,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Thinking",
            "component_kind": "model_router",
            "workflow_node_id": "runtime.model-router",
        })),
    )
    .await
}

pub(crate) async fn fetch_tui_thread_usage(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_thread(TUI_THREAD_USAGE_ROUTE_TEMPLATE, thread_id),
        None,
    )
    .await
}

pub(crate) async fn evaluate_tui_context_budget(
    thread_id: &str,
    usage: &Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "eventKind": "RuntimeContextBudget.Evaluate",
            "event_kind": "RuntimeContextBudget.Evaluate",
            "componentKind": "context_budget",
            "component_kind": "context_budget",
            "workflowNodeId": "runtime.context-budget",
            "workflow_node_id": "runtime.context-budget",
            "scope": "thread",
            "threadId": thread_id,
            "thread_id": thread_id,
            "mode": "simulate",
            "simulationMode": true,
            "simulation_mode": true,
            "thresholds": {
                "maxTotalTokens": 4096,
                "max_total_tokens": 4096,
                "maxCostUsd": 0.25,
                "max_cost_usd": 0.25,
                "maxContextPressure": 0.85,
                "max_context_pressure": 0.85,
                "warnAtRatio": 0.8,
                "warn_at_ratio": 0.8,
            },
            "usageTelemetry": usage,
            "usage_telemetry": usage,
        })),
    )
    .await
}

pub(crate) async fn evaluate_tui_compaction_policy(
    thread_id: &str,
    turn_id: Option<&str>,
    context_budget: &Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "eventKind": "RuntimeCompactionPolicy.Evaluate",
            "event_kind": "RuntimeCompactionPolicy.Evaluate",
            "componentKind": "compaction_policy",
            "component_kind": "compaction_policy",
            "workflowNodeId": "runtime.compaction-policy",
            "workflow_node_id": "runtime.compaction-policy",
            "threadId": thread_id,
            "thread_id": thread_id,
            "turnId": turn_id,
            "turn_id": turn_id,
            "contextBudget": context_budget,
            "context_budget": context_budget,
            "contextBudgetStatus": json_path_string(context_budget, "/status")
                .unwrap_or_else(|| "ok".to_string()),
            "context_budget_status": json_path_string(context_budget, "/status")
                .unwrap_or_else(|| "ok".to_string()),
            "policy": {
                "okAction": "noop",
                "ok_action": "noop",
                "warnAction": "warn",
                "warn_action": "warn",
                "blockedAction": "compact",
                "blocked_action": "compact",
                "approvalRequired": false,
                "approval_required": false,
                "approvalGranted": false,
                "approval_granted": false,
                "executeCompaction": false,
                "execute_compaction": false,
                "compactReason": "Inspect context from TUI /context.",
                "compact_reason": "Inspect context from TUI /context.",
                "compactScope": "thread",
                "compact_scope": "thread",
                "compactWorkflowNodeId": "runtime.context-compact",
                "compact_workflow_node_id": "runtime.context-compact",
            },
        })),
    )
    .await
}

pub(crate) async fn inspect_tui_mcp_status(
    thread_id: &str,
    source_mode: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MCP_STATUS_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Mcp",
            "component_kind": "mcp_provider",
            "workflow_node_id": "runtime.mcp-manager",
            "live_discovery": true,
            "mcp_config_source_mode": source_mode,
        })),
    )
    .await
}

pub(crate) async fn validate_tui_mcp(
    thread_id: &str,
    source_mode: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MCP_VALIDATE_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.McpValidate",
            "component_kind": "mcp_validator",
            "workflow_node_id": "runtime.mcp-manager.validate",
            "mcp_config_source_mode": source_mode,
        })),
    )
    .await
}

pub(crate) async fn search_tui_mcp_tools(
    thread_id: &str,
    query: &str,
    server_id: Option<&str>,
    source_mode: Option<&str>,
    limit: Option<u64>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut params = vec![
        ("q", query.to_string()),
        ("query", query.to_string()),
        ("live_discovery", "true".to_string()),
        ("source", "cli_tui".to_string()),
    ];
    if let Some(server_id) = server_id.filter(|value| !value.trim().is_empty()) {
        params.push(("server_id", server_id.to_string()));
    }
    if let Some(source_mode) = source_mode.filter(|value| !value.trim().is_empty()) {
        params.push(("mcp_config_source_mode", source_mode.to_string()));
    }
    if let Some(limit) = limit {
        params.push(("limit", limit.to_string()));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_query(
            route_with_thread(TUI_THREAD_MCP_TOOL_SEARCH_ROUTE_TEMPLATE, thread_id),
            params,
        ),
        None,
    )
    .await
}

pub(crate) async fn fetch_tui_mcp_tool(
    thread_id: &str,
    tool_id: &str,
    server_id: Option<&str>,
    source_mode: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut params = vec![
        ("live_discovery", "true".to_string()),
        ("source", "cli_tui".to_string()),
    ];
    if let Some(server_id) = server_id.filter(|value| !value.trim().is_empty()) {
        params.push(("server_id", server_id.to_string()));
    }
    if let Some(source_mode) = source_mode.filter(|value| !value.trim().is_empty()) {
        params.push(("mcp_config_source_mode", source_mode.to_string()));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_query(
            route_with_thread_and_mcp_tool(
                TUI_THREAD_MCP_TOOL_FETCH_ROUTE_TEMPLATE,
                thread_id,
                tool_id,
            ),
            params,
        ),
        None,
    )
    .await
}

pub(crate) async fn import_tui_mcp(
    thread_id: &str,
    mcp_json: Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MCP_IMPORT_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.McpImport",
            "component_kind": "mcp_provider",
            "workflow_node_id": "runtime.mcp-manager.import",
            "mcp_json": mcp_json,
        })),
    )
    .await
}

pub(crate) async fn add_tui_mcp_server(
    thread_id: &str,
    label: &str,
    config: Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MCP_SERVER_ADD_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.McpAdd",
            "component_kind": "mcp_provider",
            "workflow_node_id": format!("runtime.mcp-server.{}", safe_id(label)),
            "label": label,
            "server": config,
        })),
    )
    .await
}

pub(crate) async fn remove_tui_mcp_server(
    thread_id: &str,
    server_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::DELETE,
        &route_with_thread_and_mcp_server(
            TUI_THREAD_MCP_SERVER_REMOVE_ROUTE_TEMPLATE,
            thread_id,
            server_id,
        ),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.McpRemove",
            "component_kind": "mcp_provider",
            "workflow_node_id": format!("runtime.mcp-server.{}", safe_id(server_id)),
        })),
    )
    .await
}

pub(crate) async fn set_tui_mcp_server_enabled(
    thread_id: &str,
    server_id: &str,
    enabled: bool,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let template = if enabled {
        TUI_THREAD_MCP_SERVER_ENABLE_ROUTE_TEMPLATE
    } else {
        TUI_THREAD_MCP_SERVER_DISABLE_ROUTE_TEMPLATE
    };
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_mcp_server(template, thread_id, server_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": if enabled { "OperatorControl.McpEnable" } else { "OperatorControl.McpDisable" },
            "component_kind": "mcp_provider",
            "workflow_node_id": format!("runtime.mcp-server.{}", safe_id(server_id)),
        })),
    )
    .await
}

pub(crate) async fn invoke_tui_mcp_tool(
    thread_id: &str,
    server_id: &str,
    tool_name: &str,
    input: Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let tool_id = format!("{server_id}.{tool_name}");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_mcp_tool(TUI_THREAD_MCP_TOOL_INVOKE_ROUTE_TEMPLATE, thread_id, &tool_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.McpInvoke",
            "component_kind": "mcp_tool_call",
            "workflow_node_id": format!("runtime.mcp-tool.{}.{}", safe_id(server_id), safe_id(tool_name)),
            "server_id": server_id,
            "tool_name": tool_name,
            "input": input,
            "side_effect_class": "read",
        })),
    )
    .await
}

pub(crate) async fn inspect_tui_memory_status(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MEMORY_STATUS_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Memory",
            "component_kind": "memory_policy",
            "workflow_node_id": "runtime.memory-manager",
        })),
    )
    .await
}

pub(crate) async fn validate_tui_memory(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MEMORY_VALIDATE_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.MemoryValidate",
            "component_kind": "memory_policy",
            "workflow_node_id": "runtime.memory-manager.validate",
        })),
    )
    .await
}

pub(crate) async fn list_tui_memory_records(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_thread(TUI_THREAD_MEMORY_ROUTE_TEMPLATE, thread_id),
        None,
    )
    .await
}

pub(crate) async fn inspect_tui_memory_policy(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_thread(TUI_THREAD_MEMORY_POLICY_ROUTE_TEMPLATE, thread_id),
        None,
    )
    .await
}

pub(crate) async fn inspect_tui_memory_path(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_thread(TUI_THREAD_MEMORY_PATH_ROUTE_TEMPLATE, thread_id),
        None,
    )
    .await
}

pub(crate) async fn update_tui_memory_policy(
    thread_id: &str,
    disabled: bool,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::PATCH,
        &route_with_thread(TUI_THREAD_MEMORY_POLICY_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "disabled": disabled,
            "injectionEnabled": !disabled,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.MemoryPolicy",
            "component_kind": "memory_policy",
            "workflow_node_id": "runtime.memory-manager.policy",
        })),
    )
    .await
}

pub(crate) async fn remember_tui_memory(
    thread_id: &str,
    text: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_MEMORY_ROUTE_TEMPLATE, thread_id),
        Some(serde_json::json!({
            "text": text,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.MemoryWrite",
            "component_kind": "memory_write",
            "workflow_node_id": "runtime.memory.write",
        })),
    )
    .await
}

pub(crate) async fn edit_tui_memory(
    thread_id: &str,
    memory_id: &str,
    text: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::PATCH,
        &route_with_thread_and_memory(
            TUI_THREAD_MEMORY_RECORD_ROUTE_TEMPLATE,
            thread_id,
            memory_id,
        ),
        Some(serde_json::json!({
            "text": text,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.MemoryEdit",
            "component_kind": "memory_write",
            "workflow_node_id": "runtime.memory.edit",
        })),
    )
    .await
}

pub(crate) async fn delete_tui_memory(
    thread_id: &str,
    memory_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::DELETE,
        &route_with_thread_and_memory(
            TUI_THREAD_MEMORY_RECORD_ROUTE_TEMPLATE,
            thread_id,
            memory_id,
        ),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.MemoryDelete",
            "component_kind": "memory_write",
            "workflow_node_id": "runtime.memory.delete",
        })),
    )
    .await
}

pub(crate) async fn list_tui_subagents(
    thread_id: &str,
    role: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut params = vec![("source", "cli_tui".to_string())];
    if let Some(role) = role.filter(|value| !value.trim().is_empty()) {
        params.push(("role", role.to_string()));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_query(
            route_with_thread(TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE, thread_id),
            params,
        ),
        None,
    )
    .await
}

pub(crate) async fn spawn_tui_subagent(
    thread_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentSpawn");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE, thread_id),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn wait_tui_subagent(
    thread_id: &str,
    subagent_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentWait");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_subagent(
            TUI_THREAD_SUBAGENT_WAIT_ROUTE_TEMPLATE,
            thread_id,
            subagent_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn fetch_tui_subagent_result(
    thread_id: &str,
    subagent_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_thread_and_subagent(
            TUI_THREAD_SUBAGENT_RESULT_ROUTE_TEMPLATE,
            thread_id,
            subagent_id,
        ),
        None,
    )
    .await
}

pub(crate) async fn send_tui_subagent_input(
    thread_id: &str,
    subagent_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentSendInput");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_subagent(
            TUI_THREAD_SUBAGENT_INPUT_ROUTE_TEMPLATE,
            thread_id,
            subagent_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn cancel_tui_subagent(
    thread_id: &str,
    subagent_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentCancel");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_subagent(
            TUI_THREAD_SUBAGENT_CANCEL_ROUTE_TEMPLATE,
            thread_id,
            subagent_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn resume_tui_subagent(
    thread_id: &str,
    subagent_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentResume");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_subagent(
            TUI_THREAD_SUBAGENT_RESUME_ROUTE_TEMPLATE,
            thread_id,
            subagent_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn assign_tui_subagent(
    thread_id: &str,
    subagent_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentAssign");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_subagent(
            TUI_THREAD_SUBAGENT_ASSIGN_ROUTE_TEMPLATE,
            thread_id,
            subagent_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn propagate_tui_subagent_cancellation(
    thread_id: &str,
    body: Map<String, Value>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let body = tui_subagent_control_body(body, "OperatorControl.SubagentCancel");
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread(
            TUI_THREAD_SUBAGENT_CANCEL_PROPAGATE_ROUTE_TEMPLATE,
            thread_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

fn tui_subagent_control_body(mut body: Map<String, Value>, event_kind: &str) -> Map<String, Value> {
    body.entry("source".to_string())
        .or_insert_with(|| Value::String("cli_tui".to_string()));
    body.entry("actor".to_string())
        .or_insert_with(|| Value::String("operator".to_string()));
    body.entry("event_kind".to_string())
        .or_insert_with(|| Value::String(event_kind.to_string()));
    body.entry("component_kind".to_string())
        .or_insert_with(|| Value::String("subagent_lifecycle".to_string()));
    body
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

pub(crate) async fn invoke_tui_coding_tool(
    thread_id: &str,
    tool_id: &str,
    input: Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let route = route_with_thread(TUI_CODING_TOOL_INVOKE_ROUTE_TEMPLATE, thread_id)
        .replace("{tool_id}", tool_id);
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route,
        Some(serde_json::json!({
            "source": "cli_tui",
            "workflow_node_id": format!("runtime.coding-tool.{}", safe_id(tool_id)),
            "component_kind": "coding_tool",
            "input": input,
        })),
    )
    .await
}

pub(crate) async fn list_tui_workspace_snapshots(
    thread_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_thread(TUI_SNAPSHOT_LIST_ROUTE_TEMPLATE, thread_id),
        None,
    )
    .await
}

pub(crate) async fn preview_tui_workspace_restore(
    thread_id: &str,
    snapshot_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_snapshot(TUI_RESTORE_PREVIEW_ROUTE_TEMPLATE, thread_id, snapshot_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "component_kind": "restore_gate",
            "workflow_node_id": "runtime.restore-gate.tui-preview",
        })),
    )
    .await
}

pub(crate) async fn apply_tui_workspace_restore(
    thread_id: &str,
    snapshot_id: &str,
    allow_conflicts: bool,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_snapshot(TUI_RESTORE_APPLY_ROUTE_TEMPLATE, thread_id, snapshot_id),
        Some(serde_json::json!({
            "source": "cli_tui",
            "actor": "operator",
            "component_kind": "restore_gate",
            "workflow_node_id": "runtime.restore-gate.tui-apply",
            "approval_granted": true,
            "approvalGranted": true,
            "allow_conflicts": allow_conflicts,
            "allowConflicts": allow_conflicts,
            "override_conflicts": allow_conflicts,
            "overrideConflicts": allow_conflicts,
        })),
    )
    .await
}

pub(crate) async fn execute_tui_diagnostics_repair_decision(
    thread_id: &str,
    decision_id: &str,
    action: &str,
    message: Option<&str>,
    approved: bool,
    allow_conflicts: bool,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut body = serde_json::Map::new();
    body.insert("source".to_string(), Value::String("cli_tui".to_string()));
    body.insert("actor".to_string(), Value::String("operator".to_string()));
    body.insert(
        "component_kind".to_string(),
        Value::String("lsp_diagnostics_repair".to_string()),
    );
    body.insert(
        "workflow_node_id".to_string(),
        Value::String(format!(
            "runtime.lsp-diagnostics.repair.{}",
            safe_id(action)
        )),
    );
    body.insert("action".to_string(), Value::String(action.to_string()));
    body.insert(
        "decision_id".to_string(),
        Value::String(decision_id.to_string()),
    );
    body.insert("approval_granted".to_string(), Value::Bool(approved));
    body.insert("approvalGranted".to_string(), Value::Bool(approved));
    body.insert("approved".to_string(), Value::Bool(approved));
    body.insert("confirm".to_string(), Value::Bool(approved));
    body.insert(
        "operatorOverrideApproved".to_string(),
        Value::Bool(approved),
    );
    body.insert(
        "operator_override_approved".to_string(),
        Value::Bool(approved),
    );
    body.insert("allow_conflicts".to_string(), Value::Bool(allow_conflicts));
    body.insert("allowConflicts".to_string(), Value::Bool(allow_conflicts));
    body.insert(
        "override_conflicts".to_string(),
        Value::Bool(allow_conflicts),
    );
    body.insert(
        "overrideConflicts".to_string(),
        Value::Bool(allow_conflicts),
    );
    if let Some(message) = message.filter(|value| !value.trim().is_empty()) {
        body.insert("message".to_string(), Value::String(message.to_string()));
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_thread_and_diagnostics_repair_decision(
            TUI_THREAD_DIAGNOSTICS_REPAIR_DECISION_EXECUTE_ROUTE_TEMPLATE,
            thread_id,
            decision_id,
        ),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn list_tui_jobs_for_thread(
    thread: &Value,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Vec<Value>> {
    let thread_id = json_path_string(thread, "/thread_id");
    let agent_id = json_path_string(thread, "/agent_id")
        .or_else(|| json_path_string(thread, "/agentId"))
        .or_else(|| json_path_string(thread, "/session_id"))
        .or_else(|| json_path_string(thread, "/sessionId"));
    let mut route = TUI_JOB_LIST_ROUTE.to_string();
    if let Some(agent_id) = agent_id.as_deref().filter(|value| !value.trim().is_empty()) {
        route.push_str(&format!("?agentId={agent_id}"));
    }
    let value = daemon_request(Some(endpoint), token, Method::GET, &route, None).await?;
    let jobs = value
        .as_array()
        .ok_or_else(|| anyhow!("daemon job list did not return an array"))?;
    Ok(jobs
        .iter()
        .filter(|job| {
            let job_thread_id =
                json_path_string(job, "/threadId").or_else(|| json_path_string(job, "/thread_id"));
            match (thread_id.as_deref(), job_thread_id.as_deref()) {
                (Some(expected), Some(actual)) => actual == expected,
                _ => true,
            }
        })
        .cloned()
        .collect())
}

pub(crate) async fn fetch_tui_job(
    job_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_job(TUI_JOB_ROUTE_TEMPLATE, job_id),
        None,
    )
    .await
}

pub(crate) async fn cancel_tui_job(
    job_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_job(TUI_JOB_CANCEL_ROUTE_TEMPLATE, job_id),
        None,
    )
    .await
}

pub(crate) async fn fetch_tui_run(
    run_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_run(TUI_RUN_ROUTE_TEMPLATE, run_id),
        None,
    )
    .await
}

pub(crate) async fn cancel_tui_run(
    run_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_run(TUI_RUN_CANCEL_ROUTE_TEMPLATE, run_id),
        None,
    )
    .await
}

pub(crate) async fn fetch_tui_run_trace(
    run_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_run(TUI_RUN_TRACE_ROUTE_TEMPLATE, run_id),
        None,
    )
    .await
}

pub(crate) async fn inspect_tui_run(
    run_id: &str,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    daemon_request(
        Some(endpoint),
        token,
        Method::GET,
        &route_with_run(TUI_RUN_INSPECT_ROUTE_TEMPLATE, run_id),
        None,
    )
    .await
}

pub(crate) async fn execute_tui_run_coding_tool_budget_recovery(
    run_id: &str,
    action: &str,
    thread_id: Option<&str>,
    approval_id: Option<&str>,
    endpoint: &str,
    token: Option<&str>,
) -> Result<Value> {
    let mut body = serde_json::Map::new();
    body.insert("source".to_string(), Value::String("cli_tui".to_string()));
    body.insert("actor".to_string(), Value::String("operator".to_string()));
    body.insert("action".to_string(), Value::String(action.to_string()));
    body.insert(
        "reason".to_string(),
        Value::String("coding_tool_budget_preflight_blocked".to_string()),
    );
    if let Some(thread_id) = thread_id.filter(|value| !value.trim().is_empty()) {
        body.insert("threadId".to_string(), Value::String(thread_id.to_string()));
        body.insert(
            "thread_id".to_string(),
            Value::String(thread_id.to_string()),
        );
    }
    if let Some(approval_id) = approval_id.filter(|value| !value.trim().is_empty()) {
        body.insert(
            "approvalId".to_string(),
            Value::String(approval_id.to_string()),
        );
        body.insert(
            "approval_id".to_string(),
            Value::String(approval_id.to_string()),
        );
    }
    daemon_request(
        Some(endpoint),
        token,
        Method::POST,
        &route_with_run(TUI_RUN_CODING_TOOL_BUDGET_RECOVERY_ROUTE_TEMPLATE, run_id),
        Some(Value::Object(body)),
    )
    .await
}

pub(crate) async fn replay_tui_run_events(
    run_id: &str,
    endpoint: &str,
    token: Option<&str>,
    last_event_id: Option<&str>,
) -> Result<TuiEventBatch> {
    let event_route = route_with_run(TUI_RUN_REPLAY_ROUTE_TEMPLATE, run_id);
    let event_url = runtime_event_url(endpoint, &event_route);
    let events = fetch_runtime_event_stream(&event_url, token, last_event_id, false).await?;
    Ok(TuiEventBatch {
        event_route,
        events,
    })
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
    let workspace_trust_rows = tui_workspace_trust_rows(&render.events, thread_id.as_deref());
    let job_rows = tui_job_rows(&render.jobs, thread_id.as_deref());
    let run_lifecycle_rows = tui_run_lifecycle_rows(&render.jobs, thread_id.as_deref());
    let cost_rows = tui_usage_delta_rows(&render.events, thread_id.as_deref());
    let context_rows = tui_context_pressure_rows(&render.events, thread_id.as_deref());
    let coding_tool_rows = tui_coding_tool_rows(&render.events, thread_id.as_deref());
    let usage_status = latest_usage_delta_status(&render.events, thread_id.as_deref())
        .unwrap_or_else(|| tui_usage_status(&render.thread, thread_id.as_deref()));

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
        "thread_id": thread_id.clone(),
        "current_turn_id": current_turn_id,
        "last_cursor": last_cursor,
        "last_event_id": last_event_id,
        "mode_status": tui_mode_status(&render.thread, current_turn_id.as_deref()),
        "usage_status": usage_status,
        "approval_rows": approval_rows,
        "approval_decisions": approval_decisions,
        "workspace_trust_rows": workspace_trust_rows,
        "job_rows": job_rows,
        "run_lifecycle_rows": run_lifecycle_rows,
        "cost_rows": cost_rows,
        "context_rows": context_rows,
        "coding_tool_rows": coding_tool_rows,
        "command_history": command_history,
        "validation_errors": [],
    })
}

pub(crate) fn tui_mode_status(thread: &Value, current_turn_id: Option<&str>) -> Value {
    let turn = selected_turn_value(thread, current_turn_id);
    let runtime_controls = thread.pointer("/runtime_controls");
    let model_controls = runtime_controls.and_then(|value| value.pointer("/model"));
    let model_route_decision = thread.pointer("/model_route_decision");
    serde_json::json!({
        "mode": json_path_string(turn.unwrap_or(thread), "/mode")
            .or_else(|| json_path_string(thread, "/runtime_controls/mode"))
            .or_else(|| json_path_string(thread, "/mode"))
            .unwrap_or_else(|| "agent".to_string()),
        "approval_mode": json_path_string(turn.unwrap_or(thread), "/approval_mode")
            .or_else(|| json_path_string(thread, "/runtime_controls/approvalMode"))
            .or_else(|| json_path_string(thread, "/runtime_controls/approval_mode"))
            .or_else(|| json_path_string(thread, "/approval_mode"))
            .unwrap_or_else(|| "suggest".to_string()),
        "trust_profile": json_path_string(thread, "/trust_profile")
            .unwrap_or_else(|| "local_private".to_string()),
        "thread_status": json_path_string(thread, "/status"),
        "current_turn_status": turn.and_then(|value| json_path_string(value, "/status")),
        "current_turn_id": current_turn_id,
        "requested_model": json_path_string(thread, "/requested_model")
            .or_else(|| model_controls.and_then(|value| json_path_string(value, "/id"))),
        "selected_model": json_path_string(thread, "/selected_model")
            .or_else(|| json_path_string(thread, "/model_route"))
            .or_else(|| model_controls.and_then(|value| json_path_string(value, "/selectedModel"))),
        "model_route_id": json_path_string(thread, "/model_route_id")
            .or_else(|| model_controls.and_then(|value| json_path_string(value, "/routeId"))),
        "model_route_receipt_id": json_path_string(thread, "/model_route_receipt_id")
            .or_else(|| model_controls.and_then(|value| json_path_string(value, "/receiptId"))),
        "model_route_decision_id": model_route_decision
            .and_then(|value| json_path_string(value, "/decisionId")),
        "reasoning_effort": json_path_string(thread, "/reasoning_effort")
            .or_else(|| model_route_decision.and_then(|value| json_path_string(value, "/reasoningEffort")))
            .or_else(|| model_controls.and_then(|value| json_path_string(value, "/reasoningEffort"))),
        "workflow_graph_id": json_path_string(thread, "/workflow_graph_id")
            .or_else(|| model_controls.and_then(|value| json_path_string(value, "/workflowGraphId"))),
        "workflow_node_id": model_controls
            .and_then(|value| json_path_string(value, "/workflowNodeId"))
            .unwrap_or_else(|| "runtime.model-router".to_string()),
        "source": "daemon_thread",
    })
}

pub(crate) fn tui_usage_status(thread: &Value, fallback_thread_id: Option<&str>) -> Value {
    let usage = thread
        .pointer("/usage_telemetry")
        .or_else(|| thread.pointer("/usageTelemetry"))
        .or_else(|| thread.pointer("/runtime_usage"))
        .or_else(|| thread.pointer("/runtimeUsage"))
        .or_else(|| thread.pointer("/usage"));
    let status = usage.unwrap_or(thread);
    let thread_id = json_path_string(status, "/thread_id")
        .or_else(|| json_path_string(status, "/threadId"))
        .or_else(|| json_path_string(thread, "/thread_id"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let total_tokens = json_path_string(status, "/total_tokens")
        .or_else(|| json_path_string(status, "/totalTokens"))
        .unwrap_or_else(|| "0".to_string());
    let cost_estimate = json_path_string(status, "/estimated_cost_usd")
        .or_else(|| json_path_string(status, "/estimatedCostUsd"))
        .unwrap_or_else(|| "0".to_string());
    let context_pressure = json_path_string(status, "/context_pressure")
        .or_else(|| json_path_string(status, "/contextPressure"))
        .unwrap_or_else(|| "0".to_string());
    let context_status = json_path_string(status, "/context_pressure_status")
        .or_else(|| json_path_string(status, "/contextPressureStatus"))
        .unwrap_or_else(|| "nominal".to_string());
    serde_json::json!({
        "schema_version": json_path_string(status, "/schema_version")
            .or_else(|| json_path_string(status, "/schemaVersion"))
            .unwrap_or_else(|| "ioi.runtime.usage-telemetry.v1".to_string()),
        "object": "ioi.runtime_usage_tui_status",
        "scope": json_path_string(status, "/scope").unwrap_or_else(|| "thread".to_string()),
        "status": context_status,
        "thread_id": thread_id,
        "usage_total_tokens": total_tokens,
        "usage_input_tokens": json_path_string(status, "/input_tokens")
            .or_else(|| json_path_string(status, "/inputTokens"))
            .unwrap_or_else(|| "0".to_string()),
        "usage_output_tokens": json_path_string(status, "/output_tokens")
            .or_else(|| json_path_string(status, "/outputTokens"))
            .unwrap_or_else(|| "0".to_string()),
        "usage_cost_estimate_usd": cost_estimate,
        "usage_context_pressure": context_pressure,
        "usage_context_pressure_status": json_path_string(status, "/context_pressure_status")
            .or_else(|| json_path_string(status, "/contextPressureStatus"))
            .unwrap_or_else(|| "nominal".to_string()),
        "usage_run_count": json_path_string(status, "/source_counts/runs")
            .or_else(|| json_path_string(status, "/sourceCounts/runs"))
            .unwrap_or_else(|| "0".to_string()),
        "usage_subagent_count": json_path_string(status, "/source_counts/subagents")
            .or_else(|| json_path_string(status, "/sourceCounts/subagents"))
            .unwrap_or_else(|| "0".to_string()),
        "workflow_node_id": "runtime.usage-telemetry",
        "message": format!("tokens={total_tokens} cost=${cost_estimate} context={context_pressure}"),
        "source": "daemon_thread",
    })
}

pub(crate) fn tui_cost_rows(status: &Value, fallback_thread_id: Option<&str>) -> Vec<Value> {
    let usage = tui_usage_status(status, fallback_thread_id);
    let thread_id = json_path_string(&usage, "/thread_id")
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let workflow_node_id = "runtime.usage-telemetry";
    vec![serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "surface": "tui",
        "id": format!(
            "tui-cost-{}",
            thread_id.clone().unwrap_or_else(|| "detached".to_string())
        ),
        "row_kind": "cost_status",
        "status": "current",
        "command": "cost",
        "raw_input": "/cost",
        "thread_id": thread_id,
        "scope": json_path_string(&usage, "/scope").unwrap_or_else(|| "thread".to_string()),
        "usage_total_tokens": json_path_string(&usage, "/usage_total_tokens")
            .unwrap_or_else(|| "0".to_string()),
        "usage_input_tokens": json_path_string(&usage, "/usage_input_tokens")
            .unwrap_or_else(|| "0".to_string()),
        "usage_output_tokens": json_path_string(&usage, "/usage_output_tokens")
            .unwrap_or_else(|| "0".to_string()),
        "usage_cost_estimate_usd": json_path_string(&usage, "/usage_cost_estimate_usd")
            .unwrap_or_else(|| "0".to_string()),
        "usage_context_pressure": json_path_string(&usage, "/usage_context_pressure")
            .unwrap_or_else(|| "0".to_string()),
        "usage_context_pressure_status": json_path_string(&usage, "/usage_context_pressure_status")
            .unwrap_or_else(|| "nominal".to_string()),
        "usage_run_count": json_path_string(&usage, "/usage_run_count")
            .unwrap_or_else(|| "0".to_string()),
        "usage_subagent_count": json_path_string(&usage, "/usage_subagent_count")
            .unwrap_or_else(|| "0".to_string()),
        "workflow_node_id": workflow_node_id,
        "message": json_path_string(&usage, "/message"),
        "routes": {
            "usage": fallback_thread_id
                .map(|thread_id| route_with_thread(TUI_THREAD_USAGE_ROUTE_TEMPLATE, thread_id)),
            "context_budget": fallback_thread_id
                .map(|thread_id| route_with_thread(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE, thread_id)),
            "compaction_policy": fallback_thread_id
                .map(|thread_id| route_with_thread(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE, thread_id)),
        },
        "tui_reopen": {
            "command": "ioi agent tui",
            "args": tui_reopen_args(fallback_thread_id, None),
            "thread_id": fallback_thread_id,
        },
        "react_flow": {
            "workflow_node_id": workflow_node_id,
            "thread_id": fallback_thread_id,
        }
    })]
}

pub(crate) fn tui_usage_delta_rows(
    events: &[Value],
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    let Some(event) = latest_tui_usage_delta_event(events) else {
        return Vec::new();
    };
    let Some(usage_status) = latest_usage_delta_status(events, fallback_thread_id) else {
        return Vec::new();
    };
    let mut rows = tui_cost_rows(&usage_status, fallback_thread_id);
    let seq = event.pointer("/seq").and_then(Value::as_u64);
    if let Some(object) = rows.first_mut().and_then(Value::as_object_mut) {
        let thread_id = json_path_string(event, "/thread_id")
            .or_else(|| json_path_string(&usage_status, "/thread_id"))
            .or_else(|| fallback_thread_id.map(ToOwned::to_owned))
            .unwrap_or_else(|| "detached".to_string());
        object.insert(
            "id".to_string(),
            Value::String(format!("tui-usage-delta-{thread_id}")),
        );
        object.insert("status".to_string(), Value::String("running".to_string()));
        object.insert("command".to_string(), Value::String("events".to_string()));
        object.insert(
            "raw_input".to_string(),
            Value::String("/events".to_string()),
        );
        object.insert(
            "label".to_string(),
            Value::String("Streaming usage".to_string()),
        );
        if let Some(stage) = json_path_string(&usage_status, "/stage") {
            object.insert("usage_delta_stage".to_string(), Value::String(stage));
        }
        if let Some(index) = json_path_string(&usage_status, "/delta_index") {
            object.insert("usage_delta_index".to_string(), Value::String(index));
        }
        if let Some(total) = json_path_string(&usage_status, "/delta_total") {
            object.insert("usage_delta_total".to_string(), Value::String(total));
        }
        if let Some(event_id) = json_path_string(event, "/event_id") {
            object.insert("event_id".to_string(), Value::String(event_id));
        }
        if let Some(cursor) = tui_event_cursor(event, seq) {
            object.insert("cursor".to_string(), Value::String(cursor));
        }
        if let Some(seq) = seq {
            object.insert("seq".to_string(), Value::Number(seq.into()));
        }
        object.insert(
            "message".to_string(),
            Value::String(
                json_path_string(&usage_status, "/summary").unwrap_or_else(|| {
                    format!(
                        "streaming tokens={} context={}",
                        json_path_string(&usage_status, "/total_tokens")
                            .or_else(|| json_path_string(&usage_status, "/totalTokens"))
                            .unwrap_or_else(|| "0".to_string()),
                        json_path_string(&usage_status, "/context_pressure")
                            .or_else(|| json_path_string(&usage_status, "/contextPressure"))
                            .unwrap_or_else(|| "0".to_string())
                    )
                }),
            ),
        );
    }
    rows
}

pub(crate) fn tui_context_pressure_rows(
    events: &[Value],
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    let Some(event) = latest_tui_context_pressure_event(events) else {
        return Vec::new();
    };
    let payload = event_payload_summary(event);
    let seq = event.pointer("/seq").and_then(Value::as_u64);
    let thread_id = json_path_string(payload, "/thread_id")
        .or_else(|| json_path_string(payload, "/threadId"))
        .or_else(|| json_path_string(event, "/thread_id"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let pressure_status = json_path_string(payload, "/usage_context_pressure_status")
        .or_else(|| json_path_string(payload, "/usageContextPressureStatus"))
        .or_else(|| json_path_string(payload, "/context_pressure_status"))
        .or_else(|| json_path_string(payload, "/contextPressureStatus"))
        .unwrap_or_else(|| "nominal".to_string());
    let status = match pressure_status.as_str() {
        "high" => "blocked",
        "elevated" => "warn",
        _ => "ok",
    };
    vec![serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "surface": "tui",
        "id": format!(
            "tui-context-pressure-{}",
            thread_id.clone().unwrap_or_else(|| "detached".to_string())
        ),
        "row_kind": "context_budget",
        "status": status,
        "command": "events",
        "raw_input": "/events",
        "label": "Context pressure",
        "thread_id": thread_id,
        "turn_id": json_path_string(payload, "/turn_id")
            .or_else(|| json_path_string(payload, "/turnId"))
            .or_else(|| json_path_string(event, "/turn_id")),
        "usage_total_tokens": json_path_string(payload, "/usage_total_tokens")
            .or_else(|| json_path_string(payload, "/usageTotalTokens"))
            .or_else(|| json_path_string(payload, "/total_tokens"))
            .or_else(|| json_path_string(payload, "/totalTokens"))
            .unwrap_or_else(|| "0".to_string()),
        "usage_cost_estimate_usd": json_path_string(payload, "/usage_cost_estimate_usd")
            .or_else(|| json_path_string(payload, "/usageCostEstimateUsd"))
            .or_else(|| json_path_string(payload, "/estimated_cost_usd"))
            .or_else(|| json_path_string(payload, "/estimatedCostUsd"))
            .unwrap_or_else(|| "0".to_string()),
        "usage_context_pressure": json_path_string(payload, "/usage_context_pressure")
            .or_else(|| json_path_string(payload, "/usageContextPressure"))
            .or_else(|| json_path_string(payload, "/context_pressure"))
            .or_else(|| json_path_string(payload, "/contextPressure"))
            .unwrap_or_else(|| "0".to_string()),
        "usage_context_pressure_status": pressure_status,
        "context_budget_status": status,
        "summary": json_path_string(payload, "/summary"),
        "workflow_node_id": json_path_string(event, "/workflow_node_id")
            .or_else(|| json_path_string(payload, "/workflow_node_id"))
            .or_else(|| json_path_string(payload, "/workflowNodeId"))
            .unwrap_or_else(|| "runtime.context-budget".to_string()),
        "event_id": json_path_string(event, "/event_id"),
        "seq": seq,
        "cursor": tui_event_cursor(event, seq),
        "routes": {
            "usage": fallback_thread_id
                .map(|thread_id| route_with_thread(TUI_THREAD_USAGE_ROUTE_TEMPLATE, thread_id)),
            "context_budget": fallback_thread_id
                .map(|thread_id| route_with_thread(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE, thread_id)),
            "compaction_policy": fallback_thread_id
                .map(|thread_id| route_with_thread(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE, thread_id)),
        },
        "react_flow": {
            "workflow_node_id": "runtime.context-budget",
            "thread_id": fallback_thread_id,
        }
    })]
}

pub(crate) fn tui_coding_tool_rows(
    events: &[Value],
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    events
        .iter()
        .filter(|event| is_tui_coding_tool_budget_block_event(event))
        .map(|event| tui_coding_tool_budget_row(event, fallback_thread_id))
        .collect()
}

fn tui_coding_tool_budget_row(event: &Value, fallback_thread_id: Option<&str>) -> Value {
    let null = Value::Null;
    let payload = event_payload_summary(event);
    let result = payload.pointer("/result").unwrap_or(&null);
    let result_summary = payload
        .pointer("/result_summary")
        .or_else(|| payload.pointer("/resultSummary"))
        .unwrap_or(&null);
    let error = payload
        .pointer("/error")
        .or_else(|| result.pointer("/error"))
        .unwrap_or(&null);
    let error_details = error.pointer("/details").unwrap_or(&null);
    let context_budget = payload
        .pointer("/context_budget")
        .or_else(|| payload.pointer("/contextBudget"))
        .or_else(|| result.pointer("/context_budget"))
        .or_else(|| result.pointer("/contextBudget"))
        .or_else(|| error_details.pointer("/context_budget"))
        .or_else(|| error_details.pointer("/contextBudget"))
        .unwrap_or(&null);
    let policy_decision = context_budget
        .pointer("/policy_decision")
        .or_else(|| context_budget.pointer("/policyDecision"))
        .unwrap_or(&null);
    let budget_usage_telemetry = payload
        .pointer("/budget_usage_telemetry")
        .or_else(|| payload.pointer("/budgetUsageTelemetry"))
        .or_else(|| result.pointer("/budget_usage_telemetry"))
        .or_else(|| result.pointer("/budgetUsageTelemetry"))
        .or_else(|| error_details.pointer("/budget_usage_telemetry"))
        .or_else(|| error_details.pointer("/budgetUsageTelemetry"))
        .or_else(|| context_budget.pointer("/usage_telemetry"))
        .or_else(|| context_budget.pointer("/usageTelemetry"))
        .unwrap_or(&null);
    let usage_summary = context_budget
        .pointer("/usage_summary")
        .or_else(|| context_budget.pointer("/usageSummary"))
        .or_else(|| budget_usage_telemetry.pointer("/usage_summary"))
        .or_else(|| budget_usage_telemetry.pointer("/usageSummary"))
        .unwrap_or(budget_usage_telemetry);
    let checks = context_budget
        .pointer("/checks")
        .or_else(|| policy_decision.pointer("/checks"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let violations = context_budget
        .pointer("/violations")
        .or_else(|| policy_decision.pointer("/violations"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let check_count = checks.as_array().map(|items| items.len()).unwrap_or(0);
    let violation_count = violations.as_array().map(|items| items.len()).unwrap_or(0);
    let seq = event.pointer("/seq").and_then(Value::as_u64);
    let cursor = tui_event_cursor(event, seq);
    let tool_name = json_path_string(payload, "/tool_name")
        .or_else(|| json_path_string(payload, "/toolName"))
        .or_else(|| json_path_string(payload, "/tool_id"))
        .or_else(|| json_path_string(payload, "/toolId"))
        .or_else(|| json_path_string(result, "/toolName"))
        .or_else(|| json_path_string(result, "/tool_name"))
        .or_else(|| json_path_string(error_details, "/toolId"))
        .or_else(|| json_path_string(error_details, "/tool_id"));
    let tool_call_id = json_path_string(payload, "/tool_call_id")
        .or_else(|| json_path_string(payload, "/toolCallId"))
        .or_else(|| json_path_string(result, "/tool_call_id"))
        .or_else(|| json_path_string(result, "/toolCallId"))
        .or_else(|| json_path_string(error_details, "/tool_call_id"))
        .or_else(|| json_path_string(error_details, "/toolCallId"))
        .or_else(|| json_path_string(event, "/tool_call_id"))
        .or_else(|| json_path_string(event, "/toolCallId"));
    let tool_key = tool_name
        .clone()
        .or_else(|| tool_call_id.clone())
        .unwrap_or_else(|| "coding_tool".to_string());
    let thread_id = json_path_string(payload, "/thread_id")
        .or_else(|| json_path_string(payload, "/threadId"))
        .or_else(|| json_path_string(event, "/thread_id"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let turn_id = json_path_string(payload, "/turn_id")
        .or_else(|| json_path_string(payload, "/turnId"))
        .or_else(|| json_path_string(event, "/turn_id"));
    let run_id = json_path_string(payload, "/run_id")
        .or_else(|| json_path_string(payload, "/runId"))
        .or_else(|| {
            turn_id.as_deref().map(|turn_id| {
                if let Some(suffix) = turn_id.strip_prefix("turn_") {
                    format!("run_{suffix}")
                } else {
                    format!("run_{turn_id}")
                }
            })
        });
    let workflow_graph_id = json_path_string(event, "/workflow_graph_id")
        .or_else(|| json_path_string(payload, "/workflow_graph_id"))
        .or_else(|| json_path_string(payload, "/workflowGraphId"));
    let workflow_node_id = json_path_string(event, "/workflow_node_id")
        .or_else(|| json_path_string(payload, "/workflow_node_id"))
        .or_else(|| json_path_string(payload, "/workflowNodeId"))
        .unwrap_or_else(|| format!("runtime.coding-tool-budget.{}", safe_id(&tool_key)));
    let budget_status = json_path_string(payload, "/budget_status")
        .or_else(|| json_path_string(payload, "/budgetStatus"))
        .or_else(|| json_path_string(result, "/budget_status"))
        .or_else(|| json_path_string(result, "/budgetStatus"))
        .or_else(|| json_path_string(error_details, "/budget_status"))
        .or_else(|| json_path_string(error_details, "/budgetStatus"))
        .unwrap_or_else(|| "exceeded".to_string());
    let context_budget_status = json_path_string(payload, "/context_budget_status")
        .or_else(|| json_path_string(payload, "/contextBudgetStatus"))
        .or_else(|| json_path_string(result, "/context_budget_status"))
        .or_else(|| json_path_string(result, "/contextBudgetStatus"))
        .or_else(|| json_path_string(error_details, "/context_budget_status"))
        .or_else(|| json_path_string(error_details, "/contextBudgetStatus"))
        .or_else(|| json_path_string(context_budget, "/status"))
        .unwrap_or_else(|| "blocked".to_string());
    let budget_mode = json_path_string(payload, "/budget_mode")
        .or_else(|| json_path_string(payload, "/budgetMode"))
        .or_else(|| json_path_string(context_budget, "/mode"));
    let decision_id = json_path_string(payload, "/context_budget_decision_id")
        .or_else(|| json_path_string(payload, "/contextBudgetDecisionId"))
        .or_else(|| json_path_string(payload, "/budget_decision_id"))
        .or_else(|| json_path_string(payload, "/budgetDecisionId"))
        .or_else(|| json_path_string(context_budget, "/policy_decision_id"))
        .or_else(|| json_path_string(context_budget, "/policyDecisionId"))
        .or_else(|| json_path_string(policy_decision, "/policy_decision_id"))
        .or_else(|| json_path_string(policy_decision, "/policyDecisionId"));
    let reason = json_path_string(payload, "/reason")
        .or_else(|| json_path_string(payload, "/block_reason"))
        .or_else(|| json_path_string(payload, "/blockReason"))
        .or_else(|| json_path_string(result_summary, "/reason"))
        .or_else(|| json_path_string(error_details, "/reason"))
        .or_else(|| json_path_string(error, "/code"));
    let receipt_refs = event
        .pointer("/receipt_refs")
        .or_else(|| event.pointer("/receiptRefs"))
        .or_else(|| payload.pointer("/receipt_refs"))
        .or_else(|| payload.pointer("/receiptRefs"))
        .or_else(|| context_budget.pointer("/receipt_refs"))
        .or_else(|| context_budget.pointer("/receiptRefs"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let policy_decision_refs = event
        .pointer("/policy_decision_refs")
        .or_else(|| event.pointer("/policyDecisionRefs"))
        .or_else(|| payload.pointer("/policy_decision_refs"))
        .or_else(|| payload.pointer("/policyDecisionRefs"))
        .or_else(|| context_budget.pointer("/policy_decision_refs"))
        .or_else(|| context_budget.pointer("/policyDecisionRefs"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let row_id = format!(
        "tui-coding-tool-budget-{}-{}",
        safe_id(&tool_key),
        seq.unwrap_or(0)
    );
    let event_id = json_path_string(event, "/event_id");
    let usage_total_tokens = json_path_string(usage_summary, "/total_tokens")
        .or_else(|| json_path_string(usage_summary, "/totalTokens"))
        .unwrap_or_else(|| "0".to_string());
    let usage_cost_estimate_usd = json_path_string(usage_summary, "/estimated_cost_usd")
        .or_else(|| json_path_string(usage_summary, "/estimatedCostUsd"))
        .or_else(|| json_path_string(usage_summary, "/cost_estimate_usd"))
        .or_else(|| json_path_string(usage_summary, "/costEstimateUsd"))
        .unwrap_or_else(|| "0".to_string());
    let usage_context_pressure = json_path_string(usage_summary, "/context_pressure")
        .or_else(|| json_path_string(usage_summary, "/contextPressure"))
        .unwrap_or_else(|| "0".to_string());
    let usage_context_pressure_status = json_path_string(usage_summary, "/context_pressure_status")
        .or_else(|| json_path_string(usage_summary, "/contextPressureStatus"))
        .unwrap_or_else(|| "blocked".to_string());

    let mut row = Map::new();
    row.insert(
        "schema_version".to_string(),
        Value::String(TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION.to_string()),
    );
    row.insert("surface".to_string(), Value::String("tui".to_string()));
    row.insert("id".to_string(), Value::String(row_id));
    row.insert(
        "row_kind".to_string(),
        Value::String("coding_tool_budget".to_string()),
    );
    row.insert(
        "status".to_string(),
        Value::String(json_path_string(event, "/status").unwrap_or_else(|| "blocked".to_string())),
    );
    row.insert("command".to_string(), Value::String("run".to_string()));
    row.insert(
        "raw_input".to_string(),
        Value::String(match run_id.as_deref() {
            Some(run_id) => format!("/run recovery request {run_id}"),
            None => "/run recovery request".to_string(),
        }),
    );
    row.insert(
        "label".to_string(),
        Value::String(format!("Coding tool budget: {tool_key}")),
    );
    row.insert(
        "message".to_string(),
        json_path_string(payload, "/summary")
            .or_else(|| json_path_string(error, "/message"))
            .or_else(|| reason.clone())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    row.insert(
        "summary".to_string(),
        json_path_string(payload, "/summary")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    row.insert(
        "reason".to_string(),
        reason.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "thread_id".to_string(),
        thread_id.clone().map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "turn_id".to_string(),
        turn_id.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "run_id".to_string(),
        run_id.clone().map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "workflow_graph_id".to_string(),
        workflow_graph_id
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    row.insert(
        "workflow_node_id".to_string(),
        Value::String(workflow_node_id.clone()),
    );
    row.insert(
        "tool_name".to_string(),
        tool_name.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "tool_call_id".to_string(),
        tool_call_id.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert("budget_status".to_string(), Value::String(budget_status));
    row.insert(
        "context_budget_status".to_string(),
        Value::String(context_budget_status),
    );
    row.insert(
        "context_budget_mode".to_string(),
        budget_mode.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "context_budget_decision_id".to_string(),
        decision_id.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "coding_tool_budget_check_count".to_string(),
        Value::Number((check_count as u64).into()),
    );
    row.insert(
        "coding_tool_budget_violation_count".to_string(),
        Value::Number((violation_count as u64).into()),
    );
    row.insert(
        "usage_total_tokens".to_string(),
        Value::String(usage_total_tokens),
    );
    row.insert(
        "usage_cost_estimate_usd".to_string(),
        Value::String(usage_cost_estimate_usd),
    );
    row.insert(
        "usage_context_pressure".to_string(),
        Value::String(usage_context_pressure),
    );
    row.insert(
        "usage_context_pressure_status".to_string(),
        Value::String(usage_context_pressure_status),
    );
    row.insert("context_budget".to_string(), context_budget.clone());
    row.insert(
        "budget_usage_telemetry".to_string(),
        budget_usage_telemetry.clone(),
    );
    row.insert("result_summary".to_string(), result_summary.clone());
    row.insert("error".to_string(), error.clone());
    row.insert("checks".to_string(), checks);
    row.insert("violations".to_string(), violations);
    row.insert("mutation_blocked".to_string(), Value::Bool(true));
    row.insert("receipt_refs".to_string(), receipt_refs);
    row.insert("policy_decision_refs".to_string(), policy_decision_refs);
    row.insert(
        "event_id".to_string(),
        event_id.clone().map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "event_kind".to_string(),
        json_path_string(event, "/event_kind")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    row.insert(
        "source_event_kind".to_string(),
        json_path_string(event, "/source_event_kind")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    row.insert(
        "component_kind".to_string(),
        json_path_string(event, "/component_kind")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    row.insert(
        "seq".to_string(),
        seq.map(|value| Value::Number(value.into()))
            .unwrap_or(Value::Null),
    );
    row.insert(
        "sequence".to_string(),
        seq.map(|value| Value::Number(value.into()))
            .unwrap_or(Value::Null),
    );
    row.insert(
        "cursor".to_string(),
        cursor.clone().map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "tui_reopen".to_string(),
        serde_json::json!({
            "command": "ioi agent tui",
            "args": tui_reopen_args(thread_id.as_deref(), seq),
            "thread_id": thread_id,
            "since_seq": seq,
            "last_event_id": event_id,
        }),
    );
    row.insert(
        "routes".to_string(),
        serde_json::json!({
            "recovery": run_id
                .as_deref()
                .map(|run_id| route_with_run(TUI_RUN_CODING_TOOL_BUDGET_RECOVERY_ROUTE_TEMPLATE, run_id)),
        }),
    );
    row.insert(
        "react_flow".to_string(),
        serde_json::json!({
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "event_id": json_path_string(event, "/event_id"),
            "cursor": cursor,
        }),
    );
    Value::Object(row)
}

pub(crate) fn tui_context_rows(
    usage: &Value,
    context_budget: &Value,
    compaction_policy: &Value,
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    let usage_status = tui_usage_status(usage, fallback_thread_id);
    let thread_id = json_path_string(&usage_status, "/thread_id")
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let context_pressure = json_path_string(&usage_status, "/usage_context_pressure")
        .unwrap_or_else(|| "0".to_string());
    let context_pressure_status = json_path_string(&usage_status, "/usage_context_pressure_status")
        .unwrap_or_else(|| "nominal".to_string());
    let budget_status =
        json_path_string(context_budget, "/status").unwrap_or_else(|| "ok".to_string());
    let budget_node_id = json_path_string(context_budget, "/workflow_node_id")
        .or_else(|| json_path_string(context_budget, "/workflowNodeId"))
        .unwrap_or_else(|| "runtime.context-budget".to_string());
    let compaction_status =
        json_path_string(compaction_policy, "/status").unwrap_or_else(|| "ok".to_string());
    let compaction_action =
        json_path_string(compaction_policy, "/action").unwrap_or_else(|| "noop".to_string());
    let compaction_node_id = json_path_string(compaction_policy, "/workflow_node_id")
        .or_else(|| json_path_string(compaction_policy, "/workflowNodeId"))
        .unwrap_or_else(|| "runtime.compaction-policy".to_string());
    vec![
        serde_json::json!({
            "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
            "surface": "tui",
            "id": format!(
                "tui-context-budget-{}",
                thread_id.clone().unwrap_or_else(|| "detached".to_string())
            ),
            "row_kind": "context_budget",
            "status": budget_status,
            "command": "context",
            "raw_input": "/context",
            "thread_id": thread_id,
            "scope": json_path_string(context_budget, "/scope").unwrap_or_else(|| "thread".to_string()),
            "usage_total_tokens": json_path_string(&usage_status, "/usage_total_tokens")
                .unwrap_or_else(|| "0".to_string()),
            "usage_cost_estimate_usd": json_path_string(&usage_status, "/usage_cost_estimate_usd")
                .unwrap_or_else(|| "0".to_string()),
            "usage_context_pressure": context_pressure,
            "usage_context_pressure_status": context_pressure_status,
            "context_budget_status": json_path_string(context_budget, "/status"),
            "context_budget_mode": json_path_string(context_budget, "/mode"),
            "context_budget_decision_id": json_path_string(context_budget, "/policy_decision_id")
                .or_else(|| json_path_string(context_budget, "/policyDecisionId")),
            "summary": json_path_string(context_budget, "/summary"),
            "workflow_node_id": budget_node_id,
            "receipt_refs": context_budget
                .pointer("/receipt_refs")
                .or_else(|| context_budget.pointer("/receiptRefs"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            "policy_decision_refs": context_budget
                .pointer("/policy_decision_refs")
                .or_else(|| context_budget.pointer("/policyDecisionRefs"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            "event_id": json_path_string(context_budget, "/event_id")
                .or_else(|| json_path_string(context_budget, "/eventId")),
            "seq": context_budget.pointer("/seq").and_then(Value::as_u64),
            "routes": {
                "usage": fallback_thread_id
                    .map(|thread_id| route_with_thread(TUI_THREAD_USAGE_ROUTE_TEMPLATE, thread_id)),
                "context_budget": fallback_thread_id
                    .map(|thread_id| route_with_thread(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE, thread_id)),
                "compaction_policy": fallback_thread_id
                    .map(|thread_id| route_with_thread(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE, thread_id)),
            },
            "react_flow": {
                "workflow_node_id": json_path_string(context_budget, "/workflow_node_id")
                    .or_else(|| json_path_string(context_budget, "/workflowNodeId"))
                    .unwrap_or_else(|| "runtime.context-budget".to_string()),
                "thread_id": fallback_thread_id,
            }
        }),
        serde_json::json!({
            "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
            "surface": "tui",
            "id": format!(
                "tui-compaction-policy-{}",
                fallback_thread_id.unwrap_or("detached")
            ),
            "row_kind": "compaction_policy",
            "status": compaction_status,
            "command": "context",
            "raw_input": "/context",
            "thread_id": fallback_thread_id,
            "turn_id": json_path_string(compaction_policy, "/turn_id")
                .or_else(|| json_path_string(compaction_policy, "/turnId")),
            "usage_context_pressure": json_path_string(&usage_status, "/usage_context_pressure")
                .unwrap_or_else(|| "0".to_string()),
            "usage_context_pressure_status": json_path_string(&usage_status, "/usage_context_pressure_status")
                .unwrap_or_else(|| "nominal".to_string()),
            "context_budget_status": json_path_string(compaction_policy, "/budget_status")
                .or_else(|| json_path_string(compaction_policy, "/budgetStatus")),
            "compaction_policy_status": json_path_string(compaction_policy, "/status"),
            "compaction_policy_action": compaction_action,
            "compaction_policy_decision_id": json_path_string(compaction_policy, "/policy_decision_id")
                .or_else(|| json_path_string(compaction_policy, "/policyDecisionId")),
            "compaction_executed": json_path_string(compaction_policy, "/compaction_executed")
                .or_else(|| json_path_string(compaction_policy, "/compactionExecuted"))
                .unwrap_or_else(|| "false".to_string()),
            "summary": json_path_string(compaction_policy, "/summary"),
            "workflow_node_id": compaction_node_id,
            "receipt_refs": compaction_policy
                .pointer("/receipt_refs")
                .or_else(|| compaction_policy.pointer("/receiptRefs"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            "policy_decision_refs": compaction_policy
                .pointer("/policy_decision_refs")
                .or_else(|| compaction_policy.pointer("/policyDecisionRefs"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            "event_id": json_path_string(compaction_policy, "/event_id")
                .or_else(|| json_path_string(compaction_policy, "/eventId")),
            "seq": compaction_policy.pointer("/seq").and_then(Value::as_u64),
            "routes": {
                "context_budget": fallback_thread_id
                    .map(|thread_id| route_with_thread(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE, thread_id)),
                "compaction_policy": fallback_thread_id
                    .map(|thread_id| route_with_thread(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE, thread_id)),
            },
            "react_flow": {
                "workflow_node_id": json_path_string(compaction_policy, "/workflow_node_id")
                    .or_else(|| json_path_string(compaction_policy, "/workflowNodeId"))
                    .unwrap_or_else(|| "runtime.compaction-policy".to_string()),
                "thread_id": fallback_thread_id,
            }
        }),
    ]
}

pub(crate) fn latest_usage_delta_status(
    events: &[Value],
    fallback_thread_id: Option<&str>,
) -> Option<Value> {
    let event = latest_tui_usage_delta_event(events)?;
    let payload = event_payload_summary(event);
    let mut status = payload.clone();
    if let Some(object) = status.as_object_mut() {
        if let Some(thread_id) = json_path_string(event, "/thread_id")
            .or_else(|| fallback_thread_id.map(ToOwned::to_owned))
        {
            object
                .entry("thread_id".to_string())
                .or_insert_with(|| Value::String(thread_id));
        }
        if let Some(turn_id) = json_path_string(event, "/turn_id") {
            object
                .entry("turn_id".to_string())
                .or_insert_with(|| Value::String(turn_id));
        }
        if let Some(event_id) = json_path_string(event, "/event_id") {
            object.insert("event_id".to_string(), Value::String(event_id));
        }
        if let Some(seq) = event.pointer("/seq").and_then(Value::as_u64) {
            object.insert("seq".to_string(), Value::Number(seq.into()));
        }
        if let Some(cursor) = tui_event_cursor(event, event.pointer("/seq").and_then(Value::as_u64))
        {
            object.insert("cursor".to_string(), Value::String(cursor));
        }
        object
            .entry("workflow_node_id".to_string())
            .or_insert_with(|| Value::String("runtime.usage-telemetry".to_string()));
    }
    Some(status)
}

pub(crate) fn tui_mcp_rows(status: &Value, fallback_thread_id: Option<&str>) -> Vec<Value> {
    let thread_id = json_path_string(status, "/thread_id")
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let event_id = json_path_string(status, "/event/event_id");
    let cursor = status.pointer("/event").and_then(|event| {
        let stream = json_path_string(event, "/event_stream_id")?;
        let seq = event.pointer("/seq")?.as_u64()?;
        Some(format!("{stream}:{seq}"))
    });
    let receipt_refs = status
        .pointer("/receipt_refs")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let policy_refs = status
        .pointer("/policy_decision_refs")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let object = json_path_string(status, "/object").unwrap_or_default();
    let tool_raw_input = if object == "ioi.runtime_mcp_tool_fetch" {
        "/mcp fetch"
    } else if object == "ioi.runtime_mcp_tool_search" {
        "/mcp search"
    } else {
        "/mcp tools"
    };
    let tool_operation = if object == "ioi.runtime_mcp_tool_fetch" {
        "fetch"
    } else if object == "ioi.runtime_mcp_tool_search" {
        "search"
    } else {
        "catalog"
    };
    let mut rows = Vec::new();
    if let Some(servers) = status.pointer("/servers").and_then(Value::as_array) {
        for server in servers {
            let server_id =
                json_path_string(server, "/id").unwrap_or_else(|| "mcp.unknown".to_string());
            let label = json_path_string(server, "/label")
                .or_else(|| json_path_string(server, "/name"))
                .unwrap_or_else(|| server_id.clone());
            rows.push(serde_json::json!({
                "id": format!("tui-mcp-server-{}", safe_id(&server_id)),
                "row_kind": "mcp_server",
                "status": json_path_string(server, "/status").unwrap_or_else(|| "configured".to_string()),
                "label": "MCP server",
                "command": "mcp",
                "raw_input": "/mcp",
                "message": format!("{} · {}", label, json_path_string(server, "/transport").unwrap_or_else(|| "stdio".to_string())),
                "thread_id": thread_id.clone(),
                "event_id": event_id.clone(),
                "cursor": cursor.clone(),
                "mcp_server_id": server_id,
                "mcp_tool_name": Value::Null,
                "mcp_operation": if json_path_string(server, "/status").unwrap_or_else(|| "configured".to_string()) == "disabled" { "disable" } else { "status" },
                "workflow_node_id": "runtime.mcp-manager",
                "receipt_refs": receipt_refs.clone(),
                "policy_decision_refs": policy_refs.clone(),
            }));
        }
    }
    if let Some(tools) = status.pointer("/tools").and_then(Value::as_array) {
        for tool in tools {
            let server_id = json_path_string(tool, "/server_id")
                .or_else(|| json_path_string(tool, "/serverId"))
                .unwrap_or_else(|| "mcp.unknown".to_string());
            let tool_name = json_path_string(tool, "/tool_name")
                .or_else(|| json_path_string(tool, "/toolName"))
                .unwrap_or_else(|| "unknown".to_string());
            rows.push(serde_json::json!({
                "id": format!("tui-mcp-tool-{}-{}", safe_id(&server_id), safe_id(&tool_name)),
                "row_kind": "mcp_tool",
                "status": json_path_string(tool, "/status").unwrap_or_else(|| "configured".to_string()),
                "label": "MCP tool",
                "command": "mcp",
                "raw_input": tool_raw_input,
                "message": format!("{} · {}", server_id, tool_name),
                "thread_id": thread_id.clone(),
                "event_id": event_id.clone(),
                "cursor": cursor.clone(),
                "mcp_server_id": server_id,
                "mcp_tool_name": tool_name,
                "mcp_operation": tool_operation,
                "workflow_node_id": json_path_string(tool, "/workflow_node_id")
                    .or_else(|| json_path_string(tool, "/workflowNodeId"))
                    .unwrap_or_else(|| "runtime.mcp-tool".to_string()),
                "receipt_refs": receipt_refs.clone(),
                "policy_decision_refs": policy_refs.clone(),
            }));
        }
    }
    if let Some(resources) = status.pointer("/resources").and_then(Value::as_array) {
        for resource in resources {
            let server_id = json_path_string(resource, "/server_id")
                .or_else(|| json_path_string(resource, "/serverId"))
                .unwrap_or_else(|| "mcp.unknown".to_string());
            let uri = json_path_string(resource, "/uri").unwrap_or_else(|| "resource".to_string());
            rows.push(serde_json::json!({
                "id": format!("tui-mcp-resource-{}-{}", safe_id(&server_id), safe_id(&uri)),
                "row_kind": "mcp_resource",
                "status": json_path_string(resource, "/status").unwrap_or_else(|| "configured".to_string()),
                "label": "MCP resource",
                "command": "mcp",
                "raw_input": "/mcp resources",
                "message": format!("{} · {}", server_id, uri),
                "thread_id": thread_id.clone(),
                "event_id": event_id.clone(),
                "cursor": cursor.clone(),
                "mcp_server_id": server_id,
                "mcp_tool_name": Value::Null,
                "mcp_resource_uri": uri,
                "mcp_operation": "resource_catalog",
                "workflow_node_id": json_path_string(resource, "/workflow_node_id")
                    .or_else(|| json_path_string(resource, "/workflowNodeId"))
                    .unwrap_or_else(|| "runtime.mcp-resource".to_string()),
                "receipt_refs": receipt_refs.clone(),
                "policy_decision_refs": policy_refs.clone(),
            }));
        }
    }
    if let Some(prompts) = status.pointer("/prompts").and_then(Value::as_array) {
        for prompt in prompts {
            let server_id = json_path_string(prompt, "/server_id")
                .or_else(|| json_path_string(prompt, "/serverId"))
                .unwrap_or_else(|| "mcp.unknown".to_string());
            let prompt_name =
                json_path_string(prompt, "/name").unwrap_or_else(|| "prompt".to_string());
            rows.push(serde_json::json!({
                "id": format!("tui-mcp-prompt-{}-{}", safe_id(&server_id), safe_id(&prompt_name)),
                "row_kind": "mcp_prompt",
                "status": json_path_string(prompt, "/status").unwrap_or_else(|| "configured".to_string()),
                "label": "MCP prompt",
                "command": "mcp",
                "raw_input": "/mcp prompts",
                "message": format!("{} · {}", server_id, prompt_name),
                "thread_id": thread_id.clone(),
                "event_id": event_id.clone(),
                "cursor": cursor.clone(),
                "mcp_server_id": server_id,
                "mcp_tool_name": Value::Null,
                "mcp_prompt_name": prompt_name,
                "mcp_operation": "prompt_catalog",
                "workflow_node_id": json_path_string(prompt, "/workflow_node_id")
                    .or_else(|| json_path_string(prompt, "/workflowNodeId"))
                    .unwrap_or_else(|| "runtime.mcp-prompt".to_string()),
                "receipt_refs": receipt_refs.clone(),
                "policy_decision_refs": policy_refs.clone(),
            }));
        }
    }
    if let Some(invocation) = status.pointer("/invocation").or_else(|| {
        if json_path_string(status, "/tool_call_id").is_some() {
            Some(status)
        } else {
            None
        }
    }) {
        let server_id = json_path_string(invocation, "/server_id")
            .or_else(|| json_path_string(invocation, "/serverId"))
            .unwrap_or_else(|| "mcp.unknown".to_string());
        let tool_name = json_path_string(invocation, "/tool_name")
            .or_else(|| json_path_string(invocation, "/toolName"))
            .unwrap_or_else(|| "unknown".to_string());
        let tool_call_id = json_path_string(invocation, "/tool_call_id")
            .or_else(|| json_path_string(invocation, "/toolCallId"))
            .unwrap_or_else(|| format!("{}:{}", server_id, tool_name));
        rows.push(serde_json::json!({
            "id": format!("tui-mcp-invoke-{}", safe_id(&tool_call_id)),
            "row_kind": "mcp_tool",
            "status": json_path_string(invocation, "/status").unwrap_or_else(|| "completed".to_string()),
            "label": "MCP invocation",
            "command": "mcp",
            "raw_input": "/mcp invoke",
            "message": json_path_string(status, "/summary")
                .unwrap_or_else(|| format!("{} · {}", server_id, tool_name)),
            "thread_id": thread_id.clone(),
            "event_id": event_id.clone(),
            "cursor": cursor.clone(),
            "mcp_server_id": server_id,
            "mcp_tool_name": tool_name,
            "mcp_tool_call_id": tool_call_id,
            "mcp_operation": "invoke",
            "workflow_node_id": json_path_string(status, "/event/workflow_node_id")
                .unwrap_or_else(|| "runtime.mcp-tool".to_string()),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_refs.clone(),
        }));
    }
    rows
}

pub(crate) fn tui_memory_rows(status: &Value, fallback_thread_id: Option<&str>) -> Vec<Value> {
    let thread_id = json_path_string(status, "/thread_id")
        .or_else(|| json_path_string(status, "/threadId"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let event_id = json_path_string(status, "/event/event_id");
    let cursor = status.pointer("/event").and_then(|event| {
        let stream = json_path_string(event, "/event_stream_id")?;
        let seq = event.pointer("/seq")?.as_u64()?;
        Some(format!("{stream}:{seq}"))
    });
    let receipt_refs = status
        .pointer("/receipt_refs")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let policy_refs = status
        .pointer("/policy_decision_refs")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    if let Some(projected_rows) = status
        .pointer("/memory_rows")
        .or_else(|| status.pointer("/rows"))
        .and_then(Value::as_array)
    {
        return projected_rows
            .iter()
            .map(|row| {
                let mut row = row.clone();
                if let Some(object) = row.as_object_mut() {
                    object.entry("thread_id").or_insert_with(|| {
                        thread_id.clone().map(Value::String).unwrap_or(Value::Null)
                    });
                    object.entry("event_id").or_insert_with(|| {
                        event_id.clone().map(Value::String).unwrap_or(Value::Null)
                    });
                    object.entry("cursor").or_insert_with(|| {
                        cursor.clone().map(Value::String).unwrap_or(Value::Null)
                    });
                    object
                        .entry("receipt_refs")
                        .or_insert_with(|| receipt_refs.clone());
                    object
                        .entry("policy_decision_refs")
                        .or_insert_with(|| policy_refs.clone());
                }
                row
            })
            .collect();
    }
    let policy = status.pointer("/policy").unwrap_or(&Value::Null);
    let memory_status = json_path_string(status, "/status").unwrap_or_else(|| "ready".to_string());
    let row_status = if memory_status == "ready" || memory_status == "completed" {
        "completed"
    } else {
        "blocked"
    };
    let mut rows = vec![
        serde_json::json!({
            "id": format!("tui-memory-status-{}", safe_id(thread_id.as_deref().unwrap_or("runtime"))),
            "row_kind": "memory_status",
            "status": row_status,
            "label": "Memory status",
            "command": "memory",
            "raw_input": "/memory status",
            "message": format!(
                "records={} injection={}",
                json_path_string(status, "/record_count")
                    .or_else(|| json_path_string(status, "/recordCount"))
                    .unwrap_or_else(|| "0".to_string()),
                json_path_string(status, "/injection_enabled")
                    .or_else(|| json_path_string(status, "/injectionEnabled"))
                    .unwrap_or_else(|| "true".to_string())
            ),
            "thread_id": thread_id.clone(),
            "event_id": event_id.clone(),
            "cursor": cursor.clone(),
            "memory_record_id": Value::Null,
            "memory_scope": json_path_string(policy, "/scope"),
            "memory_key": Value::Null,
            "memory_operation": "status",
            "workflow_node_id": "runtime.memory-manager",
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_refs.clone(),
        }),
        serde_json::json!({
            "id": format!(
                "tui-memory-policy-{}",
                safe_id(&json_path_string(policy, "/id").unwrap_or_else(|| thread_id.clone().unwrap_or_else(|| "runtime".to_string())))
            ),
            "row_kind": "memory_policy",
            "status": if policy.pointer("/disabled").and_then(Value::as_bool).unwrap_or(false) {
                "blocked"
            } else {
                "completed"
            },
            "label": "Memory policy",
            "command": "memory",
            "raw_input": "/memory policy",
            "message": format!(
                "scope={} readOnly={} approval={}",
                json_path_string(policy, "/scope").unwrap_or_else(|| "thread".to_string()),
                json_path_string(policy, "/readOnly").unwrap_or_else(|| "false".to_string()),
                json_path_string(policy, "/writeRequiresApproval").unwrap_or_else(|| "false".to_string())
            ),
            "thread_id": thread_id.clone(),
            "event_id": event_id.clone(),
            "cursor": cursor.clone(),
            "memory_record_id": Value::Null,
            "memory_scope": json_path_string(policy, "/scope"),
            "memory_key": Value::Null,
            "memory_operation": "policy",
            "workflow_node_id": "runtime.memory-manager.policy",
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_refs.clone(),
        }),
    ];
    let mutation_operation = json_path_string(status, "/memory_operation")
        .or_else(|| json_path_string(status, "/memoryOperation"));
    let mutation_record_id = status
        .pointer("/record")
        .and_then(|record| json_path_string(record, "/id"));
    if let (Some(operation), Some(record)) =
        (mutation_operation.as_deref(), status.pointer("/record"))
    {
        let record_id = mutation_record_id
            .clone()
            .unwrap_or_else(|| "memory".to_string());
        let raw_input = match operation {
            "edit" => "/memory edit",
            "delete" => "/memory delete",
            "write" => "/memory remember",
            _ => "/memory",
        };
        rows.push(serde_json::json!({
            "id": format!("tui-memory-record-{}", safe_id(&record_id)),
            "row_kind": "memory_record",
            "status": "completed",
            "label": match operation {
                "edit" => "Memory edit",
                "delete" => "Memory delete",
                "write" => "Memory write",
                _ => "Memory record",
            },
            "command": "memory",
            "raw_input": raw_input,
            "message": json_path_string(record, "/fact").unwrap_or_else(|| format!("memory {operation}")),
            "thread_id": json_path_string(record, "/threadId").or_else(|| thread_id.clone()),
            "event_id": event_id.clone(),
            "cursor": cursor.clone(),
            "memory_record_id": record_id,
            "memory_scope": json_path_string(record, "/scope"),
            "memory_key": json_path_string(record, "/memoryKey"),
            "memory_operation": operation,
            "workflow_node_id": json_path_string(record, "/workflowNodeId")
                .or_else(|| json_path_string(status, "/event/workflow_node_id"))
                .unwrap_or_else(|| "runtime.memory".to_string()),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_refs.clone(),
        }));
    }
    if let Some(records) = status.pointer("/records").and_then(Value::as_array) {
        for record in records {
            let record_id = json_path_string(record, "/id").unwrap_or_else(|| "memory".to_string());
            if mutation_record_id.as_deref() == Some(record_id.as_str())
                && mutation_operation.as_deref().unwrap_or("read") != "read"
            {
                continue;
            }
            rows.push(serde_json::json!({
                "id": format!("tui-memory-record-{}", safe_id(&record_id)),
                "row_kind": "memory_record",
                "status": "completed",
                "label": "Memory record",
                "command": "memory",
                "raw_input": "/memory show",
                "message": json_path_string(record, "/fact").unwrap_or_else(|| "[memory]".to_string()),
                "thread_id": json_path_string(record, "/threadId").or_else(|| thread_id.clone()),
                "event_id": event_id.clone(),
                "cursor": cursor.clone(),
                "memory_record_id": record_id,
                "memory_scope": json_path_string(record, "/scope"),
                "memory_key": json_path_string(record, "/memoryKey"),
                "memory_operation": "read",
                "workflow_node_id": json_path_string(record, "/workflowNodeId")
                    .unwrap_or_else(|| "runtime.memory".to_string()),
                "receipt_refs": receipt_refs.clone(),
                "policy_decision_refs": policy_refs.clone(),
            }));
        }
    }
    rows
}

pub(crate) fn tui_subagent_rows(status: &Value, fallback_thread_id: Option<&str>) -> Vec<Value> {
    let thread_id = json_path_string(status, "/thread_id")
        .or_else(|| json_path_string(status, "/threadId"))
        .or_else(|| json_path_string(status, "/parent_thread_id"))
        .or_else(|| json_path_string(status, "/parentThreadId"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let event_id = json_path_string(status, "/event/event_id")
        .or_else(|| json_path_string(status, "/event_id"));
    let cursor = status.pointer("/event").and_then(|event| {
        let stream = json_path_string(event, "/event_stream_id")?;
        let seq = event.pointer("/seq")?.as_u64()?;
        Some(format!("{stream}:{seq}"))
    });
    let receipt_refs = status
        .pointer("/receipt_refs")
        .or_else(|| status.pointer("/receiptRefs"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let policy_refs = status
        .pointer("/policy_decision_refs")
        .or_else(|| status.pointer("/policyDecisionRefs"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let operation = tui_subagent_operation_for_status(status);
    let mut rows = Vec::new();

    if let Some(subagents) = status.pointer("/subagents").and_then(Value::as_array) {
        for subagent in subagents {
            rows.push(tui_subagent_row(
                subagent,
                thread_id.as_deref(),
                event_id.as_deref(),
                cursor.as_deref(),
                "list",
                &receipt_refs,
                &policy_refs,
            ));
        }
    }
    if let Some(subagent) = status.pointer("/subagent") {
        rows.push(tui_subagent_row(
            subagent,
            thread_id.as_deref(),
            event_id.as_deref(),
            cursor.as_deref(),
            &operation,
            &receipt_refs,
            &policy_refs,
        ));
    }
    if json_path_string(status, "/object").as_deref() == Some("ioi.runtime_subagent")
        || json_path_string(status, "/subagent_id").is_some()
        || json_path_string(status, "/subagentId").is_some()
    {
        rows.push(tui_subagent_row(
            status,
            thread_id.as_deref(),
            event_id.as_deref(),
            cursor.as_deref(),
            &operation,
            &receipt_refs,
            &policy_refs,
        ));
    }
    for (pointer, operation) in [
        ("/canceled_subagents", "cancel"),
        ("/canceledSubagents", "cancel"),
        ("/skipped_subagents", "propagate_skip"),
        ("/skippedSubagents", "propagate_skip"),
    ] {
        if let Some(subagents) = status.pointer(pointer).and_then(Value::as_array) {
            for subagent in subagents {
                rows.push(tui_subagent_row(
                    subagent,
                    thread_id.as_deref(),
                    event_id.as_deref(),
                    cursor.as_deref(),
                    operation,
                    &receipt_refs,
                    &policy_refs,
                ));
            }
        }
    }

    let mut unique_rows = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let key = json_path_string(&row, "/subagent_id")
            .or_else(|| json_path_string(&row, "/id"))
            .unwrap_or_default();
        if key.is_empty() || seen.insert(key) {
            unique_rows.push(row);
        }
    }
    unique_rows
}

fn tui_subagent_operation_for_status(status: &Value) -> String {
    let source_event_kind = json_path_string(status, "/event/source_event_kind")
        .or_else(|| json_path_string(status, "/source_event_kind"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if source_event_kind.contains("subagentspawn") {
        return "spawn".to_string();
    }
    if source_event_kind.contains("subagentwait") {
        return "wait".to_string();
    }
    if source_event_kind.contains("subagentresult") {
        return "result".to_string();
    }
    if source_event_kind.contains("subagentsendinput") {
        return "input".to_string();
    }
    if source_event_kind.contains("subagentcancel") {
        return "cancel".to_string();
    }
    if source_event_kind.contains("subagentresume") {
        return "resume".to_string();
    }
    if source_event_kind.contains("subagentassign") {
        return "assign".to_string();
    }
    if status.pointer("/assignment").is_some() {
        return "assign".to_string();
    }
    if status.pointer("/resume").is_some() {
        return "resume".to_string();
    }
    if status.pointer("/input").is_some() {
        return "input".to_string();
    }
    if status.pointer("/cancellation").is_some() {
        return "cancel".to_string();
    }
    if json_path_string(status, "/object").as_deref() == Some("ioi.runtime_subagent_result") {
        return "result".to_string();
    }
    "list".to_string()
}

fn tui_subagent_row(
    record: &Value,
    fallback_thread_id: Option<&str>,
    fallback_event_id: Option<&str>,
    fallback_cursor: Option<&str>,
    operation: &str,
    receipt_refs: &Value,
    policy_refs: &Value,
) -> Value {
    let subagent_id = json_path_string(record, "/subagent_id")
        .or_else(|| json_path_string(record, "/subagentId"))
        .or_else(|| json_path_string(record, "/agent_id"))
        .or_else(|| json_path_string(record, "/agentId"))
        .unwrap_or_else(|| "subagent".to_string());
    let thread_id = json_path_string(record, "/parent_thread_id")
        .or_else(|| json_path_string(record, "/parentThreadId"))
        .or_else(|| json_path_string(record, "/thread_id"))
        .or_else(|| json_path_string(record, "/threadId"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let run_id = json_path_string(record, "/run_id").or_else(|| json_path_string(record, "/runId"));
    let child_thread_id = json_path_string(record, "/child_thread_id")
        .or_else(|| json_path_string(record, "/childThreadId"));
    let role = json_path_string(record, "/role").unwrap_or_else(|| "general".to_string());
    let lifecycle_status = json_path_string(record, "/lifecycle_status")
        .or_else(|| json_path_string(record, "/lifecycleStatus"))
        .or_else(|| json_path_string(record, "/status"))
        .unwrap_or_else(|| "unknown".to_string());
    let output_contract_status = json_path_string(record, "/output_contract_status")
        .or_else(|| json_path_string(record, "/outputContractStatus/status"))
        .or_else(|| json_path_string(record, "/output_contract_validation/status"))
        .unwrap_or_else(|| "unknown".to_string());
    let budget_status = json_path_string(record, "/budget_status")
        .or_else(|| json_path_string(record, "/budgetStatus/status"))
        .unwrap_or_else(|| "untracked".to_string());
    let cost_estimate_usd = json_path_string(record, "/cost_estimate_usd")
        .or_else(|| json_path_string(record, "/costEstimateUsd"))
        .or_else(|| json_path_string(record, "/usage_telemetry/cumulative_cost_estimate_usd"))
        .or_else(|| json_path_string(record, "/usageTelemetry/cumulativeCostEstimateUsd"));
    let token_estimate = json_path_string(record, "/token_estimate")
        .or_else(|| json_path_string(record, "/tokenEstimate"))
        .or_else(|| json_path_string(record, "/usage_telemetry/cumulative_total_tokens"))
        .or_else(|| json_path_string(record, "/usageTelemetry/cumulativeTotalTokens"));
    let workflow_node_id = json_path_string(record, "/workflow_node_id")
        .or_else(|| json_path_string(record, "/workflowNodeId"))
        .unwrap_or_else(|| format!("runtime.subagent.{}.{}", operation, safe_id(&role)));
    let mut row = serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "surface": "tui",
        "id": format!("tui-subagent-{}", safe_id(&subagent_id)),
        "row_kind": "subagent",
        "status": lifecycle_status.clone(),
        "label": "Subagent",
        "command": "subagent",
        "raw_input": format!("/subagent {operation}"),
        "message": format!("{role} · contract={output_contract_status}"),
        "thread_id": thread_id,
        "turn_id": json_path_string(record, "/parent_turn_id").or_else(|| json_path_string(record, "/parentTurnId")),
        "event_id": json_path_string(record, "/event_id").or_else(|| fallback_event_id.map(ToOwned::to_owned)),
        "cursor": fallback_cursor,
        "subagent_id": subagent_id.clone(),
        "subagent_role": role.clone(),
        "subagent_operation": operation,
        "subagent_lifecycle_status": lifecycle_status.clone(),
        "subagent_output_contract_status": output_contract_status.clone(),
        "subagent_cancellation_inheritance": json_path_string(record, "/cancellation_inheritance")
            .or_else(|| json_path_string(record, "/cancellationInheritance")),
        "subagent_cancellation_reason": json_path_string(record, "/cancellation_reason")
            .or_else(|| json_path_string(record, "/cancellationReason")),
        "subagent_merge_policy": json_path_string(record, "/merge_policy")
            .or_else(|| json_path_string(record, "/mergePolicy")),
        "subagent_tool_pack": json_path_string(record, "/tool_pack")
            .or_else(|| json_path_string(record, "/toolPack")),
        "subagent_child_thread_id": child_thread_id,
        "subagent_run_id": run_id.clone(),
        "subagent_restart_count": json_path_string(record, "/restart_count")
            .or_else(|| json_path_string(record, "/restartCount"))
            .unwrap_or_else(|| "0".to_string()),
        "subagent_input_count": json_path_string(record, "/input_count")
            .or_else(|| json_path_string(record, "/inputCount"))
            .unwrap_or_else(|| "0".to_string()),
        "subagent_assignment_count": json_path_string(record, "/assignment_count")
            .or_else(|| json_path_string(record, "/assignmentCount"))
            .unwrap_or_else(|| "0".to_string()),
        "workflow_graph_id": json_path_string(record, "/workflow_graph_id")
            .or_else(|| json_path_string(record, "/workflowGraphId")),
        "workflow_node_id": workflow_node_id,
        "routes": {
            "list": thread_id.as_deref().map(|thread_id| route_with_thread(TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE, thread_id)),
            "wait": thread_id.as_deref().map(|thread_id| route_with_thread_and_subagent(TUI_THREAD_SUBAGENT_WAIT_ROUTE_TEMPLATE, thread_id, &subagent_id)),
            "result": thread_id.as_deref().map(|thread_id| route_with_thread_and_subagent(TUI_THREAD_SUBAGENT_RESULT_ROUTE_TEMPLATE, thread_id, &subagent_id)),
            "input": thread_id.as_deref().map(|thread_id| route_with_thread_and_subagent(TUI_THREAD_SUBAGENT_INPUT_ROUTE_TEMPLATE, thread_id, &subagent_id)),
            "cancel": thread_id.as_deref().map(|thread_id| route_with_thread_and_subagent(TUI_THREAD_SUBAGENT_CANCEL_ROUTE_TEMPLATE, thread_id, &subagent_id)),
            "resume": thread_id.as_deref().map(|thread_id| route_with_thread_and_subagent(TUI_THREAD_SUBAGENT_RESUME_ROUTE_TEMPLATE, thread_id, &subagent_id)),
            "assign": thread_id.as_deref().map(|thread_id| route_with_thread_and_subagent(TUI_THREAD_SUBAGENT_ASSIGN_ROUTE_TEMPLATE, thread_id, &subagent_id)),
            "propagate_cancel": thread_id.as_deref().map(|thread_id| route_with_thread(TUI_THREAD_SUBAGENT_CANCEL_PROPAGATE_ROUTE_TEMPLATE, thread_id)),
            "run": run_id.as_deref().map(|run_id| route_with_run(TUI_RUN_ROUTE_TEMPLATE, run_id)),
        },
        "receipt_refs": record.pointer("/receipt_refs")
            .or_else(|| record.pointer("/receiptRefs"))
            .cloned()
            .unwrap_or_else(|| receipt_refs.clone()),
        "policy_decision_refs": record.pointer("/policy_decision_refs")
            .or_else(|| record.pointer("/policyDecisionRefs"))
            .cloned()
            .unwrap_or_else(|| policy_refs.clone()),
    });
    if let Some(object) = row.as_object_mut() {
        object.insert(
            "subagent_budget_status".to_string(),
            Value::String(budget_status.clone()),
        );
        object.insert(
            "subagent_cost_estimate_usd".to_string(),
            cost_estimate_usd.map(Value::String).unwrap_or(Value::Null),
        );
        object.insert(
            "subagent_token_estimate".to_string(),
            token_estimate.map(Value::String).unwrap_or(Value::Null),
        );
    }
    row
}

pub(crate) fn tui_approval_rows(events: &[Value], fallback_thread_id: Option<&str>) -> Vec<Value> {
    events
        .iter()
        .filter(|event| is_pending_approval_event(event))
        .map(|event| tui_approval_row(event, fallback_thread_id))
        .collect()
}

pub(crate) fn tui_workspace_trust_rows(
    events: &[Value],
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    events
        .iter()
        .filter(|event| is_tui_workspace_trust_warning_event(event))
        .map(|event| tui_workspace_trust_row(event, fallback_thread_id))
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

fn tui_workspace_trust_row(event: &Value, fallback_thread_id: Option<&str>) -> Value {
    let payload = event_payload_summary(event);
    let seq = event.pointer("/seq").and_then(Value::as_u64);
    let warning_id = json_path_string(payload, "/warning_id")
        .or_else(|| json_path_string(payload, "/warningId"))
        .or_else(|| json_path_string(event, "/event_id"))
        .unwrap_or_else(|| "workspace_trust".to_string());
    let workflow_node_id = json_path_string(event, "/workflow_node_id")
        .or_else(|| json_path_string(payload, "/workflow_node_id"))
        .or_else(|| json_path_string(payload, "/workflowNodeId"))
        .unwrap_or_else(|| "runtime.workspace-trust".to_string());
    let mode = json_path_string(payload, "/mode")
        .or_else(|| json_path_string(payload, "/thread_mode"))
        .unwrap_or_else(|| "review".to_string());
    let severity = json_path_string(payload, "/severity").unwrap_or_else(|| "warning".to_string());
    serde_json::json!({
        "id": format!("tui-workspace-trust-{}-{}", safe_id(&warning_id), seq.unwrap_or(0)),
        "row_kind": "workspace_trust_warning",
        "warning_id": warning_id,
        "status": json_path_string(payload, "/status")
            .or_else(|| json_path_string(event, "/status"))
            .unwrap_or_else(|| "warning".to_string()),
        "severity": severity,
        "label": "Workspace trust warning",
        "command": "mode",
        "raw_input": format!("/mode {mode}"),
        "message": json_path_string(payload, "/message")
            .or_else(|| json_path_string(payload, "/summary"))
            .unwrap_or_else(|| "Daemon recorded a workspace trust warning.".to_string()),
        "thread_id": json_path_string(payload, "/thread_id")
            .or_else(|| json_path_string(payload, "/threadId"))
            .or_else(|| json_path_string(event, "/thread_id"))
            .or_else(|| fallback_thread_id.map(ToOwned::to_owned)),
        "turn_id": json_path_string(payload, "/turn_id")
            .or_else(|| json_path_string(payload, "/turnId"))
            .or_else(|| json_path_string(event, "/turn_id")),
        "cursor": tui_event_cursor(event, seq),
        "event_id": json_path_string(event, "/event_id"),
        "sequence": seq,
        "workflow_graph_id": json_path_string(event, "/workflow_graph_id")
            .or_else(|| json_path_string(payload, "/workflow_graph_id"))
            .or_else(|| json_path_string(payload, "/workflowGraphId")),
        "workflow_node_id": workflow_node_id,
        "mode": mode,
        "approval_mode": json_path_string(payload, "/approval_mode")
            .or_else(|| json_path_string(payload, "/approvalMode")),
        "trust_profile": json_path_string(payload, "/trust_profile")
            .or_else(|| json_path_string(payload, "/trustProfile")),
        "dirty": payload.pointer("/dirty").cloned().unwrap_or(Value::Null),
        "warning_reasons": payload.pointer("/warning_reasons")
            .or_else(|| payload.pointer("/warningReasons"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        "ignored_ui_fields": payload.pointer("/ignored_ui_fields")
            .or_else(|| payload.pointer("/ignoredUiFields"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        "receipt_refs": event.pointer("/receipt_refs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "policy_decision_refs": event.pointer("/policy_decision_refs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
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

pub(crate) fn tui_job_rows(jobs: &[Value], fallback_thread_id: Option<&str>) -> Vec<Value> {
    jobs.iter()
        .enumerate()
        .map(|(index, job)| tui_job_row(job, fallback_thread_id, index))
        .collect()
}

fn tui_job_row(job: &Value, fallback_thread_id: Option<&str>, index: usize) -> Value {
    let job_id = json_path_string(job, "/jobId")
        .or_else(|| json_path_string(job, "/job_id"))
        .unwrap_or_else(|| format!("job_{index}"));
    let run_id = json_path_string(job, "/runId").or_else(|| json_path_string(job, "/run_id"));
    let task_id = json_path_string(job, "/taskId").or_else(|| json_path_string(job, "/task_id"));
    let thread_id = json_path_string(job, "/threadId")
        .or_else(|| json_path_string(job, "/thread_id"))
        .or_else(|| fallback_thread_id.map(ToOwned::to_owned));
    let turn_id = json_path_string(job, "/turnId").or_else(|| json_path_string(job, "/turn_id"));
    let status = json_path_string(job, "/status").unwrap_or_else(|| "unknown".to_string());
    let workflow_node_id = json_path_string(job, "/workflowNodeId")
        .or_else(|| json_path_string(job, "/workflow_node_id"))
        .unwrap_or_else(|| "runtime.runtime-job".to_string());
    let cancel_endpoint = json_path_string(job, "/cancelEndpoint")
        .or_else(|| json_path_string(job, "/cancel_endpoint"))
        .or_else(|| json_path_string(job, "/endpoints/cancel"))
        .unwrap_or_else(|| route_with_job(TUI_JOB_CANCEL_ROUTE_TEMPLATE, &job_id));
    serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "surface": "tui",
        "id": format!("tui-job-{job_id}"),
        "row_kind": "job",
        "job_id": job_id,
        "task_id": task_id,
        "run_id": run_id,
        "agent_id": json_path_string(job, "/agentId").or_else(|| json_path_string(job, "/agent_id")),
        "thread_id": thread_id,
        "turn_id": turn_id,
        "status": status,
        "lifecycle": job.pointer("/lifecycle").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "queue_name": json_path_string(job, "/queueName").or_else(|| json_path_string(job, "/queue_name")),
        "runner": json_path_string(job, "/runner"),
        "job_type": json_path_string(job, "/jobType").or_else(|| json_path_string(job, "/job_type")),
        "priority": json_path_string(job, "/priority"),
        "progress_percent": json_path_string(job, "/progress/percent").unwrap_or_else(|| "0".to_string()),
        "cancelable": job.pointer("/cancelable").cloned().unwrap_or(Value::Bool(false)),
        "cancel_endpoint": cancel_endpoint,
        "endpoints": job.pointer("/endpoints").cloned().unwrap_or_else(|| serde_json::json!({
            "self": route_with_job(TUI_JOB_ROUTE_TEMPLATE, json_path_string(job, "/jobId").or_else(|| json_path_string(job, "/job_id")).as_deref().unwrap_or("job")),
            "cancel": route_with_job(TUI_JOB_CANCEL_ROUTE_TEMPLATE, json_path_string(job, "/jobId").or_else(|| json_path_string(job, "/job_id")).as_deref().unwrap_or("job")),
            "run": run_id.as_deref().map(|run_id| route_with_run(TUI_RUN_ROUTE_TEMPLATE, run_id)),
            "events": run_id.as_deref().map(|run_id| route_with_run(TUI_RUN_EVENTS_ROUTE_TEMPLATE, run_id)),
            "replay": run_id.as_deref().map(|run_id| route_with_run(TUI_RUN_REPLAY_ROUTE_TEMPLATE, run_id)),
            "trace": run_id.as_deref().map(|run_id| route_with_run(TUI_RUN_TRACE_ROUTE_TEMPLATE, run_id)),
            "inspect": run_id.as_deref().map(|run_id| route_with_run(TUI_RUN_INSPECT_ROUTE_TEMPLATE, run_id)),
        })),
        "workflow_node_id": workflow_node_id,
        "artifact_names": job.pointer("/artifactNames").or_else(|| job.pointer("/artifact_names")).cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "receipt_kinds": job.pointer("/receiptKinds").or_else(|| job.pointer("/receipt_kinds")).cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "evidence_refs": job.pointer("/evidenceRefs").or_else(|| job.pointer("/evidence_refs")).cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "tui_reopen": {
            "command": "ioi agent tui",
            "args": tui_reopen_args(thread_id.as_deref(), None),
            "thread_id": thread_id,
            "run_id": run_id,
        },
        "react_flow": {
            "workflow_node_id": workflow_node_id,
            "job_id": json_path_string(job, "/jobId").or_else(|| json_path_string(job, "/job_id")),
            "run_id": json_path_string(job, "/runId").or_else(|| json_path_string(job, "/run_id")),
        }
    })
}

pub(crate) fn tui_run_lifecycle_rows(
    jobs: &[Value],
    fallback_thread_id: Option<&str>,
) -> Vec<Value> {
    jobs.iter()
        .enumerate()
        .map(|(index, job)| tui_run_lifecycle_row(job, fallback_thread_id, index))
        .collect()
}

fn tui_run_lifecycle_row(job: &Value, fallback_thread_id: Option<&str>, index: usize) -> Value {
    let job_row = tui_job_row(job, fallback_thread_id, index);
    let run_id = json_path_string(&job_row, "/run_id").unwrap_or_else(|| format!("run_{index}"));
    let status = json_path_string(&job_row, "/status").unwrap_or_else(|| "unknown".to_string());
    let thread_id = json_path_string(&job_row, "/thread_id");
    let workflow_node_id = json_path_string(&job_row, "/workflow_node_id")
        .unwrap_or_else(|| "runtime.runtime-job".to_string());
    serde_json::json!({
        "schema_version": TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION,
        "surface": "tui",
        "id": format!("tui-run-lifecycle-{run_id}"),
        "row_kind": "run_lifecycle",
        "run_id": run_id,
        "job_id": json_path_string(&job_row, "/job_id"),
        "task_id": json_path_string(&job_row, "/task_id"),
        "thread_id": thread_id,
        "turn_id": json_path_string(&job_row, "/turn_id"),
        "status": status,
        "lifecycle": job_row.pointer("/lifecycle").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "progress_percent": json_path_string(&job_row, "/progress_percent").unwrap_or_else(|| "0".to_string()),
        "workflow_node_id": workflow_node_id,
        "routes": {
            "run": route_with_run(TUI_RUN_ROUTE_TEMPLATE, json_path_string(&job_row, "/run_id").as_deref().unwrap_or("run")),
            "events": route_with_run(TUI_RUN_EVENTS_ROUTE_TEMPLATE, json_path_string(&job_row, "/run_id").as_deref().unwrap_or("run")),
            "replay": route_with_run(TUI_RUN_REPLAY_ROUTE_TEMPLATE, json_path_string(&job_row, "/run_id").as_deref().unwrap_or("run")),
            "trace": route_with_run(TUI_RUN_TRACE_ROUTE_TEMPLATE, json_path_string(&job_row, "/run_id").as_deref().unwrap_or("run")),
            "inspect": route_with_run(TUI_RUN_INSPECT_ROUTE_TEMPLATE, json_path_string(&job_row, "/run_id").as_deref().unwrap_or("run")),
            "cancel": route_with_run(TUI_RUN_CANCEL_ROUTE_TEMPLATE, json_path_string(&job_row, "/run_id").as_deref().unwrap_or("run")),
        },
        "tui_reopen": {
            "command": "ioi agent tui",
            "args": tui_reopen_args(thread_id.as_deref(), None),
            "thread_id": thread_id,
            "run_id": json_path_string(&job_row, "/run_id"),
        },
        "react_flow": {
            "workflow_node_id": workflow_node_id,
            "run_id": json_path_string(&job_row, "/run_id"),
            "job_id": json_path_string(&job_row, "/job_id"),
        }
    })
}

pub(crate) fn selected_run_id_from_thread(thread: &Value) -> Option<String> {
    selected_turn_value(thread, None)
        .and_then(|turn| {
            json_path_string(turn, "/request_id")
                .or_else(|| json_path_string(turn, "/requestId"))
                .or_else(|| json_path_string(turn, "/run_id"))
                .or_else(|| json_path_string(turn, "/runId"))
        })
        .or_else(|| json_path_string(thread, "/latest_run_id"))
        .or_else(|| json_path_string(thread, "/latestRunId"))
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

fn latest_tui_usage_delta_event(events: &[Value]) -> Option<&Value> {
    events
        .iter()
        .filter(|event| is_tui_usage_delta_event(event))
        .max_by_key(|event| event.pointer("/seq").and_then(Value::as_u64).unwrap_or(0))
}

fn latest_tui_context_pressure_event(events: &[Value]) -> Option<&Value> {
    events
        .iter()
        .filter(|event| is_tui_context_pressure_event(event))
        .max_by_key(|event| event.pointer("/seq").and_then(Value::as_u64).unwrap_or(0))
}

fn is_tui_usage_delta_event(event: &Value) -> bool {
    let haystack = [
        json_path_string(event, "/event_kind"),
        json_path_string(event, "/source_event_kind"),
        json_path_string(event, "/component_kind"),
        json_path_string(event, "/payload_summary/eventKind"),
        json_path_string(event, "/payload/eventKind"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    haystack.contains("usage.delta")
        || haystack.contains("runtimeusagetelemetry.delta")
        || (haystack.contains("usage_telemetry") && haystack.contains("delta"))
}

fn is_tui_context_pressure_event(event: &Value) -> bool {
    let haystack = [
        json_path_string(event, "/event_kind"),
        json_path_string(event, "/source_event_kind"),
        json_path_string(event, "/component_kind"),
        json_path_string(event, "/payload_summary/eventKind"),
        json_path_string(event, "/payload/eventKind"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    haystack.contains("context.pressure_delta")
        || haystack.contains("runtimecontextpressure.delta")
        || haystack.contains("context_pressure")
}

fn is_tui_coding_tool_budget_block_event(event: &Value) -> bool {
    let component_kind = json_path_string(event, "/component_kind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if component_kind != "coding_tool" {
        return false;
    }
    let event_kind = json_path_string(event, "/event_kind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let status = json_path_string(event, "/status")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if event_kind != "policy.blocked" && status != "blocked" {
        return false;
    }
    let null = Value::Null;
    let payload = event_payload_summary(event);
    let result = payload.pointer("/result").unwrap_or(&null);
    let error = payload
        .pointer("/error")
        .or_else(|| result.pointer("/error"))
        .unwrap_or(&null);
    let error_details = error.pointer("/details").unwrap_or(&null);
    let result_summary = payload
        .pointer("/result_summary")
        .or_else(|| payload.pointer("/resultSummary"))
        .unwrap_or(&null);
    matches!(
        json_path_string(result_summary, "/reason").as_deref(),
        Some("coding_tool_budget_exceeded")
    ) || matches!(
        json_path_string(error, "/code").as_deref(),
        Some("coding_tool_budget_exceeded")
    ) || matches!(
        json_path_string(error_details, "/reason").as_deref(),
        Some("coding_tool_budget_exceeded")
    ) || matches!(
        json_path_string(payload, "/budget_status")
            .or_else(|| json_path_string(payload, "/budgetStatus"))
            .as_deref(),
        Some("exceeded")
    ) || matches!(
        json_path_string(payload, "/context_budget_status")
            .or_else(|| json_path_string(payload, "/contextBudgetStatus"))
            .as_deref(),
        Some("blocked")
    ) || matches!(
        json_path_string(result, "/context_budget_status")
            .or_else(|| json_path_string(result, "/contextBudgetStatus"))
            .as_deref(),
        Some("blocked")
    ) || matches!(
        json_path_string(error_details, "/context_budget_status")
            .or_else(|| json_path_string(error_details, "/contextBudgetStatus"))
            .as_deref(),
        Some("blocked")
    )
}

fn is_tui_workspace_trust_warning_event(event: &Value) -> bool {
    let haystack = [
        json_path_string(event, "/event_kind"),
        json_path_string(event, "/source_event_kind"),
        json_path_string(event, "/component_kind"),
        json_path_string(event, "/payload_summary/event_kind"),
        json_path_string(event, "/payload_summary/eventKind"),
        json_path_string(event, "/payload_summary/object"),
        json_path_string(event, "/payload/event_kind"),
        json_path_string(event, "/payload/eventKind"),
        json_path_string(event, "/payload/object"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    haystack.contains("workspace.trust_warning")
        || haystack.contains("workspacetrust.warning")
        || haystack.contains("workspace_trust")
        || haystack.contains("ioi.workspace_trust_warning")
}

fn event_payload_summary(event: &Value) -> &Value {
    event
        .pointer("/payload_summary")
        .or_else(|| event.pointer("/payload"))
        .unwrap_or(event)
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

fn route_with_thread_and_mcp_server(template: &str, thread_id: &str, server_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{server_id}", server_id)
}

fn route_with_thread_and_mcp_tool(template: &str, thread_id: &str, tool_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{tool_id}", tool_id)
}

fn route_with_thread_and_subagent(template: &str, thread_id: &str, subagent_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{subagent_id}", subagent_id)
}

fn route_with_query(route: String, params: Vec<(&str, String)>) -> String {
    let query = params
        .into_iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(key, value)| format!("{}={}", key, encode_query_component(&value)))
        .collect::<Vec<_>>()
        .join("&");
    if query.is_empty() {
        route
    } else {
        format!("{route}?{query}")
    }
}

fn encode_query_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn route_with_thread_and_memory(template: &str, thread_id: &str, memory_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{memory_id}", memory_id)
}

fn route_with_thread_and_snapshot(template: &str, thread_id: &str, snapshot_id: &str) -> String {
    route_with_thread(template, thread_id).replace("{snapshot_id}", snapshot_id)
}

fn route_with_thread_and_diagnostics_repair_decision(
    template: &str,
    thread_id: &str,
    decision_id: &str,
) -> String {
    route_with_thread(template, thread_id).replace("{decision_id}", decision_id)
}

fn route_with_job(template: &str, job_id: &str) -> String {
    template.replace("{job_id}", job_id)
}

fn route_with_run(template: &str, run_id: &str) -> String {
    template.replace("{run_id}", run_id)
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
        assert_eq!(
            route_with_thread_and_snapshot(
                TUI_RESTORE_PREVIEW_ROUTE_TEMPLATE,
                "thread_live",
                "workspace_snapshot_live"
            ),
            "/v1/threads/thread_live/snapshots/workspace_snapshot_live/restore-preview"
        );
        assert_eq!(
            route_with_thread_and_diagnostics_repair_decision(
                TUI_THREAD_DIAGNOSTICS_REPAIR_DECISION_EXECUTE_ROUTE_TEMPLATE,
                "thread_live",
                "restore_apply"
            ),
            "/v1/threads/thread_live/diagnostics/repair-decisions/restore_apply/execute"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_MODE_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/mode"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_MODEL_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/model"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_THINKING_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/thinking"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_USAGE_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/usage"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_CONTEXT_BUDGET_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/context-budget"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_COMPACTION_POLICY_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/compaction-policy"
        );
        assert_eq!(
            route_with_job(TUI_JOB_CANCEL_ROUTE_TEMPLATE, "job_run_live"),
            "/v1/jobs/job_run_live/cancel"
        );
        assert_eq!(
            route_with_run(TUI_RUN_REPLAY_ROUTE_TEMPLATE, "run_live"),
            "/v1/runs/run_live/replay"
        );
        assert_eq!(
            route_with_thread(TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE, "thread_live"),
            "/v1/threads/thread_live/subagents"
        );
        assert_eq!(
            route_with_thread_and_subagent(
                TUI_THREAD_SUBAGENT_WAIT_ROUTE_TEMPLATE,
                "thread_live",
                "agent_live"
            ),
            "/v1/threads/thread_live/subagents/agent_live/wait"
        );
        assert_eq!(
            route_with_thread(
                TUI_THREAD_SUBAGENT_CANCEL_PROPAGATE_ROUTE_TEMPLATE,
                "thread_live"
            ),
            "/v1/threads/thread_live/subagents/cancel"
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
    fn tui_streaming_usage_rows_preserve_runtime_node_identity() {
        let events = vec![
            serde_json::json!({
                "event_id": "usage_delta_prompt",
                "event_stream_id": "events_thread_live",
                "seq": 12,
                "thread_id": "thread_live",
                "turn_id": "turn_live",
                "event_kind": "usage.delta",
                "source_event_kind": "RuntimeUsageTelemetry.Delta",
                "status": "running",
                "component_kind": "usage_telemetry",
                "workflow_node_id": "runtime.usage-telemetry",
                "payload_summary": {
                    "eventKind": "RuntimeUsageTelemetry.Delta",
                    "stage": "completion_streamed",
                    "total_tokens": 1200,
                    "input_tokens": 900,
                    "output_tokens": 300,
                    "estimated_cost_usd": 0.0012,
                    "context_pressure": 0.01,
                    "context_pressure_status": "nominal",
                    "summary": "Usage delta 2/2: 1200 tokens, context 0.01."
                }
            }),
            serde_json::json!({
                "event_id": "context_pressure_delta",
                "event_stream_id": "events_thread_live",
                "seq": 13,
                "thread_id": "thread_live",
                "turn_id": "turn_live",
                "event_kind": "context.pressure_delta",
                "source_event_kind": "RuntimeContextPressure.Delta",
                "status": "running",
                "component_kind": "context_pressure",
                "workflow_node_id": "runtime.context-budget",
                "payload_summary": {
                    "eventKind": "RuntimeContextPressure.Delta",
                    "usage_total_tokens": 1200,
                    "usage_cost_estimate_usd": 0.0012,
                    "usage_context_pressure": 0.01,
                    "usage_context_pressure_status": "nominal",
                    "summary": "Context pressure delta 2/2: nominal at 0.01."
                }
            }),
        ];

        let usage_rows = tui_usage_delta_rows(&events, Some("thread_live"));
        assert_eq!(usage_rows.len(), 1);
        assert_eq!(usage_rows[0]["row_kind"], "cost_status");
        assert_eq!(usage_rows[0]["status"], "running");
        assert_eq!(usage_rows[0]["usage_delta_stage"], "completion_streamed");
        assert_eq!(usage_rows[0]["usage_total_tokens"], "1200");
        assert_eq!(usage_rows[0]["workflow_node_id"], "runtime.usage-telemetry");
        assert_eq!(usage_rows[0]["cursor"], "events_thread_live:12");

        let context_rows = tui_context_pressure_rows(&events, Some("thread_live"));
        assert_eq!(context_rows.len(), 1);
        assert_eq!(context_rows[0]["row_kind"], "context_budget");
        assert_eq!(context_rows[0]["status"], "ok");
        assert_eq!(context_rows[0]["usage_context_pressure"], "0.01");
        assert_eq!(
            context_rows[0]["workflow_node_id"],
            "runtime.context-budget"
        );
        assert_eq!(context_rows[0]["cursor"], "events_thread_live:13");
    }

    #[test]
    fn tui_coding_tool_budget_rows_project_policy_blocks() {
        let events = vec![serde_json::json!({
            "event_id": "event_coding_budget_blocked",
            "event_stream_id": "events_thread_live",
            "seq": 14,
            "thread_id": "thread_live",
            "turn_id": "turn_live",
            "event_kind": "policy.blocked",
            "source_event_kind": "CodingTool.FileApplyPatch",
            "status": "blocked",
            "component_kind": "coding_tool",
            "workflow_graph_id": "workflow.react-flow.coding-tool-summary-budget",
            "workflow_node_id": "workflow.coding.file.apply_patch.summary-budget",
            "tool_call_id": "coding_tool_summary_budget_blocked",
            "receipt_refs": [
                "receipt_coding_tool_file_apply_patch_budget",
                "receipt_context_budget_thread_budget",
            ],
            "policy_decision_refs": ["policy_context_budget_thread_budget_blocked"],
            "payload_summary": {
                "tool_name": "file.apply_patch",
                "tool_call_id": "coding_tool_summary_budget_blocked",
                "budget_status": "exceeded",
                "context_budget_status": "blocked",
                "summary": "file.apply_patch blocked because the workflow coding-tool budget was exceeded.",
                "result_summary": {
                    "status": "blocked",
                    "reason": "coding_tool_budget_exceeded",
                },
                "context_budget": {
                    "status": "blocked",
                    "mode": "block",
                    "policy_decision_id": "policy_context_budget_thread_budget_blocked",
                    "checks": [
                        { "id": "total_tokens", "severity": "violation", "actual": 720, "limit": 100 },
                    ],
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
        })];

        let rows = tui_coding_tool_rows(&events, Some("thread_live"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["row_kind"], "coding_tool_budget");
        assert_eq!(rows[0]["status"], "blocked");
        assert_eq!(rows[0]["command"], "events");
        assert_eq!(rows[0]["raw_input"], "/events");
        assert_eq!(rows[0]["tool_name"], "file.apply_patch");
        assert_eq!(
            rows[0]["tool_call_id"],
            "coding_tool_summary_budget_blocked"
        );
        assert_eq!(rows[0]["budget_status"], "exceeded");
        assert_eq!(rows[0]["context_budget_status"], "blocked");
        assert_eq!(rows[0]["context_budget_mode"], "block");
        assert_eq!(
            rows[0]["context_budget_decision_id"],
            "policy_context_budget_thread_budget_blocked"
        );
        assert_eq!(rows[0]["coding_tool_budget_check_count"], 1);
        assert_eq!(rows[0]["coding_tool_budget_violation_count"], 1);
        assert_eq!(rows[0]["usage_total_tokens"], "720");
        assert_eq!(rows[0]["usage_cost_estimate_usd"], "0.0042");
        assert_eq!(rows[0]["usage_context_pressure"], "0.72");
        assert_eq!(rows[0]["mutation_blocked"], true);
        assert_eq!(
            rows[0]["receipt_refs"],
            serde_json::json!([
                "receipt_coding_tool_file_apply_patch_budget",
                "receipt_context_budget_thread_budget",
            ])
        );
        assert_eq!(
            rows[0]["policy_decision_refs"],
            serde_json::json!(["policy_context_budget_thread_budget_blocked"])
        );
        assert_eq!(
            rows[0]["workflow_node_id"],
            "workflow.coding.file.apply_patch.summary-budget"
        );
        assert_eq!(rows[0]["cursor"], "events_thread_live:14");

        let render = TuiRender {
            endpoint: "http://127.0.0.1:8765".to_string(),
            event_route: "/v1/threads/thread_live/events?since_seq=0".to_string(),
            thread: serde_json::json!({ "thread_id": "thread_live" }),
            submitted_turn: None,
            control: None,
            events,
            jobs: Vec::new(),
            since_seq: Some(0),
            last_event_id: None,
            follow: false,
        };
        let state = tui_control_state_for_render(&render, Some("thread_live"));
        assert_eq!(
            state["coding_tool_rows"][0]["row_kind"],
            "coding_tool_budget"
        );
        assert_eq!(
            state["coding_tool_rows"][0]["tool_call_id"],
            "coding_tool_summary_budget_blocked"
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
            jobs: Vec::new(),
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
                "usage": {
                    "scope": "thread",
                    "total_tokens": 2048,
                    "input_tokens": 1536,
                    "output_tokens": 512,
                    "estimated_cost_usd": 0.002048,
                    "context_pressure": 0.016,
                    "context_pressure_status": "nominal",
                    "source_counts": {
                        "runs": 1,
                        "subagents": 1
                    }
                },
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
                serde_json::json!({
                    "event_id": "event_workspace_trust",
                    "event_stream_id": "events_thread_live",
                    "seq": 12,
                    "thread_id": "thread_live",
                    "event_kind": "workspace.trust_warning",
                    "source_event_kind": "WorkspaceTrust.Warning",
                    "status": "warning",
                    "component_kind": "workspace_trust",
                    "workflow_graph_id": "graph_live",
                    "workflow_node_id": "runtime.thread-mode.yolo.workspace-trust",
                    "receipt_refs": ["receipt_workspace_trust"],
                    "policy_decision_refs": ["policy_workspace_trust_yolo"],
                    "payload_summary": {
                        "warning_id": "workspace_trust_live",
                        "mode": "yolo",
                        "approval_mode": "never_prompt",
                        "trust_profile": "local_private",
                        "severity": "high",
                        "dirty": true,
                        "warning_reasons": ["thread_yolo_mode_never_prompts"],
                        "message": "YOLO mode can run without further prompts."
                    }
                }),
            ],
            jobs: Vec::new(),
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
        assert_eq!(state["usage_status"]["usage_total_tokens"], "2048");
        assert_eq!(state["usage_status"]["usage_subagent_count"], "1");
        assert_eq!(
            state["usage_status"]["workflow_node_id"],
            "runtime.usage-telemetry"
        );
        assert_eq!(state["approval_decisions"][0]["decision"], "approve");
        assert_eq!(
            state["approval_decisions"][0]["receipt_refs"],
            serde_json::json!(["receipt_approval"])
        );
        assert_eq!(
            state["workspace_trust_rows"][0]["warning_id"],
            "workspace_trust_live"
        );
        assert_eq!(
            state["workspace_trust_rows"][0]["workflow_node_id"],
            "runtime.thread-mode.yolo.workspace-trust"
        );
        assert_eq!(
            state["workspace_trust_rows"][0]["receipt_refs"],
            serde_json::json!(["receipt_workspace_trust"])
        );
    }

    #[test]
    fn tui_job_and_run_lifecycle_rows_preserve_daemon_routes() {
        let jobs = vec![serde_json::json!({
            "jobId": "job_run_live",
            "taskId": "task_live",
            "runId": "run_live",
            "agentId": "agent_live",
            "threadId": "thread_live",
            "turnId": "turn_live",
            "status": "running",
            "lifecycle": ["queued", "started"],
            "queueName": "local-agentgres",
            "progress": { "percent": 50 },
            "cancelable": true,
            "workflowNodeId": "runtime.runtime-job",
        })];
        let job_rows = tui_job_rows(&jobs, Some("thread_live"));
        let lifecycle_rows = tui_run_lifecycle_rows(&jobs, Some("thread_live"));

        assert_eq!(
            job_rows[0]["schema_version"],
            TUI_WORKFLOW_DEEP_LINK_SCHEMA_VERSION
        );
        assert_eq!(job_rows[0]["job_id"], "job_run_live");
        assert_eq!(job_rows[0]["run_id"], "run_live");
        assert_eq!(job_rows[0]["thread_id"], "thread_live");
        assert_eq!(
            job_rows[0]["cancel_endpoint"],
            "/v1/jobs/job_run_live/cancel"
        );
        assert_eq!(
            job_rows[0]["react_flow"]["workflow_node_id"],
            "runtime.runtime-job"
        );
        assert_eq!(lifecycle_rows[0]["row_kind"], "run_lifecycle");
        assert_eq!(
            lifecycle_rows[0]["routes"]["replay"],
            "/v1/runs/run_live/replay"
        );
        assert_eq!(
            lifecycle_rows[0]["routes"]["trace"],
            "/v1/runs/run_live/trace"
        );
        assert_eq!(
            lifecycle_rows[0]["routes"]["cancel"],
            "/v1/runs/run_live/cancel"
        );
    }
}
