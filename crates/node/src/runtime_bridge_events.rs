use ioi_types::app::{
    KernelEvent, RoutingReceiptEvent, WorkloadActivityEvent, WorkloadActivityKind, WorkloadReceipt,
    WorkloadReceiptEvent,
};
use serde_json::{json, Value};

const EVENT_SCHEMA_VERSION: &str = "ioi.runtime.event.v1";
const KERNEL_EVENT_PAYLOAD_SCHEMA_VERSION: &str = "ioi.runtime.kernel-event.v1";
pub const PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION: &str = "ioi.runtime.event.product_projection.v1";
const BRIDGE_EVENT_TEXT_PREVIEW_BYTES: usize = 4096;
const PRODUCT_TEXT_PREVIEW_BYTES: usize = 640;

pub struct RuntimeBridgeEventContext<'a> {
    pub thread_id: &'a str,
    pub turn_id: &'a str,
    pub workspace_root: Option<&'a str>,
    pub created_at: &'a str,
    pub ordinal: usize,
}

pub fn kernel_event_to_tti_event(
    event: &KernelEvent,
    context: &RuntimeBridgeEventContext<'_>,
) -> Option<Value> {
    let kernel_payload = compact_json_value(serde_json::to_value(event).ok()?);
    match event {
        KernelEvent::AgentStep(trace) => Some(runtime_kernel_event(
            context,
            "KernelEvent::AgentStep",
            "turn.step",
            "running",
            "runtime",
            "runtime_step",
            "runtime.runtime-step",
            format!("step:{}", trace.step_index),
            json!({
                "event_kind": "KernelEvent::AgentStep",
                "session_id": hex::encode(trace.session_id),
                "step_index": trace.step_index,
                "success": trace.success,
                "error": trace.error,
                "raw_output": compact_text(&trace.raw_output),
                "cost_incurred": trace.cost_incurred,
                "fitness_score": trace.fitness_score,
                "timestamp": trace.timestamp,
                "kernel_event": kernel_payload,
            }),
        )),
        KernelEvent::AgentThought { session_id, token } => Some(runtime_kernel_event(
            context,
            "KernelEvent::AgentThought",
            "reasoning.delta",
            "running",
            "assistant",
            "reasoning_delta",
            "runtime.reasoning",
            format!("thought:{}", context.ordinal),
            json!({
                "event_kind": "KernelEvent::AgentThought",
                "session_id": hex::encode(session_id),
                "delta": token,
                "token": token,
                "kernel_event": kernel_payload,
            }),
        )),
        KernelEvent::AgentAnswerDelta { session_id, token } => Some(runtime_kernel_event(
            context,
            "KernelEvent::AgentAnswerDelta",
            "answer.delta",
            "running",
            "assistant",
            "answer_delta",
            "runtime.answer",
            format!("answer:{}", context.ordinal),
            json!({
                "event_kind": "KernelEvent::AgentAnswerDelta",
                "session_id": hex::encode(session_id),
                "delta": token,
                "token": token,
                "kernel_event": kernel_payload,
            }),
        )),
        KernelEvent::FirewallInterception {
            verdict,
            target,
            request_hash,
            session_id,
        } => {
            let verdict_normalized = verdict.trim().to_ascii_uppercase();
            let requires_approval = verdict_normalized.contains("REQUIRE_APPROVAL")
                || verdict_normalized.contains("APPROVAL")
                || verdict_normalized.contains("REVIEW");
            let (event_kind, component_kind, workflow_node_id) = if requires_approval {
                (
                    "approval.required",
                    "approval_required",
                    "runtime.approval-gate",
                )
            } else {
                ("policy.blocked", "policy_blocked", "runtime.policy-gate")
            };
            Some(runtime_kernel_event(
                context,
                "KernelEvent::FirewallInterception",
                event_kind,
                "blocked",
                "policy",
                component_kind,
                workflow_node_id,
                format!("firewall:{}", hex::encode(request_hash)),
                json!({
                    "event_kind": "KernelEvent::FirewallInterception",
                    "verdict": verdict,
                    "target": target,
                    "request_hash": hex::encode(request_hash),
                    "session_id": session_id.map(hex::encode),
                    "kernel_event": kernel_payload,
                }),
            ))
        }
        KernelEvent::AgentActionResult {
            session_id,
            step_index,
            tool_name,
            output,
            error_class,
            agent_status,
        } => {
            let failed = error_class.is_some()
                && !benign_retained_shell_lifecycle_observation(
                    tool_name,
                    output,
                    error_class.as_deref(),
                );
            Some(runtime_kernel_event(
                context,
                "KernelEvent::AgentActionResult",
                if failed {
                    "tool.failed"
                } else {
                    "tool.completed"
                },
                if failed { "failed" } else { "completed" },
                "tool",
                "tool_result",
                "runtime.tool-result",
                format!("tool:{step_index}:{tool_name}:{}", context.ordinal),
                json!({
                    "event_kind": "KernelEvent::AgentActionResult",
                    "session_id": hex::encode(session_id),
                    "step_index": step_index,
                    "tool_name": tool_name,
                    "output": compact_text(output),
                    "error_class": error_class,
                    "agent_status": agent_status,
                    "kernel_event": kernel_payload,
                }),
            ))
        }
        KernelEvent::WorkloadReceipt(receipt) => Some(workload_receipt_to_tti_event(
            receipt,
            context,
            kernel_payload,
        )),
        KernelEvent::WorkloadActivity(activity) => Some(workload_activity_to_tti_event(
            activity,
            context,
            kernel_payload,
        )),
        KernelEvent::RoutingReceipt(receipt) => Some(routing_receipt_to_tti_event(
            receipt,
            context,
            kernel_payload,
        )),
        _ => None,
    }
}

fn benign_retained_shell_lifecycle_observation(
    tool_name: &str,
    output: &str,
    error_class: Option<&str>,
) -> bool {
    if !tool_name.starts_with("shell__") {
        return false;
    }
    let lower = output.to_ascii_lowercase();
    match tool_name {
        "shell__input" => [
            "already sent",
            "duplicate input",
            "duplicate stdin",
            "continuing with status/cleanup",
            "already stopped",
            "already terminated",
            "continuing with retained shell cleanup",
        ]
        .iter()
        .any(|needle| lower.contains(needle)),
        "shell__status" => {
            lower.trim() == "status checked"
                || lower.contains("same action fingerprint")
                || lower.contains("already checked")
        }
        _ => error_class.is_some() && lower.contains("already"),
    }
}

fn compact_text(text: &str) -> String {
    if text.len() <= BRIDGE_EVENT_TEXT_PREVIEW_BYTES {
        return text.to_string();
    }
    let mut end = BRIDGE_EVENT_TEXT_PREVIEW_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}...[truncated {} bytes]",
        &text[..end],
        text.len().saturating_sub(end)
    )
}

fn compact_product_text(text: &str) -> String {
    compact_text_to_bytes(text, PRODUCT_TEXT_PREVIEW_BYTES)
}

fn compact_text_to_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &text[..end])
}

fn compact_json_value(value: Value) -> Value {
    match value {
        Value::String(text) if text.len() > BRIDGE_EVENT_TEXT_PREVIEW_BYTES => json!({
            "preview": compact_text(&text),
            "truncated": true,
            "original_bytes": text.len(),
        }),
        Value::Array(items) => Value::Array(items.into_iter().map(compact_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, compact_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)?
        .as_str()
        .filter(|text| !text.trim().is_empty())
}

fn tool_label(tool_name: &str) -> String {
    tool_name
        .trim()
        .trim_start_matches("agent__")
        .trim_start_matches("browser__")
        .trim_start_matches("file__")
        .trim_start_matches("shell__")
        .replace("__", " ")
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn product_visibility(event_kind: &str, component_kind: &str) -> &'static str {
    let kind = event_kind.to_ascii_lowercase();
    let component = component_kind.to_ascii_lowercase();
    if kind.starts_with("answer.")
        || kind.starts_with("reasoning.")
        || kind.starts_with("tool.")
        || kind.starts_with("approval.")
        || kind.starts_with("policy.")
        || kind.starts_with("browser.")
        || kind.starts_with("computer.")
        || kind.starts_with("artifact.")
    {
        return "product_chat";
    }
    if component.contains("receipt")
        || kind.starts_with("receipt.")
        || kind.ends_with(".route_decision")
    {
        return "runs_tracing";
    }
    "work_lane"
}

fn source_refs_from_payload(payload: &Value) -> Vec<Value> {
    let mut refs = Vec::new();
    collect_source_refs(payload, &mut refs, 0);
    refs.truncate(6);
    refs
}

fn collect_source_refs(value: &Value, refs: &mut Vec<Value>, depth: usize) {
    if depth > 8 || refs.len() >= 6 {
        return;
    }
    match value {
        Value::String(text) => {
            if text.trim_start().starts_with('{') || text.trim_start().starts_with('[') {
                if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                    collect_source_refs(&parsed, refs, depth + 1);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_source_refs(item, refs, depth + 1);
                if refs.len() >= 6 {
                    break;
                }
            }
        }
        Value::Object(map) => {
            let url = map
                .get("url")
                .or_else(|| map.get("href"))
                .or_else(|| map.get("link"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let title = map
                .get("title")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("label"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if !url.is_empty() || !title.is_empty() {
                let domain = map
                    .get("domain")
                    .or_else(|| map.get("hostname"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches("www.");
                let excerpt = map
                    .get("excerpt")
                    .or_else(|| map.get("snippet"))
                    .or_else(|| map.get("summary"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                refs.push(json!({
                    "title": compact_product_text(title),
                    "domain": compact_product_text(domain),
                    "url": url,
                    "excerpt": compact_product_text(excerpt),
                    "state": "used",
                }));
            }
            for key in [
                "sources",
                "source_refs",
                "sourceRefs",
                "documents",
                "results",
                "citations",
                "items",
                "payload",
                "output",
                "preview",
            ] {
                if let Some(next) = map.get(key) {
                    collect_source_refs(next, refs, depth + 1);
                }
                if refs.len() >= 6 {
                    break;
                }
            }
        }
        _ => {}
    }
}

pub fn product_projection_for_event(
    event_kind: &str,
    status: &str,
    actor: &str,
    component_kind: &str,
    payload: &Value,
) -> Value {
    let tool_name = string_field(payload, "tool_name").unwrap_or("");
    let shell_projection = if matches!(
        event_kind,
        "tool.started" | "tool.output" | "tool.completed" | "tool.failed"
    ) {
        public_shell_tool_projection(event_kind, status, tool_name, payload)
    } else {
        None
    };
    let readable_tool = if tool_name.is_empty() {
        String::new()
    } else {
        tool_label(tool_name)
    };
    let headline = match event_kind {
        "reasoning.delta" => "Thinking".to_string(),
        "answer.delta" => "Streaming final answer".to_string(),
        "tool.started" => {
            if let Some(shell) = shell_projection.as_ref() {
                shell.headline.clone()
            } else if readable_tool.is_empty() {
                "Tool started".to_string()
            } else {
                format!("Using {}", readable_tool)
            }
        }
        "tool.output" => {
            if let Some(shell) = shell_projection.as_ref() {
                shell.headline.clone()
            } else if readable_tool.is_empty() {
                "Tool output".to_string()
            } else {
                format!("{} output", readable_tool)
            }
        }
        "tool.completed" => {
            if let Some(shell) = shell_projection.as_ref() {
                shell.headline.clone()
            } else if readable_tool.is_empty() {
                "Tool completed".to_string()
            } else {
                format!("Used {}", readable_tool)
            }
        }
        "tool.failed" => {
            if let Some(shell) = shell_projection.as_ref() {
                shell.headline.clone()
            } else if readable_tool.is_empty() {
                "Tool failed".to_string()
            } else {
                format!("{} failed", readable_tool)
            }
        }
        "approval.required" => "Approval required".to_string(),
        "policy.blocked" => "Policy blocked an action".to_string(),
        "receipt.emitted" => "Runtime receipt recorded".to_string(),
        "model.route_decision" => "Model route selected".to_string(),
        "tool.route_decision" => "Tool route selected".to_string(),
        _ => event_kind.replace(['.', '_'], " "),
    };
    let has_shell_projection = shell_projection.is_some();
    let mut summary = shell_projection
        .as_ref()
        .map(|projection| projection.summary.clone())
        .unwrap_or_default();
    if summary.is_empty() && !has_shell_projection {
        if let Some(query) = string_field(payload, "query") {
            summary = format!("query: {}", compact_product_text(query));
        } else if let Some(url) = string_field(payload, "url") {
            summary = compact_product_text(url);
        } else if let Some(output) = string_field(payload, "output") {
            summary = compact_product_text(output);
        } else if let Some(result) = string_field(payload, "result") {
            summary = compact_product_text(result);
        } else if let Some(message) = string_field(payload, "message") {
            summary = compact_product_text(message);
        } else if let Some(existing_summary) = string_field(payload, "summary") {
            summary = compact_product_text(existing_summary);
        } else if let Some(prompt) = string_field(payload, "prompt") {
            summary = compact_product_text(prompt);
        } else if let Some(error) = string_field(payload, "error_class") {
            summary = compact_product_text(error);
        } else if let Some(chunk) = string_field(payload, "chunk") {
            summary = compact_product_text(chunk);
        } else if let Some(delta) = string_field(payload, "delta") {
            summary = compact_product_text(delta);
        }
    }
    let source_refs = source_refs_from_payload(payload);
    let mut projection = json!({
        "schema_version": PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION,
        "visibility": product_visibility(event_kind, component_kind),
        "event_kind": event_kind,
        "status": status,
        "actor": actor,
        "component_kind": component_kind,
        "tool_name": if tool_name.is_empty() { Value::Null } else { Value::String(tool_name.to_string()) },
        "headline": headline,
        "summary": summary,
        "source_refs": source_refs,
        "payload_detail_visibility": "runs_tracing",
    });
    if let Some(shell) = shell_projection {
        if let Some(command_label) = shell.command_label {
            projection["command_label"] = Value::String(command_label);
        }
        if let Some(excerpt_preview) = shell.excerpt_preview {
            projection["excerpt_preview"] = Value::String(excerpt_preview);
        }
    }
    projection
}

struct PublicShellToolProjection {
    headline: String,
    summary: String,
    command_label: Option<String>,
    excerpt_preview: Option<String>,
}

fn public_shell_tool_projection(
    event_kind: &str,
    event_status: &str,
    tool_name: &str,
    payload: &Value,
) -> Option<PublicShellToolProjection> {
    if !tool_name.starts_with("shell__") {
        return None;
    }
    let output = string_field(payload, "output").unwrap_or("");
    let parsed = serde_json::from_str::<Value>(output).ok();
    let command_label = string_field(payload, "display_label")
        .map(compact_product_text)
        .or_else(|| parsed.as_ref().and_then(public_shell_command_label))
        .filter(|label| !label.is_empty());
    let status = parsed
        .as_ref()
        .and_then(|value| string_field(value, "status"))
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let running = parsed
        .as_ref()
        .and_then(|value| value.get("running"))
        .and_then(Value::as_bool)
        .unwrap_or(status == "running");
    let excerpt_preview = parsed
        .as_ref()
        .and_then(|value| string_field(value, "output_tail"))
        .and_then(public_shell_output_excerpt)
        .or_else(|| string_field(payload, "chunk").and_then(public_shell_output_excerpt));
    let failed = event_kind == "tool.failed";
    let event_running = event_status.eq_ignore_ascii_case("running");
    let duplicate_input_noop = tool_name == "shell__input"
        && [
            "already sent",
            "duplicate input",
            "duplicate stdin",
            "continuing with status/cleanup",
        ]
        .iter()
        .any(|needle| output.to_ascii_lowercase().contains(needle));
    let obsolete_input_noop = tool_name == "shell__input"
        && [
            "already stopped",
            "already terminated",
            "continuing with retained shell cleanup",
        ]
        .iter()
        .any(|needle| output.to_ascii_lowercase().contains(needle));
    let headline = match tool_name {
        "shell__start" if failed => "Command failed",
        "shell__start" if running || event_running => "Running command",
        "shell__start" => "Started command",
        "shell__run" if failed => "Command failed",
        "shell__run" if running || event_running => "Running command",
        "shell__run" => "Ran command",
        "shell__status" => "Checked command status",
        "shell__input" if obsolete_input_noop => "Skipped obsolete input",
        "shell__input" if duplicate_input_noop => "Skipped duplicate input",
        "shell__input" if failed => "Command input failed",
        "shell__input" => "Sent input to retained command",
        "shell__terminate" => "Terminated retained command",
        "shell__reset" => "Reset retained shell state",
        _ if failed => "Command step failed",
        _ => "Command step completed",
    }
    .to_string();
    let summary = match tool_name {
        "shell__start" | "shell__run" if failed => {
            let mut parts = Vec::new();
            if let Some(label) = command_label.as_ref() {
                parts.push(label.clone());
            }
            parts.push("failed".to_string());
            parts.join(" · ")
        }
        "shell__start" | "shell__run" => {
            let mut parts = Vec::new();
            if let Some(label) = command_label.as_ref() {
                parts.push(label.clone());
            }
            if !status.is_empty() {
                parts.push(status.clone());
            } else if running || event_running {
                parts.push("running".to_string());
            }
            if parts.is_empty() {
                headline.clone()
            } else if (running || event_running)
                && command_label.is_none()
                && parts
                    .iter()
                    .all(|part| part.eq_ignore_ascii_case("running"))
            {
                String::new()
            } else {
                parts.join(" · ")
            }
        }
        "shell__status" => {
            if status.is_empty() {
                "Status checked".to_string()
            } else {
                format!("status: {status}")
            }
        }
        "shell__input" if duplicate_input_noop => {
            "Input was already sent; continuing with status/cleanup.".to_string()
        }
        "shell__input" if obsolete_input_noop => {
            "Retained command was already stopped; continuing with cleanup.".to_string()
        }
        "shell__input" if failed => "input failed".to_string(),
        "shell__input" => "stdin sent".to_string(),
        "shell__terminate" => "retained command terminated".to_string(),
        "shell__reset" => "retained shell state reset".to_string(),
        _ => compact_product_text(output),
    };
    Some(PublicShellToolProjection {
        headline,
        summary: compact_product_text(&summary),
        command_label,
        excerpt_preview,
    })
}

fn public_shell_command_label(value: &Value) -> Option<String> {
    let command = string_field(value, "command")?.trim();
    if command.is_empty() {
        return None;
    }
    let args = value
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if args.iter().any(|arg| arg.as_str() == Some("-e")) {
        return Some(format!("{command} -e <inline script>"));
    }
    let mut parts = vec![command.to_string()];
    for arg in args.iter().filter_map(Value::as_str).take(4) {
        let arg = arg.trim();
        if arg.is_empty() || arg.contains("shell__start:") || arg.contains("ioi-session-stdin") {
            continue;
        }
        if arg.starts_with("/tmp/") || arg.len() > 80 {
            parts.push("<arg>".to_string());
        } else {
            parts.push(arg.to_string());
        }
    }
    Some(parts.join(" "))
}

fn public_shell_output_excerpt(output_tail: &str) -> Option<String> {
    let mut lines = Vec::new();
    for raw_line in output_tail.lines() {
        let line = raw_line.trim().trim_matches('\0').trim();
        if line.is_empty()
            || line.contains("shell__start:")
            || line.contains("command_id")
            || line.contains("ioi-session-stdin")
            || line.contains("__IOI")
            || line.contains("ioi_rc=")
            || line.starts_with("<ell__start:")
        {
            continue;
        }
        lines.push(line.to_string());
        if lines.len() >= 4 {
            break;
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(compact_product_text(&lines.join("\n")))
    }
}

fn workload_activity_to_tti_event(
    activity: &WorkloadActivityEvent,
    context: &RuntimeBridgeEventContext<'_>,
    kernel_payload: Value,
) -> Value {
    let tool_name = workload_tool_name(activity.workload_id.as_str());
    let display_label = activity.display_label.as_deref();
    let (event_kind, status, component_kind, workflow_node_id, payload) = match &activity.kind {
        WorkloadActivityKind::Lifecycle { phase, exit_code } => {
            let normalized_phase = phase.trim().to_ascii_lowercase();
            let (event_kind, status) = match normalized_phase.as_str() {
                "failed" => ("tool.failed", "failed"),
                "completed" => ("tool.completed", "completed"),
                "started" | "running" | "detached" => ("tool.started", "running"),
                _ => ("tool.started", "running"),
            };
            (
                event_kind,
                status,
                "tool_lifecycle",
                "runtime.tool-lifecycle",
                json!({
                    "event_kind": "KernelEvent::WorkloadActivity",
                    "session_id": hex::encode(activity.session_id),
                    "step_index": activity.step_index,
                    "workload_id": activity.workload_id,
                    "display_label": display_label,
                    "timestamp_ms": activity.timestamp_ms,
                    "tool_name": tool_name,
                    "phase": phase,
                    "exit_code": exit_code,
                    "kernel_event": kernel_payload,
                }),
            )
        }
        WorkloadActivityKind::Stdio {
            stream,
            chunk,
            seq,
            is_final,
            exit_code,
        } => (
            "tool.output",
            if *is_final { "completed" } else { "running" },
            "tool_output",
            "runtime.tool-output",
            json!({
                "event_kind": "KernelEvent::WorkloadActivity",
                "session_id": hex::encode(activity.session_id),
                "step_index": activity.step_index,
                "workload_id": activity.workload_id,
                "display_label": display_label,
                "timestamp_ms": activity.timestamp_ms,
                "tool_name": tool_name,
                "stream": stream,
                "chunk": compact_text(chunk),
                "seq": seq,
                "is_final": is_final,
                "exit_code": exit_code,
                "kernel_event": kernel_payload,
            }),
        ),
    };
    runtime_kernel_event(
        context,
        "KernelEvent::WorkloadActivity",
        event_kind,
        status,
        "tool",
        component_kind,
        workflow_node_id,
        format!("workload:{}:{}", activity.workload_id, context.ordinal),
        payload,
    )
}

fn workload_tool_name(workload_id: &str) -> &str {
    workload_id
        .split_once(':')
        .map(|(tool, _)| tool)
        .filter(|tool| !tool.trim().is_empty())
        .unwrap_or("tool")
}

fn workload_receipt_to_tti_event(
    receipt: &WorkloadReceiptEvent,
    context: &RuntimeBridgeEventContext<'_>,
    kernel_payload: Value,
) -> Value {
    let summary = workload_receipt_summary(&receipt.receipt);
    runtime_kernel_event(
        context,
        "KernelEvent::WorkloadReceipt",
        "receipt.emitted",
        if summary.success {
            "completed"
        } else {
            "failed"
        },
        "runtime",
        "receipt",
        "runtime.receipt",
        format!("workload:{}:{}", receipt.step_index, receipt.workload_id),
        json!({
            "event_kind": "KernelEvent::WorkloadReceipt",
            "session_id": hex::encode(receipt.session_id),
            "step_index": receipt.step_index,
            "workload_id": receipt.workload_id,
            "timestamp_ms": receipt.timestamp_ms,
            "receipt_kind": summary.receipt_kind,
            "tool_name": summary.tool_name,
            "success": summary.success,
            "error_class": summary.error_class,
            "receipt": receipt.receipt,
            "kernel_event": kernel_payload,
        }),
    )
}

fn routing_receipt_to_tti_event(
    receipt: &RoutingReceiptEvent,
    context: &RuntimeBridgeEventContext<'_>,
    kernel_payload: Value,
) -> Value {
    let route_family = receipt
        .route_decision
        .route_family
        .trim()
        .to_ascii_lowercase();
    let is_model_route = route_family.contains("model")
        || route_family.contains("inference")
        || receipt.tool_name.contains("model");
    runtime_kernel_event(
        context,
        "KernelEvent::RoutingReceipt",
        if is_model_route {
            "model.route_decision"
        } else {
            "tool.route_decision"
        },
        "completed",
        "runtime",
        if is_model_route {
            "model_router"
        } else {
            "tool_router"
        },
        if is_model_route {
            "runtime.model-router"
        } else {
            "runtime.tool-router"
        },
        format!("routing:{}:{}", receipt.step_index, receipt.intent_hash),
        json!({
            "event_kind": "KernelEvent::RoutingReceipt",
            "session_id": hex::encode(receipt.session_id),
            "step_index": receipt.step_index,
            "intent_hash": receipt.intent_hash,
            "policy_decision": receipt.policy_decision,
            "tool_name": receipt.tool_name,
            "tool_version": receipt.tool_version,
            "gate_state": receipt.gate_state,
            "failure_class_name": receipt.failure_class_name,
            "route_decision": receipt.route_decision,
            "kernel_event": kernel_payload,
        }),
    )
}

fn runtime_kernel_event(
    context: &RuntimeBridgeEventContext<'_>,
    source_event_kind: &str,
    event_kind: &str,
    status: &str,
    actor: &str,
    component_kind: &str,
    workflow_node_id: &str,
    event_key: String,
    payload: Value,
) -> Value {
    let payload_summary =
        product_projection_for_event(event_kind, status, actor, component_kind, &payload);
    json!({
        "event_stream_id": format!("{}:events", context.thread_id),
        "thread_id": context.thread_id,
        "turn_id": context.turn_id,
        "item_id": format!("{}:item:kernel:{}:{}", context.turn_id, context.ordinal, event_kind),
        "idempotency_key": format!(
            "runtime-agent-service:{}:{}:{}",
            context.turn_id,
            source_event_kind,
            event_key,
        ),
        "source": "runtime_service",
        "source_event_kind": source_event_kind,
        "event_kind": event_kind,
        "status": status,
        "actor": actor,
        "created_at": context.created_at,
        "workspace_root": context.workspace_root,
        "component_kind": component_kind,
        "workflow_node_id": workflow_node_id,
        "payload_schema_version": KERNEL_EVENT_PAYLOAD_SCHEMA_VERSION,
        "product_projection_schema_version": PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION,
        "payload_detail_visibility": "runs_tracing",
        "payload_summary": payload_summary,
        "payload": payload,
        "schema_version": EVENT_SCHEMA_VERSION,
        "fixture_profile": Value::Null,
    })
}

struct WorkloadReceiptSummary<'a> {
    receipt_kind: &'static str,
    tool_name: &'a str,
    success: bool,
    error_class: Option<&'a str>,
}

fn workload_receipt_summary(receipt: &WorkloadReceipt) -> WorkloadReceiptSummary<'_> {
    match receipt {
        WorkloadReceipt::Exec(item) => WorkloadReceiptSummary {
            receipt_kind: "exec",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::FsWrite(item) => WorkloadReceiptSummary {
            receipt_kind: "fs_write",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::NetFetch(item) => WorkloadReceiptSummary {
            receipt_kind: "net_fetch",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::WebRetrieve(item) => WorkloadReceiptSummary {
            receipt_kind: "web_retrieve",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::MemoryRetrieve(item) => WorkloadReceiptSummary {
            receipt_kind: "memory_retrieve",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Inference(item) => WorkloadReceiptSummary {
            receipt_kind: "inference",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Media(item) => WorkloadReceiptSummary {
            receipt_kind: "media",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::ModelLifecycle(item) => WorkloadReceiptSummary {
            receipt_kind: "model_lifecycle",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Worker(item) => WorkloadReceiptSummary {
            receipt_kind: "worker",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::ParentPlaybook(item) => WorkloadReceiptSummary {
            receipt_kind: "parent_playbook",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Adapter(item) => WorkloadReceiptSummary {
            receipt_kind: "adapter",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        KernelEvent, WorkloadActivityEvent, WorkloadActivityKind, WorkloadExecReceipt,
    };

    fn context<'a>() -> RuntimeBridgeEventContext<'a> {
        RuntimeBridgeEventContext {
            thread_id: "thread_kernel_mapper",
            turn_id: "turn_kernel_mapper",
            workspace_root: Some("/tmp/ioi"),
            created_at: "2026-05-12T00:00:00Z",
            ordinal: 7,
        }
    }

    #[test]
    fn maps_agent_thought_to_reasoning_delta() {
        let session_id = [1u8; 32];
        let event = KernelEvent::AgentThought {
            session_id,
            token: "thinking".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(mapped["source_event_kind"], "KernelEvent::AgentThought");
        assert_eq!(mapped["event_kind"], "reasoning.delta");
        assert_eq!(mapped["component_kind"], "reasoning_delta");
        assert_eq!(mapped["workflow_node_id"], "runtime.reasoning");
        assert_eq!(mapped["payload"]["session_id"], hex::encode(session_id));
        assert_eq!(mapped["payload"]["delta"], "thinking");
        assert_eq!(mapped["fixture_profile"], Value::Null);
    }

    #[test]
    fn maps_agent_answer_delta_to_answer_delta() {
        let session_id = [9u8; 32];
        let event = KernelEvent::AgentAnswerDelta {
            session_id,
            token: "final answer".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(mapped["source_event_kind"], "KernelEvent::AgentAnswerDelta");
        assert_eq!(mapped["event_kind"], "answer.delta");
        assert_eq!(mapped["component_kind"], "answer_delta");
        assert_eq!(mapped["workflow_node_id"], "runtime.answer");
        assert_eq!(mapped["payload"]["session_id"], hex::encode(session_id));
        assert_eq!(mapped["payload"]["delta"], "final answer");
        assert_eq!(mapped["fixture_profile"], Value::Null);
        assert_eq!(
            mapped["payload_summary"]["schema_version"],
            PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION
        );
        assert_eq!(mapped["payload_summary"]["visibility"], "product_chat");
        assert_eq!(
            mapped["payload_summary"]["headline"],
            "Streaming final answer"
        );
        assert_eq!(mapped["payload_detail_visibility"], "runs_tracing");
    }

    #[test]
    fn maps_action_result_status_from_error_class() {
        let event = KernelEvent::AgentActionResult {
            session_id: [2u8; 32],
            step_index: 3,
            tool_name: "shell__run".to_string(),
            output: "permission denied".to_string(),
            error_class: Some("permission_or_approval_required".to_string()),
            agent_status: "Paused".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(
            mapped["source_event_kind"],
            "KernelEvent::AgentActionResult"
        );
        assert_eq!(mapped["event_kind"], "tool.failed");
        assert_eq!(mapped["status"], "failed");
        assert_eq!(mapped["component_kind"], "tool_result");
        assert_eq!(mapped["payload"]["tool_name"], "shell__run");
        assert_eq!(
            mapped["payload"]["error_class"],
            "permission_or_approval_required"
        );
        assert_eq!(mapped["payload_summary"]["tool_name"], "shell__run");
        assert_eq!(mapped["payload_summary"]["headline"], "Command failed");
    }

    #[test]
    fn product_projection_extracts_source_refs_without_kernel_payload() {
        let event = KernelEvent::AgentActionResult {
            session_id: [8u8; 32],
            step_index: 2,
            tool_name: "web__search".to_string(),
            output: r#"{"sources":[{"title":"Akash price today","url":"https://example.test/akt","snippet":"AKT market data excerpt"}]}"#.to_string(),
            error_class: None,
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(projection["visibility"], "product_chat");
        assert_eq!(projection["tool_name"], "web__search");
        assert_eq!(projection["source_refs"][0]["title"], "Akash price today");
        assert_eq!(
            projection["source_refs"][0]["excerpt"],
            "AKT market data excerpt"
        );
        let projection_text = serde_json::to_string(projection).expect("projection json");
        assert!(!projection_text.contains("kernel_event"));
        assert!(!projection_text.contains("session_id"));
        assert!(!projection_text.contains("receipt_ref"));
    }

    #[test]
    fn product_projection_sanitizes_retained_shell_work_lane_summary() {
        let event = KernelEvent::AgentActionResult {
            session_id: [4u8; 32],
            step_index: 7,
            tool_name: "shell__input".to_string(),
            output: serde_json::json!({
                "command": "node",
                "args": ["-e", "process.stdin.on('data', chunk => console.log(chunk.toString()))"],
                "command_id": "shell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9",
                "status": "running",
                "running": true,
                "output_tail": "<ell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9-1\nHELPER: ready\nioi_rc=0\n"
            })
            .to_string(),
            error_class: None,
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(projection["headline"], "Sent input to retained command");
        assert_eq!(projection["summary"], "stdin sent");
        assert_eq!(projection["command_label"], "node -e <inline script>");
        assert_eq!(projection["excerpt_preview"], "HELPER: ready");
        let projection_text = serde_json::to_string(projection).expect("projection json");
        assert!(!projection_text.contains("shell__start:"));
        assert!(!projection_text.contains("command_id"));
        assert!(!projection_text.contains("ioi_rc="));
    }

    #[test]
    fn product_projection_labels_retained_shell_start_failure_as_failure() {
        let event = KernelEvent::AgentActionResult {
            session_id: [4u8; 32],
            step_index: 8,
            tool_name: "shell__start".to_string(),
            output: serde_json::json!({
                "command": "node",
                "args": ["-e", "process.stdin.resume()"],
                "status": "failed",
                "output_tail": "ERROR_CLASS=PermissionDenied shell execution denied\n"
            })
            .to_string(),
            error_class: Some("PermissionDenied".to_string()),
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["event_kind"], "tool.failed");
        assert_eq!(projection["headline"], "Command failed");
        assert_eq!(projection["summary"], "node -e <inline script> · failed");
        assert_ne!(projection["headline"], "Started command");
    }

    #[test]
    fn workload_activity_lifecycle_projects_live_shell_start_row() {
        let event = KernelEvent::WorkloadActivity(WorkloadActivityEvent {
            session_id: [4u8; 32],
            step_index: 8,
            workload_id:
                "shell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9"
                    .to_string(),
            display_label: Some("node -e <inline script>".to_string()),
            timestamp_ms: 1_772_000_000_000,
            kind: WorkloadActivityKind::Lifecycle {
                phase: "started".to_string(),
                exit_code: None,
            },
        });
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["source_event_kind"], "KernelEvent::WorkloadActivity");
        assert_eq!(mapped["event_kind"], "tool.started");
        assert_eq!(mapped["status"], "running");
        assert_eq!(mapped["payload"]["tool_name"], "shell__start");
        assert_eq!(projection["headline"], "Running command");
        assert_eq!(projection["command_label"], "node -e <inline script>");
        assert_eq!(projection["summary"], "");
        let projection_text = serde_json::to_string(projection).expect("projection json");
        assert!(!projection_text.contains("shell__start:"));
        assert!(!projection_text.contains("command_id"));
    }

    #[test]
    fn workload_activity_stdio_projects_sanitized_shell_output_excerpt() {
        let event = KernelEvent::WorkloadActivity(WorkloadActivityEvent {
            session_id: [4u8; 32],
            step_index: 8,
            workload_id:
                "shell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9"
                    .to_string(),
            display_label: Some("node -e <inline script>".to_string()),
            timestamp_ms: 1_772_000_000_001,
            kind: WorkloadActivityKind::Stdio {
                stream: "stdout".to_string(),
                chunk:
                    "<ell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9-1\nHELPER: ready\nioi_rc=0\n"
                        .to_string(),
                seq: 1,
                is_final: false,
                exit_code: None,
            },
        });
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["event_kind"], "tool.output");
        assert_eq!(mapped["status"], "running");
        assert_eq!(projection["headline"], "Running command");
        assert_eq!(projection["command_label"], "node -e <inline script>");
        assert_eq!(projection["excerpt_preview"], "HELPER: ready");
        let projection_text = serde_json::to_string(projection).expect("projection json");
        assert!(!projection_text.contains("shell__start:"));
        assert!(!projection_text.contains("ioi_rc="));
    }

    #[test]
    fn retained_shell_duplicate_input_noop_projects_as_completed_work() {
        let event = KernelEvent::AgentActionResult {
            session_id: [4u8; 32],
            step_index: 9,
            tool_name: "shell__input".to_string(),
            output: "Input was already sent; continuing with status/cleanup.".to_string(),
            error_class: Some("NoEffectAfterAction".to_string()),
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["event_kind"], "tool.completed");
        assert_eq!(mapped["status"], "completed");
        assert_eq!(projection["headline"], "Skipped duplicate input");
        assert_eq!(
            projection["summary"],
            "Input was already sent; continuing with status/cleanup."
        );
    }

    #[test]
    fn retained_shell_obsolete_input_after_stop_projects_as_completed_work() {
        let event = KernelEvent::AgentActionResult {
            session_id: [4u8; 32],
            step_index: 9,
            tool_name: "shell__input".to_string(),
            output: "Retained command was already stopped; continuing with retained shell cleanup."
                .to_string(),
            error_class: Some("NoEffectAfterAction".to_string()),
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["event_kind"], "tool.completed");
        assert_eq!(mapped["status"], "completed");
        assert_eq!(projection["headline"], "Skipped obsolete input");
        assert_eq!(
            projection["summary"],
            "Retained command was already stopped; continuing with cleanup."
        );
    }

    #[test]
    fn retained_shell_duplicate_status_noop_projects_as_completed_work() {
        let event = KernelEvent::AgentActionResult {
            session_id: [4u8; 32],
            step_index: 10,
            tool_name: "shell__status".to_string(),
            output: "Status checked".to_string(),
            error_class: Some("NoEffectAfterAction".to_string()),
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["event_kind"], "tool.completed");
        assert_eq!(mapped["status"], "completed");
        assert_eq!(projection["headline"], "Checked command status");
        assert_eq!(projection["summary"], "Status checked");
    }

    #[test]
    fn retained_shell_status_noop_without_error_class_projects_as_completed_work() {
        let event = KernelEvent::AgentActionResult {
            session_id: [4u8; 32],
            step_index: 10,
            tool_name: "shell__status".to_string(),
            output: "Status checked".to_string(),
            error_class: None,
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let projection = &mapped["payload_summary"];
        assert_eq!(mapped["event_kind"], "tool.completed");
        assert_eq!(mapped["status"], "completed");
        assert_eq!(projection["headline"], "Checked command status");
        assert_eq!(projection["summary"], "Status checked");
    }

    #[test]
    fn route_decision_does_not_project_shell_execution_as_started() {
        let projection = product_projection_for_event(
            "tool.route_decision",
            "completed",
            "runtime",
            "tool_router",
            &serde_json::json!({
                "tool_name": "shell__start"
            }),
        );
        assert_eq!(projection["headline"], "Tool route selected");
        assert_ne!(projection["summary"], "Started command");
    }

    #[test]
    fn compacts_large_tool_output_in_bridge_events() {
        let large_output = "x".repeat(BRIDGE_EVENT_TEXT_PREVIEW_BYTES * 3);
        let event = KernelEvent::AgentActionResult {
            session_id: [9u8; 32],
            step_index: 1,
            tool_name: "file__read".to_string(),
            output: large_output,
            error_class: None,
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let output = mapped["payload"]["output"].as_str().expect("string output");
        assert!(output.len() < BRIDGE_EVENT_TEXT_PREVIEW_BYTES + 128);
        assert!(output.contains("[truncated"));
        assert_eq!(
            mapped["payload"]["kernel_event"]["AgentActionResult"]["output"]["truncated"],
            true
        );
    }

    #[test]
    fn maps_firewall_interception_to_approval_or_policy() {
        let approval = KernelEvent::FirewallInterception {
            verdict: "REQUIRE_APPROVAL".to_string(),
            target: "net::fetch".to_string(),
            request_hash: [3u8; 32],
            session_id: Some([4u8; 32]),
        };
        let mapped = kernel_event_to_tti_event(&approval, &context()).expect("mapped event");
        assert_eq!(mapped["event_kind"], "approval.required");
        assert_eq!(mapped["component_kind"], "approval_required");
        assert_eq!(mapped["workflow_node_id"], "runtime.approval-gate");

        let blocked = KernelEvent::FirewallInterception {
            verdict: "BLOCK".to_string(),
            target: "fs::delete".to_string(),
            request_hash: [5u8; 32],
            session_id: None,
        };
        let mapped = kernel_event_to_tti_event(&blocked, &context()).expect("mapped event");
        assert_eq!(mapped["event_kind"], "policy.blocked");
        assert_eq!(mapped["component_kind"], "policy_blocked");
        assert_eq!(mapped["workflow_node_id"], "runtime.policy-gate");
    }

    #[test]
    fn maps_workload_receipt_to_receipt_event() {
        let event = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [6u8; 32],
            step_index: 9,
            workload_id: "workload-1".to_string(),
            timestamp_ms: 1_765_000_000_000,
            receipt: WorkloadReceipt::Exec(WorkloadExecReceipt {
                tool_name: "shell__run".to_string(),
                command: "printf".to_string(),
                args: vec!["ok".to_string()],
                cwd: "/tmp/ioi".to_string(),
                detach: false,
                timeout_ms: 1000,
                success: true,
                exit_code: Some(0),
                error_class: None,
                command_preview: "printf ok".to_string(),
            }),
        });
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(mapped["source_event_kind"], "KernelEvent::WorkloadReceipt");
        assert_eq!(mapped["event_kind"], "receipt.emitted");
        assert_eq!(mapped["component_kind"], "receipt");
        assert_eq!(mapped["workflow_node_id"], "runtime.receipt");
        assert_eq!(mapped["payload"]["receipt_kind"], "exec");
        assert_eq!(mapped["payload"]["tool_name"], "shell__run");
        assert_eq!(mapped["payload"]["success"], true);
        assert_eq!(mapped["payload_summary"]["visibility"], "runs_tracing");
        assert_eq!(
            mapped["payload_summary"]["headline"],
            "Runtime receipt recorded"
        );
    }
}
