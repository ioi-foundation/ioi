use super::worker::{execute_worker_step, WorkerExecutionResult};
use crate::agentic::desktop::service::lifecycle::spawn_delegated_child_session;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, ExecutionPlanState, WorkerAssignment,
};
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, ChatMessage};
use ioi_types::app::{KernelEvent, PlanReceiptEvent, PlanWorkerNode};
use ioi_types::error::TransactionError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecutionPlan {
    plan_id: String,
    query: String,
    intent_id: String,
    selected_route: String,
    steps: Vec<PlannedStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlannedStep {
    step_key: String,
    goal: String,
    success_criteria: String,
    max_retries: u8,
    tool_name: String,
    arguments: serde_json::Value,
}

#[derive(Debug, Clone)]
enum TimerOperation {
    Set {
        duration_seconds: u64,
        label: Option<String>,
    },
    Cancel {
        timer_id: Option<String>,
    },
    List,
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn format_epoch_ms_utc(epoch_ms: u64) -> String {
    let epoch_seconds = (epoch_ms / 1000) as i64;
    match OffsetDateTime::from_unix_timestamp(epoch_seconds) {
        Ok(dt) => dt
            .format(&Rfc3339)
            .unwrap_or_else(|_| format!("unix:{}s", epoch_seconds)),
        Err(_) => format!("unix:{}s", epoch_seconds),
    }
}

fn duration_regex() -> &'static Regex {
    static DURATION_RE: OnceLock<Regex> = OnceLock::new();
    DURATION_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(\d+)\s*(seconds?|secs?|minutes?|mins?|hours?|hrs?)\b")
            .expect("duration regex")
    })
}

fn parse_duration_seconds(query: &str) -> Option<u64> {
    let caps = duration_regex().captures(query)?;
    let value: u64 = caps.get(1)?.as_str().parse().ok()?;
    let unit = caps.get(2)?.as_str().to_ascii_lowercase();
    let factor = if unit.starts_with("sec") {
        1
    } else if unit.starts_with("min") {
        60
    } else if unit.starts_with("hour") || unit.starts_with("hr") {
        3600
    } else {
        1
    };
    Some(value.saturating_mul(factor))
}

fn parse_timer_operation(query: &str) -> TimerOperation {
    let query_lc = query.to_ascii_lowercase();
    if query_lc.contains("cancel") || query_lc.contains("stop timer") {
        let timer_id = Regex::new(r"\b[a-f0-9]{8,64}\b")
            .ok()
            .and_then(|re| re.find(&query_lc))
            .map(|m| m.as_str().to_string());
        return TimerOperation::Cancel { timer_id };
    }
    if query_lc.contains("list") || query_lc.contains("show") {
        return TimerOperation::List;
    }
    let duration_seconds = parse_duration_seconds(query).unwrap_or(15 * 60);
    TimerOperation::Set {
        duration_seconds,
        label: None,
    }
}

fn build_timer_tool(operation: &TimerOperation) -> (String, serde_json::Value, AgentTool) {
    match operation {
        TimerOperation::Set {
            duration_seconds,
            label,
        } => {
            let args = json!({
                "duration_seconds": duration_seconds,
                "label": label,
            });
            (
                "timer__set".to_string(),
                args.clone(),
                AgentTool::TimerSet {
                    duration_seconds: *duration_seconds,
                    label: label.clone(),
                },
            )
        }
        TimerOperation::Cancel { timer_id } => {
            let id = timer_id.clone().unwrap_or_else(|| "latest".to_string());
            let args = json!({ "timer_id": id });
            (
                "timer__cancel".to_string(),
                args.clone(),
                AgentTool::TimerCancel { timer_id: id },
            )
        }
        TimerOperation::List => (
            "timer__list".to_string(),
            json!({}),
            AgentTool::TimerList {},
        ),
    }
}

fn synthesize_execution_plan(
    query: &str,
    intent_id: &str,
    operation: &TimerOperation,
) -> ExecutionPlan {
    let (tool_name, tool_args, _) = build_timer_tool(operation);
    ExecutionPlan {
        plan_id: format!("plan-{}", now_epoch_ms()),
        query: query.to_string(),
        intent_id: intent_id.to_string(),
        selected_route: "route.pending_host_inspection".to_string(),
        steps: vec![
            PlannedStep {
                step_key: "inspect_host".to_string(),
                goal: "Inspect host environment and available timer surfaces".to_string(),
                success_criteria: "Returns OS, distro, desktop environment, and timer surfaces"
                    .to_string(),
                max_retries: 1,
                tool_name: "system__inspect_host".to_string(),
                arguments: json!({}),
            },
            PlannedStep {
                step_key: "timer_action".to_string(),
                goal: "Execute timer workflow action".to_string(),
                success_criteria: "Timer set/list/cancel result returned from runtime".to_string(),
                max_retries: 1,
                tool_name,
                arguments: tool_args,
            },
        ],
    }
}

fn plan_hash(plan: &ExecutionPlan) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(plan).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn emit_plan_receipt(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    plan_hash: [u8; 32],
    selected_route: &str,
    worker_graph: &[PlanWorkerNode],
    policy_bindings: &[String],
) {
    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::PlanReceipt(PlanReceiptEvent {
            session_id: Some(session_id),
            plan_hash,
            selected_route: selected_route.to_string(),
            worker_graph: worker_graph.to_vec(),
            policy_bindings: policy_bindings.to_vec(),
        }));
    }
}

fn worker_node_for(step: &WorkerAssignment) -> PlanWorkerNode {
    PlanWorkerNode {
        worker_session_id_hex: step
            .assigned_session_id
            .map(hex::encode)
            .unwrap_or_else(|| "pending".to_string()),
        step_key: step.step_key.clone(),
        goal: step.goal.clone(),
        status: step.status.clone(),
    }
}

fn parse_host_timer_surface(host_output: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(host_output) else {
        return false;
    };
    value
        .get("timer_surfaces")
        .and_then(|v| v.as_array())
        .map(|surfaces| {
            surfaces.iter().any(|surface| {
                surface
                    .as_str()
                    .map(|s| matches!(s, "timer__set" | "timer__cancel" | "timer__list"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn build_guidance(host_output: Option<&str>) -> String {
    if let Some(raw) = host_output {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
            let os = value
                .get("os")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let desktop = value
                .get("desktop_environment")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return format!(
                "No executable timer route was available. Host detected as '{}' (desktop '{}'). Use your desktop clock/timer app or run `sleep <duration> && notify-send \"Timer finished\"` manually.",
                os, desktop
            );
        }
    }
    "No executable timer route was available. Use your desktop clock/timer app or a terminal-based sleep+notification fallback.".to_string()
}

fn step_as_assignment(step: &PlannedStep) -> WorkerAssignment {
    WorkerAssignment {
        step_key: step.step_key.clone(),
        goal: step.goal.clone(),
        success_criteria: step.success_criteria.clone(),
        max_retries: step.max_retries,
        retries_used: 0,
        assigned_session_id: None,
        status: "pending".to_string(),
    }
}

fn finalize_set_message(result_output: Option<&str>, selected_route: &str) -> String {
    let Some(raw) = result_output else {
        return format!(
            "Planner route: {}. Timer action executed but runtime returned no payload.",
            selected_route
        );
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return format!(
            "Planner route: {}. Timer action executed. Raw output: {}",
            selected_route, raw
        );
    };
    let timer_id = value
        .get("timer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let target_epoch_ms = value
        .get("target_epoch_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let absolute_timestamp = format_epoch_ms_utc(target_epoch_ms);
    format!(
        "Timer scheduled. Route: {}. Timer ID: {}. Target UTC: {}.",
        selected_route, timer_id, absolute_timestamp
    )
}

pub async fn try_execute_planned_workflow(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    call_context: ServiceCallContext<'_>,
    block_height: u64,
) -> Result<bool, TransactionError> {
    let resolved = match agent_state.resolved_intent.as_ref() {
        Some(resolved) => resolved,
        None => return Ok(false),
    };
    if resolved.intent_id != "timer.manage" {
        return Ok(false);
    }

    let query = service
        .hydrate_session_history(agent_state.session_id)
        .ok()
        .and_then(|history| {
            history
                .iter()
                .rfind(|message| message.role == "user")
                .map(|message| message.content.clone())
        })
        .unwrap_or_else(|| agent_state.goal.clone());
    let operation = parse_timer_operation(&query);
    let (_tool_name, _tool_args, timer_tool) = build_timer_tool(&operation);
    let mut plan = synthesize_execution_plan(&query, &resolved.intent_id, &operation);
    let plan_hash = plan_hash(&plan)?;

    let mut plan_state = ExecutionPlanState {
        plan_id: plan.plan_id.clone(),
        plan_hash,
        selected_route: plan.selected_route.clone(),
        status: "synthesized".to_string(),
        worker_assignments: plan.steps.iter().map(step_as_assignment).collect(),
    };

    let mut worker_graph = plan_state
        .worker_assignments
        .iter()
        .map(worker_node_for)
        .collect::<Vec<_>>();
    emit_plan_receipt(
        service,
        agent_state.session_id,
        plan_hash,
        &plan_state.selected_route,
        &worker_graph,
        &[
            "system::inspect_host".to_string(),
            "timer::manage".to_string(),
        ],
    );

    let mut host_output: Option<String> = None;
    let mut timer_output: Option<String> = None;
    for assignment in &mut plan_state.worker_assignments {
        let worker_goal = assignment.goal.clone();
        let worker_session_id = spawn_delegated_child_session(
            service,
            state,
            agent_state,
            plan_hash,
            &worker_goal,
            0,
            agent_state.step_count,
            block_height,
        )
        .await?;
        assignment.assigned_session_id = Some(worker_session_id);
        assignment.status = "running".to_string();

        let worker_tool = if assignment.step_key == "inspect_host" {
            AgentTool::SystemInspectHost {}
        } else {
            timer_tool.clone()
        };
        let worker_result: WorkerExecutionResult = execute_worker_step(
            service,
            state,
            call_context,
            rules,
            worker_session_id,
            worker_tool,
            assignment.max_retries,
        )
        .await?;

        assignment.retries_used = worker_result.attempts;
        assignment.status = if worker_result.success {
            "completed".to_string()
        } else {
            "failed".to_string()
        };
        if assignment.step_key == "inspect_host" {
            host_output = worker_result.output.clone();
        } else {
            timer_output = worker_result.output.clone();
        }
    }

    let timer_supported = host_output
        .as_deref()
        .map(parse_host_timer_surface)
        .unwrap_or(false);
    plan.selected_route = if timer_supported {
        "runtime.timer_toolchain".to_string()
    } else {
        "fallback.guidance_only".to_string()
    };
    plan_state.selected_route = plan.selected_route.clone();

    let final_message = if !timer_supported {
        build_guidance(host_output.as_deref())
    } else {
        match operation {
            TimerOperation::Set { .. } => {
                finalize_set_message(timer_output.as_deref(), &plan_state.selected_route)
            }
            TimerOperation::Cancel { .. } => format!(
                "Timer cancellation attempted via route {}. Result: {}",
                plan_state.selected_route,
                timer_output.unwrap_or_else(|| "no runtime payload".to_string())
            ),
            TimerOperation::List => format!(
                "Timer list retrieved via route {}. Payload: {}",
                plan_state.selected_route,
                timer_output.unwrap_or_else(|| "no runtime payload".to_string())
            ),
        }
    };

    plan_state.status = "completed".to_string();
    worker_graph = plan_state
        .worker_assignments
        .iter()
        .map(worker_node_for)
        .collect::<Vec<_>>();
    emit_plan_receipt(
        service,
        agent_state.session_id,
        plan_hash,
        &plan_state.selected_route,
        &worker_graph,
        &[
            "system::inspect_host".to_string(),
            "timer::manage".to_string(),
        ],
    );

    agent_state.status = AgentStatus::Completed(Some(final_message.clone()));
    agent_state.pending_tool_call = None;
    agent_state.pending_tool_jcs = None;
    agent_state.pending_approval = None;
    agent_state.execution_queue.clear();
    agent_state.recent_actions.clear();
    agent_state.step_count = agent_state.step_count.saturating_add(1);

    let chat = ChatMessage {
        role: "assistant".to_string(),
        content: final_message.clone(),
        timestamp: now_epoch_ms(),
        trace_hash: None,
    };
    let _ = service
        .append_chat_to_scs(agent_state.session_id, &chat, block_height)
        .await;

    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::AgentActionResult {
            session_id: agent_state.session_id,
            step_index: agent_state.step_count.saturating_sub(1),
            tool_name: "planner::execute".to_string(),
            output: final_message,
            agent_status: "Completed".to_string(),
        });
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        build_timer_tool, parse_duration_seconds, parse_host_timer_surface, parse_timer_operation,
        plan_hash, synthesize_execution_plan, ExecutionPlan, PlannedStep, TimerOperation,
    };
    use serde_json::json;

    #[test]
    fn parses_duration_seconds_from_query() {
        assert_eq!(
            parse_duration_seconds("Set a timer for 15 minutes"),
            Some(900)
        );
        assert_eq!(parse_duration_seconds("Remind me in 2 hours"), Some(7200));
        assert_eq!(parse_duration_seconds("No duration"), None);
    }

    #[test]
    fn parses_timer_operation_from_query() {
        match parse_timer_operation("Set a timer for 30 minutes") {
            TimerOperation::Set {
                duration_seconds, ..
            } => assert_eq!(duration_seconds, 1800),
            other => panic!("expected set op, got {:?}", other),
        }
        assert!(matches!(
            parse_timer_operation("list active timers"),
            TimerOperation::List
        ));
        assert!(matches!(
            parse_timer_operation("cancel timer abcdef12"),
            TimerOperation::Cancel { .. }
        ));
    }

    #[test]
    fn synthesizes_plan_with_host_inspect_and_timer_action() {
        let op = TimerOperation::Set {
            duration_seconds: 600,
            label: None,
        };
        let plan = synthesize_execution_plan("set timer", "timer.manage", &op);
        assert_eq!(plan.intent_id, "timer.manage");
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].tool_name, "system__inspect_host");
        assert_eq!(plan.steps[1].tool_name, "timer__set");
    }

    #[test]
    fn build_timer_tool_matches_operation() {
        let (name, _args, tool) = build_timer_tool(&TimerOperation::List);
        assert_eq!(name, "timer__list");
        assert!(matches!(
            tool,
            ioi_types::app::agentic::AgentTool::TimerList {}
        ));
    }

    #[test]
    fn plan_hash_is_deterministic() {
        let plan = ExecutionPlan {
            plan_id: "plan-fixed".to_string(),
            query: "set timer".to_string(),
            intent_id: "timer.manage".to_string(),
            selected_route: "runtime.timer_toolchain".to_string(),
            steps: vec![PlannedStep {
                step_key: "timer_action".to_string(),
                goal: "set timer".to_string(),
                success_criteria: "timer scheduled".to_string(),
                max_retries: 1,
                tool_name: "timer__set".to_string(),
                arguments: json!({"duration_seconds": 900}),
            }],
        };
        let a = plan_hash(&plan).expect("plan hash a");
        let b = plan_hash(&plan).expect("plan hash b");
        assert_eq!(a, b);
    }

    #[test]
    fn detects_timer_surface_from_host_payload() {
        let payload = json!({
            "timer_surfaces": ["notify-send", "timer__set", "timer__cancel"]
        })
        .to_string();
        assert!(parse_host_timer_surface(&payload));
        assert!(!parse_host_timer_surface(
            r#"{"timer_surfaces":["notify-send"]}"#
        ));
    }
}
