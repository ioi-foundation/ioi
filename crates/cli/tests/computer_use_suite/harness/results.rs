use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::support::extract_error_class;
use crate::computer_use_suite::types::{
    AgentBackend, ArtifactBundle, BenchmarkSupportState, BridgeState, ComputerUseCase,
    ComputerUseCaseResult, ComputerUseMode, KernelBehaviorObservation, ToolStepRecord,
    ValidationSummary,
};
use ioi_types::app::{KernelEvent, WorkloadReceipt};

#[derive(Default)]
pub(super) struct AgentKernelObservations {
    pub tool_steps: Vec<ToolStepRecord>,
    pub executed_tools: Vec<String>,
    pub routing_receipt_count: usize,
    pub intent_receipt_count: usize,
    pub execution_contract_receipt_count: usize,
    pub workload_receipt_count: usize,
    pub workload_activity_count: usize,
    pub failure_class: Option<String>,
}

fn parse_action_json_parts(action_json: &str) -> Option<(String, Value)> {
    let parsed = serde_json::from_str::<Value>(action_json).ok()?;
    let name = parsed.get("name").and_then(Value::as_str)?.to_string();
    let arguments = parsed
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some((name, arguments))
}

fn raw_output_is_action_echo(raw_output: &str, action_json: &str) -> bool {
    let trimmed = raw_output.trim();
    if trimmed.is_empty() || trimmed == action_json.trim() {
        return true;
    }

    serde_json::from_str::<Value>(trimmed)
        .ok()
        .and_then(|value| {
            Some(
                value.get("name").and_then(Value::as_str).is_some()
                    && value.get("arguments").is_some(),
            )
        })
        .unwrap_or(false)
}

pub(super) fn collect_agent_kernel_observations(
    kernel_events: &[KernelEvent],
    tool_steps: &[ToolStepRecord],
    bridge_state: &BridgeState,
) -> AgentKernelObservations {
    let mut observations = AgentKernelObservations::default();
    let mut step_traces = BTreeMap::<u32, String>::new();
    let mut action_results = BTreeMap::<(u32, String), (String, Option<String>)>::new();
    let mut matched_action_results = BTreeSet::<(u32, String)>::new();

    for event in kernel_events {
        match event {
            KernelEvent::AgentStep(trace) => {
                step_traces
                    .entry(trace.step_index)
                    .or_insert_with(|| trace.raw_output.clone());
            }
            KernelEvent::AgentActionResult {
                step_index,
                tool_name,
                output,
                error_class,
                ..
            } => {
                action_results.insert(
                    (*step_index, tool_name.clone()),
                    (output.clone(), error_class.clone()),
                );
                if observations.failure_class.is_none()
                    && !tool_name.starts_with("system::")
                    && error_class.is_some()
                {
                    observations.failure_class = error_class.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                observations.routing_receipt_count =
                    observations.routing_receipt_count.saturating_add(1);
                if observations.failure_class.is_none()
                    && !receipt.tool_name.starts_with("system::")
                    && !receipt.post_state.success
                    && !receipt.failure_class_name.is_empty()
                {
                    observations.failure_class = Some(receipt.failure_class_name.clone());
                }
            }
            KernelEvent::IntentResolutionReceipt(_) => {
                observations.intent_receipt_count =
                    observations.intent_receipt_count.saturating_add(1);
            }
            KernelEvent::ExecutionContractReceipt(_) => {
                observations.execution_contract_receipt_count = observations
                    .execution_contract_receipt_count
                    .saturating_add(1);
            }
            KernelEvent::WorkloadReceipt(receipt) => {
                observations.workload_receipt_count =
                    observations.workload_receipt_count.saturating_add(1);
                if observations.failure_class.is_none() {
                    observations.failure_class = match &receipt.receipt {
                        WorkloadReceipt::Exec(item) => item.error_class.clone(),
                        WorkloadReceipt::FsWrite(item) => item.error_class.clone(),
                        WorkloadReceipt::NetFetch(item) => item.error_class.clone(),
                        WorkloadReceipt::WebRetrieve(item) => item.error_class.clone(),
                        WorkloadReceipt::MemoryRetrieve(item) => item.error_class.clone(),
                        WorkloadReceipt::Adapter(item) => item.error_class.clone(),
                    };
                }
            }
            KernelEvent::WorkloadActivity(_) => {
                observations.workload_activity_count =
                    observations.workload_activity_count.saturating_add(1);
            }
            _ => {}
        }
    }

    for event in kernel_events {
        let KernelEvent::RoutingReceipt(receipt) = event else {
            continue;
        };

        let (tool_name, arguments) = parse_action_json_parts(&receipt.action_json)
            .unwrap_or_else(|| (receipt.tool_name.clone(), json!({})));
        let action_result_key = (receipt.step_index, receipt.tool_name.clone());
        let action_result = action_results.get(&action_result_key);
        if action_result.is_some() {
            matched_action_results.insert(action_result_key);
        }
        let history_entry = action_result.map(|(output, _)| output.clone()).or_else(|| {
            step_traces
                .get(&receipt.step_index)
                .filter(|raw_output| !raw_output_is_action_echo(raw_output, &receipt.action_json))
                .cloned()
        });
        let error = action_result
            .and_then(|(_, error_class)| error_class.clone())
            .or_else(|| {
                (!receipt.post_state.success && !receipt.failure_class_name.is_empty())
                    .then(|| receipt.failure_class_name.clone())
            });

        observations.executed_tools.push(tool_name.clone());
        observations.tool_steps.push(ToolStepRecord {
            step_index: receipt.step_index,
            tool_name,
            arguments,
            success: receipt.post_state.success,
            history_entry,
            error,
            bridge_reward: bridge_state.reward,
            bridge_terminated: bridge_state.terminated,
        });
    }

    for event in kernel_events {
        let KernelEvent::AgentActionResult {
            step_index,
            tool_name,
            output,
            error_class,
            ..
        } = event
        else {
            continue;
        };

        if matched_action_results.contains(&(*step_index, tool_name.clone())) {
            continue;
        }

        observations.executed_tools.push(tool_name.clone());
        observations.tool_steps.push(ToolStepRecord {
            step_index: *step_index,
            tool_name: tool_name.clone(),
            arguments: json!({}),
            success: error_class.is_none(),
            history_entry: Some(output.clone()),
            error: error_class.clone(),
            bridge_reward: bridge_state.reward,
            bridge_terminated: bridge_state.terminated,
        });
    }

    if observations.executed_tools.is_empty() && !tool_steps.is_empty() {
        observations.executed_tools = tool_steps
            .iter()
            .map(|step| step.tool_name.clone())
            .collect::<Vec<_>>();
        observations.tool_steps = tool_steps.to_vec();
        if observations.failure_class.is_none() {
            observations.failure_class = tool_steps.iter().find_map(|step| step.error.clone());
        }
    }

    observations
}

pub(super) fn error_case_result(
    case: &ComputerUseCase,
    mode: ComputerUseMode,
    agent_backend: Option<AgentBackend>,
    artifact_root: PathBuf,
    elapsed_ms: u128,
    failure_class: String,
) -> ComputerUseCaseResult {
    let extracted_failure = extract_error_class(&failure_class).or(Some(failure_class));
    ComputerUseCaseResult {
        case_id: case.id.clone(),
        env_id: case.env_id.clone(),
        seed: case.seed,
        mode,
        agent_backend,
        task_set: case.task_set,
        utterance: String::new(),
        elapsed_ms,
        expected_reward_floor: case.expected_reward_floor,
        final_reward: 0.0,
        expected_pass: case.expected_pass,
        terminated: false,
        truncated: false,
        overall_pass: false,
        tool_steps: Vec::new(),
        oracle_steps: Vec::new(),
        kernel_events: Vec::new(),
        bridge_state: BridgeState::default(),
        kernel_behavior: KernelBehaviorObservation::default(),
        validation: ValidationSummary::default(),
        artifacts: ArtifactBundle {
            artifact_root: artifact_root.to_string_lossy().to_string(),
            bridge_state_path: None,
            kernel_events_path: None,
            agent_state_path: None,
            json_report_path: None,
            markdown_summary_path: None,
            csv_summary_path: None,
            inference_trace_path: None,
            inference_calls_path: None,
            screenshot_paths: Vec::new(),
            snapshot_paths: Vec::new(),
        },
        failure_class: extracted_failure,
        support_state: BenchmarkSupportState::NotYetAttempted,
        primary_gap_class: None,
        secondary_gap_tags: Vec::new(),
    }
}
