use anyhow::{anyhow, Result};
use ioi_types::app::agentic::AgentTool;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::timeout;

use super::model::AgentModelClient;
use super::prompt::{build_system_prompt, build_user_prompt};
use super::tool_surface::browser_tools;
use crate::computer_use_suite::live_inference_support::InferenceCallRecord;
use crate::computer_use_suite::types::{
    AgentBackend, ArtifactBundle, BenchmarkSupportState, ComputerUseCase, ComputerUseCaseResult,
    KernelBehaviorObservation, SuiteConfig, ValidationSummary,
};

use super::super::bridge::BridgeClient;
use super::super::case_harness::{settle_final_bridge_state, CaseHarness};
use super::super::context::ToolExecutionContext;
use super::super::results::collect_agent_kernel_observations;
use super::super::support::{extract_error_class, now_ms, repo_root, write_json_file};

#[derive(Debug, Serialize)]
struct LivePhaseTimings {
    harness_run_started_at_ms: u64,
    browser_launch_started_at_ms: Option<u64>,
    browser_launch_finished_at_ms: Option<u64>,
    session_created_at_ms: Option<u64>,
    browser_navigation_started_at_ms: Option<u64>,
    browser_navigation_finished_at_ms: Option<u64>,
    initial_bridge_sync_at_ms: Option<u64>,
    initial_bridge_ready_observed_at_ms: Option<u64>,
    agent_start_service_started_at_ms: Option<u64>,
    agent_start_service_finished_at_ms: Option<u64>,
    first_step_service_started_at_ms: Option<u64>,
    first_step_service_finished_at_ms: Option<u64>,
    case_finished_at_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LiveInferenceTrace {
    backend: &'static str,
    runtime_kind: &'static str,
    api_url: String,
    model: String,
    call_count: usize,
    phase_timings: Option<LivePhaseTimings>,
}

pub(crate) struct AgentExecutionContext {
    tools: ToolExecutionContext,
    model: AgentModelClient,
    backend: AgentBackend,
}

impl AgentExecutionContext {
    pub(crate) async fn start(config: &SuiteConfig) -> Result<Self> {
        let model = match config.agent_backend {
            AgentBackend::LiveHttp => AgentModelClient::from_env().await?,
            AgentBackend::DeterministicMiniwob => {
                anyhow::bail!(
                    "ERROR_CLASS=backend_not_supported deterministic_miniwob was removed in the modular harness rewrite; use COMPUTER_USE_SUITE_AGENT_BACKEND=live_http"
                );
            }
        };
        let tools = ToolExecutionContext::start(config).await?;
        Ok(Self {
            tools,
            model,
            backend: config.agent_backend,
        })
    }

    pub(crate) async fn stop(&self) {
        self.tools.stop().await;
    }
}

fn should_capture_artifacts(config: &SuiteConfig, final_reward: f32, terminated: bool) -> bool {
    config.retain_artifacts_for_all_runs || !terminated || final_reward <= 0.0
}

fn tool_from_decision(tool_name: &str, arguments: serde_json::Value) -> Result<AgentTool> {
    serde_json::from_value(json!({
        "name": tool_name,
        "arguments": arguments,
    }))
    .map_err(|err| anyhow!("invalid model tool call {}: {}", tool_name, err))
}

fn write_live_inference_artifacts(
    artifact_root: &Path,
    model: &AgentModelClient,
    call_records: &[InferenceCallRecord],
    phase_timings: LivePhaseTimings,
) -> Result<(String, String)> {
    let trace = LiveInferenceTrace {
        backend: AgentBackend::LiveHttp.as_str(),
        runtime_kind: "OpenAiChatCompletionsHarness",
        api_url: model.api_url().to_string(),
        model: model.model().to_string(),
        call_count: call_records.len(),
        phase_timings: Some(phase_timings),
    };
    let trace_path = artifact_root.join("inference_trace.json");
    let calls_path = artifact_root.join("inference_calls.json");
    write_json_file(&trace_path, &trace)?;
    write_json_file(&calls_path, &call_records)?;
    Ok((
        trace_path.to_string_lossy().to_string(),
        calls_path.to_string_lossy().to_string(),
    ))
}

fn generate_miniwob_case_diagnostics(
    python_bin: &str,
    artifact_root: &Path,
) -> Result<(Option<String>, Option<String>)> {
    let script_path = repo_root()
        .join("tools")
        .join("miniwob")
        .join("diagnose_case.py");
    let output = std::process::Command::new(python_bin)
        .arg(&script_path)
        .arg("--case-dir")
        .arg(artifact_root)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "MiniWoB diagnostics failed for {}: {}",
            artifact_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let json_path = artifact_root.join("diagnostic_summary.json");
    let markdown_path = artifact_root.join("diagnostic_summary.md");
    Ok((
        json_path
            .exists()
            .then(|| json_path.to_string_lossy().to_string()),
        markdown_path
            .exists()
            .then(|| markdown_path.to_string_lossy().to_string()),
    ))
}

pub(crate) async fn run_agent_case(
    config: &SuiteConfig,
    context: &AgentExecutionContext,
    client: BridgeClient,
    case: &ComputerUseCase,
    artifact_root: PathBuf,
) -> Result<ComputerUseCaseResult> {
    let created = client.create_session(case).await?;
    let session_id = created.session_id.clone();
    let result = run_agent_case_session(
        config,
        context,
        client.clone(),
        case,
        artifact_root,
        created,
    )
    .await;
    let close_result = client.close(&session_id).await;
    match (result, close_result) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(case_err), Err(close_err)) => Err(anyhow!(
            "{:#}\n\nsession close failure after case error: {:#}",
            case_err,
            close_err
        )),
    }
}

async fn run_agent_case_session(
    config: &SuiteConfig,
    context: &AgentExecutionContext,
    client: BridgeClient,
    case: &ComputerUseCase,
    artifact_root: PathBuf,
    created: super::super::bridge::BridgeCreateResponse,
) -> Result<ComputerUseCaseResult> {
    let harness_run_started_at_ms = now_ms();
    let launch_timing_ms = context.tools.take_launch_timing_ms();
    let session_created_at_ms = now_ms();
    let mut harness = CaseHarness::new(
        client,
        created.session_id.clone(),
        created.state,
        case.seed,
        &context.tools,
    )
    .await?;

    let result = async {
        let browser_navigation_started_at_ms = Some(now_ms());
        let navigate_result = harness
            .execute_tool(AgentTool::BrowserNavigate {
                url: created.url.clone(),
            })
            .await?;
        if !navigate_result.success {
            return Err(anyhow!(
                "navigate MiniWoB browser to {}: {}",
                created.url,
                navigate_result
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            ));
        }
        let browser_navigation_finished_at_ms = Some(now_ms());
        let ready_state = harness.wait_until_ready().await?;
        let initial_bridge_sync_at_ms = ready_state.last_sync_ms;
        let initial_bridge_ready_observed_at_ms = Some(now_ms());

        let system_prompt = build_system_prompt();
        let tools = browser_tools(case.allowed_tool_profile);
        let started = Instant::now();
        let deadline = Duration::from_secs(case.timeout_seconds);
        let mut call_records = Vec::<InferenceCallRecord>::new();
        let mut first_step_service_started_at_ms = None;
        let mut first_step_service_finished_at_ms = None;
        let mut failure_class = None;

        while started.elapsed() <= deadline && harness.step_count() < case.max_steps {
            let bridge_state = harness.refresh_bridge_state().await?;
            if bridge_state.terminated
                || super::super::reward_meets_floor(bridge_state.reward, case.expected_reward_floor)
            {
                break;
            }

            let user_prompt = build_user_prompt(case, &bridge_state, &harness.tool_steps);
            let decision = context
                .model
                .choose_tool(call_records.len() + 1, &system_prompt, &user_prompt, &tools)
                .await?;
            let tool = match tool_from_decision(&decision.tool_name, decision.arguments.clone()) {
                Ok(tool) => tool,
                Err(err) => {
                    let mut record = decision.call_record;
                    record.error = Some(err.to_string());
                    call_records.push(record);
                    failure_class = extract_error_class(&err.to_string())
                        .or(Some("invalid_model_tool_call".to_string()));
                    break;
                }
            };
            call_records.push(decision.call_record);

            let tool_started_at_ms = now_ms();
            if first_step_service_started_at_ms.is_none() {
                first_step_service_started_at_ms = Some(tool_started_at_ms);
            }
            let tool_result = timeout(
                deadline.saturating_sub(started.elapsed()),
                harness.execute_tool(tool),
            )
            .await;
            match tool_result {
                Ok(Ok(result)) => {
                    if first_step_service_finished_at_ms.is_none() {
                        first_step_service_finished_at_ms = Some(now_ms());
                    }
                    if !result.success && failure_class.is_none() {
                        failure_class = result
                            .error
                            .as_deref()
                            .and_then(extract_error_class)
                            .or(Some("tool_execution_failed".to_string()));
                    }
                }
                Ok(Err(err)) => {
                    if first_step_service_finished_at_ms.is_none() {
                        first_step_service_finished_at_ms = Some(now_ms());
                    }
                    failure_class = extract_error_class(&err.to_string())
                        .or(Some("tool_execution_failed".to_string()));
                    break;
                }
                Err(_) => {
                    failure_class = Some("agent_step_timeout".to_string());
                    break;
                }
            }
        }

        if started.elapsed() > deadline && failure_class.is_none() {
            failure_class = Some("TimeoutOrHang".to_string());
        }

        let case_finished_at_ms = now_ms();
        let bridge_state = settle_final_bridge_state(&mut harness, case.local_judge).await?;
        let screenshot_path = artifact_root.join("final.png");
        let bridge_state_path = artifact_root.join("bridge_state.json");
        let kernel_events_path = artifact_root.join("kernel_events.json");
        let should_capture =
            should_capture_artifacts(config, bridge_state.reward, bridge_state.terminated);
        if should_capture {
            if let Some(parent) = screenshot_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Ok(Ok(())) = timeout(
                Duration::from_secs(2),
                harness.capture_screenshot(&screenshot_path),
            )
            .await
            {
                // written
            }
            write_json_file(&bridge_state_path, &bridge_state)?;
            write_json_file(&kernel_events_path, &harness.kernel_events)?;
        }

        let phase_timings = LivePhaseTimings {
            harness_run_started_at_ms,
            browser_launch_started_at_ms: launch_timing_ms.map(|timing| timing.0),
            browser_launch_finished_at_ms: launch_timing_ms.map(|timing| timing.1),
            session_created_at_ms: Some(session_created_at_ms),
            browser_navigation_started_at_ms,
            browser_navigation_finished_at_ms,
            initial_bridge_sync_at_ms,
            initial_bridge_ready_observed_at_ms,
            agent_start_service_started_at_ms: None,
            agent_start_service_finished_at_ms: None,
            first_step_service_started_at_ms,
            first_step_service_finished_at_ms,
            case_finished_at_ms: Some(case_finished_at_ms),
        };
        let (inference_trace_path, inference_calls_path) = if should_capture {
            write_live_inference_artifacts(
                &artifact_root,
                &context.model,
                &call_records,
                phase_timings,
            )?
        } else {
            (String::new(), String::new())
        };
        let (json_report_path, markdown_summary_path) =
            if should_capture && case.id.starts_with("miniwob_") {
                generate_miniwob_case_diagnostics(&config.python_bin, &artifact_root)?
            } else {
                (None, None)
            };

        let observations = collect_agent_kernel_observations(
            &harness.kernel_events,
            &harness.tool_steps,
            &bridge_state,
        );
        let mut final_failure_class = observations.failure_class.or(failure_class);
        if final_failure_class.is_none() && call_records.is_empty() {
            final_failure_class = Some("live_inference_not_observed".to_string());
        }

        let mut snapshot_paths = Vec::new();
        for (index, step) in harness.tool_steps.iter().enumerate() {
            if step.tool_name == "browser__inspect" {
                let path = artifact_root.join(format!("snapshot_{}.xml", index + 1));
                if let Some(xml) = &step.history_entry {
                    let _ = fs::write(&path, xml);
                    snapshot_paths.push(path.to_string_lossy().to_string());
                }
            }
        }

        let kernel_behavior = KernelBehaviorObservation {
            executed_tools: observations.executed_tools,
            action_result_count: if harness.kernel_events.is_empty() {
                harness.tool_steps.len()
            } else {
                harness
                    .kernel_events
                    .iter()
                    .filter(|event| {
                        matches!(event, ioi_types::app::KernelEvent::AgentActionResult { .. })
                    })
                    .count()
            },
            routing_receipt_count: observations.routing_receipt_count,
            intent_receipt_count: observations.intent_receipt_count,
            execution_contract_receipt_count: observations.execution_contract_receipt_count,
            workload_receipt_count: observations.workload_receipt_count,
            workload_activity_count: observations.workload_activity_count,
            disallowed_tools: Vec::new(),
        };

        Ok(ComputerUseCaseResult {
            case_id: case.id.clone(),
            env_id: case.env_id.clone(),
            seed: case.seed,
            mode: crate::computer_use_suite::types::ComputerUseMode::Agent,
            agent_backend: Some(context.backend),
            task_set: case.task_set,
            utterance: bridge_state.utterance.clone(),
            elapsed_ms: started.elapsed().as_millis(),
            expected_reward_floor: case.expected_reward_floor,
            final_reward: bridge_state.reward,
            expected_pass: case.expected_pass,
            terminated: bridge_state.terminated,
            truncated: bridge_state.truncated,
            overall_pass: false,
            tool_steps: harness.tool_steps.clone(),
            oracle_steps: Vec::new(),
            kernel_events: harness.kernel_events.clone(),
            bridge_state: bridge_state.clone(),
            kernel_behavior,
            validation: ValidationSummary::default(),
            artifacts: ArtifactBundle {
                artifact_root: artifact_root.to_string_lossy().to_string(),
                bridge_state_path: should_capture
                    .then(|| bridge_state_path.to_string_lossy().to_string()),
                kernel_events_path: should_capture
                    .then(|| kernel_events_path.to_string_lossy().to_string()),
                agent_state_path: None,
                json_report_path,
                markdown_summary_path,
                csv_summary_path: None,
                inference_trace_path: should_capture.then_some(inference_trace_path),
                inference_calls_path: should_capture.then_some(inference_calls_path),
                screenshot_paths: if should_capture {
                    vec![screenshot_path.to_string_lossy().to_string()]
                } else {
                    Vec::new()
                },
                snapshot_paths,
            },
            failure_class: final_failure_class,
            support_state: BenchmarkSupportState::NotYetAttempted,
            primary_gap_class: None,
            secondary_gap_tags: Vec::new(),
        })
    }
    .await;
    harness.stop().await;
    result
}
