use super::super::live_inference_support::{
    self, configured_model_candidates, select_http_inference_model, CountingInferenceRuntime,
};
use super::agent_backend::{
    FindGreatestState, GuessNumberState, MiniwobAgentRuntime, PendingSocialMediaMenuAction,
    TextEditorPhase,
};
use super::*;
use crate::computer_use_suite::types::AgentBackend;
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use serde::Serialize;
use std::path::Path;
use std::process::Command;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
pub(super) struct SharedAgentExecutionContext {
    browser: Arc<BrowserDriver>,
    gui: Arc<RecordingGuiDriver>,
    terminal: Arc<TerminalDriver>,
    initial_launch_timing_ms: Arc<Mutex<Option<(u64, u64)>>>,
}

impl SharedAgentExecutionContext {
    pub(super) async fn start(config: &SuiteConfig) -> Result<Self> {
        let headless = headless_for_run(config)?;
        let browser = Arc::new(BrowserDriver::new());
        browser.set_lease(true);
        let gui = Arc::new(RecordingGuiDriver::new(browser.clone()));
        let terminal = Arc::new(TerminalDriver::new());
        let browser_launch_started_at_ms = now_ms();
        browser
            .launch(headless)
            .await
            .map_err(|err| anyhow!("launch Chromium for agent mode: {}", err))?;
        let browser_launch_finished_at_ms = now_ms();

        Ok(Self {
            browser,
            gui,
            terminal,
            initial_launch_timing_ms: Arc::new(Mutex::new(Some((
                browser_launch_started_at_ms,
                browser_launch_finished_at_ms,
            )))),
        })
    }

    fn browser(&self) -> Arc<BrowserDriver> {
        self.browser.clone()
    }

    fn gui(&self) -> Arc<RecordingGuiDriver> {
        self.gui.clone()
    }

    fn terminal(&self) -> Arc<TerminalDriver> {
        self.terminal.clone()
    }

    fn take_launch_timing_ms(&self) -> Option<(u64, u64)> {
        self.initial_launch_timing_ms
            .lock()
            .expect("shared launch timing mutex poisoned")
            .take()
    }

    pub(super) async fn stop(&self) {
        self.browser.stop().await;
    }
}

#[derive(Clone)]
pub(super) struct AgentRuntimeFactory {
    backend: AgentBackend,
    live_http: Option<LiveHttpRuntimeContext>,
}

#[derive(Clone)]
struct LiveHttpRuntimeContext {
    api_url: String,
    model: String,
    runtime_kind: &'static str,
    runtime: Arc<CountingInferenceRuntime>,
}

#[derive(Clone)]
struct AgentRuntimeBinding {
    backend: AgentBackend,
    inference_runtime: Arc<dyn InferenceRuntime>,
    deterministic_runtime: Option<Arc<MiniwobAgentRuntime>>,
    live_http: Option<LiveHttpCaseContext>,
}

#[derive(Clone)]
struct LiveHttpCaseContext {
    api_url: String,
    model: String,
    runtime_kind: &'static str,
    runtime: Arc<CountingInferenceRuntime>,
    call_start_index: usize,
}

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

fn should_generate_miniwob_case_diagnostics(
    case: &ComputerUseCase,
    runtime_binding: &AgentRuntimeBinding,
    should_capture_artifacts: bool,
) -> bool {
    should_capture_artifacts && runtime_binding.is_live() && case.id.starts_with("miniwob_")
}

fn generate_miniwob_case_diagnostics(
    python_bin: &str,
    artifact_root: &Path,
) -> Result<(Option<String>, Option<String>)> {
    let script_path = repo_root()
        .join("tools")
        .join("miniwob")
        .join("diagnose_case.py");
    let output = Command::new(python_bin)
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

async fn wait_for_agent_bridge_ready(
    client: &BridgeClient,
    session_id: &str,
    timeout: Duration,
) -> Result<BridgeState> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = client.state(session_id).await?;
        if state.info.task_ready.unwrap_or(false) && !state.utterance.is_empty() {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "ERROR_CLASS=bridge_not_ready session {} did not become ready (last reason: {:?})",
                session_id,
                state.info.reason
            ));
        }
        sleep(Duration::from_millis(80)).await;
    }
}

async fn settle_agent_bridge_state(
    client: &BridgeClient,
    session_id: &str,
    local_judge: LocalJudge,
) -> Result<BridgeState> {
    let mut state = client.state(session_id).await?;
    if matches!(local_judge, LocalJudge::HoverShapeReceipts) || state.terminated || state.truncated
    {
        return Ok(state);
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        sleep(Duration::from_millis(100)).await;
        let refreshed = client.state(session_id).await?;
        let changed = refreshed.last_sync_ms != state.last_sync_ms
            || refreshed.reward != state.reward
            || refreshed.info.raw_reward != state.info.raw_reward
            || refreshed.terminated != state.terminated
            || refreshed.truncated != state.truncated;
        if changed {
            state = refreshed;
            if state.terminated || state.truncated {
                break;
            }
        }
    }

    Ok(state)
}

fn bridge_task_brief(bridge_state: &BridgeState) -> Option<&str> {
    bridge_state
        .info
        .query_text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .or_else(|| {
            let utterance = bridge_state.utterance.trim();
            (!utterance.is_empty()).then_some(utterance)
        })
}

fn suite_agent_goal(env_id: &str, task_brief: Option<&str>) -> String {
    match task_brief.map(str::trim).filter(|text| !text.is_empty()) {
        Some(task_brief) => format!(
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: {}",
            task_brief
        ),
        None => format!(
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task: {}",
            env_id
        ),
    }
}

fn remaining_agent_step_budget(started: &Instant, deadline: Duration) -> Option<Duration> {
    deadline
        .checked_sub(started.elapsed())
        .filter(|budget| !budget.is_zero())
}

impl AgentRuntimeFactory {
    pub(super) async fn from_config(config: &SuiteConfig) -> Result<Self> {
        match config.agent_backend {
            AgentBackend::DeterministicMiniwob => Ok(Self {
                backend: AgentBackend::DeterministicMiniwob,
                live_http: None,
            }),
            AgentBackend::LiveHttp => {
                let openai_api_key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                    anyhow!(
                        "OPENAI_API_KEY is required for COMPUTER_USE_SUITE_AGENT_BACKEND=live_http"
                    )
                })?;
                let api_url = std::env::var("OPENAI_API_URL").unwrap_or_else(|_| {
                    live_inference_support::OPENAI_CHAT_COMPLETIONS_URL.to_string()
                });
                let model_candidates =
                    configured_model_candidates("COMPUTER_USE_SUITE_AGENT_MODELS", "OPENAI_MODEL");
                let model = select_http_inference_model(
                    &api_url,
                    &openai_api_key,
                    &model_candidates,
                    "COMPUTER_USE_SUITE_INFERENCE_MODEL_SELECTED",
                )
                .await?;
                let runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
                    api_url.clone(),
                    openai_api_key,
                    model.clone(),
                ));
                Ok(Self {
                    backend: AgentBackend::LiveHttp,
                    live_http: Some(LiveHttpRuntimeContext {
                        api_url,
                        model,
                        runtime_kind: "HttpInferenceRuntime",
                        runtime: Arc::new(CountingInferenceRuntime::new(runtime)),
                    }),
                })
            }
        }
    }

    fn bind_case(
        &self,
        case: &ComputerUseCase,
        client: BridgeClient,
        session_id: String,
        url: String,
    ) -> AgentRuntimeBinding {
        match self.backend {
            AgentBackend::DeterministicMiniwob => {
                let runtime = Arc::new(MiniwobAgentRuntime {
                    case: case.clone(),
                    client,
                    session_id,
                    url,
                    startup_navigation_issued: Mutex::new(false),
                    pending_followup: Mutex::new(None),
                    optimistic_checked_labels: Mutex::new(BTreeSet::new()),
                    last_scroll_action: Mutex::new(None),
                    last_copy_paste_action: Mutex::new(None),
                    last_hover_shape_phase: Mutex::new(None),
                    text_editor_phase: Mutex::new(TextEditorPhase::default()),
                    guess_number_state: Mutex::new(GuessNumberState::default()),
                    find_greatest_state: Mutex::new(FindGreatestState::default()),
                    count_sides_estimate: Mutex::new(None),
                    pending_social_media_menu_action: Mutex::new(
                        None::<PendingSocialMediaMenuAction>,
                    ),
                });
                let inference_runtime: Arc<dyn InferenceRuntime> = runtime.clone();
                AgentRuntimeBinding {
                    backend: AgentBackend::DeterministicMiniwob,
                    inference_runtime,
                    deterministic_runtime: Some(runtime),
                    live_http: None,
                }
            }
            AgentBackend::LiveHttp => {
                let live_http = self
                    .live_http
                    .as_ref()
                    .expect("live_http backend should be initialized");
                let inference_runtime: Arc<dyn InferenceRuntime> = live_http.runtime.clone();
                AgentRuntimeBinding {
                    backend: AgentBackend::LiveHttp,
                    inference_runtime,
                    deterministic_runtime: None,
                    live_http: Some(LiveHttpCaseContext {
                        api_url: live_http.api_url.clone(),
                        model: live_http.model.clone(),
                        runtime_kind: live_http.runtime_kind,
                        runtime: live_http.runtime.clone(),
                        call_start_index: live_http.runtime.call_count(),
                    }),
                }
            }
        }
    }
}

impl AgentRuntimeBinding {
    fn observe_kernel_events(&self, kernel_events: &[KernelEvent]) {
        if let Some(runtime) = &self.deterministic_runtime {
            runtime.observe_kernel_events(kernel_events);
        }
    }

    fn is_live(&self) -> bool {
        self.live_http.is_some()
    }

    fn agent_backend(&self) -> AgentBackend {
        self.backend
    }

    fn write_live_inference_artifacts(
        &self,
        artifact_root: &PathBuf,
        phase_timings: Option<LivePhaseTimings>,
    ) -> Result<(Option<String>, Option<String>, usize)> {
        let Some(live_http) = &self.live_http else {
            return Ok((None, None, 0));
        };

        let call_records = live_http.runtime.call_records();
        let case_call_records = call_records
            .into_iter()
            .skip(live_http.call_start_index)
            .collect::<Vec<_>>();
        let trace = LiveInferenceTrace {
            backend: AgentBackend::LiveHttp.as_str(),
            runtime_kind: live_http.runtime_kind,
            api_url: live_http.api_url.clone(),
            model: live_http.model.clone(),
            call_count: case_call_records.len(),
            phase_timings,
        };

        let trace_path = artifact_root.join("inference_trace.json");
        let calls_path = artifact_root.join("inference_calls.json");
        write_json_file(&trace_path, &trace)?;
        write_json_file(&calls_path, &case_call_records)?;
        Ok((
            Some(trace_path.to_string_lossy().to_string()),
            Some(calls_path.to_string_lossy().to_string()),
            case_call_records.len(),
        ))
    }
}

pub(super) async fn run_agent_case(
    config: &SuiteConfig,
    runtime_factory: &AgentRuntimeFactory,
    execution_context: &SharedAgentExecutionContext,
    client: BridgeClient,
    case: &ComputerUseCase,
    artifact_root: PathBuf,
) -> Result<ComputerUseCaseResult> {
    let harness_run_started_at_ms = now_ms();
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let browser = execution_context.browser();
    let gui = execution_context.gui();
    let terminal = execution_context.terminal();
    let launch_timing_ms = execution_context.take_launch_timing_ms();
    browser
        .reset_active_page_for_navigation()
        .await
        .map_err(|err| anyhow!("reset shared agent browser page: {}", err))?;
    let created = client.create_session(case).await?;
    let session_created_at_ms = now_ms();

    let runtime_binding = runtime_factory.bind_case(
        case,
        client.clone(),
        created.session_id.clone(),
        created.url.clone(),
    );
    let mut browser_navigation_started_at_ms = None;
    let mut browser_navigation_finished_at_ms = None;
    let mut initial_bridge_sync_at_ms = None;
    let mut initial_bridge_ready_observed_at_ms = None;
    let initial_bridge_state = if runtime_binding.is_live() {
        browser_navigation_started_at_ms = Some(now_ms());
        browser
            .navigate(&created.url)
            .await
            .map_err(|err| anyhow!("navigate MiniWoB agent browser to {}: {}", created.url, err))?;
        browser_navigation_finished_at_ms = Some(now_ms());
        let ready_state =
            wait_for_agent_bridge_ready(&client, &created.session_id, Duration::from_secs(6))
                .await?;
        initial_bridge_sync_at_ms = ready_state.last_sync_ms;
        initial_bridge_ready_observed_at_ms = Some(now_ms());
        Some(ready_state)
    } else {
        None
    };
    let inference_runtime = runtime_binding.inference_runtime.clone();
    let agent_backend = runtime_binding.agent_backend();

    let (scs, _scs_tmp_dir) = build_scs(&format!("computer_use_suite_{}.scs", case.id))?;
    let service = DesktopAgentService::new_hybrid(
        gui,
        terminal,
        browser.clone(),
        inference_runtime.clone(),
        inference_runtime,
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(event_tx)
    .with_os_driver(Arc::new(StaticOsDriver::default()));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(Vec::<Arc<dyn BlockchainService>>::new());
    let mut ctx = build_ctx(&services_dir);
    let session_id = compute_session_id(case.seed, ComputerUseMode::Agent);
    let start_goal = suite_agent_goal(
        &case.env_id,
        initial_bridge_state.as_ref().and_then(bridge_task_brief),
    );

    let start_params = StartAgentParams {
        session_id,
        goal: start_goal,
        max_steps: case.max_steps,
        parent_session_id: None,
        initial_budget: 4_000,
        mode: AgentMode::Agent,
    };
    let agent_start_service_started_at_ms = now_ms();
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params)
                .map_err(|err| anyhow!("encode start params: {}", err))?,
            &mut ctx,
        )
        .await?;
    let agent_start_service_finished_at_ms = now_ms();
    apply_allow_all_policy(&mut state, session_id);
    seed_browser_resolved_intent(&mut state, session_id);

    let started = Instant::now();
    let deadline = Duration::from_secs(case.timeout_seconds);
    let mut kernel_events = Vec::new();
    let mut first_step_service_started_at_ms = None;
    let mut first_step_service_finished_at_ms = None;
    let mut loop_failure_class = None;
    loop {
        drain_events(&mut event_rx, &mut kernel_events);
        let live_bridge_state = client.state(&created.session_id).await?;
        if live_bridge_state.terminated
            || should_break_agent_loop_for_reward(&live_bridge_state, case.expected_reward_floor)
        {
            break;
        }
        let current = read_agent_state(&state, session_id);
        match &current.status {
            AgentStatus::Completed(_)
            | AgentStatus::Failed(_)
            | AgentStatus::Paused(_)
            | AgentStatus::Terminated => break,
            AgentStatus::Idle | AgentStatus::Running => {}
        }
        if started.elapsed() > deadline {
            break;
        }
        let Some(step_budget) = remaining_agent_step_budget(&started, deadline) else {
            break;
        };

        let previous_event_count = kernel_events.len();
        let step_started_at_ms = now_ms();
        if first_step_service_started_at_ms.is_none() {
            first_step_service_started_at_ms = Some(step_started_at_ms);
        }
        let step_params = codec::to_bytes_canonical(&StepAgentParams { session_id })
            .map_err(|err| anyhow!("encode step params: {}", err))?;
        let step_call = service.handle_service_call(&mut state, "step@v1", &step_params, &mut ctx);
        match timeout(step_budget, step_call).await {
            Ok(step_result) => step_result?,
            Err(_) => {
                loop_failure_class = Some("agent_step_timeout".to_string());
                break;
            }
        }
        if first_step_service_finished_at_ms.is_none() {
            first_step_service_finished_at_ms = Some(now_ms());
        }
        drain_events(&mut event_rx, &mut kernel_events);
        runtime_binding.observe_kernel_events(&kernel_events[previous_event_count..]);
    }

    let final_state = read_agent_state(&state, session_id);
    if matches!(
        final_state.status,
        AgentStatus::Completed(_)
            | AgentStatus::Failed(_)
            | AgentStatus::Paused(_)
            | AgentStatus::Terminated
    ) {
        drain_events_until_quiescent(&mut event_rx, &mut kernel_events).await;
    }
    let case_finished_at_ms = now_ms();

    let bridge_state =
        settle_agent_bridge_state(&client, &created.session_id, case.local_judge).await?;
    let screenshot_path = artifact_root.join("final.png");
    let bridge_state_path = artifact_root.join("bridge_state.json");
    let kernel_events_path = artifact_root.join("kernel_events.json");
    let agent_state_path = artifact_root.join("agent_state.json");
    let mut screenshot_paths = Vec::new();
    let should_capture_artifacts = config.retain_artifacts_for_all_runs
        || runtime_binding.is_live()
        || !bridge_state.terminated
        || bridge_state.reward < case.expected_reward_floor;
    if should_capture_artifacts {
        if let Some(parent) = screenshot_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Ok(Ok(bytes)) = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            browser.capture_tab_screenshot(false),
        )
        .await
        {
            fs::write(&screenshot_path, bytes)?;
            screenshot_paths.push(screenshot_path.to_string_lossy().to_string());
        }
        write_json_file(&bridge_state_path, &bridge_state)?;
        write_json_file(&kernel_events_path, &kernel_events)?;
        write_json_file(&agent_state_path, &final_state)?;
    }

    let phase_timings = runtime_binding.is_live().then_some(LivePhaseTimings {
        harness_run_started_at_ms,
        browser_launch_started_at_ms: launch_timing_ms.map(|timing| timing.0),
        browser_launch_finished_at_ms: launch_timing_ms.map(|timing| timing.1),
        session_created_at_ms: Some(session_created_at_ms),
        browser_navigation_started_at_ms,
        browser_navigation_finished_at_ms,
        initial_bridge_sync_at_ms,
        initial_bridge_ready_observed_at_ms,
        agent_start_service_started_at_ms: Some(agent_start_service_started_at_ms),
        agent_start_service_finished_at_ms: Some(agent_start_service_finished_at_ms),
        first_step_service_started_at_ms,
        first_step_service_finished_at_ms,
        case_finished_at_ms: Some(case_finished_at_ms),
    });

    let (inference_trace_path, inference_calls_path, live_call_count) = if should_capture_artifacts
    {
        runtime_binding.write_live_inference_artifacts(&artifact_root, phase_timings)?
    } else {
        (None, None, 0)
    };
    let (json_report_path, markdown_summary_path) = if should_generate_miniwob_case_diagnostics(
        case,
        &runtime_binding,
        should_capture_artifacts,
    ) {
        match generate_miniwob_case_diagnostics(&config.python_bin, &artifact_root) {
            Ok(paths) => paths,
            Err(err) => {
                eprintln!("warning: {}", err);
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let observations = collect_agent_kernel_observations(&kernel_events, &bridge_state);
    let tool_steps = observations.tool_steps;
    let executed_tools = observations.executed_tools;
    let routing_receipt_count = observations.routing_receipt_count;
    let intent_receipt_count = observations.intent_receipt_count;
    let execution_contract_receipt_count = observations.execution_contract_receipt_count;
    let workload_receipt_count = observations.workload_receipt_count;
    let workload_activity_count = observations.workload_activity_count;
    let mut failure_class = observations.failure_class;

    if failure_class.is_none() {
        failure_class = loop_failure_class;
    }
    if failure_class.is_none() {
        failure_class = match &final_state.status {
            AgentStatus::Paused(reason) => {
                extract_error_class(reason).or_else(|| Some("agent_paused".to_string()))
            }
            AgentStatus::Failed(reason) => {
                extract_error_class(reason).or_else(|| Some("agent_failed".to_string()))
            }
            _ => None,
        };
    }
    if failure_class.is_none() && runtime_binding.is_live() && live_call_count == 0 {
        failure_class = Some("live_inference_not_observed".to_string());
    }

    let mut snapshot_paths = Vec::new();
    for (index, step) in tool_steps.iter().enumerate() {
        if step.tool_name == "browser__snapshot" {
            let path = artifact_root.join(format!("snapshot_{}.xml", index + 1));
            if let Some(xml) = &step.history_entry {
                let _ = write_text_file(&path, xml);
                snapshot_paths.push(path.to_string_lossy().to_string());
            }
        }
    }

    client.close(&created.session_id).await?;
    browser.stop().await;

    Ok(ComputerUseCaseResult {
        case_id: case.id.clone(),
        env_id: case.env_id.clone(),
        seed: case.seed,
        mode: ComputerUseMode::Agent,
        agent_backend: Some(agent_backend),
        task_set: case.task_set,
        utterance: bridge_state.utterance.clone(),
        elapsed_ms: started.elapsed().as_millis(),
        expected_reward_floor: case.expected_reward_floor,
        final_reward: bridge_state.reward,
        expected_pass: case.expected_pass,
        terminated: bridge_state.terminated,
        truncated: bridge_state.truncated,
        overall_pass: false,
        tool_steps,
        oracle_steps: Vec::new(),
        kernel_events: kernel_events.clone(),
        bridge_state: bridge_state.clone(),
        kernel_behavior: KernelBehaviorObservation {
            executed_tools,
            action_result_count: kernel_events
                .iter()
                .filter(|event| matches!(event, KernelEvent::AgentActionResult { .. }))
                .count(),
            routing_receipt_count,
            intent_receipt_count,
            execution_contract_receipt_count,
            workload_receipt_count,
            workload_activity_count,
            disallowed_tools: Vec::new(),
        },
        validation: ValidationSummary::default(),
        artifacts: ArtifactBundle {
            artifact_root: artifact_root.to_string_lossy().to_string(),
            bridge_state_path: should_capture_artifacts
                .then(|| bridge_state_path.to_string_lossy().to_string()),
            kernel_events_path: should_capture_artifacts
                .then(|| kernel_events_path.to_string_lossy().to_string()),
            agent_state_path: should_capture_artifacts
                .then(|| agent_state_path.to_string_lossy().to_string()),
            json_report_path,
            markdown_summary_path,
            csv_summary_path: None,
            inference_trace_path,
            inference_calls_path,
            screenshot_paths,
            snapshot_paths,
        },
        failure_class,
        support_state: BenchmarkSupportState::NotYetAttempted,
        primary_gap_class: None,
        secondary_gap_tags: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::{generate_miniwob_case_diagnostics, remaining_agent_step_budget, suite_agent_goal};
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn suite_agent_goal_prefers_bridge_task_brief() {
        let goal = suite_agent_goal(
            "workflow-ticket-routing",
            Some(
                "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-204\".",
            ),
        );

        assert!(goal.contains("Task brief: Sign in to the dispatch console"));
        assert!(!goal.contains("Task: workflow-ticket-routing"));
    }

    #[test]
    fn suite_agent_goal_falls_back_to_env_id_without_task_brief() {
        let goal = suite_agent_goal("workflow-ticket-routing", None);

        assert!(goal.contains("Task: workflow-ticket-routing"));
    }

    #[test]
    fn generate_miniwob_case_diagnostics_writes_summary_artifacts() {
        let temp_dir = tempdir().expect("tempdir");
        let case_dir = temp_dir.path();
        fs::write(
            case_dir.join("inference_trace.json"),
            r#"{"backend":"live_http","model":"gpt-4o","call_count":1,"phase_timings":{}}"#,
        )
        .expect("trace");
        fs::write(
            case_dir.join("inference_calls.json"),
            r#"[{"ordinal":0,"method":"execute_inference","started_at_ms":1,"finished_at_ms":2,"elapsed_ms":1,"input_utf8":"[{\"role\":\"system\",\"content\":\"RECENT BROWSER OBSERVATION:\nIMPORTANT TARGETS: grp_start tag=button name=Start | btn_submit tag=button name=Submit\n\nRECENT PENDING BROWSER STATE:\nUse `browser__click_element` on `grp_start` now.\n\nRECENT SUCCESS SIGNAL:\n\nRECENT SESSION EVENTS:\n- none\n\n[AVAILABLE TOOLS]\"}]","output_utf8":"{\"name\":\"browser__click_element\",\"arguments\":{\"id\":\"grp_start\"}}"}]"#,
        )
        .expect("calls");
        fs::write(
            case_dir.join("bridge_state.json"),
            r#"{"env_id":"miniwob/click-button","reward":0.0,"terminated":false,"truncated":false,"episode_step":1,"utterance":"Click the start button.","last_sync_ms":5,"info":{"query_text":"Click the start button.","raw_reward":0.0,"trigger":"sync","visible_text_excerpt":"Click the start button.","interactive_elements":[],"last_event":{"timestamp_ms":5,"kind":"click","target_id":"grp_start"}},"sync_history":[]}"#,
        )
        .expect("bridge");
        fs::write(case_dir.join("kernel_events.json"), "[]").expect("kernel");

        let python_bin =
            std::env::var("COMPUTER_USE_SUITE_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let (json_path, markdown_path) =
            generate_miniwob_case_diagnostics(&python_bin, case_dir).expect("diagnostics");

        let json_path = json_path.expect("json path");
        let markdown_path = markdown_path.expect("markdown path");
        assert!(Path::new(&json_path).exists(), "{json_path}");
        assert!(Path::new(&markdown_path).exists(), "{markdown_path}");

        let json_summary = fs::read_to_string(&json_path).expect("read json");
        assert!(
            json_summary.contains("\"timeline\""),
            "diagnostic json should include timeline"
        );

        let markdown_summary = fs::read_to_string(&markdown_path).expect("read markdown");
        assert!(
            markdown_summary.contains("## Step Outcome Matrix"),
            "diagnostic markdown should include the step outcome matrix"
        );
        assert!(
            markdown_summary.contains("post_action_observation_delta"),
            "diagnostic markdown should include post-action observation deltas"
        );
    }

    #[test]
    fn remaining_agent_step_budget_clamps_to_remaining_case_time() {
        let started = Instant::now();
        let budget = remaining_agent_step_budget(&started, Duration::from_secs(3))
            .expect("remaining budget");

        assert!(budget <= Duration::from_secs(3));
        assert!(budget > Duration::from_secs(0));
    }

    #[test]
    fn remaining_agent_step_budget_returns_none_after_deadline_expires() {
        let started = Instant::now() - Duration::from_secs(5);

        assert_eq!(
            remaining_agent_step_budget(&started, Duration::from_secs(1)),
            None
        );
    }
}
