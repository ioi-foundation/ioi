use anyhow::{anyhow, Result};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::AGENT_POLICY_PREFIX;
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, ResumeAgentParams, StartAgentParams,
    StepAgentParams,
};
use ioi_services::agentic::rules::DefaultPolicy;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::agentic::{
    CapabilityId, IntentAmbiguityAction, IntentConfidenceBand, IntentScopeProfile,
    ResolvedIntentState,
};
use ioi_types::app::{
    ActionRequest, ContextSlice, KernelEvent, RoutingReceiptEvent, SignatureSuite, WorkloadReceipt,
};
use ioi_types::{codec, error::VmError};
use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;

use super::types::{ActionEvidence, QueryCase, RunObservation};

#[derive(Clone)]
struct MockGuiDriver;

#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));

        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;

        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0; 32],
            frame_id: 0,
            chunks: vec![],
            mhnsw_root: [0; 32],
            traversal_proof: None,
            intent_id: [0; 32],
        })
    }

    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

pub fn load_env_from_workspace_dotenv_if_present() {
    let mut cursor = std::env::current_dir().ok();
    let mut dotenv_path: Option<PathBuf> = None;

    while let Some(path) = cursor.clone() {
        let candidate = path.join(".env");
        if candidate.is_file() {
            dotenv_path = Some(candidate);
            break;
        }
        cursor = path.parent().map(|parent| parent.to_path_buf());
    }

    let Some(path) = dotenv_path else {
        return;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || std::env::var(key).is_ok() {
            continue;
        }
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if !value.is_empty() {
            std::env::set_var(key, value);
        }
    }
}

fn build_ctx<'a>(services: &'a ServiceDirectory) -> TxContext<'a> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    TxContext {
        block_height: 1,
        block_timestamp: now_ns,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn deterministic_id(run_index: usize, salt: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = (run_index as u8)
            .wrapping_add((idx as u8).wrapping_mul(17))
            .wrapping_add(salt);
    }
    out
}

fn session_id_for_index(run_index: usize) -> [u8; 32] {
    deterministic_id(run_index, 0x63)
}

fn build_approval_token_for_resume(
    request_hash: [u8; 32],
    now_ms: u64,
    pending_visual_hash: Option<[u8; 32]>,
) -> ApprovalToken {
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&request_hash);
    ApprovalToken {
        schema_version: 2,
        request_hash,
        audience: [0u8; 32],
        revocation_epoch: 0,
        nonce,
        counter: 1,
        scope: ApprovalScope {
            expires_at: now_ms.saturating_add(120_000),
            max_usages: Some(1),
        },
        visual_hash: pending_visual_hash,
        pii_action: None,
        scoped_exception: None,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    }
}

fn read_agent_state(state: &IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) -> AgentState {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    codec::from_bytes_canonical(&bytes).expect("agent state should decode")
}

fn seeded_required_capabilities(scope: IntentScopeProfile) -> Vec<CapabilityId> {
    match scope {
        IntentScopeProfile::Conversation => vec![CapabilityId::from("conversation.reply")],
        IntentScopeProfile::WebResearch => vec![
            CapabilityId::from("web.retrieve"),
            CapabilityId::from("browser.interact"),
            CapabilityId::from("browser.inspect"),
            CapabilityId::from("conversation.reply"),
            CapabilityId::from("sys.time.read"),
        ],
        IntentScopeProfile::WorkspaceOps => vec![
            CapabilityId::from("filesystem.read"),
            CapabilityId::from("filesystem.write"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::AppLaunch => vec![
            CapabilityId::from("app.launch"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::UiInteraction => vec![
            CapabilityId::from("ui.interact"),
            CapabilityId::from("ui.inspect"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::CommandExecution => vec![
            CapabilityId::from("command.exec"),
            CapabilityId::from("command.probe"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::Delegation => vec![
            CapabilityId::from("delegation.manage"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::Unknown => vec![CapabilityId::from("conversation.reply")],
    }
}

fn seed_resolved_intent(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
    intent_id: &str,
    scope: IntentScopeProfile,
) {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    let mut agent_state: AgentState =
        codec::from_bytes_canonical(&bytes).expect("agent state should decode");
    agent_state.resolved_intent = Some(ResolvedIntentState {
        intent_id: intent_id.to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: seeded_required_capabilities(scope),
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        embedding_model_id: "test-embed".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        constrained: false,
    });
    agent_state.awaiting_intent_clarification = false;
    agent_state.status = AgentStatus::Running;
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("state encode"),
        )
        .expect("state insert should not fail");
}

fn enable_intent_shadow_mode(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let mut rules = default_safe_policy();
    // Dedicated live capabilities suite should validate execution success without
    // interactive approval gates blocking baseline command/app flows.
    rules.defaults = DefaultPolicy::AllowAll;
    rules.ontology_policy.intent_routing.shadow_mode = true;
    rules
        .ontology_policy
        .intent_routing
        .ambiguity
        .low_confidence_action = IntentAmbiguityAction::Proceed;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state
        .insert(
            &policy_key,
            &codec::to_bytes_canonical(&rules).expect("policy encode"),
        )
        .expect("policy insert should not fail");
}

fn build_scs(path_name: &str) -> Result<(SovereignContextStore, tempfile::TempDir)> {
    let temp_dir = tempdir()?;
    let scs_path = temp_dir.path().join(path_name);
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x11; 32],
        },
    )?;
    Ok((scs, temp_dir))
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(event);
    }
}

fn requires_human_intervention(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    [
        "waiting for approval",
        "waiting for user intervention",
        "human verification",
        "captcha",
        "sudo password",
        "credential",
        "clarification",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        compact
    } else {
        compact.chars().take(max_chars).collect::<String>() + "..."
    }
}

fn event_summary_line(event: &KernelEvent) -> String {
    match event {
        KernelEvent::AgentActionResult {
            tool_name,
            output,
            agent_status,
            ..
        } => format!(
            "action tool={} status={} output={}",
            tool_name,
            agent_status,
            truncate_for_log(output, 140)
        ),
        KernelEvent::RoutingReceipt(RoutingReceiptEvent {
            tool_name,
            policy_decision,
            post_state,
            ..
        }) => format!(
            "routing tool={} decision={} success={} checks={}",
            tool_name,
            policy_decision,
            post_state.success,
            truncate_for_log(&post_state.verification_checks.join(","), 280)
        ),
        KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
            WorkloadReceipt::WebRetrieve(web) => format!(
                "workload web tool={} success={} sources={} docs={}",
                web.tool_name, web.success, web.sources_count, web.documents_count
            ),
            _ => "workload other".to_string(),
        },
        KernelEvent::IntentResolutionReceipt(receipt) => {
            format!("intent scope={:?} band={:?}", receipt.scope, receipt.band)
        }
        _ => "event(other)".to_string(),
    }
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn render_query_for_run(query_template: &str, run_index: usize, run_timestamp_ms: u64) -> String {
    let run_unique_num = format!("{}{:03}", run_timestamp_ms, run_index);
    query_template
        .replace("{RUN_UNIQUE_NUM}", &run_unique_num)
        .replace("{RUN_INDEX}", &run_index.to_string())
}

pub async fn run_case(
    case: &QueryCase,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
) -> Result<RunObservation> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("capabilities_{}_{}.scs", case.id, run_index))?;
    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        agent_runtime.clone(),
        agent_runtime,
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(event_tx);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = session_id_for_index(run_index);
    let run_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let run_query = render_query_for_run(case.query, run_index, run_timestamp_ms);

    let start_params = StartAgentParams {
        session_id,
        goal: run_query.clone(),
        max_steps: case.max_steps,
        parent_session_id: None,
        initial_budget: 4_000,
        mode: AgentMode::Agent,
    };

    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params)
                .map_err(|e| anyhow!("failed to encode start params: {}", e))?,
            &mut ctx,
        )
        .await?;

    enable_intent_shadow_mode(&mut state, session_id);
    seed_resolved_intent(
        &mut state,
        session_id,
        case.seeded_intent_id,
        case.intent_scope,
    );

    let started = Instant::now();
    let deadline = Duration::from_secs(case.sla_seconds);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut paused_reason: Option<String> = None;
    let mut auto_resume_count = 0usize;
    const MAX_AUTO_APPROVAL_RESUMES: usize = 2;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        let current = read_agent_state(&state, session_id);

        if matches!(current.status, AgentStatus::Completed(_))
            || matches!(current.status, AgentStatus::Failed(_))
        {
            break;
        }
        if started.elapsed() > deadline {
            break;
        }

        match &current.status {
            AgentStatus::Running => {}
            AgentStatus::Paused(reason) => {
                let waiting_for_approval = reason.to_ascii_lowercase().contains("approval");
                if waiting_for_approval && auto_resume_count < MAX_AUTO_APPROVAL_RESUMES {
                    if let Some(request_hash) = current.pending_tool_hash {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let approval_token = build_approval_token_for_resume(
                            request_hash,
                            now_ms,
                            current.pending_visual_hash,
                        );
                        service
                            .handle_service_call(
                                &mut state,
                                "resume@v1",
                                &codec::to_bytes_canonical(&ResumeAgentParams {
                                    session_id,
                                    approval_token: Some(approval_token),
                                })
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                                &mut ctx,
                            )
                            .await?;
                        auto_resume_count = auto_resume_count.saturating_add(1);
                        continue;
                    }
                }
                paused_reason = Some(reason.clone());
                break;
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                break;
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }

        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }

    drain_events(&mut event_rx, &mut captured_events);
    let elapsed_ms = started.elapsed().as_millis();

    let final_state = read_agent_state(&state, session_id);

    let mut action_tools = BTreeSet::new();
    let mut routing_tools = BTreeSet::new();
    let mut workload_tools = BTreeSet::new();
    let mut verification_checks = BTreeSet::new();
    let mut action_evidence = Vec::new();
    let mut final_reply = String::new();
    let mut chat_reply_count = 0usize;
    let mut approval_required_events = 0usize;

    for event in &captured_events {
        match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                action_tools.insert(tool_name.clone());
                action_evidence.push(ActionEvidence {
                    tool_name: tool_name.clone(),
                    agent_status: agent_status.clone(),
                    output_excerpt: truncate_for_log(output, 220),
                });
                if tool_name == "chat__reply" && agent_status.eq_ignore_ascii_case("completed") {
                    chat_reply_count = chat_reply_count.saturating_add(1);
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                routing_tools.insert(receipt.tool_name.clone());
                for check in &receipt.post_state.verification_checks {
                    verification_checks.insert(check.clone());
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    workload_tools.insert(web.tool_name.clone());
                }
            }
            KernelEvent::FirewallInterception { verdict, .. } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            _ => {}
        }
    }

    if let Some(reason) = paused_reason {
        if requires_human_intervention(&reason) {
            approval_required_events = approval_required_events.saturating_add(1);
            verification_checks.insert(format!("human_intervention_pause_reason={}", reason));
        } else {
            verification_checks.insert(format!("terminal_pause_reason={}", reason));
        }
    }

    let event_excerpt = captured_events
        .iter()
        .rev()
        .take(24)
        .map(event_summary_line)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();

    Ok(RunObservation {
        case_id: case.id.to_string(),
        query: run_query,
        run_timestamp_ms,
        run_timestamp_iso_utc: iso_datetime_from_unix_ms(run_timestamp_ms),
        elapsed_ms,
        completed: matches!(final_state.status, AgentStatus::Completed(_)),
        failed: matches!(final_state.status, AgentStatus::Failed(_)),
        final_status: format!("{:?}", final_state.status),
        final_reply,
        chat_reply_count,
        action_tools: action_tools.into_iter().collect(),
        routing_tools: routing_tools.into_iter().collect(),
        workload_tools: workload_tools.into_iter().collect(),
        verification_checks: verification_checks.into_iter().collect(),
        approval_required_events,
        action_evidence,
        event_excerpt,
    })
}
