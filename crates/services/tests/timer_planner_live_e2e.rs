use anyhow::Result;
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus, DesktopAgentService};
use ioi_services::agentic::desktop::{ResumeAgentParams, StartAgentParams, StepAgentParams};
use ioi_services::agentic::rules::{ActionRules, Rule, Verdict};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::agentic::{InferenceOptions, IntentAmbiguityAction};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent, SignatureSuite};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const LIVE_TIMER_QUERY: &str = "Set a timer for 15 minutes.";
const LIVE_E2E_SLA: Duration = Duration::from_secs(45);
const LIVE_STEP_DEADLINE: Duration = Duration::from_secs(45);
const LIVE_EVENT_DRAIN_WINDOW: Duration = Duration::from_millis(500);
const LIVE_SERVICE_CALL_TIMEOUT: Duration = Duration::from_secs(70);
const LIVE_ARBITER_INFERENCE_TIMEOUT: Duration = Duration::from_secs(70);
const OPENAI_CHAT_COMPLETIONS_URL: &str = "https://api.openai.com/v1/chat/completions";
const APPROVAL_TOKEN_TTL_MS: u64 = 120_000;
const LIVE_MAX_AUTO_APPROVAL_RESUMES: usize = 8;
const LIVE_TIMER_EXPECTED_DELAY_SECS: i64 = 15 * 60;
const LIVE_TIMER_DELAY_TOLERANCE_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize)]
struct QueryFacets {
    query_id: String,
    query_text: String,
    requires_external_evidence: bool,
    requires_absolute_utc_timestamp: bool,
    intent_scope: String,
}

impl QueryFacets {
    fn from_query(query: &str) -> Self {
        let digest = sha256(query.as_bytes()).expect("query hash");
        Self {
            query_id: hex::encode(digest.as_ref()),
            query_text: query.to_string(),
            requires_external_evidence: false,
            requires_absolute_utc_timestamp: true,
            intent_scope: "command.exec".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DeterministicCheckSet {
    terminal_reply_emitted_once: bool,
    runtime_within_sla: bool,
    query_facets_and_query_id_present: bool,
    run_utc_timestamp_present: bool,
    absolute_utc_timestamp_present: bool,
    target_not_before_run_timestamp: bool,
    target_matches_expected_delay_window: bool,
    mechanism_field_present: bool,
    work_evidence_present: bool,
    multiple_exec_steps_present: bool,
    capability_route_evidence_present: bool,
    capability_discovery_phase_present: bool,
    capability_execution_phase_present: bool,
    capability_verification_phase_present: bool,
    cec_receipt_host_discovery_present: bool,
    cec_receipt_provider_selection_present: bool,
    cec_receipt_provider_selection_commit_present: bool,
    cec_receipt_execution_present: bool,
    cec_receipt_verification_present: bool,
    cec_receipt_verification_commit_present: bool,
    cec_receipt_notification_strategy_present: bool,
    cec_postcondition_execution_artifact_present: bool,
    cec_postcondition_timer_sleep_backend_present: bool,
    cec_postcondition_notification_path_armed_present: bool,
    timer_delay_command_evidence_present: bool,
    notification_command_evidence_present: bool,
    deferred_notification_command_evidence_present: bool,
    no_duplicate_successful_exec_fingerprint: bool,
    terminalized_after_first_verified_exec: bool,
    no_churn_signature: bool,
    no_approval_churn: bool,
    failures: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ArbiterVerdict {
    pass: bool,
    confidence: String,
    rationale: String,
    failures: Vec<String>,
}

#[derive(Clone)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
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
        Ok("<root/>".to_string())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![b"<root/>".to_vec()],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

#[derive(Clone)]
struct NoopOsDriver;

#[async_trait]
impl OsDriver for NoopOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("UnitTest Window".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "UnitTest Window".to_string(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            app_name: "UnitTest".to_string(),
        }))
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

#[derive(Debug, Default, Clone)]
struct TimerIntentRuntime;

#[async_trait]
impl InferenceRuntime for TimerIntentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(br#"{"name":"chat__reply","arguments":{"text":"ok"}}"#.to_vec())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let text_lc = text.to_ascii_lowercase();
        if text_lc.contains("timer") || text_lc.contains("countdown") {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        if text_lc.contains("clock") || text_lc.contains("timestamp") {
            return Ok(vec![0.0, 1.0, 0.0]);
        }
        Ok(vec![0.0, 0.0, 1.0])
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
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

fn read_agent_state(
    state: &IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Result<AgentState> {
    let key = get_state_key(&session_id);
    let bytes = state
        .get(&key)?
        .ok_or_else(|| anyhow::anyhow!("session state not found"))?;
    codec::from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)
}

fn apply_policy_for_session(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
    mut rules: ActionRules,
) -> Result<()> {
    rules
        .ontology_policy
        .intent_routing
        .ambiguity
        .low_confidence_action = IntentAmbiguityAction::Proceed;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state.insert(
        &policy_key,
        &codec::to_bytes_canonical(&rules).map_err(anyhow::Error::msg)?,
    )?;
    Ok(())
}

fn load_env_from_workspace_dotenv_if_present() {
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

fn parse_arbiter_verdict(raw: &str) -> Result<ArbiterVerdict> {
    if let Ok(verdict) = serde_json::from_str::<ArbiterVerdict>(raw) {
        return Ok(verdict);
    }
    let start = raw
        .find('{')
        .ok_or_else(|| anyhow::anyhow!("arbiter response missing JSON object"))?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| anyhow::anyhow!("arbiter response missing closing brace"))?;
    serde_json::from_str::<ArbiterVerdict>(&raw[start..=end]).map_err(anyhow::Error::msg)
}

fn extract_structured_field(message: &str, marker: &str) -> Option<String> {
    let mut matched = None;
    for line in message.lines() {
        if let Some(start) = line.find(marker) {
            let token = line[start + marker.len()..].trim().trim_end_matches('.');
            if !token.is_empty() {
                matched = Some(token.to_string());
            }
        }
    }
    matched
}

fn extract_target_utc_timestamp(message: &str) -> Option<String> {
    let token = extract_structured_field(message, "Target UTC:")?;
    let has_t_separator = token.contains('T');
    let has_utc_zone = token.ends_with('Z')
        || token.contains("+00:00")
        || token.contains("-00:00")
        || token.contains("+0000")
        || token.contains("-0000");
    (has_t_separator && has_utc_zone).then_some(token.to_string())
}

fn extract_run_utc_timestamp(message: &str) -> Option<String> {
    let token = extract_structured_field(message, "Run timestamp (UTC):")?;
    let has_t_separator = token.contains('T');
    let has_utc_zone = token.ends_with('Z')
        || token.contains("+00:00")
        || token.contains("-00:00")
        || token.contains("+0000")
        || token.contains("-0000");
    (has_t_separator && has_utc_zone).then_some(token.to_string())
}

fn parse_utc_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value.trim(), &Rfc3339).ok()
}

fn extract_mechanism(message: &str) -> Option<String> {
    extract_structured_field(message, "Mechanism:")
}

fn action_tool_names(events: &[KernelEvent], session_id: [u8; 32]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::AgentActionResult {
                session_id: event_session_id,
                tool_name,
                ..
            } if *event_session_id == session_id => Some(tool_name.clone()),
            _ => None,
        })
        .collect()
}

fn sys_exec_command_previews(events: &[KernelEvent], session_id: [u8; 32]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::WorkloadReceipt(receipt_event)
                if receipt_event.session_id == session_id =>
            {
                if let ioi_types::app::WorkloadReceipt::Exec(exec_receipt) = &receipt_event.receipt
                {
                    if matches!(
                        exec_receipt.tool_name.as_str(),
                        "sys__exec" | "sys__exec_session"
                    ) {
                        return Some(exec_receipt.command_preview.clone());
                    }
                }
                None
            }
            _ => None,
        })
        .collect()
}

fn command_arms_notification_path(command_preview: &str) -> bool {
    let command_lc = command_preview.to_ascii_lowercase();
    const NOTIFICATION_MARKERS: [&str; 10] = [
        "notify-send",
        "paplay",
        "pw-play",
        "aplay",
        "canberra-gtk-play",
        "zenity --notification",
        "kdialog --passivepopup",
        "spd-say",
        "terminal-notifier",
        "osascript",
    ];
    NOTIFICATION_MARKERS
        .iter()
        .any(|marker| command_lc.contains(marker))
}

fn command_arms_timer_delay_backend(command_preview: &str) -> bool {
    let command_lc = command_preview.to_ascii_lowercase();
    command_lc.contains("sleep ")
        || (command_lc.contains("systemd-run") && command_lc.contains("--on-active"))
        || command_lc.starts_with("at ")
        || command_lc.contains(" at now")
}

fn command_arms_deferred_notification_path(command_preview: &str) -> bool {
    command_arms_notification_path(command_preview)
        && command_arms_timer_delay_backend(command_preview)
}

fn successful_sys_exec_fingerprints(events: &[KernelEvent], session_id: [u8; 32]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::WorkloadReceipt(receipt_event)
                if receipt_event.session_id == session_id =>
            {
                if let ioi_types::app::WorkloadReceipt::Exec(exec_receipt) = &receipt_event.receipt
                {
                    if matches!(
                        exec_receipt.tool_name.as_str(),
                        "sys__exec" | "sys__exec_session"
                    ) && exec_receipt.success
                    {
                        return Some(format!(
                            "{}|{}|{}|{}",
                            exec_receipt.tool_name,
                            exec_receipt.command,
                            exec_receipt.args.join("\u{1f}"),
                            exec_receipt.detach
                        ));
                    }
                }
                None
            }
            _ => None,
        })
        .collect()
}

fn approval_require_counts(
    events: &[KernelEvent],
    session_id: [u8; 32],
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::<String, usize>::new();
    for event in events {
        if let KernelEvent::FirewallInterception {
            verdict,
            request_hash,
            session_id: Some(observed_session_id),
            ..
        } = event
        {
            if *observed_session_id != session_id
                || !verdict.eq_ignore_ascii_case("REQUIRE_APPROVAL")
            {
                continue;
            }
            let key = hex::encode(request_hash);
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    counts
}

fn routing_verification_checks(events: &[KernelEvent], session_id: [u8; 32]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::RoutingReceipt(receipt) if receipt.session_id == session_id => {
                Some(receipt.post_state.verification_checks.clone())
            }
            _ => None,
        })
        .flatten()
        .collect()
}

fn routing_verification_checks_for_arbiter(checks: &[String]) -> Vec<String> {
    checks
        .iter()
        .filter(|check| {
            !check.starts_with("execution_contract_missing_keys=")
                && !check.starts_with("timer_delay_backend_detected=false")
                && !check.starts_with("timer_notification_path_detected=false")
        })
        .cloned()
        .collect()
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
            expires_at: now_ms.saturating_add(APPROVAL_TOKEN_TTL_MS),
            max_usages: Some(1),
        },
        visual_hash: pending_visual_hash,
        pii_action: None,
        scoped_exception: None,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    }
}

fn build_deterministic_checks(
    facets: &QueryFacets,
    events: &[KernelEvent],
    session_id: [u8; 32],
    elapsed: Duration,
    final_status: &AgentStatus,
    final_message: Option<&str>,
) -> DeterministicCheckSet {
    let action_tools = action_tool_names(events, session_id);
    let chat_reply_count = action_tools
        .iter()
        .filter(|tool| tool.as_str() == "chat__reply")
        .count();
    let sys_exec_workload_count = events
        .iter()
        .filter(|event| match event {
            KernelEvent::WorkloadReceipt(receipt_event)
                if receipt_event.session_id == session_id =>
            {
                if let ioi_types::app::WorkloadReceipt::Exec(exec_receipt) = &receipt_event.receipt
                {
                    matches!(
                        exec_receipt.tool_name.as_str(),
                        "sys__exec" | "sys__exec_session"
                    )
                } else {
                    false
                }
            }
            _ => false,
        })
        .count();
    let successful_exec_fingerprints = successful_sys_exec_fingerprints(events, session_id);
    let command_previews = sys_exec_command_previews(events, session_id);
    let mut successful_exec_counts = BTreeMap::<String, usize>::new();
    for fingerprint in &successful_exec_fingerprints {
        *successful_exec_counts
            .entry(fingerprint.clone())
            .or_insert(0) += 1;
    }
    let no_duplicate_successful_exec_fingerprint =
        successful_exec_counts.values().all(|count| *count <= 1);
    let terminalized_after_first_verified_exec = if successful_exec_fingerprints.is_empty() {
        false
    } else {
        matches!(final_status, AgentStatus::Completed(_))
    };
    let approval_counts = approval_require_counts(events, session_id);
    let no_approval_churn = approval_counts.values().all(|count| *count <= 1);
    let routing_checks = routing_verification_checks(events, session_id);

    let no_churn_signature = !matches!(final_status, AgentStatus::Paused(reason) if reason.contains("Retry blocked: unchanged AttemptKey"));
    let run_utc_timestamp = final_message.and_then(extract_run_utc_timestamp);
    let target_utc_timestamp = final_message.and_then(extract_target_utc_timestamp);
    let run_utc_timestamp_present = run_utc_timestamp.is_some();
    let absolute_utc_timestamp_present = target_utc_timestamp.is_some();
    let parsed_run_utc_timestamp = run_utc_timestamp.as_deref().and_then(parse_utc_timestamp);
    let parsed_target_utc_timestamp = target_utc_timestamp
        .as_deref()
        .and_then(parse_utc_timestamp);
    let target_not_before_run_timestamp = if let (Some(target), Some(run)) =
        (&parsed_target_utc_timestamp, &parsed_run_utc_timestamp)
    {
        target.unix_timestamp_nanos() >= run.unix_timestamp_nanos()
    } else {
        false
    };
    let target_matches_expected_delay_window = if let (Some(target), Some(run)) =
        (&parsed_target_utc_timestamp, &parsed_run_utc_timestamp)
    {
        let delta_seconds = target.unix_timestamp() - run.unix_timestamp();
        (delta_seconds - LIVE_TIMER_EXPECTED_DELAY_SECS).abs() <= LIVE_TIMER_DELAY_TOLERANCE_SECS
    } else {
        false
    };
    let mechanism_field_present = final_message
        .and_then(extract_mechanism)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let capability_route_evidence_present = routing_checks
        .iter()
        .any(|check| check.starts_with("capability_route_selected="));
    let capability_discovery_phase_present = routing_checks
        .iter()
        .any(|check| check == "capability_execution_phase=discovery");
    let capability_execution_phase_present = routing_checks
        .iter()
        .any(|check| check == "capability_execution_phase=execution");
    let capability_verification_phase_present = routing_checks
        .iter()
        .any(|check| check == "capability_execution_phase=verification");
    let cec_receipt_host_discovery_present = routing_checks
        .iter()
        .any(|check| check == "receipt::host_discovery=true");
    let cec_receipt_provider_selection_present = routing_checks
        .iter()
        .any(|check| check == "receipt::provider_selection=true");
    let cec_receipt_provider_selection_commit_present = routing_checks
        .iter()
        .any(|check| check == "receipt::provider_selection_commit=true");
    let cec_receipt_execution_present = routing_checks
        .iter()
        .any(|check| check == "receipt::execution=true");
    let cec_receipt_verification_present = routing_checks
        .iter()
        .any(|check| check == "receipt::verification=true");
    let cec_receipt_verification_commit_present = routing_checks
        .iter()
        .any(|check| check == "receipt::verification_commit=true");
    let cec_receipt_notification_strategy_present = routing_checks
        .iter()
        .any(|check| check == "receipt::notification_strategy=true");
    let cec_postcondition_execution_artifact_present = routing_checks
        .iter()
        .any(|check| check == "postcondition::execution_artifact=true");
    let cec_postcondition_timer_sleep_backend_present = routing_checks
        .iter()
        .any(|check| check == "postcondition::timer_sleep_backend=true");
    let cec_postcondition_notification_path_armed_present = routing_checks
        .iter()
        .any(|check| check == "postcondition::notification_path_armed=true");
    let timer_delay_command_evidence_present = command_previews
        .iter()
        .any(|preview| command_arms_timer_delay_backend(preview));
    let notification_command_evidence_present = command_previews
        .iter()
        .any(|preview| command_arms_notification_path(preview));
    let deferred_notification_command_evidence_present = command_previews
        .iter()
        .any(|preview| command_arms_deferred_notification_path(preview));
    let multiple_exec_steps_present =
        capability_discovery_phase_present && capability_execution_phase_present;

    let mut failures = Vec::<String>::new();
    let terminal_reply_emitted_once = chat_reply_count == 1;
    if !terminal_reply_emitted_once {
        failures.push(format!(
            "terminal reply count expected 1, got {}",
            chat_reply_count
        ));
    }
    let runtime_within_sla = elapsed <= LIVE_E2E_SLA;
    if !runtime_within_sla {
        failures.push(format!(
            "runtime exceeded SLA (elapsed_ms={})",
            elapsed.as_millis()
        ));
    }
    let query_facets_and_query_id_present =
        !facets.query_id.trim().is_empty() && facets.query_text == LIVE_TIMER_QUERY;
    if !query_facets_and_query_id_present {
        failures.push("query facets/query_id missing".to_string());
    }
    if !run_utc_timestamp_present {
        failures.push("final reply missing run timestamp (UTC) field".to_string());
    }
    if !absolute_utc_timestamp_present {
        failures.push("final reply missing absolute UTC timestamp".to_string());
    }
    if !target_not_before_run_timestamp {
        failures.push("target UTC is earlier than run timestamp (UTC)".to_string());
    }
    if !target_matches_expected_delay_window {
        failures.push(format!(
            "target UTC does not align with expected delay (expected={}s tolerance={}s)",
            LIVE_TIMER_EXPECTED_DELAY_SECS, LIVE_TIMER_DELAY_TOLERANCE_SECS
        ));
    }
    if !mechanism_field_present {
        failures.push("final reply missing mechanism field".to_string());
    }
    let work_evidence_present = sys_exec_workload_count > 0;
    if !work_evidence_present {
        failures.push("missing sys__exec workload evidence".to_string());
    }
    if !multiple_exec_steps_present {
        failures.push("missing discovery/execution lifecycle progression evidence".to_string());
    }
    if !capability_route_evidence_present {
        failures.push("missing capability route evidence in routing checks".to_string());
    }
    if !capability_discovery_phase_present {
        failures.push("missing capability discovery phase evidence".to_string());
    }
    if !capability_execution_phase_present {
        failures.push("missing capability execution phase evidence".to_string());
    }
    if !capability_verification_phase_present {
        failures.push("missing capability verification phase evidence".to_string());
    }
    if !cec_receipt_host_discovery_present {
        failures.push("missing CEC receipt::host_discovery=true".to_string());
    }
    if !cec_receipt_provider_selection_present {
        failures.push("missing CEC receipt::provider_selection=true".to_string());
    }
    if !cec_receipt_provider_selection_commit_present {
        failures.push("missing CEC receipt::provider_selection_commit=true".to_string());
    }
    if !cec_receipt_execution_present {
        failures.push("missing CEC receipt::execution=true".to_string());
    }
    if !cec_receipt_verification_present {
        failures.push("missing CEC receipt::verification=true".to_string());
    }
    if !cec_receipt_verification_commit_present {
        failures.push("missing CEC receipt::verification_commit=true".to_string());
    }
    if !cec_receipt_notification_strategy_present {
        failures.push("missing CEC receipt::notification_strategy=true".to_string());
    }
    if !cec_postcondition_execution_artifact_present {
        failures.push("missing CEC postcondition::execution_artifact=true".to_string());
    }
    if !cec_postcondition_timer_sleep_backend_present {
        failures.push("missing CEC postcondition::timer_sleep_backend=true".to_string());
    }
    if !cec_postcondition_notification_path_armed_present {
        failures.push("missing CEC postcondition::notification_path_armed=true".to_string());
    }
    if !timer_delay_command_evidence_present {
        failures.push("missing timer delay command evidence in sys__exec previews".to_string());
    }
    if !notification_command_evidence_present {
        failures.push("missing notification command evidence in sys__exec previews".to_string());
    }
    if !deferred_notification_command_evidence_present {
        failures.push(
            "missing deferred notification command evidence in sys__exec previews".to_string(),
        );
    }
    if !no_duplicate_successful_exec_fingerprint {
        failures.push(format!(
            "duplicate successful exec fingerprint detected: {}",
            serde_json::to_string(&successful_exec_counts).unwrap_or_else(|_| "{}".to_string())
        ));
    }
    if !terminalized_after_first_verified_exec {
        failures.push("did not terminalize after first verified exec".to_string());
    }
    if !no_churn_signature {
        failures.push("retry churn signature detected".to_string());
    }
    if !no_approval_churn {
        failures.push(format!(
            "approval churn detected: {}",
            serde_json::to_string(&approval_counts).unwrap_or_else(|_| "{}".to_string())
        ));
    }

    DeterministicCheckSet {
        terminal_reply_emitted_once,
        runtime_within_sla,
        query_facets_and_query_id_present,
        run_utc_timestamp_present,
        absolute_utc_timestamp_present,
        target_not_before_run_timestamp,
        target_matches_expected_delay_window,
        mechanism_field_present,
        work_evidence_present,
        multiple_exec_steps_present,
        capability_route_evidence_present,
        capability_discovery_phase_present,
        capability_execution_phase_present,
        capability_verification_phase_present,
        cec_receipt_host_discovery_present,
        cec_receipt_provider_selection_present,
        cec_receipt_provider_selection_commit_present,
        cec_receipt_execution_present,
        cec_receipt_verification_present,
        cec_receipt_verification_commit_present,
        cec_receipt_notification_strategy_present,
        cec_postcondition_execution_artifact_present,
        cec_postcondition_timer_sleep_backend_present,
        cec_postcondition_notification_path_armed_present,
        timer_delay_command_evidence_present,
        notification_command_evidence_present,
        deferred_notification_command_evidence_present,
        no_duplicate_successful_exec_fingerprint,
        terminalized_after_first_verified_exec,
        no_churn_signature,
        no_approval_churn,
        failures,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn timer_query_routes_to_command_exec_without_planner_fast_path() -> Result<()> {
    let (tx, mut rx) = tokio::sync::broadcast::channel(256);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let scs_path = std::env::temp_dir().join(format!("timer_command_exec_e2e_{}.scs", now_ns));
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x44; 32],
        },
    )?;

    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(TimerIntentRuntime);
    let service = DesktopAgentService::new_hybrid(gui, terminal, browser, runtime.clone(), runtime)
        .with_scs(Arc::new(Mutex::new(scs)))
        .with_event_sender(tx)
        .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);

    let session_id = [0xAB; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Set a timer for 15 minutes".to_string(),
        max_steps: 8,
        parent_session_id: None,
        initial_budget: 1000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await?;

    apply_policy_for_session(&mut state, session_id, default_safe_policy())?;

    while rx.try_recv().is_ok() {}

    let mut events = Vec::<KernelEvent>::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(anyhow::Error::msg)?,
                &mut ctx,
            )
            .await?;

        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        let agent_state = read_agent_state(&state, session_id)?;
        match agent_state.status {
            AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Paused(_) => break,
            AgentStatus::Running | AgentStatus::Idle | AgentStatus::Terminated => {}
        }
    }

    let flush_deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        if tokio::time::Instant::now() >= flush_deadline {
            break;
        }
        let remaining = flush_deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => events.push(event),
            _ => break,
        }
    }

    let agent_state = read_agent_state(&state, session_id)?;
    let resolved = agent_state
        .resolved_intent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("resolved intent missing"))?;
    assert_eq!(resolved.intent_id, "command.exec");

    assert!(
        !events.iter().any(|event| match event {
            KernelEvent::PlanReceipt(receipt) => receipt.session_id == Some(session_id),
            _ => false,
        }),
        "planner receipts should not be emitted for timer queries anymore"
    );
    assert!(
        !events.iter().any(|event| match event {
            KernelEvent::AgentActionResult {
                session_id: event_session_id,
                tool_name,
                ..
            } => *event_session_id == session_id && tool_name == "planner::execute",
            _ => false,
        }),
        "planner::execute must not run"
    );

    assert!(
        !matches!(agent_state.status, AgentStatus::Failed(_)),
        "expected non-failed status, got {:?}",
        agent_state.status
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for OpenAI timer e2e arbiter"]
async fn timer_query_live_openai_e2e_with_model_arbiter() -> Result<()> {
    load_env_from_workspace_dotenv_if_present();
    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY is required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        OPENAI_CHAT_COMPLETIONS_URL.to_string(),
        openai_api_key,
        openai_model,
    ));

    let facets = QueryFacets::from_query(LIVE_TIMER_QUERY);
    let start = Instant::now();

    let (tx, mut rx) = tokio::sync::broadcast::channel(512);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let scs_path = std::env::temp_dir().join(format!("timer_live_openai_e2e_{}.scs", now_ns));
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x55; 32],
        },
    )?;

    let service = DesktopAgentService::new_hybrid(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(tx)
    .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = [0xCD; 32];

    tokio::time::timeout(
        LIVE_SERVICE_CALL_TIMEOUT,
        service.handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&StartAgentParams {
                session_id,
                goal: LIVE_TIMER_QUERY.to_string(),
                max_steps: 10,
                parent_session_id: None,
                initial_budget: 1600,
                mode: AgentMode::Agent,
            })
            .map_err(anyhow::Error::msg)?,
            &mut ctx,
        ),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "live e2e call timed out: method=start@v1 timeout_secs={}",
            LIVE_SERVICE_CALL_TIMEOUT.as_secs()
        )
    })?
    .map_err(anyhow::Error::msg)?;

    let mut live_rules = default_safe_policy();
    live_rules.rules.insert(
        0,
        Rule {
            rule_id: Some("require-approval-sys-exec-live-e2e".to_string()),
            target: "sys::exec".to_string(),
            conditions: Default::default(),
            action: Verdict::RequireApproval,
        },
    );
    live_rules.rules.push(Rule {
        rule_id: Some("block-install-package-live-e2e".to_string()),
        target: "sys::install_package".to_string(),
        conditions: Default::default(),
        action: Verdict::Block,
    });
    apply_policy_for_session(&mut state, session_id, live_rules)?;

    let deadline = tokio::time::Instant::now() + LIVE_STEP_DEADLINE;
    let mut events = Vec::<KernelEvent>::new();
    let mut auto_resume_count = 0usize;
    while tokio::time::Instant::now() < deadline {
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        let agent_state = read_agent_state(&state, session_id)?;
        match &agent_state.status {
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => break,
            AgentStatus::Paused(reason) => {
                let waiting_for_approval = reason.to_ascii_lowercase().contains("approval");
                if !waiting_for_approval {
                    break;
                }
                if auto_resume_count >= LIVE_MAX_AUTO_APPROVAL_RESUMES {
                    break;
                }
                let request_hash = agent_state.pending_tool_hash.ok_or_else(|| {
                    anyhow::anyhow!("pending approval hash missing during live auto-resume")
                })?;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let approval_token = build_approval_token_for_resume(
                    request_hash,
                    now_ms,
                    agent_state.pending_visual_hash,
                );
                tokio::time::timeout(
                    LIVE_SERVICE_CALL_TIMEOUT,
                    service.handle_service_call(
                        &mut state,
                        "resume@v1",
                        &codec::to_bytes_canonical(&ResumeAgentParams {
                            session_id,
                            approval_token: Some(approval_token),
                        })
                        .map_err(anyhow::Error::msg)?,
                        &mut ctx,
                    ),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "live e2e call timed out: method=resume@v1 timeout_secs={}",
                        LIVE_SERVICE_CALL_TIMEOUT.as_secs()
                    )
                })?
                .map_err(anyhow::Error::msg)?;
                auto_resume_count = auto_resume_count.saturating_add(1);
                continue;
            }
            AgentStatus::Running | AgentStatus::Idle | AgentStatus::Terminated => {}
        }
        tokio::time::timeout(
            LIVE_SERVICE_CALL_TIMEOUT,
            service.handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(anyhow::Error::msg)?,
                &mut ctx,
            ),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "live e2e call timed out: method=step@v1 timeout_secs={}",
                LIVE_SERVICE_CALL_TIMEOUT.as_secs()
            )
        })?
        .map_err(anyhow::Error::msg)?;
    }

    let drain_deadline = tokio::time::Instant::now() + LIVE_EVENT_DRAIN_WINDOW;
    while tokio::time::Instant::now() < drain_deadline {
        let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => events.push(event),
            _ => break,
        }
    }

    let elapsed = start.elapsed();
    let agent_state = read_agent_state(&state, session_id)?;
    let final_message = match &agent_state.status {
        AgentStatus::Completed(Some(text)) => Some(text.clone()),
        _ => None,
    };
    let pending_tool = agent_state
        .pending_tool_jcs
        .as_ref()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok());
    let deterministic_checks = build_deterministic_checks(
        &facets,
        &events,
        session_id,
        elapsed,
        &agent_state.status,
        final_message.as_deref(),
    );
    let routing_checks_raw = routing_verification_checks(&events, session_id);
    let routing_checks_arbiter = routing_verification_checks_for_arbiter(&routing_checks_raw);

    let evidence_payload = json!({
        "query_facets": facets,
        "agent_status": format!("{:?}", agent_state.status),
        "final_reply": final_message,
        "pending_tool": pending_tool,
        "elapsed_ms": elapsed.as_millis(),
        "deterministic_checks": deterministic_checks,
        "action_tools": action_tool_names(&events, session_id),
        "sys_exec_command_previews": sys_exec_command_previews(&events, session_id),
        "successful_sys_exec_fingerprints": successful_sys_exec_fingerprints(&events, session_id),
        "approval_require_counts": approval_require_counts(&events, session_id),
        "routing_verification_checks_raw": routing_checks_raw,
        "routing_verification_checks_arbiter": routing_checks_arbiter,
        "auto_resume_count": auto_resume_count,
    });

    let arbiter_prompt = format!(
        "Evaluate timer-query quality for query_id={query_id}.\n\
Return strict JSON only with schema:\n\
{{\"pass\": bool, \"confidence\": \"high|medium|low\", \"rationale\": \"string\", \"failures\": [string]}}\n\
Fail if:\n\
1) final reply does not directly answer the query,\n\
2) claims are unsupported by evidence,\n\
3) output quality depends on lexical phrase artifacts instead of facet/evidence grounding,\n\
	4) capability lifecycle evidence is incomplete (missing route/discovery/execution/verification),\n\
	5) final reply lacks structured evidence fields (`Run timestamp (UTC)`, `Target UTC`, `Mechanism`),\n\
	6) CEC markers are incomplete (missing any required `receipt::...=true` or `postcondition::...=true`, including notification-path evidence for timer goals),\n\
	7) `Target UTC` is earlier than `Run timestamp (UTC)` or does not reflect the requested 15-minute delay,\n\
	8) identical approval-gated command fingerprints are repeated instead of progressing state,\n\
	9) no user-visible or audible notification path is armed for timer completion,\n\
	10) no delayed timer backend is armed (for example `sleep`, scheduler, or equivalent delayed execution primitive),\n\
	11) notification evidence is immediate-only and not deferred/scheduled for timer due time.\n\
	Use `routing_verification_checks_arbiter` for normalized final-state contract evidence; treat `routing_verification_checks_raw` as transient trace.\n\
Evidence JSON:\n{evidence}",
        query_id = QueryFacets::from_query(LIVE_TIMER_QUERY).query_id,
        evidence = serde_json::to_string_pretty(&evidence_payload)?,
    );

    let arbiter_raw = tokio::time::timeout(
        LIVE_ARBITER_INFERENCE_TIMEOUT,
        runtime.execute_inference(
            [0u8; 32],
            arbiter_prompt.as_bytes(),
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 260,
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "live e2e arbiter timed out after {} seconds",
            LIVE_ARBITER_INFERENCE_TIMEOUT.as_secs()
        )
    })?
    .map_err(anyhow::Error::msg)?;
    let arbiter_raw_text = String::from_utf8_lossy(&arbiter_raw).trim().to_string();
    let arbiter_verdict = parse_arbiter_verdict(&arbiter_raw_text)?;

    let deterministic_pass = evidence_payload["deterministic_checks"]["failures"]
        .as_array()
        .map(|items| items.is_empty())
        .unwrap_or(false);
    println!(
        "timer_live_e2e_evidence={}",
        serde_json::to_string_pretty(&evidence_payload)?
    );
    println!(
        "timer_live_e2e_arbiter={}",
        serde_json::to_string(&arbiter_verdict)?
    );
    assert!(
        deterministic_pass,
        "deterministic checks failed: {}",
        serde_json::to_string_pretty(&evidence_payload)?
    );
    assert!(
        arbiter_verdict.pass,
        "arbiter rejected run: {} | evidence={}",
        serde_json::to_string(&arbiter_verdict)?,
        serde_json::to_string_pretty(&evidence_payload)?
    );

    Ok(())
}
