// Path: crates/services/src/agentic/desktop/service/lifecycle.rs

use super::DesktopAgentService;
use crate::agentic::desktop::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::service::step::incident::{mark_incident_retry_root, IncidentState};
use crate::agentic::desktop::service::step::queue::query_requires_runtime_locality_scope;
use crate::agentic::desktop::service::step::signals::infer_interaction_target;
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, PostMessageParams, RecordedMessage,
    ResumeAgentParams, SessionSummary, StartAgentParams, SwarmContext,
};
use hex;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_jcs;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;

const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";
const RUNTIME_LOCALITY_ENV_SEED_KEY: &str = "IOI_SESSION_LOCALITY";
const RUNTIME_LOCALITY_DISCOVERY_URLS: [&str; 3] = [
    "https://ipapi.co/json/",
    "https://ipwho.is/",
    "https://ipinfo.io/json",
];
const RUNTIME_LOCALITY_DISCOVERY_TIMEOUT_MS: u64 = 2_000;
const RUNTIME_LOCALITY_COMPONENT_MAX_CHARS: usize = 64;
const RUNTIME_LOCALITY_REGION_CODE_MAX_CHARS: usize = 4;
const RUNTIME_LOCALITY_ZONEINFO_MARKER: &str = "zoneinfo/";
const RUNTIME_LOCALITY_ZONEINFO_NOISE_ROOTS: [&str; 5] = ["etc", "gmt", "utc", "posix", "right"];
const TRUSTED_RUNTIME_LOCALITY_ENV_KEYS: [&str; 8] = [
    "IOI_SESSION_LOCALITY",
    "IOI_DEVICE_LOCALITY",
    "IOI_USER_LOCALITY",
    "IOI_LOCALITY",
    "SESSION_LOCALITY",
    "DEVICE_LOCALITY",
    "USER_LOCALITY",
    "LOCALITY",
];
static DEVICE_LOCALITY_SCOPE_CACHE: OnceLock<Option<String>> = OnceLock::new();
static DISCOVERED_RUNTIME_LOCALITY_SCOPE_CACHE: OnceCell<String> = OnceCell::const_new();

fn runtime_locality_env_present() -> bool {
    TRUSTED_RUNTIME_LOCALITY_ENV_KEYS.iter().any(|key| {
        std::env::var(key)
            .ok()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    })
}

fn compact_runtime_locality_whitespace(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sanitize_runtime_locality_component(raw: &str) -> Option<String> {
    let compact = compact_runtime_locality_whitespace(raw);
    let trimmed = compact.trim();
    if trimmed.is_empty() || trimmed.len() > RUNTIME_LOCALITY_COMPONENT_MAX_CHARS {
        return None;
    }
    if trimmed.chars().any(|ch| ch.is_control()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn sanitize_runtime_locality_region_code(raw: &str) -> Option<String> {
    let compact = compact_runtime_locality_whitespace(raw);
    let trimmed = compact.trim();
    if trimmed.is_empty()
        || trimmed.len() > RUNTIME_LOCALITY_REGION_CODE_MAX_CHARS
        || !trimmed.chars().all(|ch| ch.is_ascii_alphabetic())
    {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

fn compose_runtime_locality_scope(
    city: Option<&str>,
    region_code: Option<&str>,
    region: Option<&str>,
) -> Option<String> {
    let city = city.and_then(sanitize_runtime_locality_component)?;
    if let Some(code) = region_code.and_then(sanitize_runtime_locality_region_code) {
        return Some(format!("{city}, {code}"));
    }
    if let Some(region_name) = region.and_then(sanitize_runtime_locality_component) {
        if !region_name.eq_ignore_ascii_case(&city) {
            return Some(format!("{city}, {region_name}"));
        }
    }
    Some(city)
}

fn runtime_locality_scope_from_ip_discovery_payload(payload: &serde_json::Value) -> Option<String> {
    let city = payload.get("city").and_then(|value| value.as_str());
    let region_code = payload
        .get("region_code")
        .or_else(|| payload.get("regionCode"))
        .and_then(|value| value.as_str());
    let region = payload.get("region").and_then(|value| value.as_str());
    compose_runtime_locality_scope(city, region_code, region)
}

async fn discover_runtime_locality_scope_from_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(RUNTIME_LOCALITY_DISCOVERY_TIMEOUT_MS))
        .build()
        .ok()?;
    for url in RUNTIME_LOCALITY_DISCOVERY_URLS {
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let payload = match response.json::<serde_json::Value>().await {
            Ok(payload) => payload,
            Err(_) => continue,
        };
        if let Some(scope) = runtime_locality_scope_from_ip_discovery_payload(&payload) {
            return Some(scope);
        }
    }
    None
}

async fn cached_runtime_locality_scope() -> Option<String> {
    if let Some(cached) = DISCOVERED_RUNTIME_LOCALITY_SCOPE_CACHE.get() {
        return Some(cached.clone());
    }
    let discovered = discover_runtime_locality_scope_from_ip().await?;
    let _ = DISCOVERED_RUNTIME_LOCALITY_SCOPE_CACHE.set(discovered.clone());
    Some(discovered)
}

fn timezone_identifier_from_device() -> Option<String> {
    if let Ok(value) = std::env::var("TZ") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    let link = std::fs::read_link("/etc/localtime").ok()?;
    let path = link.to_string_lossy();
    let marker_idx = path.rfind(RUNTIME_LOCALITY_ZONEINFO_MARKER)?;
    let identifier = path[(marker_idx + RUNTIME_LOCALITY_ZONEINFO_MARKER.len())..].trim();
    (!identifier.is_empty()).then(|| identifier.to_string())
}

fn locality_scope_from_timezone_identifier(identifier: &str) -> Option<String> {
    let normalized = identifier.trim().trim_matches('/');
    if normalized.is_empty() {
        return None;
    }
    let segments = normalized
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 {
        return None;
    }
    let root = segments
        .first()
        .map(|segment| segment.to_ascii_lowercase())
        .unwrap_or_default();
    if RUNTIME_LOCALITY_ZONEINFO_NOISE_ROOTS
        .iter()
        .any(|blocked| *blocked == root)
    {
        return None;
    }

    let city = segments
        .last()
        .copied()
        .unwrap_or_default()
        .replace('_', " ");
    let city = city.trim();
    if city.is_empty() {
        return None;
    }

    if segments.len() >= 3 {
        let region = segments[segments.len().saturating_sub(2)].replace('_', " ");
        let region = region.trim();
        if !region.is_empty() && !region.eq_ignore_ascii_case(city) {
            return Some(format!("{city}, {region}"));
        }
    }
    Some(city.to_string())
}

fn cached_device_locality_scope() -> Option<String> {
    DEVICE_LOCALITY_SCOPE_CACHE
        .get_or_init(|| {
            timezone_identifier_from_device()
                .as_deref()
                .and_then(locality_scope_from_timezone_identifier)
        })
        .clone()
}

async fn maybe_seed_runtime_locality_context(goal: &str) {
    if cfg!(test) {
        return;
    }
    if !query_requires_runtime_locality_scope(goal) || runtime_locality_env_present() {
        return;
    }
    if let Some(scope) = cached_runtime_locality_scope()
        .await
        .or_else(cached_device_locality_scope)
    {
        std::env::set_var(RUNTIME_LOCALITY_ENV_SEED_KEY, scope);
    }
}

fn is_waiting_for_sudo_password(status: &AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Paused(reason) if reason.eq_ignore_ascii_case("Waiting for sudo password")
    )
}

fn status_mentions_sudo_password(status: &AgentStatus) -> bool {
    match status {
        AgentStatus::Paused(reason) | AgentStatus::Failed(reason) => {
            let lower = reason.to_ascii_lowercase();
            lower.contains("sudo password") || lower.contains("administrative privileges")
        }
        _ => false,
    }
}

fn incident_waiting_for_sudo_password(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let incident_key = get_incident_key(&session_id);
    let Some(incident_bytes) = state.get(&incident_key)? else {
        return Ok(false);
    };
    let incident: IncidentState = codec::from_bytes_canonical(&incident_bytes)?;
    Ok(incident
        .resolution_action
        .eq_ignore_ascii_case("wait_for_sudo_password"))
}

fn restore_pending_install_from_tool_call(
    agent_state: &mut AgentState,
) -> Result<bool, TransactionError> {
    if agent_state.pending_tool_jcs.is_some() {
        return Ok(true);
    }
    let Some(raw) = agent_state.pending_tool_call.as_deref() else {
        return Ok(false);
    };
    let parsed = match middleware::normalize_tool_call(raw) {
        Ok(tool) => tool,
        Err(_) => return Ok(false),
    };
    if !matches!(parsed, AgentTool::SysInstallPackage { .. }) {
        return Ok(false);
    }

    let tool_jcs = serde_jcs::to_vec(&parsed).map_err(|e| {
        TransactionError::Serialization(format!("Failed to encode pending install tool: {}", e))
    })?;
    let hash_bytes = sha256(&tool_jcs).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes.as_ref());

    agent_state.pending_tool_jcs = Some(tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    if agent_state.pending_visual_hash.is_none() {
        agent_state.pending_visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    }
    agent_state.pending_approval = None;
    Ok(true)
}

fn maybe_restore_pending_install_from_incident(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    agent_state: &mut AgentState,
) -> Result<(), TransactionError> {
    if agent_state.pending_tool_jcs.is_some() {
        return Ok(());
    }

    if restore_pending_install_from_tool_call(agent_state)? {
        return Ok(());
    }

    let incident_key = get_incident_key(&session_id);
    let Some(incident_bytes) = state.get(&incident_key)? else {
        return Ok(());
    };
    let incident: IncidentState = codec::from_bytes_canonical(&incident_bytes)?;
    let waiting_for_sudo = incident
        .resolution_action
        .eq_ignore_ascii_case("wait_for_sudo_password");
    let is_install_root = incident
        .root_tool_name
        .eq_ignore_ascii_case("sys__install_package")
        || incident
            .root_tool_name
            .eq_ignore_ascii_case("sys::install_package")
        || incident.root_tool_name.ends_with("install_package");
    if !waiting_for_sudo || !is_install_root || incident.root_tool_jcs.is_empty() {
        return Ok(());
    }

    let hash_bytes =
        sha256(&incident.root_tool_jcs).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes.as_ref());
    agent_state.pending_tool_jcs = Some(incident.root_tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    agent_state.pending_approval = None;
    agent_state.execution_queue.clear();
    Ok(())
}

pub async fn spawn_delegated_child_session(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    tool_hash: [u8; 32],
    goal: &str,
    budget: u64,
    step_index: u32,
    block_height: u64,
) -> Result<[u8; 32], TransactionError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ioi::agent_delegate_child::v1::");
    payload.extend_from_slice(parent_state.session_id.as_slice());
    payload.extend_from_slice(&step_index.to_le_bytes());
    payload.extend_from_slice(tool_hash.as_slice());

    let child_session_id = sha256(payload)
        .map_err(|e| TransactionError::Invalid(format!("Delegate hash failed: {}", e)))?;

    let child_key = get_state_key(&child_session_id);
    if state.get(&child_key)?.is_some() {
        if parent_state.child_session_ids.contains(&child_session_id) {
            return Ok(child_session_id);
        }

        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Delegated child session {} already exists but is not linked to parent session {}.",
            hex::encode(child_session_id),
            hex::encode(parent_state.session_id)
        )));
    }

    if parent_state.budget < budget {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Insufficient parent budget for delegation (needed {}, have {}).",
            budget, parent_state.budget
        )));
    }

    let target = infer_interaction_target(goal);

    // Initialize transcript BEFORE mutating chain state so failures do not burn budget.
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: goal.to_string(),
        timestamp: timestamp_ms,
        trace_hash: None,
    };
    let transcript_root = service
        .append_chat_to_scs(child_session_id, &initial_message, block_height)
        .await?;

    // Ensure stale remediation/incident metadata cannot leak across deterministic child ids.
    state.delete(&get_remediation_key(&child_session_id))?;
    state.delete(&get_incident_key(&child_session_id))?;

    let child_state = AgentState {
        session_id: child_session_id,
        goal: goal.to_string(),
        transcript_root,
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: parent_state.max_steps,
        last_action_type: None,
        parent_session_id: Some(parent_state.session_id),
        child_session_ids: Vec::new(),
        budget,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        pending_search_completion: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    };

    state.insert(&child_key, &codec::to_bytes_canonical(&child_state)?)?;

    // Update session history if present; best-effort to avoid blocking delegation on history corruption.
    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = state
        .get(&history_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok())
        .unwrap_or_default();

    let title_line = goal.lines().next().unwrap_or("Agent Task");
    let title = if title_line.len() > 30 {
        format!("{}...", &title_line[..30])
    } else {
        title_line.to_string()
    };
    history.insert(
        0,
        SessionSummary {
            session_id: child_session_id,
            title,
            timestamp: timestamp_ms,
        },
    );
    if history.len() > 50 {
        history.truncate(50);
    }

    if let Ok(bytes) = codec::to_bytes_canonical(&history) {
        if let Err(e) = state.insert(&history_key, &bytes) {
            log::warn!(
                "Failed to update agent::history for delegated child session {}: {}",
                hex::encode(&child_session_id[..4]),
                e
            );
        }
    }

    parent_state.budget -= budget;
    parent_state.child_session_ids.push(child_session_id);

    if let Some(tx) = &service.event_sender {
        let _ = tx.send(KernelEvent::AgentSpawn {
            parent_session_id: parent_state.session_id,
            new_session_id: child_session_id,
            name: format!("Agent-{}", hex::encode(&child_session_id[0..2])),
            role: "Sub-Worker".to_string(),
            budget,
            goal: goal.to_string(),
        });
    }

    Ok(child_session_id)
}

pub async fn handle_start(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: StartAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let remediation_key = get_remediation_key(&p.session_id);
    let incident_key = get_incident_key(&p.session_id);
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid("Session already exists".into()));
    }
    // Ensure stale remediation metadata from prior sessions cannot leak.
    state.delete(&remediation_key)?;
    state.delete(&incident_key)?;

    // [NEW] Swarm Hydration Logic
    // If the goal starts with "SWARM:", we treat it as a request to instantiate a Swarm Manifest.
    // Format: "SWARM:<swarm_hash_hex>"
    let mut swarm_context = None;
    let mut actual_goal = p.goal.clone();

    if p.goal.starts_with("SWARM:") {
        let parts: Vec<&str> = p.goal.split_whitespace().collect();
        if let Some(hash_hex) = parts.get(0).and_then(|s| s.strip_prefix("SWARM:")) {
            if let Ok(swarm_hash) = hex::decode(hash_hex) {
                if swarm_hash.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&swarm_hash);

                    // Fetch Manifest from Market/SCS
                    if let Some(manifest) = service.fetch_swarm_manifest(arr).await {
                        log::info!("Hydrating Swarm '{}' ({})", manifest.name, hash_hex);

                        // 1. Identify Root Agent (First in roster or "Manager")
                        // For MVP, we assume the first agent in roster is the entry point.
                        if let Some((root_role, _root_agent_hash)) = manifest.roster.first() {
                            // This session becomes the Root Agent
                            let delegates: Vec<String> = manifest
                                .delegation_flow
                                .iter()
                                .filter(|(from, _)| from == root_role)
                                .map(|(_, to)| to.clone())
                                .collect();

                            swarm_context = Some(SwarmContext {
                                swarm_id: arr,
                                role: root_role.clone(),
                                allowed_delegates: delegates,
                            });

                            // The goal of the root agent is the rest of the user prompt
                            actual_goal = parts[1..].join(" ");
                            if actual_goal.is_empty() {
                                actual_goal =
                                    format!("Execute swarm mission: {}", manifest.description);
                            }

                            // [TODO] Pre-provision child sessions for other roles?
                            // For now, we let the root agent spawn them lazily via `agent__delegate`.
                        }
                    }
                }
            }
        }
    }

    // Seed runtime locality context for locality-sensitive fact lookups when
    // query text omits explicit scope and no trusted session context is present.
    maybe_seed_runtime_locality_context(&actual_goal).await;

    // Derive target surface from ontology-level launch signals.
    let target = infer_interaction_target(&p.goal);

    // ... [Parent budget check unchanged] ...
    if let Some(parent_id) = p.parent_session_id {
        let parent_key = get_state_key(&parent_id);
        if let Some(parent_bytes) = state.get(&parent_key)? {
            let mut parent_state: AgentState = codec::from_bytes_canonical(&parent_bytes)?;

            if parent_state.budget < p.initial_budget {
                return Err(TransactionError::Invalid(
                    "Insufficient parent budget for delegation".into(),
                ));
            }
            parent_state.budget -= p.initial_budget;
            parent_state.child_session_ids.push(p.session_id);

            // [NEW] Inherit Swarm Context if parent is in a swarm
            if let Some(_parent_ctx) = &parent_state.swarm_context {
                // If this is a delegation, we need to determine the role of the child.
                // The parent likely called `agent__delegate` with a goal.
                // We rely on `agent__delegate` tool logic to pass the role,
                // but `StartAgentParams` doesn't have a role field in the struct yet.
                // For MVP, we assume ad-hoc delegation unless we update StartAgentParams.
                // Let's assume ad-hoc for now or infer from goal if it matches a role name.
            }

            state.insert(&parent_key, &codec::to_bytes_canonical(&parent_state)?)?;
        } else {
            return Err(TransactionError::Invalid("Parent session not found".into()));
        }
    }

    // ... [Chat Init unchanged] ...
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: actual_goal.clone(), // Use resolved goal
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };

    let root_hash = service
        .append_chat_to_scs(p.session_id, &initial_message, 0)
        .await?;

    let agent_state = AgentState {
        session_id: p.session_id,
        goal: actual_goal, // Use resolved goal
        transcript_root: root_hash,
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: p.max_steps,
        last_action_type: None,
        parent_session_id: p.parent_session_id,
        child_session_ids: Vec::new(),
        budget: p.initial_budget,
        consecutive_failures: 0,
        tokens_used: 0,
        pending_approval: None,
        pending_tool_call: None,

        // [FIX] Initialize new fields
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,

        recent_actions: Vec::new(),
        mode: p.mode,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        current_tier: ExecutionTier::DomHeadless,
        tool_execution_log: BTreeMap::new(),
        active_skill_hash: None,
        visual_som_map: None,

        // [FIX] Initialize visual_semantic_map to satisfy the new struct definition
        visual_semantic_map: None,

        swarm_context, // [NEW]
        target,        // [NEW] Set the target

        // Default relative working directory for stateful sys tools.
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),

        // [FIX] Initialize active_lens
        active_lens: None,
        pending_search_completion: None,
        command_history: Default::default(),
    };
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    // ... [History update unchanged] ...
    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = if let Some(bytes) = state.get(&history_key)? {
        codec::from_bytes_canonical(&bytes).unwrap_or_default()
    } else {
        Vec::new()
    };

    history.insert(
        0,
        SessionSummary {
            session_id: p.session_id,
            title: if agent_state.mode == AgentMode::Chat {
                let t = agent_state.goal.lines().next().unwrap_or("New Chat");
                if t.len() > 30 {
                    format!("{}...", &t[..30])
                } else {
                    t.to_string()
                }
            } else {
                let t = agent_state.goal.lines().next().unwrap_or("Agent Task");
                if t.len() > 30 {
                    format!("{}...", &t[..30])
                } else {
                    t.to_string()
                }
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        },
    );

    if history.len() > 50 {
        history.truncate(50);
    }

    state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;

    Ok(())
}

pub async fn handle_post_message(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: PostMessageParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    if let Some(bytes) = state.get(&key)? {
        let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let role = p.role.clone();
        let content = p.content.clone();
        let incident_waiting_for_sudo = incident_waiting_for_sudo_password(state, p.session_id)?;
        let waiting_for_sudo_password =
            is_waiting_for_sudo_password(&agent_state.status) || incident_waiting_for_sudo;
        if role == "user" {
            if waiting_for_sudo_password {
                if content.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "Sudo password input cannot be empty".into(),
                    ));
                }
                let session_id_hex = hex::encode(p.session_id);
                runtime_secret::set_secret(
                    &session_id_hex,
                    RUNTIME_SECRET_KIND_SUDO_PASSWORD,
                    content.clone(),
                    true,
                    120,
                )
                .map_err(TransactionError::Invalid)?;
                log::info!(
                    "Captured runtime sudo credential from user message for session {}",
                    hex::encode(&p.session_id[..4])
                );
                // Move incident state out of wait-for-user immediately so UI does not
                // re-surface the sudo prompt card while the retry is already in-flight.
                mark_incident_retry_root(state, p.session_id)?;
                maybe_restore_pending_install_from_incident(state, p.session_id, &mut agent_state)?;
            } else {
                agent_state.goal = content.clone();
                agent_state.step_count = 0;
                agent_state.last_action_type = None;
                agent_state.pending_search_completion = None;
                let remediation_key = get_remediation_key(&p.session_id);
                let incident_key = get_incident_key(&p.session_id);
                state.delete(&remediation_key)?;
                state.delete(&incident_key)?;
            }
        }
        let transcript_msg = if role == "user" && waiting_for_sudo_password {
            ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "System: Runtime sudo credential received. Retrying pending install."
                    .to_string(),
                timestamp: timestamp_ms,
                trace_hash: None,
            }
        } else {
            ioi_types::app::agentic::ChatMessage {
                role,
                content,
                timestamp: timestamp_ms,
                trace_hash: None,
            }
        };

        let new_root = service
            .append_chat_to_scs(p.session_id, &transcript_msg, ctx.block_height)
            .await?;
        agent_state.transcript_root = new_root;

        if agent_state.status != AgentStatus::Running {
            log::info!(
                "Auto-resuming agent session {} due to new message",
                hex::encode(&p.session_id[..4])
            );
            agent_state.status = AgentStatus::Running;
            agent_state.consecutive_failures = 0;
        }

        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
    } else {
        return Err(TransactionError::Invalid("Session not found".into()));
    }

    Ok(())
}

pub async fn handle_resume(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: ResumeAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;
    let session_id_hex = hex::encode(p.session_id);
    let waiting_for_sudo_password_before_resume = is_waiting_for_sudo_password(&agent_state.status);
    let status_hints_sudo_wait = status_mentions_sudo_password(&agent_state.status);
    let incident_waiting_for_sudo = incident_waiting_for_sudo_password(state, p.session_id)?;
    let runtime_secret_ready =
        runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD);
    let sudo_retry_resume = p.approval_token.is_none()
        && (waiting_for_sudo_password_before_resume
            || status_hints_sudo_wait
            || incident_waiting_for_sudo
            || runtime_secret_ready);

    // [FIX] Allow resume even if already running (Idempotency)
    // This handles the race where the UI sends resume but the system auto-recovered
    // or received another event that flipped it back to Running.
    if matches!(agent_state.status, AgentStatus::Paused(_))
        || agent_state.status == AgentStatus::Running
        || sudo_retry_resume
    {
        agent_state.status = AgentStatus::Running;
        if sudo_retry_resume {
            maybe_restore_pending_install_from_incident(state, p.session_id, &mut agent_state)?;
        }

        let resuming_pending_install = agent_state
            .pending_tool_jcs
            .as_ref()
            .and_then(|raw| serde_json::from_slice::<ioi_types::app::agentic::AgentTool>(raw).ok())
            .map(|tool| {
                matches!(
                    tool,
                    ioi_types::app::agentic::AgentTool::SysInstallPackage { .. }
                )
            })
            .unwrap_or(false);
        if sudo_retry_resume {
            // Runtime-secret resume should retry canonical pending install directly.
            // Drop stale remediation queue entries that can redirect into system__fail.
            agent_state.execution_queue.clear();
            if !resuming_pending_install {
                log::warn!(
                    "Resume requested for sudo retry, but pending install tool is unavailable for session {}. Keeping session paused.",
                    hex::encode(&p.session_id[..4])
                );
                agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                return Ok(());
            }
        }

        if let Some(token) = p.approval_token {
            log::info!(
                "Resuming session {} with Approval Token for hash {:?}",
                hex::encode(&p.session_id[0..4]),
                hex::encode(&token.request_hash)
            );

            agent_state.pending_approval = Some(token);

            let msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "Authorization GRANTED. You may retry the action immediately.".to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };

            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;
        } else {
            let msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "Resumed by user/controller without specific approval.".to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;
        }

        agent_state.consecutive_failures = 0;

        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        Ok(())
    } else {
        Err(TransactionError::Invalid(format!(
            "Agent cannot resume from status: {:?}",
            agent_state.status
        )))
    }
}

pub async fn handle_delete_session(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    session_id_bytes: &[u8],
) -> Result<(), TransactionError> {
    let session_id: [u8; 32] = session_id_bytes
        .try_into()
        .map_err(|_| TransactionError::Invalid("Invalid session ID".into()))?;

    let state_key = get_state_key(&session_id);
    state.delete(&state_key)?;
    let remediation_key = get_remediation_key(&session_id);
    state.delete(&remediation_key)?;
    let incident_key = get_incident_key(&session_id);
    state.delete(&incident_key)?;

    let history_key = b"agent::history".to_vec();
    if let Some(bytes) = state.get(&history_key)? {
        let mut history: Vec<SessionSummary> = codec::from_bytes_canonical(&bytes)?;

        let len_before = history.len();
        history.retain(|s| s.session_id != session_id);

        if history.len() < len_before {
            state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;
        }
    }

    // [NEW] Trigger Cognitive Compaction on session delete/close
    // This shreds the raw thoughts but keeps the wisdom in the overlay.
    // Note: This is an async call that locks the SCS, so it might block briefly.
    if let Err(e) = perform_cognitive_compaction(service, session_id).await {
        log::warn!("Cognitive Compaction failed during session delete: {}", e);
    }

    // [NEW] Mark session as Terminated in any remaining state keys if possible,
    // though here we deleted the main state key already.
    // In a full implementation we might move it to an archive key.
    // For now, logging the explicit termination is sufficient.

    log::info!("Deleted/Terminated session {}", hex::encode(session_id));
    Ok(())
}

/// [NEW] Performs the "Refactoring Notes" process:
/// 1. Reads raw thoughts from the current epoch.
/// 2. Summarizes them into an Overlay.
/// 3. Rotates the epoch (Shredding the keys for raw thoughts).
/// 4. Prunes the old epoch key explicitly.
pub async fn perform_cognitive_compaction(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    // [FIX] Use `service` argument instead of `self.service`
    let scs_mutex = service
        .scs
        .as_ref()
        .ok_or(TransactionError::Invalid("SCS required".into()))?;

    // 1. Retrieve Raw Thoughts (Retention::Epoch)
    // We scan the session index for frames that are both "Thought" type and belong to the current epoch.
    let raw_thoughts: Vec<String> = {
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;
        let current_epoch = store.current_epoch;

        if let Some(frame_ids) = store.session_index.get(&session_id) {
            frame_ids
                .iter()
                .filter_map(|&fid| {
                    let frame = store.toc.frames.get(fid as usize)?;
                    // Only collect thoughts from the epoch we are about to shred
                    if frame.frame_type == ioi_scs::FrameType::Thought
                        && frame.epoch_id == current_epoch
                    {
                        // Attempt to read payload (will fail if key is already gone, which is fine)
                        if let Ok(bytes) = store.read_frame_payload(fid) {
                            if let Ok(message) =
                                codec::from_bytes_canonical::<RecordedMessage>(&bytes)
                            {
                                let content = if message.scrubbed_for_scs.is_empty() {
                                    message.scrubbed_for_model
                                } else {
                                    message.scrubbed_for_scs
                                };
                                return Some(format!("{}: {}", message.role, content));
                            }
                        }
                    }
                    None
                })
                .collect()
        } else {
            vec![]
        }
    };

    // If no new thoughts to summarize, we might still want to rotate epoch for security,
    // but for now let's just skip to avoid empty overlays.
    if raw_thoughts.is_empty() {
        return Ok(());
    }

    log::info!(
        "Cognitive Compaction: Summarizing {} thoughts...",
        raw_thoughts.len()
    );

    // 2. Synthesize Summary (The Overlay)
    // Use the reasoning model (System 2) to compress the context.
    let prompt = format!(
        "SYSTEM: Summarize the following stream of consciousness into a concise set of facts, decisions, and skills learned.\n\
         Discard transient errors, retries, and verbose logs. Keep only the final working logic and key outcomes.\n\n\
         RAW LOGS:\n{:?}", 
        raw_thoughts
    );

    let options = ioi_types::app::agentic::InferenceOptions {
        temperature: 0.0,
        ..Default::default()
    };

    // Use zero hash for model ID
    let summary_bytes = service
        .reasoning_inference
        .execute_inference(
            [0u8; 32],
            &service
                .prepare_cloud_inference_input(
                    Some(session_id),
                    "desktop_agent",
                    "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
                    prompt.as_bytes(),
                )
                .await?,
            options,
        )
        .await
        .map_err(|e| TransactionError::Invalid(format!("Compaction inference failed: {}", e)))?;

    // 3. Write Overlay Frame (Retention::Archival)
    {
        let mut store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;

        // Append frame with Archival retention - this survives key shredding
        // [FIX] Explicitly type the error map
        let _overlay_id = store
            .append_frame(
                ioi_scs::FrameType::Overlay,
                &summary_bytes,
                0,         // Block height (could fetch from context if available, using 0 for now)
                [0u8; 32], // mHNSW root placeholder
                session_id,
                ioi_scs::RetentionClass::Archival, // <--- SAVED FOREVER
            )
            .map_err(|e: anyhow::Error| TransactionError::Invalid(e.to_string()))?;

        // 4. Rotate Epoch (Generates new key, archives Manifest)
        // [FIX] Explicitly type the error map
        let _manifest = store
            .rotate_epoch()
            .map_err(|e: anyhow::Error| TransactionError::Invalid(e.to_string()))?;

        // 5. Explicitly prune the old epoch key to enforce forward secrecy
        // The previous epoch is `current_epoch - 1` after rotation.
        let old_epoch = store.current_epoch.saturating_sub(1);
        store.prune_epoch(old_epoch);
    }

    log::info!(
        "Cognitive Compaction Complete: Epoch rotated, raw thoughts shredded, Overlay preserved."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        compose_runtime_locality_scope, runtime_locality_scope_from_ip_discovery_payload,
        timezone_identifier_from_device,
    };
    use serde_json::json;

    #[test]
    fn runtime_locality_scope_from_ip_payload_prefers_region_code() {
        let payload = json!({
            "city": "Anderson",
            "region": "South Carolina",
            "region_code": "SC"
        });
        assert_eq!(
            runtime_locality_scope_from_ip_discovery_payload(&payload),
            Some("Anderson, SC".to_string())
        );
    }

    #[test]
    fn runtime_locality_scope_from_ip_payload_falls_back_to_region_name() {
        let payload = json!({
            "city": "Anderson",
            "region": "South Carolina"
        });
        assert_eq!(
            runtime_locality_scope_from_ip_discovery_payload(&payload),
            Some("Anderson, South Carolina".to_string())
        );
    }

    #[test]
    fn runtime_locality_scope_from_ip_payload_requires_city() {
        let payload = json!({
            "region": "South Carolina",
            "region_code": "SC"
        });
        assert_eq!(
            runtime_locality_scope_from_ip_discovery_payload(&payload),
            None
        );
    }

    #[test]
    fn compose_runtime_locality_scope_returns_city_when_region_matches_city() {
        assert_eq!(
            compose_runtime_locality_scope(Some("Anderson"), None, Some("Anderson")),
            Some("Anderson".to_string())
        );
    }

    #[test]
    fn timezone_identifier_from_device_prefers_tz_env_when_present() {
        let previous = std::env::var("TZ").ok();
        std::env::set_var("TZ", "America/New_York");
        assert_eq!(
            timezone_identifier_from_device(),
            Some("America/New_York".to_string())
        );
        if let Some(value) = previous {
            std::env::set_var("TZ", value);
        } else {
            std::env::remove_var("TZ");
        }
    }
}
