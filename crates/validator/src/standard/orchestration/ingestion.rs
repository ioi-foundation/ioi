// Path: crates/validator/src/standard/orchestration/ingestion.rs

use crate::metrics::rpc_metrics as metrics;
use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::mempool::{AddResult, Mempool};
use futures::stream::{self, StreamExt};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::service_namespace_prefix;
use ioi_api::transaction::TransactionModel;
use ioi_client::WorkloadClient;
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::SwarmCommand;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    compute_next_timestamp, AccountId, BlockTimingParams, BlockTimingRuntime, ChainTransaction,
    KernelEvent, StateRoot, TxHash,
};
use ioi_types::codec;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{error, info, warn};

use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_pii::{
    build_decision_material, build_review_summary, check_exception_usage_increment_ok,
    decode_exception_usage_state, inspect_and_route_with_for_target, mint_default_scoped_exception,
    resolve_expected_request_hash, validate_resume_review_contract, validate_review_request_compat,
    verify_scoped_exception_for_decision, RiskSurface, ScopedExceptionVerifyError,
};

// [FIX] Update imports for Policy Engine Integration
use ioi_services::agentic::desktop::keys::{get_incident_key, get_state_key, pii};
use ioi_services::agentic::desktop::service::step::incident::IncidentState;
use ioi_services::agentic::desktop::{AgentState, ResumeAgentParams};
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, Verdict};
use ioi_types::app::agentic::{AgentTool, PiiEgressRiskSurface, PiiReviewRequest, PiiTarget};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, ApprovalToken};

/// Configuration for the ingestion worker.
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Maximum number of transactions to process in one batch.
    pub batch_size: usize,
    /// Maximum time to wait for a batch to fill before processing.
    pub batch_timeout_ms: u64,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            batch_timeout_ms: 10,
        }
    }
}

fn to_shared_risk_surface(risk_surface: PiiRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiRiskSurface::LocalProcessing => RiskSurface::LocalProcessing,
        PiiRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn to_shared_risk_surface_from_egress(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn parse_hash_hex(input: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// A simplified view of the chain tip needed for ante checks.
#[derive(Clone, Debug)]
pub struct ChainTipInfo {
    pub height: u64,
    pub timestamp: u64,
    pub gas_used: u64,
    pub state_root: Vec<u8>,
    pub genesis_root: Vec<u8>,
}

/// Helper struct to keep related transaction data aligned during batch processing.
struct ProcessedTx {
    tx: ChainTransaction,
    canonical_hash: TxHash,
    raw_bytes: Vec<u8>,
    receipt_hash_hex: String,
    account_id: Option<AccountId>,
    nonce: Option<u64>,
}

/// Cache for block timing parameters to avoid constant fetching from state.
struct TimingCache {
    params: BlockTimingParams,
    runtime: BlockTimingRuntime,
    last_fetched: Instant,
}

/// The main loop for the ingestion worker.
pub async fn run_ingestion_worker<CS>(
    mut rx: mpsc::Receiver<(TxHash, Vec<u8>)>,
    workload_client: Arc<WorkloadClient>,
    tx_pool: Arc<Mempool>,
    swarm_sender: mpsc::Sender<SwarmCommand>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    tx_model: Arc<UnifiedTransactionModel<CS>>,
    tip_watcher: watch::Receiver<ChainTipInfo>,
    status_cache: Arc<Mutex<lru::LruCache<String, TxStatusEntry>>>,
    receipt_map: Arc<Mutex<lru::LruCache<TxHash, String>>>,
    safety_model: Arc<dyn LocalSafetyModel>,
    // [NEW] Added os_driver to worker arguments
    os_driver: Arc<dyn OsDriver>,
    config: IngestionConfig,
    event_broadcaster: tokio::sync::broadcast::Sender<KernelEvent>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    info!(
        "Transaction Ingestion Worker started (Batch Size: {}, Timeout: {}ms)",
        config.batch_size, config.batch_timeout_ms
    );

    let mut batch = Vec::with_capacity(config.batch_size);
    let mut processed_batch = Vec::with_capacity(config.batch_size);
    let mut timing_cache: Option<TimingCache> = None;

    let mut nonce_cache: lru::LruCache<AccountId, u64> =
        lru::LruCache::new(std::num::NonZeroUsize::new(10000).unwrap());

    loop {
        let first_item = match rx.recv().await {
            Some(item) => item,
            None => break,
        };

        batch.push(first_item);
        let collect_start = Instant::now();
        let timeout = Duration::from_millis(config.batch_timeout_ms);

        while batch.len() < config.batch_size {
            let remaining = timeout.saturating_sub(collect_start.elapsed());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(item)) => batch.push(item),
                _ => break,
            }
        }

        processed_batch.clear();
        let mut accounts_needing_nonce = HashSet::new();

        for (receipt_hash, tx_bytes) in batch.drain(..) {
            let receipt_hash_hex = hex::encode(receipt_hash);
            match tx_model.deserialize_transaction(&tx_bytes) {
                Ok(tx) => match tx.hash() {
                    Ok(canonical_hash) => {
                        let (account_id, nonce) = match &tx {
                            ChainTransaction::System(s) => {
                                (Some(s.header.account_id), Some(s.header.nonce))
                            }
                            ChainTransaction::Settlement(s) => {
                                (Some(s.header.account_id), Some(s.header.nonce))
                            }
                            ChainTransaction::Application(a) => match a {
                                ioi_types::app::ApplicationTransaction::DeployContract {
                                    header,
                                    ..
                                }
                                | ioi_types::app::ApplicationTransaction::CallContract {
                                    header,
                                    ..
                                } => (Some(header.account_id), Some(header.nonce)),
                            },
                            _ => (None, None),
                        };

                        if let Some(acc) = account_id {
                            if !tx_pool.contains_account(&acc) && !nonce_cache.contains(&acc) {
                                accounts_needing_nonce.insert(acc);
                            }
                        }

                        processed_batch.push(ProcessedTx {
                            tx,
                            canonical_hash,
                            raw_bytes: tx_bytes,
                            receipt_hash_hex,
                            account_id,
                            nonce,
                        });
                    }
                    Err(e) => {
                        warn!(target: "ingestion", "Canonical hashing failed: {}", e);
                        status_cache.lock().await.put(
                            receipt_hash_hex,
                            TxStatusEntry {
                                status: TxStatus::Rejected,
                                error: Some(format!("Canonical hashing failed: {}", e)),
                                block_height: None,
                            },
                        );
                    }
                },
                Err(e) => {
                    warn!(target: "ingestion", "Deserialization failed: {}", e);
                    status_cache.lock().await.put(
                        receipt_hash_hex,
                        TxStatusEntry {
                            status: TxStatus::Rejected,
                            error: Some(format!("Deserialization failed: {}", e)),
                            block_height: None,
                        },
                    );
                }
            }
        }

        if processed_batch.is_empty() {
            continue;
        }

        let tip = tip_watcher.borrow().clone();
        let root_struct = StateRoot(if tip.height > 0 {
            tip.state_root.clone()
        } else {
            tip.genesis_root.clone()
        });

        if !accounts_needing_nonce.is_empty() {
            let fetch_results = stream::iter(accounts_needing_nonce)
                .map(|acc| {
                    let client = workload_client.clone();
                    let root = root_struct.clone();
                    async move {
                        let key = [ACCOUNT_NONCE_PREFIX, acc.as_ref()].concat();
                        let nonce = match client.query_state_at(root, &key).await {
                            Ok(resp) => resp
                                .membership
                                .into_option()
                                .map(|b| codec::from_bytes_canonical::<u64>(&b).unwrap_or(0))
                                .unwrap_or(0),
                            _ => 0,
                        };
                        (acc, nonce)
                    }
                })
                .buffer_unordered(50)
                .collect::<Vec<_>>()
                .await;

            for (acc, nonce) in fetch_results {
                nonce_cache.put(acc, nonce);
            }
        }

        if timing_cache
            .as_ref()
            .map_or(true, |c| c.last_fetched.elapsed() > Duration::from_secs(2))
        {
            let params_key = ioi_types::keys::BLOCK_TIMING_PARAMS_KEY;
            let runtime_key = ioi_types::keys::BLOCK_TIMING_RUNTIME_KEY;
            if let (Ok(p_resp), Ok(r_resp)) = tokio::join!(
                workload_client.query_state_at(root_struct.clone(), params_key),
                workload_client.query_state_at(root_struct.clone(), runtime_key)
            ) {
                let params = p_resp
                    .membership
                    .into_option()
                    .and_then(|v| codec::from_bytes_canonical(&v).ok())
                    .unwrap_or_default();
                let runtime = r_resp
                    .membership
                    .into_option()
                    .and_then(|v| codec::from_bytes_canonical(&v).ok())
                    .unwrap_or_default();
                timing_cache = Some(TimingCache {
                    params,
                    runtime,
                    last_fetched: Instant::now(),
                });
            }
        }

        let expected_ts = timing_cache
            .as_ref()
            .and_then(|c| {
                compute_next_timestamp(
                    &c.params,
                    &c.runtime,
                    tip.height,
                    tip.timestamp,
                    tip.gas_used,
                )
            })
            .unwrap_or(0);

        let anchor = root_struct.to_anchor().unwrap_or_default();

        // --- 4. Validation ---
        // Step A: Semantic Safety Check & Policy Enforcement (Orchestrator Local CPU)
        let mut semantically_valid_indices = Vec::new();
        let mut status_guard = status_cache.lock().await;

        for (idx, p_tx) in processed_batch.iter().enumerate() {
            let mut is_safe = true;
            if let ChainTransaction::System(sys) = &p_tx.tx {
                let ioi_types::app::SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                    ..
                } = &sys.payload;

                if service_id == "agentic"
                    || service_id == "desktop_agent"
                    || service_id == "compute_market"
                {
                    let allow_approval_bypass_for_message =
                        service_id == "desktop_agent" && method == "post_message@v1";
                    if allow_approval_bypass_for_message {
                        info!(
                            target: "ingestion",
                            "Approval-gate bypass enabled for desktop_agent post_message@v1"
                        );
                    }

                    let mut approval_token: Option<ApprovalToken> = None;
                    let mut resume_session_id: Option<[u8; 32]> = None;
                    let mut agent_state_opt: Option<AgentState> = None;
                    let mut expected_request_hash_opt: Option<[u8; 32]> = None;
                    let mut pii_request_opt: Option<PiiReviewRequest> = None;

                    if service_id == "desktop_agent" && method == "resume@v1" {
                        match codec::from_bytes_canonical::<ResumeAgentParams>(params) {
                            Ok(resume) => {
                                resume_session_id = Some(resume.session_id);
                                approval_token = resume.approval_token.clone();

                                let ns_prefix = service_namespace_prefix("desktop_agent");
                                let state_key = get_state_key(&resume.session_id);
                                let state_full_key =
                                    [ns_prefix.as_slice(), state_key.as_slice()].concat();
                                let incident_key = get_incident_key(&resume.session_id);
                                let incident_full_key =
                                    [ns_prefix.as_slice(), incident_key.as_slice()].concat();

                                let agent_state = match workload_client
                                    .query_raw_state(&state_full_key)
                                    .await
                                {
                                    Ok(Some(bytes)) => {
                                        match codec::from_bytes_canonical::<AgentState>(&bytes) {
                                            Ok(v) => Some(v),
                                            Err(_) => {
                                                is_safe = false;
                                                let reason = "Invalid desktop agent state bytes";
                                                warn!(target: "ingestion", "{}", reason);
                                                status_guard.put(
                                                    p_tx.receipt_hash_hex.clone(),
                                                    TxStatusEntry {
                                                        status: TxStatus::Rejected,
                                                        error: Some(format!(
                                                            "Firewall: {}",
                                                            reason
                                                        )),
                                                        block_height: None,
                                                    },
                                                );
                                                None
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        is_safe = false;
                                        let reason = "Missing desktop agent state for resume";
                                        warn!(target: "ingestion", "{}", reason);
                                        status_guard.put(
                                            p_tx.receipt_hash_hex.clone(),
                                            TxStatusEntry {
                                                status: TxStatus::Rejected,
                                                error: Some(format!("Firewall: {}", reason)),
                                                block_height: None,
                                            },
                                        );
                                        None
                                    }
                                    Err(e) => {
                                        is_safe = false;
                                        let reason =
                                            format!("Failed to query desktop agent state: {}", e);
                                        warn!(target: "ingestion", "{}", reason);
                                        status_guard.put(
                                            p_tx.receipt_hash_hex.clone(),
                                            TxStatusEntry {
                                                status: TxStatus::Rejected,
                                                error: Some(format!("Firewall: {}", reason)),
                                                block_height: None,
                                            },
                                        );
                                        None
                                    }
                                };

                                if let Some(agent_state) = agent_state {
                                    if approval_token.is_none() {
                                        approval_token = agent_state.pending_approval.clone();
                                    }
                                    let pending_tool_hash = match agent_state.pending_tool_hash {
                                        Some(v) => v,
                                        None => {
                                            is_safe = false;
                                            let reason =
                                                "Missing pending tool hash for resume review verification";
                                            warn!(target: "ingestion", "{}", reason);
                                            status_guard.put(
                                                p_tx.receipt_hash_hex.clone(),
                                                TxStatusEntry {
                                                    status: TxStatus::Rejected,
                                                    error: Some(format!("Firewall: {}", reason)),
                                                    block_height: None,
                                                },
                                            );
                                            [0u8; 32]
                                        }
                                    };

                                    let pending_gate_hash = match workload_client
                                        .query_raw_state(&incident_full_key)
                                        .await
                                    {
                                        Ok(Some(bytes)) => {
                                            codec::from_bytes_canonical::<IncidentState>(&bytes)
                                                .ok()
                                                .and_then(|incident| {
                                                    incident.pending_gate.as_ref().and_then(
                                                        |pending| {
                                                            parse_hash_hex(&pending.request_hash)
                                                        },
                                                    )
                                                })
                                        }
                                        Ok(None) => None,
                                        Err(_) => None,
                                    };

                                    if is_safe {
                                        let expected_request_hash = resolve_expected_request_hash(
                                            pending_gate_hash,
                                            pending_tool_hash,
                                        );
                                        expected_request_hash_opt = Some(expected_request_hash);

                                        let request_key_local =
                                            pii::review::request(&expected_request_hash);
                                        let request_key =
                                            [ns_prefix.as_slice(), request_key_local.as_slice()]
                                                .concat();
                                        match workload_client.query_raw_state(&request_key).await {
                                            Ok(Some(bytes)) => {
                                                match codec::from_bytes_canonical::<PiiReviewRequest>(
                                                    &bytes,
                                                ) {
                                                    Ok(req) => {
                                                        if let Err(e) =
                                                            validate_review_request_compat(&req)
                                                        {
                                                            is_safe = false;
                                                            let reason = format!(
                                                                "Incompatible PII review request: {}",
                                                                e
                                                            );
                                                            warn!(
                                                                target: "ingestion",
                                                                "{}",
                                                                reason
                                                            );
                                                            status_guard.put(
                                                                p_tx.receipt_hash_hex.clone(),
                                                                TxStatusEntry {
                                                                    status: TxStatus::Rejected,
                                                                    error: Some(format!(
                                                                        "Firewall: {}",
                                                                        reason
                                                                    )),
                                                                    block_height: None,
                                                                },
                                                            );
                                                        } else {
                                                            pii_request_opt = Some(req);
                                                        }
                                                    }
                                                    Err(_) => {
                                                        is_safe = false;
                                                        let reason =
                                                            "Invalid PII review request bytes";
                                                        warn!(target: "ingestion", "{}", reason);
                                                        status_guard.put(
                                                            p_tx.receipt_hash_hex.clone(),
                                                            TxStatusEntry {
                                                                status: TxStatus::Rejected,
                                                                error: Some(format!(
                                                                    "Firewall: {}",
                                                                    reason
                                                                )),
                                                                block_height: None,
                                                            },
                                                        );
                                                    }
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(e) => {
                                                is_safe = false;
                                                let reason = format!(
                                                    "Failed to query PII review request: {}",
                                                    e
                                                );
                                                warn!(target: "ingestion", "{}", reason);
                                                status_guard.put(
                                                    p_tx.receipt_hash_hex.clone(),
                                                    TxStatusEntry {
                                                        status: TxStatus::Rejected,
                                                        error: Some(format!(
                                                            "Firewall: {}",
                                                            reason
                                                        )),
                                                        block_height: None,
                                                    },
                                                );
                                            }
                                        }
                                    }

                                    agent_state_opt = Some(agent_state);
                                }
                            }
                            Err(_) => {
                                is_safe = false;
                                let reason = "Invalid resume params payload";
                                warn!(target: "ingestion", "{}", reason);
                                status_guard.put(
                                    p_tx.receipt_hash_hex.clone(),
                                    TxStatusEntry {
                                        status: TxStatus::Rejected,
                                        error: Some(format!("Firewall: {}", reason)),
                                        block_height: None,
                                    },
                                );
                            }
                        }
                    }

                    // 1. Construct ActionRequest for PolicyEngine
                    let request = ActionRequest {
                        target: ActionTarget::Custom(method.clone()),
                        params: params.clone(),
                        context: ActionContext {
                            agent_id: "unknown".into(),
                            session_id: resume_session_id,
                            window_id: None,
                        },
                        nonce: 0,
                    };

                    // Load active policy from state (Global Fallback)
                    // We use the global policy key (zero session ID) defined in `ioi-local.rs`.
                    let global_policy_key = [b"agent::policy::".as_slice(), &[0u8; 32]].concat();

                    let rules = match workload_client.query_raw_state(&global_policy_key).await {
                        Ok(Some(bytes)) => {
                            codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                        }
                        _ => ActionRules::default(), // DenyAll
                    };

                    if is_safe && service_id == "desktop_agent" && method == "resume@v1" {
                        if pii_request_opt.is_some() && approval_token.is_none() {
                            is_safe = false;
                            let reason = "Missing approval token for review request";
                            warn!(target: "ingestion", "{}", reason);
                            status_guard.put(
                                p_tx.receipt_hash_hex.clone(),
                                TxStatusEntry {
                                    status: TxStatus::Rejected,
                                    error: Some(format!("Firewall: {}", reason)),
                                    block_height: None,
                                },
                            );
                        } else if let (Some(expected_request_hash), Some(token)) =
                            (expected_request_hash_opt, approval_token.as_ref())
                        {
                            if let Err(e) = validate_resume_review_contract(
                                expected_request_hash,
                                token,
                                pii_request_opt.as_ref(),
                                expected_ts.saturating_mul(1000),
                            ) {
                                is_safe = false;
                                let reason = e.to_string();
                                warn!(target: "ingestion", "{}", reason);
                                status_guard.put(
                                    p_tx.receipt_hash_hex.clone(),
                                    TxStatusEntry {
                                        status: TxStatus::Rejected,
                                        error: Some(format!("Firewall: {}", reason)),
                                        block_height: None,
                                    },
                                );
                            }
                        }
                    }

                    if is_safe
                        && service_id == "desktop_agent"
                        && method == "resume@v1"
                        && matches!(
                            approval_token.as_ref().and_then(|t| t.pii_action.clone()),
                            Some(ioi_types::app::action::PiiApprovalAction::GrantScopedException)
                        )
                    {
                        let expected_request_hash = match expected_request_hash_opt {
                            Some(v) => v,
                            None => {
                                is_safe = false;
                                let reason =
                                    "Missing expected request hash for scoped exception verification";
                                warn!(target: "ingestion", "{}", reason);
                                status_guard.put(
                                    p_tx.receipt_hash_hex.clone(),
                                    TxStatusEntry {
                                        status: TxStatus::Rejected,
                                        error: Some(format!("Firewall: {}", reason)),
                                        block_height: None,
                                    },
                                );
                                [0u8; 32]
                            }
                        };
                        if is_safe {
                            let token = approval_token.as_ref().expect("checked above");
                            let agent_state = match agent_state_opt.as_ref() {
                                Some(v) => v,
                                None => {
                                    is_safe = false;
                                    let reason = "Missing desktop agent state for scoped exception verification";
                                    warn!(target: "ingestion", "{}", reason);
                                    status_guard.put(
                                        p_tx.receipt_hash_hex.clone(),
                                        TxStatusEntry {
                                            status: TxStatus::Rejected,
                                            error: Some(format!("Firewall: {}", reason)),
                                            block_height: None,
                                        },
                                    );
                                    continue;
                                }
                            };
                            let pending_tool_jcs = match agent_state.pending_tool_jcs.as_ref() {
                                Some(v) => v,
                                None => {
                                    is_safe = false;
                                    let reason =
                                        "Missing pending tool for scoped exception verification";
                                    warn!(target: "ingestion", "{}", reason);
                                    status_guard.put(
                                        p_tx.receipt_hash_hex.clone(),
                                        TxStatusEntry {
                                            status: TxStatus::Rejected,
                                            error: Some(format!("Firewall: {}", reason)),
                                            block_height: None,
                                        },
                                    );
                                    continue;
                                }
                            };
                            let mut tool: AgentTool = match serde_json::from_slice(pending_tool_jcs)
                            {
                                Ok(v) => v,
                                Err(e) => {
                                    is_safe = false;
                                    let reason = format!(
                                        "Failed to decode pending tool for scoped exception verification: {}",
                                        e
                                    );
                                    warn!(target: "ingestion", "{}", reason);
                                    status_guard.put(
                                        p_tx.receipt_hash_hex.clone(),
                                        TxStatusEntry {
                                            status: TxStatus::Rejected,
                                            error: Some(format!("Firewall: {}", reason)),
                                            block_height: None,
                                        },
                                    );
                                    continue;
                                }
                            };

                            let block_timestamp_secs = expected_ts;
                            let mut verified = false;
                            for spec in tool.pii_egress_specs() {
                                let Some(text) = tool.pii_egress_field_mut(spec.field) else {
                                    continue;
                                };

                                let risk_surface =
                                    to_shared_risk_surface_from_egress(spec.risk_surface);
                                let safety_model = Arc::clone(&safety_model);
                                let result = inspect_and_route_with_for_target(
                                    |input, shared_risk_surface| {
                                        let safety_model = safety_model.clone();
                                        Box::pin(async move {
                                            let api_risk_surface = match shared_risk_surface {
                                                RiskSurface::LocalProcessing => {
                                                    PiiRiskSurface::LocalProcessing
                                                }
                                                RiskSurface::Egress => PiiRiskSurface::Egress,
                                            };
                                            let inspection = safety_model
                                                .inspect_pii(input, api_risk_surface)
                                                .await?;
                                            Ok(inspection.evidence)
                                        })
                                    },
                                    text,
                                    &spec.target,
                                    risk_surface,
                                    &rules.pii_controls,
                                    spec.supports_transform,
                                )
                                .await;

                                let (evidence, routed) = match result {
                                    Ok(v) => v,
                                    Err(e) => {
                                        is_safe = false;
                                        let reason = format!(
                                            "Scoped exception PII verification failed: {}",
                                            e
                                        );
                                        warn!(target: "ingestion", "{}", reason);
                                        status_guard.put(
                                            p_tx.receipt_hash_hex.clone(),
                                            TxStatusEntry {
                                                status: TxStatus::Rejected,
                                                error: Some(format!("Firewall: {}", reason)),
                                                block_height: None,
                                            },
                                        );
                                        break;
                                    }
                                };

                                if !is_safe {
                                    break;
                                }

                                if routed.decision_hash != expected_request_hash {
                                    continue;
                                }

                                let scoped_exception = if let Some(existing) =
                                    token.scoped_exception.as_ref()
                                {
                                    existing.clone()
                                } else {
                                    match mint_default_scoped_exception(
                                        &evidence,
                                        &spec.target,
                                        risk_surface,
                                        expected_request_hash,
                                        block_timestamp_secs,
                                        "deterministic-default",
                                    ) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            is_safe = false;
                                            let reason = format!(
                                                "Failed to mint deterministic scoped exception: {}",
                                                e
                                            );
                                            warn!(target: "ingestion", "{}", reason);
                                            status_guard.put(
                                                p_tx.receipt_hash_hex.clone(),
                                                TxStatusEntry {
                                                    status: TxStatus::Rejected,
                                                    error: Some(format!("Firewall: {}", reason)),
                                                    block_height: None,
                                                },
                                            );
                                            break;
                                        }
                                    }
                                };

                                let usage_key_local =
                                    pii::review::exception_usage(&scoped_exception.exception_id);
                                let usage_key = [
                                    service_namespace_prefix("desktop_agent").as_slice(),
                                    usage_key_local.as_slice(),
                                ]
                                .concat();
                                let raw_usage =
                                    match workload_client.query_raw_state(&usage_key).await {
                                        Ok(v) => v,
                                        Err(e) => {
                                            is_safe = false;
                                            let reason = format!(
                                                "Failed to query scoped exception usage: {}",
                                                e
                                            );
                                            warn!(target: "ingestion", "{}", reason);
                                            status_guard.put(
                                                p_tx.receipt_hash_hex.clone(),
                                                TxStatusEntry {
                                                    status: TxStatus::Rejected,
                                                    error: Some(format!("Firewall: {}", reason)),
                                                    block_height: None,
                                                },
                                            );
                                            break;
                                        }
                                    };
                                let uses_consumed =
                                    match decode_exception_usage_state(raw_usage.as_deref()) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            is_safe = false;
                                            let reason = e.to_string();
                                            warn!(target: "ingestion", "{}", reason);
                                            status_guard.put(
                                                p_tx.receipt_hash_hex.clone(),
                                                TxStatusEntry {
                                                    status: TxStatus::Rejected,
                                                    error: Some(format!("Firewall: {}", reason)),
                                                    block_height: None,
                                                },
                                            );
                                            break;
                                        }
                                    };

                                if let Err(e) = verify_scoped_exception_for_decision(
                                    &scoped_exception,
                                    &evidence,
                                    &spec.target,
                                    risk_surface,
                                    expected_request_hash,
                                    &rules.pii_controls,
                                    block_timestamp_secs,
                                    uses_consumed,
                                ) {
                                    is_safe = false;
                                    let reason = match e {
                                        ScopedExceptionVerifyError::PolicyDisabled => {
                                            "Scoped exception policy disabled"
                                        }
                                        ScopedExceptionVerifyError::MissingAllowedClasses => {
                                            "Scoped exception missing allowed classes"
                                        }
                                        ScopedExceptionVerifyError::DestinationMismatch => {
                                            "Scoped exception destination mismatch"
                                        }
                                        ScopedExceptionVerifyError::ActionMismatch => {
                                            "Scoped exception action mismatch"
                                        }
                                        ScopedExceptionVerifyError::Expired => {
                                            "Scoped exception expired"
                                        }
                                        ScopedExceptionVerifyError::Overused => {
                                            "Scoped exception overused"
                                        }
                                        ScopedExceptionVerifyError::IneligibleEvidence => {
                                            "Scoped exception not eligible for this evidence"
                                        }
                                        ScopedExceptionVerifyError::ClassMismatch => {
                                            "Scoped exception class mismatch"
                                        }
                                        ScopedExceptionVerifyError::InvalidMaxUses => {
                                            "Scoped exception max_uses invalid"
                                        }
                                    };
                                    warn!(target: "ingestion", "{}", reason);
                                    status_guard.put(
                                        p_tx.receipt_hash_hex.clone(),
                                        TxStatusEntry {
                                            status: TxStatus::Rejected,
                                            error: Some(format!("Firewall: {}", reason)),
                                            block_height: None,
                                        },
                                    );
                                    break;
                                }

                                if let Err(e) = check_exception_usage_increment_ok(uses_consumed) {
                                    is_safe = false;
                                    let reason = e.to_string();
                                    warn!(target: "ingestion", "{}", reason);
                                    status_guard.put(
                                        p_tx.receipt_hash_hex.clone(),
                                        TxStatusEntry {
                                            status: TxStatus::Rejected,
                                            error: Some(format!("Firewall: {}", reason)),
                                            block_height: None,
                                        },
                                    );
                                    break;
                                }

                                verified = true;
                                break;
                            }

                            if is_safe && !verified {
                                is_safe = false;
                                let reason = "Scoped exception does not match pending PII decision";
                                warn!(target: "ingestion", "{}", reason);
                                status_guard.put(
                                    p_tx.receipt_hash_hex.clone(),
                                    TxStatusEntry {
                                        status: TxStatus::Rejected,
                                        error: Some(format!("Firewall: {}", reason)),
                                        block_height: None,
                                    },
                                );
                            }
                        }
                    }

                    // 2. Evaluate Policy (Context-Aware)
                    // NOTE: `resume@v1` carries an approval token for the *pending gated tool*,
                    // not for the resume transaction itself. Passing it into PolicyEngine causes
                    // misleading "token mismatch" logs (and doesn't change behavior).
                    let presented_approval =
                        if service_id == "desktop_agent" && method == "resume@v1" {
                            None
                        } else {
                            approval_token.as_ref()
                        };
                    let verdict = PolicyEngine::evaluate(
                        &rules,
                        &request,
                        &safety_model,
                        &os_driver,
                        presented_approval,
                    )
                    .await;

                    match verdict {
                        Verdict::Allow => {
                            // Proceed
                        }
                        Verdict::Block => {
                            is_safe = false;
                            let reason = "Blocked by active policy rules";
                            warn!(target: "ingestion", "Transaction blocked: {}", reason);

                            let _ = event_broadcaster.send(KernelEvent::FirewallInterception {
                                verdict: "BLOCK".to_string(),
                                target: method.clone(),
                                request_hash: p_tx.canonical_hash,
                                session_id: None, // session_id unavailable at this level
                            });

                            status_guard.put(
                                p_tx.receipt_hash_hex.clone(),
                                TxStatusEntry {
                                    status: TxStatus::Rejected,
                                    error: Some(format!("Policy: {}", reason)),
                                    block_height: None,
                                },
                            );
                        }
                        Verdict::RequireApproval => {
                            if allow_approval_bypass_for_message {
                                info!(
                                    target: "ingestion",
                                    "Downgrading REQUIRE_APPROVAL to ALLOW for desktop_agent post_message@v1"
                                );
                            } else {
                                // [FIX] Allow the transaction into mempool so it can execute and transition state to Paused.
                                is_safe = true;

                                let reason = "Manual approval required";
                                warn!(target: "ingestion", "Transaction halted (Policy Gate): {}. Allowing for state transition.", reason);

                                let _ = event_broadcaster.send(KernelEvent::FirewallInterception {
                                    verdict: "REQUIRE_APPROVAL".to_string(),
                                    target: method.clone(),
                                    request_hash: p_tx.canonical_hash,
                                    session_id: None,
                                });

                                // Note: We don't set status to Rejected here anymore.
                                // It will be set to Pending/InMempool if it passes downstream checks.
                            }
                        }
                    }

                    // 3. Local-only PII inspection + Stage B routing (fail-closed on egress)
                    if is_safe {
                        let input_str = match std::str::from_utf8(params) {
                            Ok(s) => Some(s),
                            Err(_) if service_id == "desktop_agent" => None,
                            Err(_) => {
                                is_safe = false;
                                let reason =
                                    "PII firewall requires UTF-8 payload for egress evaluation";
                                warn!(target: "ingestion", "{}", reason);
                                status_guard.put(
                                    p_tx.receipt_hash_hex.clone(),
                                    TxStatusEntry {
                                        status: TxStatus::Rejected,
                                        error: Some(format!("Firewall: {}", reason)),
                                        block_height: None,
                                    },
                                );
                                None
                            }
                        };

                        if is_safe {
                            if let Some(input_str) = input_str {
                                let pii_target = PiiTarget::ServiceCall {
                                    service_id: service_id.clone(),
                                    method: method.clone(),
                                };
                                let pii_target_label = pii_target.canonical_label();
                                let safety_model = Arc::clone(&safety_model);
                                let result = inspect_and_route_with_for_target(
                                    |input, shared_risk_surface| {
                                        let safety_model = safety_model.clone();
                                        Box::pin(async move {
                                            let api_risk_surface = match shared_risk_surface {
                                                RiskSurface::LocalProcessing => {
                                                    PiiRiskSurface::LocalProcessing
                                                }
                                                RiskSurface::Egress => PiiRiskSurface::Egress,
                                            };
                                            let inspection = safety_model
                                                .inspect_pii(input, api_risk_surface)
                                                .await?;
                                            Ok(inspection.evidence)
                                        })
                                    },
                                    input_str,
                                    &pii_target,
                                    to_shared_risk_surface(PiiRiskSurface::Egress),
                                    &rules.pii_controls,
                                    false, // Ingestion cannot mutate arbitrary payloads.
                                )
                                .await;
                                match result {
                                    Ok((evidence, routed)) => {
                                        let _ =
                                        event_broadcaster.send(KernelEvent::PiiDecisionReceipt(
                                            ioi_types::app::PiiDecisionReceiptEvent {
                                                session_id: None,
                                                target: pii_target_label.clone(),
                                                target_id: Some(pii_target.clone()),
                                                risk_surface: "egress".to_string(),
                                                decision_hash: routed.decision_hash,
                                                decision: routed.decision.clone(),
                                                transform_plan_id: routed
                                                    .transform_plan
                                                    .as_ref()
                                                    .map(|p| p.plan_id.clone()),
                                                span_count: evidence.spans.len() as u32,
                                                ambiguous: evidence.ambiguous,
                                                stage2_kind: routed
                                                    .stage2_decision
                                                    .as_ref()
                                                    .map(|d| match d {
                                                        ioi_types::app::agentic::Stage2Decision::ApproveTransformPlan { .. } => {
                                                            "approve_transform_plan"
                                                        }
                                                        ioi_types::app::agentic::Stage2Decision::Deny { .. } => "deny",
                                                        ioi_types::app::agentic::Stage2Decision::RequestMoreInfo { .. } => {
                                                            "request_more_info"
                                                        }
                                                        ioi_types::app::agentic::Stage2Decision::GrantScopedException { .. } => {
                                                            "grant_scoped_exception"
                                                        }
                                                    }
                                                    .to_string()),
                                                assist_invoked: routed.assist.assist_invoked,
                                                assist_applied: routed.assist.assist_applied,
                                                assist_kind: routed.assist.assist_kind.clone(),
                                                assist_version: routed.assist.assist_version.clone(),
                                                assist_identity_hash: routed.assist.assist_identity_hash,
                                                assist_input_graph_hash: routed.assist.assist_input_graph_hash,
                                                assist_output_graph_hash: routed.assist.assist_output_graph_hash,
                                            },
                                        ));

                                        match routed.decision {
                                        ioi_types::app::agentic::FirewallDecision::Allow
                                        | ioi_types::app::agentic::FirewallDecision::AllowLocalOnly => {}
                                        ioi_types::app::agentic::FirewallDecision::RedactThenAllow
                                        | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow
                                        | ioi_types::app::agentic::FirewallDecision::Quarantine
                                        | ioi_types::app::agentic::FirewallDecision::RequireUserReview => {
                                            is_safe = false;
                                            let reason = format!(
                                                "PII review required ({:?}, stage2={:?})",
                                                routed.decision, routed.stage2_decision
                                            );
                                            warn!(
                                                target: "ingestion",
                                                "Transaction gated by PII firewall: {}",
                                                reason
                                            );
                                            let material = build_decision_material(
                                                &evidence,
                                                &routed.decision,
                                                routed.transform_plan.as_ref(),
                                                routed.stage2_decision.as_ref(),
                                                to_shared_risk_surface(PiiRiskSurface::Egress),
                                                &pii_target,
                                                false,
                                                &routed.assist,
                                            );
                                            let summary = build_review_summary(
                                                &evidence,
                                                &pii_target,
                                                routed.stage2_decision.as_ref(),
                                            );
                                            let created_at_ms = expected_ts.saturating_mul(1000);
                                            let deadline_ms = created_at_ms
                                                .saturating_add(rules.pii_controls.stage2_timeout_ms as u64);
                                            let _ = event_broadcaster.send(
                                                KernelEvent::PiiReviewRequested {
                                                    decision_hash: routed.decision_hash,
                                                    material,
                                                    summary,
                                                    deadline_ms,
                                                    session_id: None,
                                                },
                                            );
                                            let _ = event_broadcaster.send(
                                                KernelEvent::FirewallInterception {
                                                    verdict: "REQUIRE_APPROVAL".to_string(),
                                                    target: pii_target_label.clone(),
                                                    request_hash: routed.decision_hash,
                                                    session_id: None,
                                                },
                                            );

                                            status_guard.put(
                                                p_tx.receipt_hash_hex.clone(),
                                                TxStatusEntry {
                                                    status: TxStatus::Rejected,
                                                    error: Some(format!("Firewall: {}", reason)),
                                                    block_height: None,
                                                },
                                            );
                                        }
                                        ioi_types::app::agentic::FirewallDecision::Deny => {
                                            is_safe = false;
                                            let reason = format!(
                                                "PII firewall denied raw egress ({:?})",
                                                routed.stage2_decision
                                            );
                                            warn!(target: "ingestion", "{}", reason);
                                            let _ = event_broadcaster.send(
                                                KernelEvent::FirewallInterception {
                                                    verdict: "BLOCK".to_string(),
                                                    target: pii_target_label.clone(),
                                                    request_hash: p_tx.canonical_hash,
                                                    session_id: None,
                                                },
                                            );

                                            status_guard.put(
                                                p_tx.receipt_hash_hex.clone(),
                                                TxStatusEntry {
                                                    status: TxStatus::Rejected,
                                                    error: Some(format!("Firewall: {}", reason)),
                                                    block_height: None,
                                                },
                                            );
                                        }
                                    }
                                    }
                                    Err(e) => {
                                        is_safe = false;
                                        warn!(target: "ingestion", "PII inspection failure: {}", e);
                                        status_guard.put(
                                            p_tx.receipt_hash_hex.clone(),
                                            TxStatusEntry {
                                                status: TxStatus::Rejected,
                                                error: Some(format!("Firewall Error: {}", e)),
                                                block_height: None,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if is_safe {
                semantically_valid_indices.push(idx);
            }
        }
        drop(status_guard);

        if semantically_valid_indices.is_empty() {
            continue;
        }

        // Step B: Workload Validation (Execution Pre-checks)
        let txs_to_check: Vec<ChainTransaction> = semantically_valid_indices
            .iter()
            .map(|&i| processed_batch[i].tx.clone())
            .collect();

        let check_results = match workload_client
            .check_transactions_at(anchor, expected_ts, txs_to_check)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                error!(target: "ingestion", "Validation IPC failed: {}", e);
                continue;
            }
        };

        // --- 5. Mempool & Status Finalization ---
        let mut status_guard = status_cache.lock().await;
        let mut receipt_guard = receipt_map.lock().await;
        let mut accepted_count = 0;

        for (res_idx, result) in check_results.into_iter().enumerate() {
            let original_idx = semantically_valid_indices[res_idx];
            let p_tx = &processed_batch[original_idx];

            // [FIX] Handle "Approval required" error string as success for ingestion
            let is_approval_error = if let Err(e) = &result {
                e.contains("Approval required for request")
            } else {
                false
            };

            let validation_ok = result.is_ok() || is_approval_error;

            if validation_ok {
                let tx_info = p_tx.account_id.map(|acc| (acc, p_tx.nonce.unwrap()));
                let committed_nonce = p_tx
                    .account_id
                    .and_then(|acc| nonce_cache.get(&acc).copied())
                    .unwrap_or(0);

                match tx_pool.add(
                    p_tx.tx.clone(),
                    p_tx.canonical_hash,
                    tx_info,
                    committed_nonce,
                ) {
                    AddResult::Ready | AddResult::Future => {
                        accepted_count += 1;
                        status_guard.put(
                            p_tx.receipt_hash_hex.clone(),
                            TxStatusEntry {
                                status: TxStatus::InMempool,
                                error: None,
                                block_height: None,
                            },
                        );
                        receipt_guard.put(p_tx.canonical_hash, p_tx.receipt_hash_hex.clone());

                        info!(
                            target: "ingestion",
                            "Added transaction to mempool: {}",
                            p_tx.receipt_hash_hex
                        );

                        let _ = swarm_sender
                            .send(SwarmCommand::PublishTransaction(p_tx.raw_bytes.clone()))
                            .await;
                    }
                    AddResult::Rejected(r) => {
                        warn!(target: "ingestion", "Mempool rejected transaction {}: {}", p_tx.receipt_hash_hex, r);
                        status_guard.put(
                            p_tx.receipt_hash_hex.clone(),
                            TxStatusEntry {
                                status: TxStatus::Rejected,
                                error: Some(format!("Mempool: {}", r)),
                                block_height: None,
                            },
                        );
                    }
                }
            } else {
                // Real error
                let e = result.unwrap_err();
                warn!(target: "ingestion", "Validation failed for transaction {}: {}", p_tx.receipt_hash_hex, e);
                status_guard.put(
                    p_tx.receipt_hash_hex.clone(),
                    TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some(format!("Validation: {}", e)),
                        block_height: None,
                    },
                );
            }
        }

        if accepted_count > 0 {
            let _ = consensus_kick_tx.send(());
        }
        metrics().set_mempool_size(tx_pool.len() as f64);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ingestion_is_verify_only_for_scoped_exception_usage() {
        let src = include_str!("ingestion.rs");
        let src = src.split("\n#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !src.contains("insert(&usage_key"),
            "ingestion must not persist scoped exception usage counters"
        );
        assert!(
            !src.contains("insert(&usage_key_local"),
            "ingestion must not persist scoped exception usage counters"
        );
    }
}
