// Path: crates/validator/src/standard/orchestration/operator_tasks.rs

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::{
    chain::WorkloadClientApi,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, VerifyingKey},
    state::{service_namespace_prefix, StateManager, Verifier},
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
// [FIX] Updated import path to `ioi_services::market`
use ioi_services::market::{JobTicket, ProvisioningReceipt};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActionTarget, ChainTransaction, KernelEvent,
        SignHeader, SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
        WalletInterceptionContext,
    },
    codec,
    keys::{active_service_key, ACCOUNT_NONCE_PREFIX},
};
use lru::LruCache;
use once_cell::sync::Lazy;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

// [FIX] Import reqwest for HTTP Client
use reqwest::Client;

// [NEW] Imports for Agent Driver
use ioi_services::agentic::desktop::{AgentState, AgentStatus, StepAgentParams};
use tokio::sync::{watch, Mutex as TokioMutex};

// --- Compute Market Canonical Definitions ---

/// Data required to reconstruct the provider's signature payload for verification.
#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderAckPayload {
    /// The root hash of the ticket being acknowledged.
    pub ticket_root: [u8; 32],
    /// The unique identifier for the compute instance.
    pub instance_id: Vec<u8>,
    /// The hash of the provider's endpoint URI.
    pub endpoint_uri_hash: [u8; 32],
    /// The block height at which the lease expires.
    pub expiry_height: u64,
    /// The hash of the lease identifier.
    pub lease_id_hash: [u8; 32],
}

/// On-chain representation of a registered provider in the market.
#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderInfo {
    /// The provider's public key.
    pub public_key: Vec<u8>,
    /// The provider's service endpoint URL.
    pub endpoint: String,
    /// The service tier of the provider.
    pub tier: u8,
    /// List of regions where the provider operates.
    pub allowed_regions: Vec<String>,
    /// The type of provider (e.g., "bare-metal", "cloud").
    pub provider_type: String,
}

// [REBRANDED] Constants updated to match new service nomenclature
const COMPUTE_MARKET_TICKET_PREFIX: &[u8] = b"tickets::";
const COMPUTE_MARKET_PROVIDER_PREFIX: &[u8] = b"providers::";
const DCPP_ACK_DOMAIN_BASE: &[u8] = b"IOI_DCPP_PROVIDER_ACK_V1";

// Helper to compute typed hash
fn sha256_32(data: &[u8]) -> Result<[u8; 32]> {
    let digest = sha256(data)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(digest.as_ref());
    Ok(arr)
}

fn decode_state_value<T>(bytes: &[u8]) -> Result<T>
where
    T: Decode,
{
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|e| anyhow!("StateEntry decode failed: {}", e))?;
    codec::from_bytes_canonical(&entry.value)
        .map_err(|e| anyhow!("StateEntry inner decode failed: {}", e))
}

fn decode_account_nonce(bytes: &[u8]) -> u64 {
    if let Ok(value) = decode_state_value::<u64>(bytes) {
        return value;
    }
    if bytes.len() == 8 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        return u64::from_le_bytes(raw);
    }
    0
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn reserve_nonce_for_account(
    workload_client: &std::sync::Arc<dyn WorkloadClientApi>,
    nonce_manager: &std::sync::Arc<TokioMutex<BTreeMap<AccountId, u64>>>,
    account_id: AccountId,
) -> u64 {
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
        Ok(Some(bytes)) => decode_account_nonce(&bytes),
        _ => 0,
    };

    let mut guard = nonce_manager.lock().await;
    let entry = guard.entry(account_id).or_insert(state_nonce);
    if *entry < state_nonce {
        *entry = state_nonce;
    }
    let nonce = *entry;
    *entry = entry.saturating_add(1);
    nonce
}

async fn submit_wallet_interception_record(
    workload_client: &std::sync::Arc<dyn WorkloadClientApi>,
    tx_pool: &std::sync::Arc<crate::standard::orchestration::mempool::Mempool>,
    consensus_kick_tx: &tokio::sync::mpsc::UnboundedSender<()>,
    nonce_manager: &std::sync::Arc<TokioMutex<BTreeMap<AccountId, u64>>>,
    keypair: &libp2p::identity::Keypair,
    chain_id: ioi_types::app::ChainId,
    interception: WalletInterceptionContext,
) -> Result<()> {
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &public_key,
    )?);

    let nonce = reserve_nonce_for_account(workload_client, nonce_manager, account_id).await;
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    let committed_nonce = match workload_client.query_raw_state(&nonce_key).await {
        Ok(Some(bytes)) => decode_account_nonce(&bytes),
        _ => 0,
    };

    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: "record_interception@v1".to_string(),
        params: codec::to_bytes_canonical(&interception).map_err(|e| anyhow!(e))?,
    };
    let mut sys_tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = keypair.sign(&sign_bytes)?;
    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    let tx = ChainTransaction::System(Box::new(sys_tx));
    let tx_hash = tx.hash()?;
    match tx_pool.add(tx, tx_hash, Some((account_id, nonce)), committed_nonce) {
        crate::standard::orchestration::mempool::AddResult::Rejected(reason) => Err(anyhow!(
            "wallet_network interception tx rejected: {}",
            reason
        )),
        _ => {
            let _ = consensus_kick_tx.send(());
            Ok(())
        }
    }
}

/// Streams firewall interception kernel events and persists them into
/// `wallet_network` as durable audit records via signed `CallService` transactions.
pub async fn run_wallet_network_audit_bridge_task<CS, ST, CE, V>(
    context_arc: std::sync::Arc<TokioMutex<MainLoopContext<CS, ST, CE, V>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let (
        mut event_rx,
        workload_client,
        tx_pool,
        consensus_kick_tx,
        nonce_manager,
        keypair,
        chain_id,
    ) = {
        let ctx = context_arc.lock().await;
        (
            ctx.event_broadcaster.subscribe(),
            ctx.view_resolver.workload_client().clone(),
            ctx.tx_pool_ref.clone(),
            ctx.consensus_kick_tx.clone(),
            ctx.nonce_manager.clone(),
            ctx.local_keypair.clone(),
            ctx.chain_id,
        )
    };

    let mut seen_request_hashes: LruCache<[u8; 32], ()> =
        LruCache::new(NonZeroUsize::new(4096).expect("non-zero"));

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                let event = match event {
                    Ok(value) => value,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(target: "wallet_network", "wallet audit bridge lagged by {} events", skipped);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                let KernelEvent::FirewallInterception {
                    verdict,
                    target,
                    request_hash,
                    session_id,
                } = event else {
                    continue;
                };

                if verdict != "REQUIRE_APPROVAL" && verdict != "BLOCK" {
                    continue;
                }
                if seen_request_hashes.get(&request_hash).is_some() {
                    continue;
                }

                let reason = match verdict.as_str() {
                    "REQUIRE_APPROVAL" => "manual approval required",
                    "BLOCK" => "blocked by active policy rules",
                    _ => "policy interception",
                };
                let interception = WalletInterceptionContext {
                    session_id,
                    request_hash,
                    target: ActionTarget::Custom(target),
                    value_usd_micros: None,
                    reason: reason.to_string(),
                    intercepted_at_ms: now_unix_ms(),
                };

                match submit_wallet_interception_record(
                    &workload_client,
                    &tx_pool,
                    &consensus_kick_tx,
                    &nonce_manager,
                    &keypair,
                    chain_id,
                    interception,
                )
                .await
                {
                    Ok(()) => {
                        seen_request_hashes.put(request_hash, ());
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "wallet_network",
                            "failed to persist interception {}: {}",
                            hex::encode(request_hash),
                            err
                        );
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

// --- Provider Client Abstraction ---

/// Data returned from a remote provider after a successful provisioning request.
#[derive(serde::Deserialize)] // [FIX] Added Deserialize derive
pub struct ProvisioningReceiptData {
    /// The ID of the provisioned instance.
    pub instance_id: String,
    /// The URI to access the instance.
    pub endpoint_uri: String,
    /// The unique lease ID for the session.
    pub lease_id: String,
    // [FIX] Use hex decoding for byte fields in JSON
    /// The provider's cryptographic signature.
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub signature: Vec<u8>,
}

/// A client for interacting with remote compute providers.
#[async_trait]
pub trait ProviderClient: Send + Sync {
    /// Requests provisioning of a compute resource from a provider.
    async fn request_provisioning(
        &self,
        endpoint: &str,
        ticket: &JobTicket,
        domain: &[u8],
        ticket_root: &[u8; 32],
    ) -> Result<ProvisioningReceiptData>;
}

/// Real HTTP Implementation of the Provider Client.
pub struct HttpProviderClient {
    client: Client,
}

impl HttpProviderClient {
    /// Creates a new `HttpProviderClient`.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }
}

#[async_trait]
impl ProviderClient for HttpProviderClient {
    async fn request_provisioning(
        &self,
        endpoint: &str,
        ticket: &JobTicket,
        domain: &[u8],
        ticket_root: &[u8; 32],
    ) -> Result<ProvisioningReceiptData> {
        let url = format!("{}/v1/provision", endpoint.trim_end_matches('/'));

        // Serialize ticket for transport.
        // In a real implementation, we might send the full struct JSON or the canonical bytes.
        // Sending canonical bytes + metadata ensures the provider sees exactly what we signed on-chain.
        let ticket_bytes = codec::to_bytes_canonical(ticket).map_err(|e| anyhow!(e))?;

        let request_body = serde_json::json!({
            "ticket_bytes_hex": hex::encode(ticket_bytes),
            "domain_hex": hex::encode(domain),
            "ticket_root_hex": hex::encode(ticket_root),
        });

        let response = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| anyhow!("Provider connection failed: {}", e))?;

        // [FIX] Capture status before consuming body
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Provider rejected provisioning: HTTP {} - {}",
                status,
                error_text
            ));
        }

        let receipt_data: ProvisioningReceiptData = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse provider receipt: {}", e))?;

        Ok(receipt_data)
    }
}

/// Runs the background task for the Oracle operator.
/// Checks if the oracle service is active and performs necessary duties.
pub async fn run_oracle_operator_task<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let workload_client = context.view_resolver.workload_client();

    // --- STATE GATE ---
    let oracle_active_key = active_service_key("oracle");
    if workload_client
        .query_raw_state(&oracle_active_key)
        .await?
        .is_none()
    {
        return Ok(());
    }

    Ok(())
}

// [NEW] Agent Driver Task
// This acts as the "System 2" loop for the User Node, driving agents forward.
/// Runs the background task for the Agent driver.
/// Scans for active agents and triggers steps if needed.
/// Returns `true` if any agent action was taken, allowing the main loop to speed up.
pub async fn run_agent_driver_task<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Result<bool>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let workload_client = context.view_resolver.workload_client();
    let mut work_performed = false;

    // 1. Scan for agent states
    // The canonical prefix for AgentState is b"agent::state::"
    const AGENT_STATE_PREFIX_RAW: &[u8] = b"agent::state::";

    // [FIX] Use the fully namespaced key prefix so the scan actually finds the service data
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let full_scan_prefix = [ns_prefix.as_slice(), AGENT_STATE_PREFIX_RAW].concat();

    let kvs = match workload_client.prefix_scan(&full_scan_prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(target: "agent_driver", "Prefix scan failed: {}", e);
            return Ok(false);
        }
    };

    if kvs.is_empty() {
        tracing::debug!(target: "agent_driver", "No agent states found under prefix.");
        return Ok(false);
    }
    tracing::info!(
        target: "agent_driver",
        "Found {} agent state entries",
        kvs.len()
    );

    // 2. Identify Running Agents
    for (_key, val_bytes) in kvs {
        let key_suffix = _key
            .as_slice()
            .strip_prefix(full_scan_prefix.as_slice())
            .map(|s| hex::encode(&s[..s.len().min(4)]))
            .unwrap_or_else(|| "unknown".to_string());
        let state: AgentState = match decode_state_value(&val_bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    target: "agent_driver",
                    "Failed to decode agent state (raw or StateEntry) for key {}: {}",
                    key_suffix,
                    e
                );
                continue;
            }
        };

        tracing::info!(
            target: "agent_driver",
            "Agent {} status {:?} step_count {}",
            hex::encode(&state.session_id[..4]),
            state.status,
            state.step_count
        );

        if state.status == AgentStatus::Running {
            // 3. Check Mempool for Pending Step (Debounce)
            // If the mempool already has a transaction for this signer, we wait.
            // This prevents spam loops when the agent is blocked by policy or waiting for a block commit.
            let our_pk = context.local_keypair.public().encode_protobuf();
            let our_account_id = AccountId(account_id_from_key_material(
                SignatureSuite::ED25519,
                &our_pk,
            )?);

            if context.tx_pool_ref.contains_account(&our_account_id) {
                // If we already have a pending transaction (e.g. from the previous tick),
                // don't spam another one. Wait for it to clear.
                continue;
            }

            // 4. Construct Step Transaction
            let params = StepAgentParams {
                session_id: state.session_id,
                // [FIX] Removed user_input field as it was removed from StepAgentParams struct
            };

            let payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "step@v1".to_string(),
                params: codec::to_bytes_canonical(&params).unwrap(),
            };

            // Get next nonce
            // [FIX] Use NonceManager + State Hybrid Approach
            // This ensures AgentDriver respects nonces reserved by DraftTransaction
            let nonce = {
                // 1. Get state nonce
                let nonce_key = [
                    ioi_types::keys::ACCOUNT_NONCE_PREFIX,
                    our_account_id.as_ref(),
                ]
                .concat();

                let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
                    Ok(Some(b)) => match decode_state_value::<u64>(&b) {
                        Ok(n) => n,
                        Err(_) => 0,
                    },
                    _ => 0,
                };

                // 2. Sync with Manager
                let mut nm = context.nonce_manager.lock().await;
                let entry = nm.entry(our_account_id).or_insert(0);

                // Fast-forward if state is ahead
                if *entry < state_nonce {
                    *entry = state_nonce;
                }

                let use_nonce = *entry;
                // Increment to reserve
                *entry += 1;

                use_nonce
            };

            tracing::info!(
                target: "agent_driver",
                "Submitting step for session {} with nonce {}",
                hex::encode(&state.session_id[..4]),
                nonce
            );

            let mut sys_tx = SystemTransaction {
                header: SignHeader {
                    account_id: our_account_id,
                    nonce,
                    chain_id: context.chain_id,
                    tx_version: 1,
                    session_auth: None,
                },
                payload,
                signature_proof: SignatureProof::default(),
            };

            // [FIXED] Map String error to anyhow::Error
            let sign_bytes = sys_tx
                .to_sign_bytes()
                .map_err(|e| anyhow!("Failed to serialize tx: {}", e))?;

            let signature = context.local_keypair.sign(&sign_bytes)?;

            sys_tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: our_pk,
                signature,
            };

            let tx = ChainTransaction::System(Box::new(sys_tx));
            let tx_hash = tx.hash()?;

            // 5. Submit to Mempool
            // We use the pool directly to skip gRPC overhead, as we are the node itself.
            let res = context
                .tx_pool_ref
                .add(tx, tx_hash, Some((our_account_id, nonce)), 0);

            match res {
                crate::standard::orchestration::mempool::AddResult::Rejected(reason) => {
                    tracing::warn!(target: "agent_driver", "Step tx rejected by mempool (Nonce: {}): {}", nonce, reason);
                }
                _ => {
                    // Wake consensus
                    let _ = context.consensus_kick_tx.send(());

                    tracing::info!(
                        target: "agent_driver",
                        "Auto-stepping agent session {} (Step {} | Nonce {})",
                        hex::encode(&state.session_id[0..4]),
                        state.step_count,
                        nonce
                    );
                    work_performed = true;
                }
            }
        } else {
            tracing::info!(
                target: "agent_driver",
                "Agent {} not running; status {:?}",
                hex::encode(&state.session_id[..4]),
                state.status
            );
        }
    }

    Ok(work_performed)
}

// Helper for selecting a provider from the registry
fn select_provider(
    providers: &[(Vec<u8>, ProviderInfo)],
    ticket: &JobTicket,
) -> Option<(Vec<u8>, ProviderInfo)> {
    providers
        .iter()
        .find(|(_, p)| {
            p.tier >= ticket.security_tier
                && p.allowed_regions.contains(&ticket.specs.region)
                && p.provider_type == ticket.specs.provider_type
        })
        .cloned()
}

// Global in-memory cursor for ticket scanning.
static LAST_SEEN_TICKET_KEY: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

// Global in-memory timestamp for throttling the solver task.
static LAST_SOLVER_RUN: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));
const SOLVER_PERIOD: Duration = Duration::from_secs(2);

fn should_run_solver() -> bool {
    let mut last = LAST_SOLVER_RUN.lock().unwrap();
    let now = Instant::now();
    match *last {
        Some(t) if now.duration_since(t) < SOLVER_PERIOD => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

/// The Universal Compute Market Solver Task.
/// This runs periodically (throttled) to process new compute requests.
pub async fn run_infra_solver_task<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    // [DoS Protection] Throttle execution frequency
    if !should_run_solver() {
        return Ok(());
    }

    let workload_client = context.view_resolver.workload_client();

    // 1. Check if the Rebranded Compute Market Service is active
    let cloud_service_key = active_service_key("compute_market");
    if workload_client
        .query_raw_state(&cloud_service_key)
        .await?
        .is_none()
    {
        return Ok(());
    }

    let ns_prefix = service_namespace_prefix("compute_market");

    // 2. Fetch Provider Registry from the market namespace
    let provider_prefix = [ns_prefix.as_slice(), COMPUTE_MARKET_PROVIDER_PREFIX].concat();
    let provider_kvs = match workload_client.prefix_scan(&provider_prefix).await {
        Ok(kvs) => kvs,
        Err(_) => return Ok(()),
    };

    let mut providers = Vec::new();
    for (k, v) in provider_kvs {
        if k.len() <= provider_prefix.len() {
            continue;
        }
        let provider_id = k[provider_prefix.len()..].to_vec();
        // Enforce 32-byte ID constraint (sha256 hash)
        if provider_id.len() != 32 {
            continue;
        }

        if let Ok(info) = codec::from_bytes_canonical::<ProviderInfo>(&v) {
            providers.push((provider_id, info));
        }
    }

    if providers.is_empty() {
        return Ok(());
    }

    // 3. Scan Tickets with Cursor
    // WARNING: Ticket keys MUST use fixed-width big-endian request_ids (u64_be)
    // to ensure lexicographical order matches numeric order.
    let ticket_prefix = [ns_prefix.as_slice(), COMPUTE_MARKET_TICKET_PREFIX].concat();
    let all_tickets = match workload_client.prefix_scan(&ticket_prefix).await {
        Ok(kvs) => kvs,
        Err(_) => return Ok(()),
    };

    let cursor = LAST_SEEN_TICKET_KEY.lock().unwrap().clone();

    // Filter by cursor (forward progress)
    let pending_tickets: Vec<_> = all_tickets
        .into_iter()
        .filter(|(k, _)| if let Some(c) = &cursor { k > c } else { true })
        .take(10) // Batch limit
        .collect();

    // WRAP-AROUND LOGIC: If no tickets found after cursor, reset cursor to None to retry old items.
    if pending_tickets.is_empty() {
        if cursor.is_some() {
            *LAST_SEEN_TICKET_KEY.lock().unwrap() = None;
            log::debug!("Compute Market: Cursor wrapped around, rescanning from start.");
        }
        return Ok(());
    }

    // [FIX] Use real HTTP client
    let provider_client = HttpProviderClient::new();

    for (key, val_bytes) in pending_tickets {
        // ALWAYS update cursor to ensure progress, even on failure/skip
        *LAST_SEEN_TICKET_KEY.lock().unwrap() = Some(key.clone());

        let ticket: JobTicket = match codec::from_bytes_canonical(&val_bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };

        log::info!(target: "market", "Compute Market: Processing job {}", ticket.request_id);

        // 4. Select Provider (Matches Task to Capability)
        let (provider_id, provider_info) = match select_provider(&providers, &ticket) {
            Some(p) => p,
            None => {
                log::warn!(target: "market", "No suitable provider found for job {}", ticket.request_id);
                continue;
            }
        };

        log::info!(
            target: "market",
            "Compute Market: selected provider {} at {} for job {}",
            hex::encode(&provider_id),
            provider_info.endpoint,
            ticket.request_id
        );

        // 5. Construct Canonical Payload for Signing
        let canonical_ticket = codec::to_bytes_canonical(&ticket).map_err(|e| anyhow!(e))?;
        let ticket_root = sha256_32(&canonical_ticket)?;

        // Prepare domain prefix
        let mut domain = DCPP_ACK_DOMAIN_BASE.to_vec();
        domain.extend_from_slice(&context.chain_id.0.to_le_bytes());
        domain.extend_from_slice(&context.genesis_hash);

        // 6. Request Provisioning & Signature from the selected Provider
        let provider_response = match provider_client
            .request_provisioning(&provider_info.endpoint, &ticket, &domain, &ticket_root)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!(target: "market", "Market Provider request failed: {}", e);
                continue;
            }
        };

        // 7. Local Verification (Sanity Check before submitting to chain)
        let payload = ProviderAckPayload {
            ticket_root,
            instance_id: provider_response.instance_id.as_bytes().to_vec(),
            endpoint_uri_hash: sha256_32(provider_response.endpoint_uri.as_bytes())?,
            expiry_height: ticket.expiry_height,
            // [REBRANDED] Using instance_id and lease_id nomenclature
            lease_id_hash: sha256_32(provider_response.lease_id.as_bytes())?,
        };

        // Verify that the signature we got matches the provider we selected.
        let payload_bytes = codec::to_bytes_canonical(&payload).map_err(|e| anyhow!(e))?;
        let mut signing_input = Vec::new();
        signing_input.extend_from_slice(&domain);
        signing_input.extend_from_slice(&payload_bytes);

        // Robust parsing of Ed25519 key bytes
        let pk_bytes_arr: [u8; 32] = match provider_info.public_key.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => {
                log::warn!(target: "market", "Compute Market: Provider pubkey is not 32 bytes");
                continue;
            }
        };

        let sig_bytes_arr: [u8; 64] = match provider_response.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => {
                log::warn!(target: "market", "Compute Market: Provider signature is not 64 bytes");
                continue;
            }
        };

        if let Ok(pk) = Ed25519PublicKey::from_bytes(&pk_bytes_arr) {
            if let Ok(sig) = Ed25519Signature::from_bytes(&sig_bytes_arr) {
                if pk.verify(&signing_input, &sig).is_err() {
                    log::warn!(
                        target: "market",
                        "Compute Market: Provider signature verification failed for job {}",
                        ticket.request_id
                    );
                    continue;
                }
            } else {
                log::warn!(target: "market", "Compute Market: Invalid signature format from provider");
                continue;
            }
        } else {
            log::warn!(target: "market", "Compute Market: Unsupported provider key type");
            continue;
        }

        // 8. Construct Settlement Receipt
        let receipt = ProvisioningReceipt {
            request_id: ticket.request_id,
            ticket_root,
            provider_id,
            endpoint_uri: provider_response.endpoint_uri,
            instance_id: provider_response.instance_id,
            provider_signature: provider_response.signature,
        };

        // 9. Submit Settlement Transaction to Mainnet
        let our_pk = context.local_keypair.public().encode_protobuf();
        let our_account_id = AccountId(account_id_from_key_material(
            SignatureSuite::ED25519,
            &our_pk,
        )?);

        let nonce_key = [
            ioi_types::keys::ACCOUNT_NONCE_PREFIX,
            our_account_id.as_ref(),
        ]
        .concat();
        let nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(b)) => codec::from_bytes_canonical::<u64>(&b).unwrap_or(0),
            _ => 0,
        };

        let sys_payload = SystemPayload::CallService {
            service_id: "compute_market".into(),
            method: "finalize_provisioning@v1".into(),
            params: codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
        };

        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id: our_account_id,
                nonce,
                chain_id: context.chain_id,
                tx_version: 1,
                session_auth: None,
            },
            payload: sys_payload,
            signature_proof: SignatureProof::default(),
        };

        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = context.local_keypair.sign(&sign_bytes)?;

        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: our_pk,
            signature,
        };

        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;

        context
            .tx_pool_ref
            .add(tx, tx_hash, Some((our_account_id, nonce)), 0);

        log::info!(
            target: "market",
            "Compute Market: Submitted settlement for job {}, provider {}",
            ticket.request_id,
            hex::encode(&receipt.provider_id)
        );
    }

    Ok(())
}
