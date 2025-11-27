// Path: crates/client/src/workload_client/mod.rs
// UPDATED

mod actor;

use crate::security::{SecureStream, SecurityChannel};
use actor::{ClientActor, ClientRequest, PendingRequestMap};
use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use ioi_api::chain::{QueryStateResponse, WorkloadClientApi};
use ioi_api::vm::{ExecutionContext, ExecutionOutput};
use ioi_ipc::jsonrpc::{JsonRpcId, JsonRpcRequest};
use ioi_types::app::{
    AccountId, ActiveKeyRecord, Block, ChainStatus, ChainTransaction, StateAnchor, StateRoot,
    // [NEW] Debug structs
    DebugPinHeightParams, DebugTriggerGcParams, DebugTriggerGcResponse, DebugUnpinHeightParams,
};
use ioi_types::error::ChainError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Notify, RwLock};
use tokio::task::JoinHandle;

// ... (intermediate structs remain unchanged) ...
#[derive(Serialize)]
struct GetBlocksRangeParams {
    since: u64,
    max_blocks: u32,
    max_bytes: u32,
}

#[derive(Serialize)]
struct CheckTransactionsParams {
    anchor: StateAnchor,
    expected_timestamp_secs: u64,
    txs: Vec<ChainTransaction>,
}

#[derive(Serialize)]
struct DeployContractParams {
    code: Vec<u8>,
    sender: Vec<u8>,
}

#[derive(Serialize)]
struct CallContractParams {
    address: Vec<u8>,
    input_data: Vec<u8>,
    context: ExecutionContext,
}

#[derive(Serialize)]
struct QueryContractParams {
    address: Vec<u8>,
    input_data: Vec<u8>,
    context: ExecutionContext,
}

#[derive(Serialize)]
struct CheckAndTallyProposalsParams {
    current_height: u64,
}

#[derive(Serialize)]
struct PrefixScanParams<'a> {
    prefix: &'a [u8],
}

#[derive(Serialize)]
struct QueryRawStateParams<'a> {
    key: &'a [u8],
}

#[derive(Serialize)]
struct QueryStateAtParams<'a> {
    root: StateRoot,
    key: &'a [u8],
}

#[derive(Serialize)]
struct GetValidatorSetAtParams {
    anchor: StateAnchor,
}

#[derive(Serialize)]
struct GetValidatorSetForParams {
    height: u64,
}

#[derive(Serialize)]
struct GetActiveKeyAtParams<'a> {
    anchor: StateAnchor,
    account_id: &'a AccountId,
}

#[derive(Deserialize, Debug)]
pub struct GenesisStatus {
    pub ready: bool,
    pub root: Vec<u8>,
    pub chain_id: String,
}

const WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(90);
const IPC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_RETRY_ATTEMPTS: usize = 2;
const RPC_RETRY_WAIT: Duration = Duration::from_secs(3);

/// The internal state of the WorkloadClient, managed by ArcSwap for atomic updates.
#[derive(Debug)]
enum ClientState {
    Connected {
        to_actor: mpsc::Sender<ClientRequest>,
    },
    Disconnected,
}

/// A client-side proxy for communicating with the remote Workload container.
/// This is a lightweight handle that sends requests to a dedicated I/O actor.
/// It automatically handles connection drops and reconnections.
#[derive(Debug)]
pub struct WorkloadClient {
    workload_addr: String,
    request_id: Arc<AtomicI64>,
    state: Arc<ArcSwap<ClientState>>,
    ready_rx: watch::Receiver<bool>,
    shutdown: Arc<Notify>,
    _run_handle: JoinHandle<()>,
}

#[async_trait]
impl WorkloadClientApi for WorkloadClient {
    async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> ioi_types::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        self.process_block(block)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn get_blocks_range(
        &self,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    ) -> ioi_types::Result<Vec<Block<ChainTransaction>>, ChainError> {
        self.get_blocks_range(since, max_blocks, max_bytes)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn check_transactions_at(
        &self,
        anchor: StateAnchor,
        expected_timestamp_secs: u64,
        txs: Vec<ChainTransaction>,
    ) -> ioi_types::Result<Vec<Result<(), String>>, ChainError> {
        self.check_transactions_at(anchor, expected_timestamp_secs, txs)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn query_state_at(
        &self,
        root: StateRoot,
        key: &[u8],
    ) -> ioi_types::Result<QueryStateResponse, ChainError> {
        self.query_state_at(root, key)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn query_raw_state(&self, key: &[u8]) -> ioi_types::Result<Option<Vec<u8>>, ChainError> {
        self.query_raw_state(key)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> ioi_types::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        self.prefix_scan(prefix)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn get_staked_validators(
        &self,
    ) -> ioi_types::Result<BTreeMap<AccountId, u64>, ChainError> {
        self.get_staked_validators()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn get_genesis_status(&self) -> ioi_types::Result<bool, ChainError> {
        self.get_genesis_status()
            .await
            .map(|s| s.ready)
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Drop for WorkloadClient {
    fn drop(&mut self) {
        self.shutdown.notify_one();
    }
}

impl WorkloadClient {
    // ... (rest of implementation unchanged) ...
    /// Establishes a secure connection to the Workload container and spawns
    /// a dedicated management task to maintain the connection.
    pub async fn new(
        workload_addr: &str,
        ca_cert_path: &str,
        client_cert_path: &str,
        client_key_path: &str,
    ) -> Result<Self> {
        let (ready_tx, ready_rx) = watch::channel(false);
        let state = Arc::new(ArcSwap::new(Arc::new(ClientState::Disconnected)));
        let shutdown = Arc::new(Notify::new());

        let run_handle = tokio::spawn(Self::run(
            workload_addr.to_string(),
            ca_cert_path.to_string(),
            client_cert_path.to_string(),
            client_key_path.to_string(),
            ready_tx,
            state.clone(),
            shutdown.clone(),
        ));

        let client = Self {
            workload_addr: workload_addr.to_string(),
            request_id: Arc::new(AtomicI64::new(0)),
            state,
            ready_rx,
            shutdown,
            _run_handle: run_handle,
        };

        // Wait for the initial connection attempt to complete.
        if !client.wait_ready(WORKLOAD_READY_TIMEOUT).await {
            return Err(anyhow!(
                "Timeout waiting for initial connection to Workload container at {}",
                workload_addr
            ));
        }

        log::info!(
            "Successfully connected and verified IPC with Workload container at {}",
            client.destination_addr()
        );

        Ok(client)
    }

    /// The main run loop that manages the connection lifecycle.
    async fn run(
        addr: String,
        ca: String,
        cert: String,
        key: String,
        ready_tx: watch::Sender<bool>,
        state: Arc<ArcSwap<ClientState>>,
        shutdown: Arc<Notify>,
    ) {
        let mut backoff = 200u64;
        let pending_requests: PendingRequestMap = Arc::new(RwLock::new(HashMap::new()));

        loop {
            tokio::select! {
                biased;
                _ = shutdown.notified() => {
                    log::info!("[WorkloadClient] Shutdown signal received. Terminating run loop.");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(backoff)) => {
                    log::info!("[WorkloadClient] Attempting connect to {}", addr);
                    match Self::connect_once(&addr, &ca, &cert, &key).await {
                        Ok(stream) => {
                            let (to_actor, from_client) = mpsc::channel(128);
                            let actor = ClientActor::new(stream, from_client, pending_requests.clone());

                            state.store(Arc::new(ClientState::Connected { to_actor: to_actor.clone() }));
                            let _ = ready_tx.send(true);
                            log::info!("[WorkloadClient] Connection established.");
                            backoff = 200; // Reset backoff on success

                            // --- Spawn actor and heartbeat; reconnect when EITHER ends. ---
                            let mut actor_handle = tokio::spawn(async move { actor.run().await });
                            let mut hb_handle = Self::spawn_heartbeat(to_actor.clone());

                            tokio::select! {
                                res = &mut actor_handle => {
                                    match res {
                                        Ok(Ok(())) => log::info!("[WorkloadClient] Actor finished cleanly."),
                                        Ok(Err(e)) => log::warn!("[WorkloadClient] Actor terminated with error: {}.", e),
                                        Err(e) if e.is_cancelled() => { /* aborted by heartbeat */ },
                                        Err(e) => log::warn!("[WorkloadClient] Actor join error: {}", e),
                                    }
                                    hb_handle.abort();
                                    let _ = hb_handle.await;
                                }
                                res = &mut hb_handle => {
                                    match res {
                                        Ok(()) => log::warn!("[WorkloadClient] Heartbeat indicated failure; aborting actor for reconnect."),
                                        Err(e) if e.is_cancelled() => { /* actor ended first */ },
                                        Err(e) => log::warn!("[WorkloadClient] Heartbeat join error: {}", e),
                                    }
                                    actor_handle.abort();
                                    let _ = actor_handle.await;
                                }
                            }

                            state.store(Arc::new(ClientState::Disconnected));
                            let _ = ready_tx.send(false);
                        }
                        Err(e) => {
                            log::warn!("[WorkloadClient] Connection attempt failed: {}. Retrying in {}ms.", e, backoff);
                            state.store(Arc::new(ClientState::Disconnected));
                            let _ = ready_tx.send(false);
                            backoff = (backoff * 2).min(5_000);
                        }
                    }
                }
            }
        }
    }

    /// Attempts to establish a secure stream once.
    async fn connect_once(addr: &str, ca: &str, cert: &str, key: &str) -> Result<SecureStream> {
        let channel = SecurityChannel::new("orchestration", "workload");
        channel
            .establish_client(addr, "workload", ca, cert, key)
            .await?;
        channel
            .take_stream()
            .await
            .ok_or_else(|| anyhow!("Failed to take ownership of secure stream after establishment"))
    }

    /// Periodically sends a lightweight RPC to force I/O so that we detect half-open sockets.
    fn spawn_heartbeat(to_actor: mpsc::Sender<ClientRequest>) -> JoinHandle<()> {
        tokio::spawn(async move {
            use tokio::time::{interval, timeout};
            let mut ticker = interval(HEARTBEAT_INTERVAL);
            let mut hb_id: i64 = i64::MIN / 2;
            loop {
                ticker.tick().await;
                hb_id = hb_id.wrapping_add(1);

                let (tx, rx) = oneshot::channel();
                let req = JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    method: "system.getStatus.v1".to_string(),
                    params: serde_json::json!({}),
                    id: Some(JsonRpcId::Num(hb_id)),
                };

                if to_actor
                    .send(ClientRequest {
                        request: req,
                        response_tx: tx,
                    })
                    .await
                    .is_err()
                {
                    break;
                }

                match timeout(HEARTBEAT_TIMEOUT, rx).await {
                    Ok(Ok(Ok(_))) => {}
                    _ => {
                        log::warn!("[WorkloadClient] Heartbeat failed; connection likely down.");
                        break;
                    }
                }
            }
        })
    }

    /// Waits for the client to be in a connected state.
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        if *self.ready_rx.borrow() {
            return true;
        }
        tokio::time::timeout(timeout, self.ready_rx.clone().wait_for(|b| *b))
            .await
            .is_ok()
    }

    /// Checks if the client is currently connected.
    pub fn is_connected(&self) -> bool {
        *self.ready_rx.borrow()
    }

    /// Sends an RPC request to the actor and waits for the response.
    async fn send_rpc<P: serde::Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        // Serialize params once so we can reuse them across retries.
        let params_value = serde_json::to_value(params)?;
        let mut attempt = 0usize;
        let mut last_err: Option<anyhow::Error> = None;

        while attempt < RPC_RETRY_ATTEMPTS {
            attempt += 1;

            // Snapshot the current state for this attempt.
            let to_actor = match self.state.load().as_ref() {
                ClientState::Connected { to_actor } => to_actor.clone(),
                ClientState::Disconnected => {
                    last_err = Some(anyhow!("Workload client is disconnected"));
                    let _ = self.wait_ready(RPC_RETRY_WAIT).await;
                    continue;
                }
            };

            let id = self.request_id.fetch_add(1, Ordering::SeqCst);
            let (response_tx, response_rx) = oneshot::channel();

            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: method.to_string(),
                params: params_value.clone(),
                id: Some(JsonRpcId::Num(id)),
            };

            if let Err(e) = to_actor
                .send(ClientRequest {
                    request,
                    response_tx,
                })
                .await
            {
                last_err = Some(anyhow!("Failed to send request to client actor: {}", e));
                let _ = self.wait_ready(RPC_RETRY_WAIT).await;
                continue;
            }

            match tokio::time::timeout(IPC_RESPONSE_TIMEOUT, response_rx).await {
                Err(_) => {
                    last_err = Some(anyhow!("IPC response timed out"));
                    let _ = self.wait_ready(RPC_RETRY_WAIT).await;
                    continue;
                }
                Ok(Err(_canceled)) => {
                    last_err = Some(anyhow!("IPC responder dropped (actor terminated)"));
                    let _ = self.wait_ready(RPC_RETRY_WAIT).await;
                    continue;
                }
                Ok(Ok(result)) => match result {
                    Ok(value) => {
                        let decoded = serde_json::from_value::<R>(value)?;
                        return Ok(decoded);
                    }
                    Err(e) => {
                        // -32001 is the sentinel the actor uses for "connection lost".
                        if e.code == -32001 && attempt < RPC_RETRY_ATTEMPTS {
                            last_err = Some(anyhow!("IPC connection lost; retrying"));
                            let _ = self.wait_ready(RPC_RETRY_WAIT).await;
                            continue;
                        }
                        return Err(anyhow!("RPC Error (code {}): {}", e.code, e.message));
                    }
                },
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("RPC failed after {} attempts", RPC_RETRY_ATTEMPTS)))
    }

    pub fn destination_addr(&self) -> &str {
        &self.workload_addr
    }

    pub async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>)> {
        self.send_rpc("chain.processBlock.v1", block).await
    }

    pub async fn get_blocks_range(
        &self,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    ) -> Result<Vec<Block<ChainTransaction>>> {
        let params = GetBlocksRangeParams {
            since,
            max_blocks,
            max_bytes,
        };
        self.send_rpc("chain.getBlocksRange.v1", params).await
    }

    pub async fn get_status(&self) -> Result<ChainStatus> {
        self.send_rpc("system.getStatus.v1", json!({})).await
    }

    pub async fn get_last_block_hash(&self) -> Result<Vec<u8>> {
        self.send_rpc("chain.getLastBlockHash.v1", json!({})).await
    }

    pub async fn check_transactions_at(
        &self,
        anchor: StateAnchor,
        expected_timestamp_secs: u64,
        txs: Vec<ChainTransaction>,
    ) -> Result<Vec<Result<(), String>>> {
        let params = CheckTransactionsParams {
            anchor,
            expected_timestamp_secs,
            txs,
        };
        self.send_rpc("chain.checkTransactions.v1", params).await
    }

    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<(Vec<u8>, HashMap<Vec<u8>, Vec<u8>>)> {
        let params = DeployContractParams { code, sender };
        self.send_rpc("contract.deploy.v1", params).await
    }

    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<(ExecutionOutput, HashMap<Vec<u8>, Vec<u8>>)> {
        let params = CallContractParams {
            address,
            input_data,
            context,
        };
        self.send_rpc("contract.call.v1", params).await
    }

    pub async fn query_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<ExecutionOutput> {
        let params = QueryContractParams {
            address,
            input_data,
            context,
        };
        self.send_rpc("contract.query.v1", params).await
    }

    pub async fn get_validator_set(&self) -> Result<Vec<Vec<u8>>> {
        self.send_rpc("chain.getNextValidatorSet.v1", json!({}))
            .await
    }

    pub async fn get_validator_set_for(&self, height: u64) -> Result<Vec<Vec<u8>>> {
        let params = GetValidatorSetForParams { height };
        self.send_rpc("chain.getValidatorSetFor.v1", params).await
    }

    pub async fn get_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>> {
        let map_with_str_keys: BTreeMap<String, u64> =
            self.send_rpc("staking.getStakes.v1", json!({})).await?;
        map_with_str_keys
            .into_iter()
            .map(|(hex_key, stake)| {
                let bytes: [u8; 32] = hex::decode(hex_key)?
                    .try_into()
                    .map_err(|_| anyhow!("Invalid AccountId length"))?;
                Ok((AccountId(bytes), stake))
            })
            .collect()
    }

    pub async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>> {
        let map_with_str_keys: BTreeMap<String, u64> =
            self.send_rpc("staking.getNextStakes.v1", json!({})).await?;
        map_with_str_keys
            .into_iter()
            .map(|(hex_key, stake)| {
                let bytes: [u8; 32] = hex::decode(hex_key)?
                    .try_into()
                    .map_err(|_| anyhow!("Invalid AccountId length"))?;
                Ok((AccountId(bytes), stake))
            })
            .collect()
    }

    pub async fn get_state_root(&self) -> Result<StateRoot> {
        let bytes: Vec<u8> = self.send_rpc("state.getStateRoot.v1", json!({})).await?;
        Ok(StateRoot(bytes))
    }

    pub async fn get_expected_model_hash(&self) -> Result<Vec<u8>> {
        self.send_rpc("system.getExpectedModelHash.v1", json!({}))
            .await
    }

    pub async fn check_and_tally_proposals(&self, current_height: u64) -> Result<Vec<String>> {
        let params = CheckAndTallyProposalsParams { current_height };
        self.send_rpc("system.checkAndTallyProposals.v1", params)
            .await
    }

    pub async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let params = PrefixScanParams { prefix };
        self.send_rpc("state.prefixScan.v1", params).await
    }

    pub async fn query_raw_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let params = QueryRawStateParams { key };
        self.send_rpc("state.getRawState.v1", params).await
    }

    pub async fn query_state_at(&self, root: StateRoot, key: &[u8]) -> Result<QueryStateResponse> {
        let params = QueryStateAtParams { root, key };
        self.send_rpc("state.queryStateAt.v1", params).await
    }

    pub async fn get_validator_set_at(&self, anchor: StateAnchor) -> Result<Vec<AccountId>> {
        let params = GetValidatorSetAtParams { anchor };
        self.send_rpc("chain.getValidatorSetAt.v1", params).await
    }

    pub async fn get_active_key_at(
        &self,
        anchor: StateAnchor,
        acct: &AccountId,
    ) -> Result<Option<ActiveKeyRecord>> {
        let params = GetActiveKeyAtParams {
            anchor,
            account_id: acct,
        };
        self.send_rpc("state.getActiveKeyAt.v1", params).await
    }

    pub async fn get_genesis_status(&self) -> Result<GenesisStatus> {
        self.send_rpc("system.getGenesisStatus.v1", json!({})).await
    }

    pub async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<ioi_types::app::Block<ChainTransaction>>> {
        #[derive(Serialize)]
        struct Params {
            height: u64,
        }
        let params = Params { height };
        self.send_rpc("chain.getBlockByHeight.v1", params).await
    }

    // [NEW] Debug RPC methods for testing

    pub async fn debug_pin_height(&self, height: u64) -> Result<()> {
        let params = DebugPinHeightParams { height };
        self.send_rpc("system.debugPinHeight.v1", params).await
    }

    pub async fn debug_unpin_height(&self, height: u64) -> Result<()> {
        let params = DebugUnpinHeightParams { height };
        self.send_rpc("system.debugUnpinHeight.v1", params).await
    }

    pub async fn debug_trigger_gc(&self) -> Result<DebugTriggerGcResponse> {
        let params = DebugTriggerGcParams {};
        self.send_rpc("system.debugTriggerGc.v1", params).await
    }
}

// --- Re-exports to maintain public API ---

#[derive(Serialize, Deserialize, Debug)]
pub struct CallServiceParams {
    pub service_id: String,
    pub method_id: String,
    pub params: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetWorkloadConfigParams {}