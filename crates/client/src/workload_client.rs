// Path: crates/client/src/workload_client.rs
use crate::security::SecurityChannel;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use depin_sdk_api::{
    consensus::ChainStateReader,
    vm::{ExecutionContext, ExecutionOutput},
};
use depin_sdk_types::app::{
    AccountId, ActiveKeyRecord, Block, ChainStatus, ChainTransaction, Membership, StateAnchor,
    StateRoot,
};
use depin_sdk_types::keys::ACCOUNT_ID_TO_PUBKEY_PREFIX;
use ipc_protocol::jsonrpc::{JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use libp2p::identity::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::time::sleep;

// --- Structs for RPC method parameters and results ---

#[derive(Serialize)]
struct GetBlocksRangeParams {
    since: u64,
    max_blocks: u32,
    max_bytes: u32,
}

#[derive(Serialize)]
struct CheckTransactionsParams {
    anchor: StateAnchor,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryStateAtIpcResponse {
    pub msg_version: u32,
    pub scheme_id: u16,
    pub scheme_version: u16,
    pub membership: Membership,
    pub proof_bytes: Vec<u8>,
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

// --- Type Aliases for Clarity ---
type RpcResult = Result<JsonRpcResponse<Value>>;
type PendingTx = oneshot::Sender<RpcResult>;
type PendingMap = DashMap<u64, PendingTx>;

/// The public, cloneable handle to the Workload IPC client.
#[derive(Clone, Debug)]
pub struct WorkloadClient {
    inner: Arc<Inner>,
}

/// The shared core containing all state for the IPC client.
#[derive(Debug)]
struct Inner {
    workload_addr: String,
    request_id_counter: AtomicU64,
    pending_requests: Arc<PendingMap>,
    request_tx: mpsc::Sender<Vec<u8>>,
    health_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
    io_handle: tokio::task::JoinHandle<()>,
    inflight_semaphore: Arc<Semaphore>,
}

// Implement Drop on the inner struct to ensure shutdown happens only once.
impl Drop for Inner {
    fn drop(&mut self) {
        log::debug!("Dropping Inner WorkloadClient; sending shutdown signal.");
        // Best-effort signal to the I/O task. The task will see `*shutdown_rx.borrow()` become true.
        let _ = self.shutdown_tx.send(true);
        // Abort the task as a final measure if it doesn't shut down gracefully on its own.
        self.io_handle.abort();
    }
}

/// Notifies all pending request callers that the connection has failed.
fn fail_all_pending(pending: &PendingMap, reason: &str) {
    let keys: Vec<u64> = pending.iter().map(|e| *e.key()).collect();
    for id in keys {
        if let Some((_, tx)) = pending.remove(&id) {
            // The receiver may have already dropped (e.g., due to timeout),
            // so we ignore the result of the send.
            let _ = tx.send(Err(anyhow!(reason.to_string())));
        }
    }
}

/// The core I/O loop that manages the single mTLS socket.
async fn run_io_task(
    mut channel: SecurityChannel,
    mut request_rx: mpsc::Receiver<Vec<u8>>,
    pending_requests: Arc<PendingMap>,
    mut shutdown_rx: watch::Receiver<bool>,
    health_tx: watch::Sender<bool>,
) {
    loop {
        tokio::select! {
            biased; // Prioritize the shutdown signal.

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::info!("WorkloadClient I/O task: shutdown signal received.");
                    fail_all_pending(&pending_requests, "WorkloadClient is shutting down");
                    let _ = health_tx.send(false);
                    break;
                }
            },

            maybe_req = request_rx.recv() => {
                match maybe_req {
                    Some(req_bytes) => {
                        if let Err(e) = channel.send(&req_bytes).await {
                            log::error!("WorkloadClient: IPC channel send error: {}. Shutting down.", e);
                            fail_all_pending(&pending_requests, &format!("IPC send failed: {}", e));
                            let _ = health_tx.send(false);
                            break;
                        }
                    },
                    None => { // All client handles have been dropped.
                        if pending_requests.is_empty() {
                            log::info!("WorkloadClient I/O task: request channel closed and no pending requests. Shutting down.");
                            let _ = health_tx.send(false);
                            break;
                        }
                        // Otherwise, keep running to process any in-flight responses.
                    }
                }
            },

            response_result = channel.receive() => {
                let response_bytes = match response_result {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log::error!("WorkloadClient: IPC channel receive error: {}. Shutting down.", e);
                        fail_all_pending(&pending_requests, &format!("IPC receive failed: {}", e));
                        let _ = health_tx.send(false);
                        break;
                    }
                };

                match serde_json::from_slice::<JsonRpcResponse<Value>>(&response_bytes) {
                    Ok(response) => {
                        // [+] FIX: Match directly on `response.id` which is a `JsonRpcId` enum, not an Option.
                        match response.id {
                            JsonRpcId::Num(id) => {
                                if let Some((_, sender)) = pending_requests.remove(&(id as u64)) {
                                    if sender.send(Ok(response)).is_err() {
                                        log::warn!("WorkloadClient: RPC caller for request {} dropped before receiving response.", id);
                                    }
                                } else {
                                    log::warn!("WorkloadClient: Received response for unknown or timed-out request id: {}", id);
                                }
                            },
                            _ => { // This covers Str and Null
                                 log::warn!("WorkloadClient: Received response with non-numeric or null ID: {:?}", response.id);
                            }
                        }
                    },
                    Err(e) => { // Fatal protocol error
                        log::error!("WorkloadClient: Failed to parse JSON-RPC response: {}. Shutting down.", e);
                        fail_all_pending(&pending_requests, &format!("JSON-RPC parse error: {}", e));
                        let _ = health_tx.send(false);
                        break;
                    }
                }
            },
        }
    }
    log::info!("WorkloadClient: I/O task has terminated.");
}

impl WorkloadClient {
    pub async fn new(
        workload_addr: &str,
        ca_cert_path: &str,
        client_cert_path: &str,
        client_key_path: &str,
    ) -> Result<Self> {
        // [+] FIX: Use a block expression with a loop to establish the channel.
        // This is a cleaner pattern that avoids the "unused assignment" warning.
        let channel = {
            let mut attempts = 0;
            // Increase attempts for CI environments where startup can be slower.
            let max_attempts = 10;
            // Start with a shorter delay and use exponential backoff.
            let mut retry_delay = Duration::from_millis(500);

            loop {
                attempts += 1;
                let temp_channel = SecurityChannel::new("orchestration", "workload");
                match temp_channel
                    .establish_client(
                        workload_addr,
                        "workload",
                        ca_cert_path,
                        client_cert_path,
                        client_key_path,
                    )
                    .await
                {
                    Ok(_) => {
                        // Connection established, break loop and return the channel
                        break temp_channel;
                    }
                    Err(e) => {
                        if attempts >= max_attempts {
                            return Err(e.into());
                        }
                        log::warn!("Attempt {}/{} to connect to Workload container failed: {}. Retrying in {:?}...", attempts, max_attempts, e, retry_delay);
                        sleep(retry_delay).await;
                        // Exponential backoff with a cap to prevent excessively long waits.
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
        };

        let (request_tx, request_rx) = mpsc::channel(128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (health_tx, health_rx) = watch::channel(true);
        let pending_requests: Arc<PendingMap> = Arc::new(DashMap::new());

        let io_handle = tokio::spawn(run_io_task(
            channel, // Move ownership to the task
            request_rx,
            pending_requests.clone(),
            shutdown_rx,
            health_tx,
        ));

        let inner = Arc::new(Inner {
            workload_addr: workload_addr.to_string(),
            request_id_counter: AtomicU64::new(0),
            pending_requests,
            request_tx,
            health_rx,
            shutdown_tx,
            io_handle,
            inflight_semaphore: Arc::new(Semaphore::new(1024)), // Recommended: make this configurable
        });

        let client = Self { inner };

        // The readiness probe now uses the fully-functional concurrent client.
        client
            .get_status()
            .await
            .context("Workload IPC established but not responsive during readiness probe")?;

        log::info!(
            "Successfully connected and verified IPC with Workload container at {}",
            workload_addr
        );
        Ok(client)
    }

    pub fn destination_addr(&self) -> &str {
        &self.inner.workload_addr
    }

    async fn send_rpc<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        if !*self.inner.health_rx.borrow() {
            bail!("IPC connection is down");
        }

        let _permit = self
            .inner
            .inflight_semaphore
            .clone()
            .acquire_owned()
            .await?;
        let id = self
            .inner
            .request_id_counter
            .fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: serde_json::to_value(params)?,
            id: Some(JsonRpcId::Num(id as i64)),
        };

        let (tx, rx) = oneshot::channel();
        self.inner.pending_requests.insert(id, tx);

        let bytes = serde_json::to_vec(&request)?;
        if self.inner.request_tx.send(bytes).await.is_err() {
            self.inner.pending_requests.remove(&id);
            bail!("I/O task has terminated; connection is down");
        }

        // Await with timeout, using `??` to cleanly propagate errors.
        let response = tokio::time::timeout(Duration::from_secs(30), rx)
            .await // Recommended: make timeout configurable
            .map_err(|_| anyhow!("RPC '{}' (id {}) timed out", method, id))? // Maps TimeoutError
            .map_err(|_| anyhow!("Response channel closed unexpectedly"))??; // Unwraps oneshot::RecvError then the inner RpcResult

        match (response.result, response.error) {
            (Some(ok), None) => Ok(serde_json::from_value(ok)?),
            (None, Some(err)) => bail!("RPC error {}: {}", err.code, err.message),
            _ => bail!("Invalid JSON-RPC response from server"),
        }
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
        txs: Vec<ChainTransaction>,
    ) -> Result<Vec<Result<(), String>>> {
        let params = CheckTransactionsParams { anchor, txs };
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

    pub async fn query_state_at(
        &self,
        root: StateRoot,
        key: &[u8],
    ) -> Result<QueryStateAtIpcResponse> {
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
    ) -> Result<Option<depin_sdk_types::app::BlockHeader>> {
        #[derive(Serialize)]
        struct Params {
            height: u64,
        }
        let params = Params { height };
        self.send_rpc("chain.getBlockByHeight.v1", params).await
    }
}

#[async_trait]
impl ChainStateReader for WorkloadClient {
    async fn get_authority_set(&self) -> Result<Vec<Vec<u8>>, String> {
        self.send_rpc("chain.getAuthoritySet.v1", json!({}))
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, String> {
        let map_with_str_keys: BTreeMap<String, u64> = self
            .send_rpc("staking.getNextStakes.v1", json!({}))
            .await
            .map_err(|e| e.to_string())?;

        map_with_str_keys
            .into_iter()
            .map(|(hex_key, stake)| {
                let bytes: [u8; 32] = hex::decode(hex_key)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "Invalid AccountId length".to_string())?;
                Ok((AccountId(bytes), stake))
            })
            .collect::<Result<_, String>>()
    }

    async fn get_public_key_for_account(
        &self,
        account_id: &AccountId,
    ) -> Result<PublicKey, String> {
        let key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
        let pk_bytes = self
            .query_raw_state(&key)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                format!(
                    "Public key not found for AccountId: {}",
                    hex::encode(account_id)
                )
            })?;

        PublicKey::try_decode_protobuf(&pk_bytes)
            .map_err(|e| format!("Failed to decode public key protobuf: {}", e))
    }
}
