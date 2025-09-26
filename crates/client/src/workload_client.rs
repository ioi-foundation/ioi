// Path: crates/client/src/workload_client.rs
use crate::security::SecurityChannel;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput};
use depin_sdk_types::app::{
    AccountId, ActiveKeyRecord, Block, ChainStatus, ChainTransaction, Membership, StateAnchor,
    StateRoot,
};
use depin_sdk_types::keys::ACCOUNT_ID_TO_PUBKEY_PREFIX;
use ipc_protocol::jsonrpc::{JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use libp2p::identity::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;

// --- Structs for RPC method parameters and results ---

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

#[derive(Deserialize, Debug)]
pub struct QueryStateAtResponse {
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

/// A client-side proxy for communicating with the remote Workload container.
#[derive(Debug, Clone)]
pub struct WorkloadClient {
    channel: SecurityChannel,
    workload_addr: String,
    request_id: Arc<AtomicI64>,
    rpc_lock: Arc<AsyncMutex<()>>,
}

impl WorkloadClient {
    pub async fn new(
        workload_addr: &str,
        ca_cert_path: &str,
        client_cert_path: &str,
        client_key_path: &str,
    ) -> Result<Self> {
        let channel = SecurityChannel::new("orchestration", "workload");

        let mut attempts = 0;
        let max_attempts = 5;
        let retry_delay = Duration::from_secs(2);

        loop {
            match channel
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
                    log::info!(
                        "Successfully connected test client to Workload container at {}",
                        workload_addr
                    );
                    break;
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(anyhow!(
                            "Failed to connect to Workload container after {} attempts: {}",
                            max_attempts,
                            e
                        ));
                    }
                    log::warn!("Attempt {}/{} to connect to Workload container failed: {}. Retrying in {:?}...", attempts, max_attempts, e, retry_delay);
                    sleep(retry_delay).await;
                }
            }
        }

        Ok(Self {
            channel,
            workload_addr: workload_addr.to_string(),
            request_id: Arc::new(AtomicI64::new(0)),
            rpc_lock: Arc::new(AsyncMutex::new(())),
        })
    }

    pub fn destination_addr(&self) -> &str {
        &self.workload_addr
    }

    async fn send_rpc<P: serde::Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let _guard = self.rpc_lock.lock().await;
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: serde_json::to_value(params)?,
            id: Some(JsonRpcId::Num(id)),
        };

        let req_bytes = serde_json::to_vec(&request)?;
        self.channel.send(&req_bytes).await?;

        let response_bytes = self.channel.receive().await?;
        let response: JsonRpcResponse<R> = serde_json::from_slice(&response_bytes)?;

        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(anyhow!(
                "RPC Error (code {}): {}",
                error.code,
                error.message
            )),
            _ => Err(anyhow!("Invalid JSON-RPC response from server")),
        }
    }

    pub async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>)> {
        self.send_rpc("chain.processBlock.v1", block).await
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
    ) -> Result<QueryStateAtResponse> {
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
