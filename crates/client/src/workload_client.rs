// Path: crates/client/src/workload_client.rs
use crate::ipc::{WorkloadRequest, WorkloadResponse};
use crate::security::SecurityChannel;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput};
use depin_sdk_types::app::{AccountId, Block, ChainStatus, ChainTransaction};
use depin_sdk_types::keys::ACCOUNT_ID_TO_PUBKEY_PREFIX;
use libp2p::identity::PublicKey;
use std::collections::{BTreeMap, HashMap};

/// A client-side proxy for communicating with the remote Workload container.
#[derive(Debug, Clone)]
pub struct WorkloadClient {
    channel: SecurityChannel,
    workload_addr: String, // Store the connection address
}

impl WorkloadClient {
    pub async fn new(workload_addr: &str) -> Result<Self> {
        let channel = SecurityChannel::new("orchestration", "workload");
        channel
            .establish_client(workload_addr, "workload")
            .await
            .expect("Failed to connect to Workload container");

        Ok(Self {
            channel,
            workload_addr: workload_addr.to_string(),
        })
    }

    /// Returns the network address of the Workload container this client connects to.
    pub fn destination_addr(&self) -> &str {
        &self.workload_addr
    }

    async fn send_and_receive(&self, request: WorkloadRequest) -> Result<WorkloadResponse> {
        let request_bytes = serde_json::to_vec(&request)?;
        self.channel.send(&request_bytes).await?;
        let response_bytes = self.channel.receive().await?;
        let response = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    pub async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>)> {
        let request = WorkloadRequest::ProcessBlock(block);
        match self.send_and_receive(request).await? {
            WorkloadResponse::ProcessBlock(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for ProcessBlock"
            )),
        }
    }

    pub async fn get_status(&self) -> Result<ChainStatus> {
        let request = WorkloadRequest::GetStatus;
        match self.send_and_receive(request).await? {
            WorkloadResponse::GetStatus(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!("Invalid response type from workload for GetStatus")),
        }
    }

    pub async fn get_last_block_hash(&self) -> Result<Vec<u8>> {
        let request = WorkloadRequest::GetLastBlockHash;
        match self.send_and_receive(request).await? {
            WorkloadResponse::GetLastBlockHash(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for GetLastBlockHash"
            )),
        }
    }

    pub async fn execute_transaction(&self, tx: ChainTransaction) -> Result<()> {
        let request = WorkloadRequest::ExecuteTransaction(Box::new(tx));
        match self.send_and_receive(request).await? {
            WorkloadResponse::ExecuteTransaction(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!("Invalid response type from workload")),
        }
    }

    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<(Vec<u8>, HashMap<Vec<u8>, Vec<u8>>)> {
        let request = WorkloadRequest::DeployContract { code, sender };
        match self.send_and_receive(request).await? {
            WorkloadResponse::DeployContract(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!("Invalid response type from workload")),
        }
    }

    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<(ExecutionOutput, HashMap<Vec<u8>, Vec<u8>>)> {
        let request = WorkloadRequest::CallContract {
            address,
            input_data,
            context,
        };
        match self.send_and_receive(request).await? {
            WorkloadResponse::CallContract(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!("Invalid response type from workload")),
        }
    }

    pub async fn query_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<ExecutionOutput> {
        let request = WorkloadRequest::QueryContract {
            address,
            input_data,
            context,
        };
        match self.send_and_receive(request).await? {
            WorkloadResponse::QueryContract(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for QueryContract"
            )),
        }
    }

    pub async fn get_validator_set(&self) -> Result<Vec<Vec<u8>>> {
        let request = WorkloadRequest::GetValidatorSet;
        match self.send_and_receive(request).await? {
            WorkloadResponse::GetValidatorSet(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for GetValidatorSet"
            )),
        }
    }

    pub async fn get_staked_validators(&self) -> Result<BTreeMap<String, u64>> {
        let request = WorkloadRequest::GetStakedValidators;
        match self.send_and_receive(request).await? {
            WorkloadResponse::GetStakedValidators(res) => res.map_err(|e| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for GetStakedValidators"
            )),
        }
    }

    pub async fn get_state_root(&self) -> Result<Vec<u8>> {
        let request = WorkloadRequest::GetStateRoot;
        match self.send_and_receive(request).await? {
            WorkloadResponse::GetStateRoot(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for GetStateRoot"
            )),
        }
    }

    pub async fn get_expected_model_hash(&self) -> Result<Vec<u8>> {
        let request = WorkloadRequest::GetExpectedModelHash;
        match self.send_and_receive(request).await? {
            WorkloadResponse::GetExpectedModelHash(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for GetExpectedModelHash"
            )),
        }
    }

    pub async fn check_and_tally_proposals(&self, current_height: u64) -> Result<Vec<String>> {
        let request = WorkloadRequest::CheckAndTallyProposals { current_height };
        match self.send_and_receive(request).await? {
            WorkloadResponse::CheckAndTallyProposals(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for CheckAndTallyProposals"
            )),
        }
    }

    pub async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let request = WorkloadRequest::PrefixScan(prefix.to_vec());
        match self.send_and_receive(request).await? {
            WorkloadResponse::PrefixScan(res) => res.map_err(|e: String| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for PrefixScan"
            )),
        }
    }
    
    // --- FIX START ---
    pub async fn query_raw_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let request = WorkloadRequest::QueryRawState(key.to_vec());
        match self.send_and_receive(request).await? {
            WorkloadResponse::QueryRawState(res) => res.map_err(|e| anyhow!(e)),
            _ => Err(anyhow!(
                "Invalid response type from workload for QueryRawState"
            )),
        }
    }
    // --- FIX END ---
}

// --- FIX START: Add the #[async_trait] macro ---
#[async_trait]
// --- FIX END ---
impl ChainStateReader for WorkloadClient {
    async fn get_authority_set(&self) -> Result<Vec<Vec<u8>>, String> {
        let request = WorkloadRequest::GetAuthoritySet;
        match self.send_and_receive(request).await {
            Ok(WorkloadResponse::GetAuthoritySet(res)) => res,
            Ok(_) => Err("Invalid response type from workload for GetAuthoritySet".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn get_next_staked_validators(&self) -> Result<BTreeMap<String, u64>, String> {
        let request = WorkloadRequest::GetNextStakes;
        match self.send_and_receive(request).await {
            Ok(WorkloadResponse::GetNextStakes(res)) => res,
            Ok(_) => Err("Invalid response type from workload for GetNextStakes".to_string()),
            Err(e) => Err(e.to_string()),
        }
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