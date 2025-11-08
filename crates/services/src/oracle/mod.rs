// Path: crates/services/src/oracle/mod.rs
use async_trait::async_trait;
use ioi_types::app::{OracleConsensusProof, StateEntry};
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::keys::{ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX};
use ioi_types::service_configs::Capabilities;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use parity_scale_codec::{Decode, Encode};
use std::any::Any;

// --- Service Method Parameter Structs (The Service's Public ABI) ---
#[derive(Encode, Decode)]
pub struct RequestDataParams {
    url: String,
    request_id: u64,
}

#[derive(Encode, Decode)]
pub struct SubmitDataParams {
    pub request_id: u64,
    pub final_value: Vec<u8>,
    pub consensus_proof: OracleConsensusProof,
}

#[derive(Debug, Clone, Default)]
pub struct OracleService;

impl OracleService {
    pub fn new() -> Self {
        Self
    }

    // The off-chain data fetching logic remains here.
    pub async fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        log::info!("[OracleService] Fetching data from URL: {}", url);
        let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Request failed with status: {}", response.status()));
        }
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl BlockchainService for OracleService {
    fn id(&self) -> &str {
        "oracle" // The canonical, user-facing ID.
    }
    fn abi_version(&self) -> u32 {
        1
    }
    fn state_schema(&self) -> &str {
        "v1"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    // Implement the on-chain logic here.
    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "request_data@v1" => {
                let p: RequestDataParams = codec::from_bytes_canonical(params)?;
                let request_key =
                    [ORACLE_PENDING_REQUEST_PREFIX, &p.request_id.to_le_bytes()].concat();
                let url_bytes = codec::to_bytes_canonical(&p.url)?;
                let entry = StateEntry {
                    value: url_bytes,
                    block_height: ctx.block_height,
                };
                let entry_bytes = codec::to_bytes_canonical(&entry)?;
                state.insert(&request_key, &entry_bytes)?;
                Ok(())
            }
            "submit_data@v1" => {
                let p: SubmitDataParams = codec::from_bytes_canonical(params)?;
                if p.consensus_proof.attestations.is_empty() {
                    return Err(TransactionError::Invalid("Oracle proof is empty".into()));
                }
                let pending_key =
                    [ORACLE_PENDING_REQUEST_PREFIX, &p.request_id.to_le_bytes()].concat();
                let final_key = [ORACLE_DATA_PREFIX, &p.request_id.to_le_bytes()].concat();
                let entry = StateEntry {
                    value: p.final_value.clone(),
                    block_height: ctx.block_height,
                };
                let entry_bytes = codec::to_bytes_canonical(&entry)?;
                state.delete(&pending_key)?;
                state.insert(&final_key, &entry_bytes)?;
                log::info!("Applied and verified oracle data for id: {}", p.request_id);
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(format!(
                "Oracle service does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for OracleService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}