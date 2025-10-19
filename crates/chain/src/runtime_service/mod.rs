// Path: crates/chain/src/runtime_service/mod.rs

use async_trait::async_trait;
use depin_sdk_api::{
    lifecycle::OnEndBlock,
    runtime::Runnable,
    services::{BlockchainService, UpgradableService},
    state::StateAccessor,
    transaction::{context::TxContext, decorator::TxDecorator},
};
use depin_sdk_types::{
    app::ChainTransaction,
    codec::{from_bytes_canonical, to_bytes_canonical},
    error::{StateError, TransactionError, UpgradeError},
    service_configs::Capabilities,
};
use parity_scale_codec::{Decode, Encode};
use std::{any::Any, fmt};
use tokio::sync::Mutex;

#[derive(Encode, Decode)]
struct AnteHandleRequest {
    tx: ChainTransaction,
}

#[derive(Encode, Decode)]
struct AnteHandleResponse {
    result: Result<(), String>,
}

/// A generic wrapper that makes any `Runnable` artifact conform to the `BlockchainService` traits.
/// This struct is `Sync` because it synchronizes access to the `!Sync` `Runnable` via a `Mutex`.
pub struct RuntimeBackedService {
    id: &'static str,
    abi_version: u32,
    state_schema: &'static str,
    runnable: Mutex<Box<dyn Runnable>>,
    caps: Capabilities,
}

impl fmt::Debug for RuntimeBackedService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeBackedService")
            .field("id", &self.id)
            .field("abi_version", &self.abi_version)
            .field("state_schema", &self.state_schema)
            .field("capabilities", &self.caps)
            .finish_non_exhaustive()
    }
}

impl RuntimeBackedService {
    pub fn new(
        id: &'static str,
        abi_version: u32,
        state_schema: &'static str,
        runnable: Box<dyn Runnable>,
        caps: Capabilities,
    ) -> Self {
        Self {
            id,
            abi_version,
            state_schema,
            runnable: Mutex::new(runnable),
            caps,
        }
    }
}

impl BlockchainService for RuntimeBackedService {
    fn id(&self) -> &'static str {
        self.id
    }
    fn abi_version(&self) -> u32 {
        self.abi_version
    }
    fn state_schema(&self) -> &'static str {
        self.state_schema
    }
    fn capabilities(&self) -> Capabilities {
        self.caps
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_tx_decorator(&self) -> Option<&dyn TxDecorator> {
        (self.caps.contains(Capabilities::TX_DECORATOR)).then_some(self)
    }
    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        (self.caps.contains(Capabilities::ON_END_BLOCK)).then_some(self)
    }
}

#[async_trait]
impl UpgradableService for RuntimeBackedService {
    async fn prepare_upgrade(&mut self, artifact: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        let mut runnable = self.runnable.lock().await;
        runnable
            .call("prepare_upgrade", artifact)
            .await
            .map_err(|e| UpgradeError::InvalidUpgrade(e.to_string()))
    }

    async fn complete_upgrade(&mut self, snapshot: &[u8]) -> Result<(), UpgradeError> {
        let mut runnable = self.runnable.lock().await;
        runnable
            .call("complete_upgrade", snapshot)
            .await
            .map_err(|e| UpgradeError::MigrationFailed(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl TxDecorator for RuntimeBackedService {
    async fn ante_handle(
        &self,
        _state: &mut dyn StateAccessor,
        tx: &ChainTransaction,
        _ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        log::info!("[WasmService {}] Calling ante_handle in WASM", self.id());

        // Serialize the full transaction context for the service.
        let req = AnteHandleRequest { tx: tx.clone() };
        let req_bytes = to_bytes_canonical(&req).map_err(TransactionError::Serialization)?;

        let mut runnable = self.runnable.lock().await;
        let resp_bytes = runnable
            .call("ante_handle", &req_bytes)
            .await
            .map_err(|e| TransactionError::Invalid(format!("WASM ante_handle failed: {}", e)))?;

        let resp: AnteHandleResponse =
            from_bytes_canonical(&resp_bytes).map_err(TransactionError::Deserialization)?;
        resp.result.map_err(TransactionError::Invalid)
    }
}

#[async_trait]
impl OnEndBlock for RuntimeBackedService {
    async fn on_end_block(
        &self,
        _state: &mut dyn StateAccessor,
        _ctx: &TxContext,
    ) -> Result<(), StateError> {
        // Similar logic for OnEndBlock would go here.
        Ok(())
    }
}
