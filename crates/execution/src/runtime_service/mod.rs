// Path: crates/execution/src/runtime_service/mod.rs

use async_trait::async_trait;
use ioi_api::{
    lifecycle::OnEndBlock,
    runtime::Runnable,
    services::{BlockchainService, UpgradableService},
    state::StateAccess,
    transaction::{context::TxContext, decorator::TxDecorator},
};
use ioi_types::{
    app::ChainTransaction,
    codec::{self, to_bytes_canonical},
    error::{StateError, TransactionError, UpgradeError, VmError},
    service_configs::Capabilities,
};
use parity_scale_codec::{Decode, Encode};
use std::{any::Any, fmt};
use tokio::sync::Mutex;

#[derive(Encode, Decode)]
struct AnteHandleRequest {
    tx: ChainTransaction,
}

/// A generic wrapper that makes any `Runnable` artifact conform to the `BlockchainService` traits.
/// This struct is `Sync` because it synchronizes access to the `!Sync` `Runnable` via a `Mutex`.
pub struct RuntimeService {
    id: String,
    abi_version: u32,
    state_schema: String,
    runnable: Mutex<Box<dyn Runnable>>,
    caps: Capabilities,
}

impl fmt::Debug for RuntimeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeService")
            .field("id", &self.id)
            .field("abi_version", &self.abi_version)
            .field("state_schema", &self.state_schema)
            .field("capabilities", &self.caps)
            .finish_non_exhaustive()
    }
}

impl RuntimeService {
    pub fn new(
        id: String,
        abi_version: u32,
        state_schema: String,
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

#[async_trait]
impl BlockchainService for RuntimeService {
    fn id(&self) -> &str {
        &self.id
    }
    fn abi_version(&self) -> u32 {
        self.abi_version
    }
    fn state_schema(&self) -> &str {
        &self.state_schema
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

    async fn handle_service_call(
        &self,
        _state: &mut dyn StateAccess, // State is managed inside the guest via host calls
        method: &str,
        params: &[u8],
        _ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        log::info!(
            "[WasmService {}] Calling method '{}' in WASM",
            self.id(),
            method
        );

        let mut runnable = self.runnable.lock().await;

        // The `method` string is the entrypoint name, `params` is the request payload.
        let resp_bytes = runnable
            .call(method, params)
            .await
            .map_err(|e| TransactionError::Invalid(format!("WASM call failed: {}", e)))?;

        // Assume the WASM service returns a SCALE-encoded Result<(), String>
        // and translate the inner error string to a structured TransactionError.
        let resp: Result<(), String> =
            codec::from_bytes_canonical(&resp_bytes).map_err(TransactionError::Deserialization)?;

        resp.map_err(|e_str| {
            // Simple mapping for now. Can be made more sophisticated based on error content.
            if e_str.contains("Unauthorized") {
                TransactionError::UnauthorizedByCredentials
            } else if e_str.contains("OutOfGas") {
                // [+] FIX: Wrap the VmError in the generic Invalid variant.
                TransactionError::Invalid(VmError::ExecutionTrap("OutOfGas".into()).to_string())
            } else {
                TransactionError::Invalid(e_str)
            }
        })
    }
}

#[async_trait]
impl UpgradableService for RuntimeService {
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
impl TxDecorator for RuntimeService {
    async fn ante_handle(
        &self,
        state: &mut dyn StateAccess,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        // The ante_handle hook is now a specific, versioned service call.
        let method = "ante_handle@v1";
        let req = AnteHandleRequest { tx: tx.clone() };
        let params_bytes = to_bytes_canonical(&req).map_err(TransactionError::Serialization)?;

        // Create a mutable context to pass down, even if we don't modify it here.
        let mut mutable_ctx = ctx.clone();

        // Dispatch to the generic handler.
        self.handle_service_call(state, method, &params_bytes, &mut mutable_ctx)
            .await
    }
}

#[async_trait]
impl OnEndBlock for RuntimeService {
    async fn on_end_block(
        &self,
        state: &mut dyn StateAccess,
        ctx: &TxContext,
    ) -> Result<(), StateError> {
        // The on_end_block hook is also a versioned service call.
        let method = "on_end_block@v1";
        // This hook is simple and doesn't require complex parameters, just the context.
        // We can pass an empty byte slice for params.
        let params_bytes = [];

        let mut mutable_ctx = ctx.clone();

        // Dispatch and map the error type from TransactionError to StateError.
        self.handle_service_call(state, method, &params_bytes, &mut mutable_ctx)
            .await
            .map_err(|e| StateError::Apply(e.to_string()))
    }
}