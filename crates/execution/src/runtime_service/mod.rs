// Path: crates/execution/src/runtime_service/mod.rs

use async_trait::async_trait;
use ioi_api::lifecycle::OnEndBlock;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::state::VmStateAccessor;
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::decorator::TxDecorator;
use ioi_api::vm::{ExecutionContext, VirtualMachine};
use ioi_types::{
    app::ChainTransaction,
    codec::{self, to_bytes_canonical},
    error::{StateError, TransactionError, UpgradeError},
    service_configs::Capabilities,
};
use parity_scale_codec::{Decode, Encode};
use std::{any::Any, fmt, sync::Arc};
use tokio::sync::Mutex as TokioMutex;

#[derive(Encode, Decode)]
struct AnteHandleRequest {
    tx: ChainTransaction,
}

/// A bridge that adapts a synchronous, mutable `StateAccess` trait object into
/// an asynchronous `VmStateAccessor` suitable for the `VirtualMachine`.
struct VmStateBridge<'a> {
    inner: TokioMutex<&'a mut dyn StateAccess>,
}

#[async_trait]
impl<'a> VmStateAccessor for VmStateBridge<'a> {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        let guard = self.inner.lock().await;
        guard.get(key)
    }

    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let mut guard = self.inner.lock().await;
        guard.insert(key, value)
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StateError> {
        let mut guard = self.inner.lock().await;
        guard.delete(key)
    }

    async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        let guard = self.inner.lock().await;
        let iter = guard.prefix_scan(prefix)?;
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }
}

/// A read-only bridge that adapts an immutable `StateAccess` reference for the VM.
struct ReadOnlyVmStateBridge<'a> {
    inner: &'a dyn StateAccess,
}

#[async_trait]
impl<'a> VmStateAccessor for ReadOnlyVmStateBridge<'a> {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        self.inner.get(key)
    }

    async fn insert(&self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Err(StateError::PermissionDenied(
            "Write operation attempted in read-only VM context".into(),
        ))
    }

    // FIX: Corrected signature to match VmStateAccessor trait (removed _value parameter)
    async fn delete(&self, _key: &[u8]) -> Result<(), StateError> {
        Err(StateError::PermissionDenied(
            "Delete operation attempted in read-only VM context".into(),
        ))
    }

    async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        let iter = self.inner.prefix_scan(prefix)?;
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }
}

/// A generic wrapper that makes a WASM artifact conform to the `BlockchainService` traits.
pub struct RuntimeService {
    id: String,
    abi_version: u32,
    state_schema: String,
    vm: Arc<dyn VirtualMachine>,
    artifact: Vec<u8>,
    caps: Capabilities,
}

impl fmt::Debug for RuntimeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeService")
            .field("id", &self.id)
            .field("abi_version", &self.abi_version)
            .field("state_schema", &self.state_schema)
            .field("artifact_len", &self.artifact.len())
            .field("capabilities", &self.caps)
            .finish_non_exhaustive()
    }
}

impl RuntimeService {
    pub fn new(
        id: String,
        abi_version: u32,
        state_schema: String,
        vm: Arc<dyn VirtualMachine>,
        artifact: Vec<u8>,
        caps: Capabilities,
    ) -> Self {
        Self {
            id,
            abi_version,
            state_schema,
            vm,
            artifact,
            caps,
        }
    }

    async fn execute_call(
        &self,
        accessor: &dyn VmStateAccessor,
        method: &str,
        params: &[u8],
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // [OPTIMIZATION] Downgraded to debug
        log::debug!(
            "[WasmService {}] Calling method '{}' in WASM",
            self.id(),
            method
        );

        let exec_context = ExecutionContext {
            caller: ctx.signer_account_id.as_ref().to_vec(),
            block_height: ctx.block_height,
            gas_limit: u64::MAX,
            contract_address: self.id.as_bytes().to_vec(),
        };

        let output = self
            .vm
            .execute(&self.artifact, method, params, accessor, exec_context)
            .await
            .map_err(|e| TransactionError::Invalid(format!("WASM call failed: {}", e)))?;

        let resp: Result<(), String> = codec::from_bytes_canonical(&output.return_data)
            .map_err(TransactionError::Deserialization)?;

        resp.map_err(|e_str| {
            if e_str.contains("Unauthorized") {
                TransactionError::UnauthorizedByCredentials
            } else if e_str.contains("OutOfGas") {
                TransactionError::ContractRevert("OutOfGas".into())
            } else {
                TransactionError::ContractRevert(e_str)
            }
        })
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
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        let bridge = VmStateBridge {
            inner: TokioMutex::new(state),
        };
        self.execute_call(&bridge, method, params, ctx).await
    }
}

#[async_trait]
impl UpgradableService for RuntimeService {
    async fn prepare_upgrade(&self, _artifact: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
impl TxDecorator for RuntimeService {
    async fn validate_ante(
        &self,
        state: &dyn StateAccess,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let method = "ante_validate@v1";
        let req = AnteHandleRequest { tx: tx.clone() };
        let params_bytes = to_bytes_canonical(&req).map_err(TransactionError::Serialization)?;

        let bridge = ReadOnlyVmStateBridge { inner: state };

        self.execute_call(&bridge, method, &params_bytes, ctx).await
    }

    async fn write_ante(
        &self,
        state: &mut dyn StateAccess,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let method = "ante_write@v1";
        let req = AnteHandleRequest { tx: tx.clone() };
        let params_bytes = to_bytes_canonical(&req).map_err(TransactionError::Serialization)?;

        let bridge = VmStateBridge {
            inner: TokioMutex::new(state),
        };

        self.execute_call(&bridge, method, &params_bytes, ctx).await
    }
}

#[async_trait]
impl OnEndBlock for RuntimeService {
    async fn on_end_block(
        &self,
        state: &mut dyn StateAccess,
        ctx: &TxContext,
    ) -> Result<(), StateError> {
        let method = "on_end_block@v1";
        let params_bytes = [];

        let mut mutable_ctx = ctx.clone();

        self.handle_service_call(state, method, &params_bytes, &mut mutable_ctx)
            .await
            .map_err(|e| StateError::Apply(e.to_string()))
    }
}
