// Path: crates/execution/src/runtime_service/mod.rs

use async_trait::async_trait;
use ioi_api::lifecycle::OnEndBlock;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::{StateAccess, VmStateAccessor};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::decorator::TxDecorator;
use ioi_api::vm::{ExecutionContext, VirtualMachine};
use ioi_types::{
    app::ChainTransaction,
    codec::{self, to_bytes_canonical},
    error::{StateError, TransactionError, UpgradeError, VmError},
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
///
/// # Design Rationale
/// The `VirtualMachine::execute` method takes `&dyn VmStateAccessor`, which has `&self`
/// methods for `get`, `insert`, and `delete`. This makes the trait object `Send + Sync` and
/// easy to share across async tasks. However, the underlying `StateAccess` trait uses `&mut self`
/// for write operations.
///
/// This bridge uses an internal `TokioMutex` to safely allow mutations from `&self` async methods,
/// providing the necessary interior mutability to bridge the two trait designs in a concurrent environment.
struct VmStateBridge<'a> {
    inner: TokioMutex<&'a mut dyn StateAccess>,
}

#[async_trait]
impl<'a> VmStateAccessor for VmStateBridge<'a> {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        // We only need a read lock here, but since the inner type is `&mut`, we must
        // acquire the mutex to access it at all.
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
}

/// A generic wrapper that makes a WASM artifact conform to the `BlockchainService` traits.
///
/// It holds the compiled WASM bytecode and uses a `VirtualMachine` implementation
/// (like `WasmRuntime`) to execute it. This acts as the bridge between the chain's
/// service model and a sandboxed execution environment.
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
        state: &mut dyn StateAccess, // This is the transactional, namespaced state
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        log::info!(
            "[WasmService {}] Calling method '{}' in WASM",
            self.id(),
            method
        );

        // 1. Create the execution context for the VM.
        let exec_context = ExecutionContext {
            caller: ctx.signer_account_id.as_ref().to_vec(),
            block_height: ctx.block_height,
            gas_limit: u64::MAX, // TODO: Plumb gas from TxContext/config
            contract_address: self.id.as_bytes().to_vec(),
        };

        // 2. Create the state accessor bridge. This correctly wires the transactional state.
        let bridge = VmStateBridge {
            inner: TokioMutex::new(state),
        };

        // 3. Call the VM with the artifact, state bridge, and context.
        let output = self
            .vm
            .execute(&self.artifact, method, params, &bridge, exec_context)
            .await
            .map_err(|e| TransactionError::Invalid(format!("WASM call failed: {}", e)))?;

        // Assume the WASM service returns a SCALE-encoded Result<(), String>
        // and translate the inner error string to a structured TransactionError.
        let resp: Result<(), String> = codec::from_bytes_canonical(&output.return_data)
            .map_err(TransactionError::Deserialization)?;

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
    async fn prepare_upgrade(&self, _artifact: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // The RuntimeService itself is stateless. State migration is handled
        // inside the WASM module, which would need a state accessor.
        // For now, this is a no-op at the host level.
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        // Similar to prepare_upgrade, the new instance will handle state
        // migration internally when it's first called.
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
