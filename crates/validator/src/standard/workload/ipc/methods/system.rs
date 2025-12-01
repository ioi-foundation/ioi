// crates/validator/src/standard/workload/ipc/methods/system.rs

use super::RpcContext;
// [FIX] Corrected import path
use crate::standard::workload::ipc::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use ioi_api::{chain::ChainStateMachine, commitment::CommitmentScheme, state::StateManager};
use ioi_types::app::{
    DebugPinHeightParams, DebugTriggerGcParams, DebugTriggerGcResponse, DebugUnpinHeightParams,
};
use ioi_types::config::WorkloadConfig;
use serde::{Deserialize, Serialize};
use std::{any::Any, fmt::Debug, marker::PhantomData, sync::Arc};

// --- system.getStatus.v1 ---

/// Parameters for the `system.getStatus.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetStatusParams {}

/// Handler for the `system.getStatus.v1` RPC method.
pub struct GetStatusV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetStatusV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetStatusV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    const NAME: &'static str = "system.getStatus.v1";
    type Params = GetStatusParams;
    type Result = ioi_types::app::ChainStatus;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetStatusV1"))?;
        let machine = ctx.machine.lock().await;
        let status_ref = (*machine).status();
        Ok(ioi_types::app::ChainStatus {
            height: status_ref.height,
            latest_timestamp: status_ref.latest_timestamp,
            total_transactions: status_ref.total_transactions,
            is_running: status_ref.is_running,
        })
    }
}

// --- system.getExpectedModelHash.v1 ---

/// Parameters for the `system.getExpectedModelHash.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetExpectedModelHashParams {}

/// Handler for the `system.getExpectedModelHash.v1` RPC method.
pub struct GetExpectedModelHashV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetExpectedModelHashV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetExpectedModelHashV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.getExpectedModelHash.v1";
    type Params = GetExpectedModelHashParams;
    type Result = Vec<u8>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetExpectedModelHashV1"))?;
        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;
        let json_bytes = state.get(ioi_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH)?;
        let hex_str: String =
            serde_json::from_slice(&json_bytes.ok_or_else(|| anyhow!("Model hash not set"))?)?;
        Ok(hex::decode(hex_str)?)
    }
}

// --- system.checkAndTallyProposals.v1 ---

/// Parameters for the `system.checkAndTallyProposals.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CheckAndTallyProposalsParams {
    /// The current block height.
    pub current_height: u64,
}

/// Handler for the `system.checkAndTallyProposals.v1` RPC method.
pub struct CheckAndTallyProposalsV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for CheckAndTallyProposalsV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for CheckAndTallyProposalsV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.checkAndTallyProposals.v1";
    type Params = CheckAndTallyProposalsParams;
    type Result = Vec<String>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        _shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        Ok(vec![])
    }
}

// --- system.callService.v1 ---

/// Parameters for the `system.callService.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CallServiceParams {
    /// The ID of the service to call.
    pub service_id: String,
    /// The method name to call.
    pub method_id: String,
    /// The parameters for the method call.
    pub params: serde_json::Value,
}

/// Handler for the `system.callService.v1` RPC method.
pub struct CallServiceV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for CallServiceV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for CallServiceV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.callService.v1";
    type Params = CallServiceParams;
    type Result = serde_json::Value;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        _shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        Ok(serde_json::json!({"status": "not_implemented"}))
    }
}

// --- system.getWorkloadConfig.v1 ---

/// Parameters for the `system.getWorkloadConfig.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetWorkloadConfigParams {}

/// Handler for the `system.getWorkloadConfig.v1` RPC method.
pub struct GetWorkloadConfigV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetWorkloadConfigV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetWorkloadConfigV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.getWorkloadConfig.v1";
    type Params = GetWorkloadConfigParams;
    type Result = WorkloadConfig;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetWorkloadConfigV1"))?;
        Ok(ctx.workload.config().clone())
    }
}

// --- system.getGenesisStatus.v1 ---

/// Response structure for the `system.getGenesisStatus.v1` RPC method.
#[derive(Serialize, Deserialize, Debug)]
pub struct GenesisStatus {
    /// Whether the genesis block is ready.
    pub ready: bool,
    /// The genesis root hash.
    pub root: Vec<u8>,
    /// The chain ID.
    pub chain_id: String,
}

/// Parameters for the `system.getGenesisStatus.v1` RPC method.
#[derive(Deserialize, Debug)]
pub struct GetGenesisStatusParams {}

/// Handler for the `system.getGenesisStatus.v1` RPC method.
pub struct GetGenesisStatusV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetGenesisStatusV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetGenesisStatusV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.getGenesisStatus.v1";
    type Params = GetGenesisStatusParams;
    type Result = GenesisStatus;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx: Arc<RpcContext<CS, ST>> = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetGenesisStatusV1"))?;
        let machine = ctx.machine.lock().await;

        match &machine.state.genesis_state {
            ioi_execution::app::GenesisState::Ready { root, chain_id } => Ok(GenesisStatus {
                ready: true,
                root: root.clone(),
                chain_id: chain_id.to_string(),
            }),
            ioi_execution::app::GenesisState::Pending => Ok(GenesisStatus {
                ready: false,
                root: vec![],
                chain_id: "".to_string(),
            }),
        }
    }
}

// --- system.debugPinHeight.v1 ---

/// Handler for the `system.debugPinHeight.v1` RPC method.
pub struct DebugPinHeightV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for DebugPinHeightV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for DebugPinHeightV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.debugPinHeight.v1";
    type Params = DebugPinHeightParams;
    type Result = ();

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context"))?;
        ctx.workload.pins().pin(params.height);
        log::info!("[Debug] Pinned height {}", params.height);
        Ok(())
    }
}

// --- system.debugUnpinHeight.v1 ---

/// Handler for the `system.debugUnpinHeight.v1` RPC method.
pub struct DebugUnpinHeightV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for DebugUnpinHeightV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for DebugUnpinHeightV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "system.debugUnpinHeight.v1";
    type Params = DebugUnpinHeightParams;
    type Result = ();

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context"))?;
        ctx.workload.pins().unpin(params.height);
        log::info!("[Debug] Unpinned height {}", params.height);
        Ok(())
    }
}

// --- system.debugTriggerGc.v1 ---

/// Handler for the `system.debugTriggerGc.v1` RPC method.
pub struct DebugTriggerGcV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for DebugTriggerGcV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for DebugTriggerGcV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    const NAME: &'static str = "system.debugTriggerGc.v1";
    type Params = DebugTriggerGcParams;
    type Result = DebugTriggerGcResponse;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context"))?;

        let current_height = {
            let guard = ctx.machine.lock().await;
            guard.status().height
        };

        log::info!(
            "[Debug] Triggering GC pass manually at height {}",
            current_height
        );
        let stats = ctx
            .workload
            .run_gc_pass(current_height)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        Ok(DebugTriggerGcResponse {
            heights_pruned: stats.heights_pruned,
            nodes_deleted: stats.nodes_deleted,
        })
    }
}
