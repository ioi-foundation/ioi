// Path: crates/validator/src/standard/workload_ipc_server/methods/state.rs

use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::chain::ChainView;
use depin_sdk_api::{commitment::CommitmentScheme, state::StateManager};
use depin_sdk_types::app::{AccountId, ActiveKeyRecord, Membership, StateAnchor, StateRoot};
use depin_sdk_types::codec; // Import the canonical codec
use serde::{Deserialize, Serialize};
use std::{any::Any, marker::PhantomData, sync::Arc};

// --- state.getStateRoot.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetStateRootParams {}

pub struct GetStateRootV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetStateRootV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetStateRootV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "state.getStateRoot.v1";
    type Params = GetStateRootParams;
    type Result = Vec<u8>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetStateRootV1"))?;

        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;
        let root = state.root_commitment().as_ref().to_vec();
        Ok(root)
    }
}

// --- state.prefixScan.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PrefixScanParams {
    pub prefix: Vec<u8>,
}

pub struct PrefixScanV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for PrefixScanV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for PrefixScanV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "state.prefixScan.v1";
    type Params = PrefixScanParams;
    type Result = Vec<(Vec<u8>, Vec<u8>)>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for PrefixScanV1"))?;
        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;
        let result = state.prefix_scan(&params.prefix)?;
        Ok(result)
    }
}

// --- state.getRawState.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetRawStateParams {
    pub key: Vec<u8>,
}

pub struct GetRawStateV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetRawStateV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetRawStateV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "state.getRawState.v1";
    type Params = GetRawStateParams;
    type Result = Option<Vec<u8>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetRawStateV1"))?;
        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;
        let result = state.get(&params.key)?;
        Ok(result)
    }
}

// --- state.queryStateAt.v1 ---

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryStateAtResponse {
    pub msg_version: u32,
    pub scheme_id: u16,
    pub scheme_version: u16,
    pub membership: Membership,
    pub proof_bytes: Vec<u8>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QueryStateAtParams {
    pub root: StateRoot,
    pub key: Vec<u8>,
}

pub struct QueryStateAtV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for QueryStateAtV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for QueryStateAtV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> serde::Deserialize<'de>,
{
    const NAME: &'static str = "state.queryStateAt.v1";
    type Params = QueryStateAtParams;
    type Result = QueryStateAtResponse;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for QueryStateAtV1"))?;
        let start_time = std::time::Instant::now();
        let cache_key = (params.root.0.clone(), params.key.clone());
        let mut cache = ctx.workload.proof_cache.lock().await;

        if let Some((membership, proof)) = cache.get(&cache_key) {
            log::trace!(
                "[WorkloadIPC] Proof cache hit for root {}",
                hex::encode(&params.root.0)
            );
            // FIX: Use the canonical SCALE codec for serialization
            let proof_bytes = codec::to_bytes_canonical(proof);

            return Ok(QueryStateAtResponse {
                msg_version: 1,
                scheme_id: 1,
                scheme_version: 1,
                membership: membership.clone(),
                proof_bytes,
            });
        }
        drop(cache);

        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;

        let root_commitment = state.commitment_from_bytes(&params.root.0)?;
        let (membership, proof) = state.get_with_proof_at(&root_commitment, &params.key)?;

        log::trace!(
            "[WorkloadIPC] Proof cache miss. Generated proof for key {} at root {} in {:?}",
            hex::encode(&params.key),
            hex::encode(&params.root.0),
            start_time.elapsed()
        );

        // FIX: Use the canonical SCALE codec for serialization
        let proof_bytes = codec::to_bytes_canonical(&proof);

        let mut cache = ctx.workload.proof_cache.lock().await;
        cache.put(cache_key, (membership.clone(), proof));

        Ok(QueryStateAtResponse {
            msg_version: 1,
            scheme_id: 1,
            scheme_version: 1,
            membership,
            proof_bytes,
        })
    }
}

// --- state.getActiveKeyAt.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetActiveKeyAtParams {
    pub anchor: StateAnchor,
    pub account_id: AccountId,
}

pub struct GetActiveKeyAtV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetActiveKeyAtV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetActiveKeyAtV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
{
    const NAME: &'static str = "state.getActiveKeyAt.v1";
    type Params = GetActiveKeyAtParams;
    type Result = Option<ActiveKeyRecord>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetActiveKeyAtV1"))?;
        let chain = ctx.chain.lock().await;
        let view = chain.view_at(&params.anchor).await?;
        let record = view.active_consensus_key(&params.account_id).await;
        Ok(record)
    }
}
