// Path: crates/validator/src/standard/workload_ipc_server/methods/state.rs

use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use ioi_types::app::{AccountId, ActiveKeyRecord, Membership, StateAnchor, StateRoot};
use ioi_types::codec; // Import the canonical codec
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use serde::{Deserialize, Serialize};
use std::{any::Any, marker::PhantomData, sync::Arc};

// --- state.getStateRoot.v1 ---

/// The parameters for the `state.getStateRoot.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetStateRootParams {}

/// The RPC method handler for `state.getStateRoot.v1`.
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

/// The parameters for the `state.prefixScan.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PrefixScanParams {
    /// The key prefix to scan for.
    pub prefix: Vec<u8>,
}

/// The RPC method handler for `state.prefixScan.v1`.
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
        let result_iter = state.prefix_scan(&params.prefix)?;
        let result_vec = result_iter
            .map(|res| res.map(|(k, v)| (k.to_vec(), v.to_vec())))
            .collect::<Result<_, _>>()?;
        Ok(result_vec)
    }
}

// --- state.getRawState.v1 ---

/// The parameters for the `state.getRawState.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetRawStateParams {
    /// The key to retrieve from the state.
    pub key: Vec<u8>,
}

/// The RPC method handler for `state.getRawState.v1`.
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
        // Use a write lock to allow for cache warming.
        let mut state = state_tree.write().await;

        // 1) Fast path: check current in-memory state.
        if let Some(bytes) = state.get(&params.key)? {
            return Ok(Some(bytes));
        }

        // 2) Fallback: if not in memory, attempt an anchored read at the last known root.
        // This handles queries immediately after a crash before the in-memory tree is fully re-hydrated.
        let last_root = {
            let chain = ctx.chain.lock().await;
            chain.state.last_state_root.clone()
        };

        if !last_root.is_empty() {
            if let Ok(anchor) = ioi_types::app::to_root_hash(&last_root) {
                // `get_with_proof_at_anchor` can be called on `&mut` because `StateManager` is `?Sized`.
                match state.get_with_proof_at_anchor(&anchor, &params.key) {
                    Ok((Membership::Present(bytes), _proof)) => {
                        // Optional: warm the live state so subsequent reads are hot.
                        log::trace!(
                            "getRawState: cache miss, served from anchored read for key 0x{}",
                            hex::encode(&params.key)
                        );
                        let _ = state.insert(&params.key, &bytes);
                        return Ok(Some(bytes));
                    }
                    // If the proof is Absent or an error occurs, we fall through to return None.
                    _ => {}
                }
            }
        }

        // 3) If not found in either live state or last committed state, it doesn't exist.
        Ok(None)
    }
}

// --- state.queryStateAt.v1 ---

/// The response structure for the `state.queryStateAt.v1` RPC method.
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryStateAtResponse {
    /// The version of the response message format.
    pub msg_version: u32,
    /// The numeric ID of the commitment scheme used.
    pub scheme_id: u16,
    /// The version of the commitment scheme.
    pub scheme_version: u16,
    /// The proven membership outcome (Present or Absent).
    pub membership: Membership,
    /// The raw bytes of the cryptographic proof.
    pub proof_bytes: Vec<u8>,
}

/// The parameters for the `state.queryStateAt.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QueryStateAtParams {
    /// The historical state root to query against.
    pub root: StateRoot,
    /// The key to query.
    pub key: Vec<u8>,
}

/// The RPC method handler for `state.queryStateAt.v1`.
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
                hex::encode(params.root.0.get(..8).unwrap_or_default())
            );
            // Use the canonical SCALE codec for serialization. Handle potential serialization errors.
            let proof_bytes = codec::to_bytes_canonical(proof)
                .map_err(|e| anyhow!("Failed to serialize cached proof: {}", e))?;

            return Ok(QueryStateAtResponse {
                msg_version: 1,
                scheme_id: 1, // Placeholder
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
            hex::encode(params.key.get(..8).unwrap_or_default()),
            hex::encode(params.root.0.get(..8).unwrap_or_default()),
            start_time.elapsed()
        );

        // Use the canonical SCALE codec for serialization
        let proof_bytes = codec::to_bytes_canonical(&proof)
            .map_err(|e| anyhow!("Failed to serialize generated proof: {}", e))?;

        let mut cache = ctx.workload.proof_cache.lock().await;
        cache.put(cache_key, (membership.clone(), proof)); // Cache the original proof object

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

/// The parameters for the `state.getActiveKeyAt.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetActiveKeyAtParams {
    /// The state anchor at which to retrieve the active key.
    pub anchor: StateAnchor,
    /// The account ID for which to retrieve the active key.
    pub account_id: AccountId,
}

/// The RPC method handler for `state.getActiveKeyAt.v1`.
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
            .map_err(|_| anyhow!("Invalid context type"))?;

        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;

        let key = [b"identity::key_record::", params.account_id.as_ref()].concat();

        // Use the new anchor-based query method, which correctly handles all tree types.
        let (membership, _proof) = state.get_with_proof_at_anchor(&params.anchor.0, &key)?;

        let record = match membership {
            Membership::Present(bytes) => {
                codec::from_bytes_canonical::<ioi_types::app::ActiveKeyRecord>(&bytes).ok()
            }
            _ => None,
        };

        Ok(record)
    }
}
