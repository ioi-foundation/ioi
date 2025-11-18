// Path: crates/validator/src/standard/workload_ipc_server/methods/chain.rs
use super::RpcContext;
use crate::ante::check_tx;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use ioi_api::{
    chain::ChainStateMachine,
    commitment::CommitmentScheme,
    state::StateOverlay, // FIX: Import StateOverlay
    transaction::TransactionModel,
};
use ioi_types::app::{ApplicationTransaction, Block, ChainTransaction, Membership, StateAnchor};
use serde::{Deserialize, Serialize};
use std::{any::Any, fmt::Debug, marker::PhantomData, sync::Arc};

// --- chain.getBlocksRange.v1 ---

/// The parameters for the `chain.getBlocksRange.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetBlocksRangeParams {
    /// The block height after which to start fetching blocks.
    pub since: u64,
    /// The maximum number of blocks to return in the response.
    pub max_blocks: u32,
    /// The maximum total size in bytes for the returned blocks.
    pub max_bytes: u32,
}

/// The RPC method handler for `chain.getBlocksRange.v1`.
pub struct GetBlocksRangeV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetBlocksRangeV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetBlocksRangeV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof: Debug,
{
    const NAME: &'static str = "chain.getBlocksRange.v1";
    type Params = GetBlocksRangeParams;
    type Result = Vec<Block<ChainTransaction>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetBlocksRangeV1"))?;
        let blocks = ctx.workload.store.get_blocks_range(
            params.since,
            params.max_blocks,
            params.max_bytes,
        )?;
        Ok(blocks)
    }
}

// --- chain.processBlock.v1 ---

/// The RPC method handler for `chain.processBlock.v1`.
pub struct ProcessBlockV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for ProcessBlockV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for ProcessBlockV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.processBlock.v1";
    type Params = Block<ChainTransaction>;
    type Result = (Block<ChainTransaction>, Vec<Vec<u8>>);

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        mut block: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for ProcessBlockV1"))?;

        {
            let machine = ctx.machine.lock().await;
            let enable_coinbase = std::env::var("ENABLE_COINBASE")
                .map(|s| s != "0")
                .unwrap_or(false);

            if enable_coinbase
                && !block.transactions.iter().any(|tx| {
                    matches!(
                        tx,
                        ChainTransaction::Application(ApplicationTransaction::UTXO(utxo))
                            if utxo.inputs.is_empty()
                    )
                })
            {
                let coinbase = (*machine).transaction_model().create_coinbase_transaction(
                    block.header.height,
                    &block.header.producer_account_id.0,
                )?;
                block.transactions.insert(0, coinbase);
            }
        }

        let prepared_block = {
            let machine = ctx.machine.lock().await;
            machine.prepare_block(block, &ctx.workload).await?
        };

        let (processed_block, events) = {
            let mut machine = ctx.machine.lock().await;
            machine.commit_block(prepared_block, &ctx.workload).await?
        };

        Ok((processed_block, events))
    }
}

// --- chain.checkTransactions.v1 ---

/// The parameters for the `chain.checkTransactions.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CheckTransactionsParams {
    /// The state anchor against which to validate the transactions.
    pub anchor: StateAnchor,
    /// The authoritative timestamp for the block being checked.
    pub expected_timestamp_secs: u64,
    /// The list of transactions to validate.
    pub txs: Vec<ChainTransaction>,
}

/// The RPC method handler for `chain.checkTransactions.v1`.
pub struct CheckTransactionsV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for CheckTransactionsV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for CheckTransactionsV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.checkTransactions.v1";
    type Params = CheckTransactionsParams;
    type Result = Vec<Result<(), String>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for CheckTransactionsV1"))?;

        let mut results = Vec::with_capacity(params.txs.len());
        let chain_guard = ctx.machine.lock().await;
        let base_state_tree = ctx.workload.state_tree();
        let base_state = base_state_tree.read().await;

        // FIX: Create a mutable StateOverlay for the pre-check simulation.
        // This allows `check_tx` to have the mutable reference it needs for
        // namespaced state lookups during signature verification.
        let mut overlay = StateOverlay::new(&*base_state);

        for tx in params.txs {
            let check_result = check_tx(
                &mut overlay, // Pass the mutable overlay
                &chain_guard.services,
                &tx,
                chain_guard.state.chain_id,
                chain_guard.status().height + 1,
                params.expected_timestamp_secs,
            )
            .await
            .map_err(|e: ioi_types::error::TransactionError| e.to_string());

            results.push(check_result);
        }

        Ok(results)
    }
}

// --- chain.getLastBlockHash.v1 ---

/// The parameters for the `chain.getLastBlockHash.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetLastBlockHashParams {}

/// The RPC method handler for `chain.getLastBlockHash.v1`.
pub struct GetLastBlockHashV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetLastBlockHashV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetLastBlockHashV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.getLastBlockHash.v1";
    type Params = GetLastBlockHashParams;
    type Result = Vec<u8>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetLastBlockHashV1"))?;

        let machine = ctx.machine.lock().await;
        let hash = match machine.state.recent_blocks.last() {
            Some(b) => b.header.hash()?,
            None => vec![0; 32],
        };
        Ok(hash)
    }
}

// --- chain.getAuthoritySet.v1 ---

/// The parameters for the `chain.getAuthoritySet.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetAuthoritySetParams {}

/// The RPC method handler for `chain.getAuthoritySet.v1`.
pub struct GetAuthoritySetV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetAuthoritySetV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetAuthoritySetV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.getAuthoritySet.v1";
    type Params = GetAuthoritySetParams;
    type Result = Vec<Vec<u8>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetAuthoritySetV1"))?;
        let machine = ctx.machine.lock().await;
        let h = (*machine).status().height;
        log::debug!("[RPC] {} -> height={} (current)", Self::NAME, h);
        let set = (*machine).get_validator_set_for(&ctx.workload, h).await?;
        log::debug!(
            "[RPC] {} -> height={} returned {} validators",
            Self::NAME,
            h,
            set.len()
        );
        Ok(set)
    }
}

// --- chain.getNextValidatorSet.v1 ---

/// The parameters for the `chain.getNextValidatorSet.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetNextValidatorSetParams {}

/// The RPC method handler for `chain.getNextValidatorSet.v1`.
pub struct GetNextValidatorSetV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetNextValidatorSetV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetNextValidatorSetV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.getNextValidatorSet.v1";
    type Params = GetNextValidatorSetParams;
    type Result = Vec<Vec<u8>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetNextValidatorSetV1"))?;
        let machine = ctx.machine.lock().await;
        let next_height = (*machine).status().height + 1;
        let set = (*machine)
            .get_validator_set_for(&ctx.workload, next_height)
            .await?;
        Ok(set)
    }
}

// --- chain.getValidatorSetFor.v1 ---

/// The parameters for the `chain.getValidatorSetFor.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetValidatorSetForParams {
    /// The block height for which to retrieve the validator set.
    pub height: u64,
}

/// The RPC method handler for `chain.getValidatorSetFor.v1`.
pub struct GetValidatorSetForV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetValidatorSetForV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetValidatorSetForV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.getValidatorSetFor.v1";
    type Params = GetValidatorSetForParams;
    type Result = Vec<Vec<u8>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetValidatorSetForV1"))?;
        let machine = ctx.machine.lock().await;
        let set = (*machine)
            .get_validator_set_for(&ctx.workload, params.height)
            .await?;
        Ok(set)
    }
}

// --- chain.getValidatorSetAt.v1 ---

/// The parameters for the `chain.getValidatorSetAt.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetValidatorSetAtParams {
    /// The state anchor at which to retrieve the validator set.
    pub anchor: StateAnchor,
}

/// The RPC method handler for `chain.getValidatorSetAt.v1`.
pub struct GetValidatorSetAtV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetValidatorSetAtV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetValidatorSetAtV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
{
    const NAME: &'static str = "chain.getValidatorSetAt.v1";
    type Params = GetValidatorSetAtParams;
    type Result = Vec<ioi_types::app::AccountId>;

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

        let (membership, _proof) =
            state.get_with_proof_at_anchor(&params.anchor.0, ioi_types::keys::VALIDATOR_SET_KEY)?;

        if let Membership::Present(bytes) = membership {
            let sets = ioi_types::app::read_validator_sets(&bytes)?;
            let account_ids = sets
                .current
                .validators
                .into_iter()
                .map(|v| v.account_id)
                .collect();
            Ok(account_ids)
        } else {
            Ok(vec![])
        }
    }
}

// --- chain.getBlockByHeight.v1 ---

/// The parameters for the `chain.getBlockByHeight.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetBlockByHeightParams {
    /// The height of the block to retrieve.
    pub height: u64,
}

/// The RPC method handler for `chain.getBlockByHeight.v1`.
pub struct GetBlockByHeightV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetBlockByHeightV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetBlockByHeightV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: ioi_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: Serialize
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
    const NAME: &'static str = "chain.getBlockByHeight.v1";
    type Params = GetBlockByHeightParams;
    type Result = Option<Block<ChainTransaction>>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetBlockByHeightV1"))?;

        let block_opt = match ctx.workload.store.get_block_by_height(params.height) {
            Ok(v) => v,
            Err(e) => {
                // Normalize transport/parse glitches into "None" (not yet produced).
                // Keep only hard storage errors as real failures if you can distinguish.
                log::warn!(
                    "get_block_by_height({}) transient error: {}",
                    params.height,
                    e
                );
                None
            }
        };

        Ok(block_opt)
    }
}
