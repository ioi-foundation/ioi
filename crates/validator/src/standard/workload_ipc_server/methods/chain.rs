// Path: crates/validator/src/standard/workload_ipc_server/methods/chain.rs
use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    state::{StateAccessor, StateOverlay},
    transaction::{context::TxContext, TransactionModel},
};
use depin_sdk_transaction_models::system::{nonce, validation};
use depin_sdk_types::{
    app::{
        evidence_id, AccountId, ApplicationTransaction, Block, BlockHeader, ChainTransaction,
        Membership, StateAnchor, SystemPayload,
    },
    codec,
    error::TransactionError,
    keys::EVIDENCE_REGISTRY_KEY,
};
use serde::{Deserialize, Serialize};
use std::{any::Any, collections::BTreeSet, marker::PhantomData, sync::Arc};

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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
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
            let chain = ctx.chain.lock().await;
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
                let coinbase = (*chain).transaction_model().create_coinbase_transaction(
                    block.header.height,
                    &block.header.producer_account_id.0,
                )?;
                block.transactions.insert(0, coinbase);
            }
        }

        let prepared_block = {
            let chain = ctx.chain.lock().await;
            chain.prepare_block(block, &ctx.workload).await?
        };

        let (processed_block, events) = {
            let mut chain = ctx.chain.lock().await;
            chain.commit_block(prepared_block, &ctx.workload).await?
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
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

        let initial_tx_count = params.txs.len();
        let mut results = Vec::with_capacity(initial_tx_count);

        let chain_guard = ctx.chain.lock().await;

        let base_state_tree = ctx.workload.state_tree();
        let base_state = base_state_tree.read().await;
        let mut overlay = StateOverlay::new(&*base_state);

        for tx in params.txs {
            // Run the full validation flow inside a closure to handle errors cleanly.
            let check_result = async {
                let status = (*chain_guard).status();
                let chain_id = chain_guard.state.chain_id;
                // Derive signer exactly like the chain's apply path does
                let signer_account_id = match &tx {
                    ChainTransaction::System(sys_tx) => sys_tx.header.account_id,
                    ChainTransaction::Application(app_tx) => match app_tx {
                        ApplicationTransaction::DeployContract { header, .. } => header.account_id,
                        ApplicationTransaction::CallContract { header, .. } => header.account_id,
                        ApplicationTransaction::UTXO(_) => AccountId::default(),
                    },
                };

                let mut tx_ctx = TxContext {
                    block_height: status.height + 1,
                    chain_id,
                    signer_account_id,
                    services: &chain_guard.services,
                    simulation: true,
                    is_internal: false,
                };

                // Mirror the real path's auth checks: verify signature & nonce first.
                validation::verify_transaction_signature(
                    &overlay,
                    &chain_guard.services,
                    &tx,
                    &tx_ctx,
                )?;
                nonce::assert_next_nonce(&overlay, &tx)?;

                // Run TxDecorator services.
                for service in chain_guard.services.services_in_deterministic_order() {
                    if let Some(decorator) = service.as_tx_decorator() {
                        decorator.ante_handle(&mut overlay, &tx, &tx_ctx).await?;
                    }
                }

                if let ChainTransaction::System(sys_tx) = &tx {
                    if let SystemPayload::ReportMisbehavior { report } = &sys_tx.payload {
                        let id = evidence_id(report)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                        let already_seen = match overlay.get(EVIDENCE_REGISTRY_KEY)? {
                            Some(bytes) => {
                                codec::from_bytes_canonical::<BTreeSet<[u8; 32]>>(&bytes)
                                    .map(|set| set.contains(&id))
                                    .unwrap_or(false)
                            }
                            None => false,
                        };
                        if already_seen {
                            return Err(TransactionError::Invalid("DuplicateEvidence".to_string()));
                        }
                    }
                }

                // Bump nonce *within the overlay* so subsequent txs in the same batch see it.
                nonce::bump_nonce(&mut overlay, &tx)?;

                // Apply the core logic to the overlay to check for state-based errors
                (*chain_guard)
                    .transaction_model()
                    .apply_payload(&*chain_guard, &mut overlay, &tx, &mut tx_ctx)
                    .await?;

                Ok(())
            }
            .await
            .map_err(|e: TransactionError| e.to_string());

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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
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

        let chain = ctx.chain.lock().await;
        let hash = match chain.state.recent_blocks.last() {
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
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
        let chain = ctx.chain.lock().await;
        let h = (*chain).status().height;
        log::debug!("[RPC] {} -> height={} (current)", Self::NAME, h);
        let set = (*chain).get_validator_set_for(&ctx.workload, h).await?;
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
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
        let chain = ctx.chain.lock().await;
        let next_height = (*chain).status().height + 1;
        let set = (*chain)
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
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
        let chain = ctx.chain.lock().await;
        let set = (*chain)
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    const NAME: &'static str = "chain.getValidatorSetAt.v1";
    type Params = GetValidatorSetAtParams;
    type Result = Vec<depin_sdk_types::app::AccountId>;

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

        let (membership, _proof) = state
            .get_with_proof_at_anchor(&params.anchor.0, depin_sdk_types::keys::VALIDATOR_SET_KEY)?;

        if let Membership::Present(bytes) = membership {
            let sets = depin_sdk_types::app::read_validator_sets(&bytes)?;
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
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + AsRef<[u8]>,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    const NAME: &'static str = "chain.getBlockByHeight.v1";
    type Params = GetBlockByHeightParams;
    type Result = Option<BlockHeader>;

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

        Ok(block_opt.map(|b| b.header))
    }
}
