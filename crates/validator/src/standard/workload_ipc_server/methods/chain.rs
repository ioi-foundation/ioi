// Path: crates/validator/src/standard/workload_ipc_server/methods/chain.rs
use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    state::{StateAccessor, StateManager, StateOverlay},
    transaction::{context::TxContext, TransactionModel},
};
use depin_sdk_types::{
    app::{
        evidence_id, AccountId, ApplicationTransaction, Block, BlockHeader, ChainTransaction,
        StateAnchor, SystemPayload,
    },
    codec,
    error::TransactionError,
    keys::{EVIDENCE_REGISTRY_KEY, IBC_PROCESSED_RECEIPT_PREFIX},
};
use serde::{Deserialize, Serialize};
use std::{any::Any, collections::BTreeSet, marker::PhantomData, sync::Arc};

// --- chain.processBlock.v1 ---

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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

        // --- Phase A: Coinbase addition (brief write lock) ---
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
        } // Mutex lock on chain is released here

        // --- Phase B: Prepare block (read-only on chain) ---
        // This is the long, async part of the operation.
        let prepared_block = {
            let chain = ctx.chain.lock().await; // Brief read-lock
            chain.prepare_block(block, &ctx.workload).await?
        }; // Read-lock is released

        // --- Phase C: Commit block (write lock on chain) ---
        // This part should be fast and deterministic.
        let result = {
            let mut chain = ctx.chain.lock().await; // Write-lock for mutation
            chain.commit_block(prepared_block, &ctx.workload).await?
        }; // Write-lock is released

        Ok(result)
    }
}

// --- chain.checkTransactions.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CheckTransactionsParams {
    pub anchor: StateAnchor,
    pub txs: Vec<ChainTransaction>,
}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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

        // The total number of transactions we must provide a result for.
        let initial_tx_count = params.txs.len();
        let mut results = Vec::with_capacity(initial_tx_count);

        let chain_guard = ctx.chain.lock().await;
        // FIX: Handle the Result from to_anchor()
        let latest_anchor = chain_guard.state.last_state_root.to_anchor()?;

        if params.anchor != StateAnchor::default() && params.anchor != latest_anchor {
            // Stale anchor is a batch-level error. Fill all results with it.
            results.resize(
                initial_tx_count,
                Err(
                    "StaleAnchor: The provided state anchor is not the latest known root."
                        .to_string(),
                ),
            );
            return Ok(results);
        }

        let base_state_tree = ctx.workload.state_tree();
        let base_state = base_state_tree.read().await;
        // The overlay simulates state changes, ensuring correct nonce handling for sequential txs.
        let mut overlay = StateOverlay::new(&*base_state);

        for tx in params.txs {
            // Run the full validation flow inside a closure to handle errors cleanly.
            let check_result = async {
                let status = (*chain_guard).status().clone();
                let chain_id = chain_guard.state.chain_id;
                let tx_ctx = TxContext {
                    block_height: status.height + 1,
                    chain_id,
                    services: &chain_guard.services,
                    simulation: true, // This is a read-only check.
                };

                // Perform pre-flight checks that don't need decorators (e.g., replay protection)
                if let ChainTransaction::System(sys_tx) = &tx {
                    if let SystemPayload::ReportMisbehavior { report } = &sys_tx.payload {
                        let id = evidence_id(report);
                        let already_seen = match overlay.get(EVIDENCE_REGISTRY_KEY)? {
                            Some(bytes) => {
                                let set: BTreeSet<[u8; 32]> =
                                    codec::from_bytes_canonical(&bytes).unwrap_or_default();
                                set.contains(&id)
                            }
                            None => false,
                        };
                        if already_seen {
                            return Err(TransactionError::Invalid("DuplicateEvidence".to_string()));
                        }
                    }
                    if let SystemPayload::VerifyForeignReceipt { receipt, .. } = &sys_tx.payload {
                        let receipt_key =
                            [IBC_PROCESSED_RECEIPT_PREFIX, &receipt.unique_leaf_id].concat();
                        if overlay.get(&receipt_key)?.is_some() {
                            return Err(TransactionError::Invalid(
                                "Foreign receipt has already been processed (replay attack)"
                                    .to_string(),
                            ));
                        }
                    }
                }

                // Run the full ante-handler chain against the overlay
                depin_sdk_transaction_models::system::nonce::assert_next_nonce(&overlay, &tx)?;
                depin_sdk_transaction_models::system::validation::verify_transaction_signature(
                    &overlay,
                    &chain_guard.services,
                    &tx,
                    &tx_ctx,
                )?;

                for service in chain_guard.services.services_in_deterministic_order() {
                    if let Some(decorator) = service.as_tx_decorator() {
                        decorator.ante_handle(&mut overlay, &tx, &tx_ctx)?;
                    }
                }

                // Bump nonce *within the overlay* for the next tx in the batch
                depin_sdk_transaction_models::system::nonce::bump_nonce(&mut overlay, &tx)?;

                // Apply the core logic to the overlay to check for state-based errors
                (*chain_guard)
                    .transaction_model()
                    .apply_payload(&*chain_guard, &mut overlay, &tx, tx_ctx)
                    .await?;

                Ok(())
            }
            .await
            .map_err(|e: TransactionError| e.to_string());

            // Push the result for the current transaction.
            results.push(check_result);
        }

        // Final sanity check to ensure our logic is correct.
        assert_eq!(
            results.len(),
            initial_tx_count,
            "BUG in checkTransactions.v1: result count does not match input count."
        );

        Ok(results)
    }
}

// --- chain.getLastBlockHash.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetLastBlockHashParams {}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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
        let hash = chain
            .state
            .recent_blocks
            .last()
            .map(|b| b.header.hash())
            .unwrap_or(Ok(vec![0; 32]))?;
        Ok(hash)
    }
}

// --- chain.getAuthoritySet.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetAuthoritySetParams {}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetNextValidatorSetParams {}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetValidatorSetForParams {
    pub height: u64,
}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetValidatorSetAtParams {
    pub anchor: StateAnchor,
}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetValidatorSetAtV1"))?;

        let chain = ctx.chain.lock().await;

        let h = (*chain).status().height;
        log::debug!("[RPC] {} -> height={} (current)", Self::NAME, h);
        let set_bytes: Vec<Vec<u8>> = (*chain).get_validator_set_for(&ctx.workload, h).await?;
        log::debug!(
            "[RPC] {} -> height={} returned {} validators",
            Self::NAME,
            h,
            set_bytes.len()
        );

        Ok(set_bytes
            .into_iter()
            .map(|b| AccountId(b.try_into().unwrap_or_default()))
            .collect())
    }
}

// --- chain.getBlockByHeight.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetBlockByHeightParams {
    pub height: u64,
}

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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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

        let chain = ctx.chain.lock().await;
        let block_opt = (*chain).get_block(params.height);

        if let Some(block) = block_opt {
            Ok(Some(block.header.clone()))
        } else {
            // It might not be in the in-memory cache, so this is not an error.
            Ok(None)
        }
    }
}