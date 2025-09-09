// Path: crates/validator/src/standard/workload_ipc_server/methods/chain.rs
use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    chain::{AppChain, ChainView},
    commitment::CommitmentScheme,
    state::{StateAccessor, StateManager, StateOverlay},
    transaction::{context::TxContext, TransactionModel},
};
use depin_sdk_types::{
    app::{evidence_id, Block, ChainTransaction, StateAnchor, SystemPayload},
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
        + 'static,
    // FIX: Add trait bounds required by AppChain
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
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

        // --- Phase A: Pre-flight checks in a limited scope (READ-ONLY) ---
        {
            let chain = ctx.chain.lock().await;
            let base_state_tree = ctx.workload.state_tree();
            let base_state = base_state_tree.read().await;
            let overlay = StateOverlay::new(&*base_state);

            for tx in &block.transactions {
                let status = chain.status().clone();
                let chain_id = chain.state.chain_id.parse().unwrap_or(1);
                let _ctx = TxContext {
                    block_height: status.height + 1,
                    chain_id,
                    services: &chain.services,
                    simulation: true,
                };
                depin_sdk_transaction_models::system::nonce::assert_next_nonce(&overlay, tx)?;
            }
        } // Read lock is released here

        // --- Phase B: Coinbase addition and actual processing (WRITE) ---
        let mut chain = ctx.chain.lock().await;

        if !block.transactions.iter().any(|tx| {
            matches!(
                tx,
                depin_sdk_types::app::ChainTransaction::Application(
                    depin_sdk_types::app::ApplicationTransaction::UTXO(utxo)
                ) if utxo.inputs.is_empty()
            )
        }) {
            let coinbase = chain.transaction_model().create_coinbase_transaction(
                block.header.height,
                &block.header.producer_account_id.0,
            )?;
            block.transactions.insert(0, coinbase);
        }

        let result = chain.process_block(block, &ctx.workload).await?;
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
        + 'static,
    // FIX: Add trait bounds required by AppChain
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
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
        let chain = ctx.chain.lock().await;
        let latest_anchor = chain.state.last_state_root.to_anchor();

        if params.anchor != StateAnchor::default() && params.anchor != latest_anchor {
            return Ok(vec![Err("StaleAnchor".to_string())]);
        }

        let base_state_tree = ctx.workload.state_tree();
        let base_state = base_state_tree.read().await;
        let mut overlay = StateOverlay::new(&*base_state);

        let mut results = Vec::with_capacity(params.txs.len());
        let initial_tx_count = params.txs.len();

        for tx in params.txs {
            let check_result = async {
                let status = chain.status().clone();
                let chain_id = chain.state.chain_id.parse().unwrap_or(1);
                let tx_ctx = TxContext {
                    block_height: status.height + 1,
                    chain_id,
                    services: &chain.services,
                    simulation: true,
                };

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

                depin_sdk_transaction_models::system::nonce::assert_next_nonce(&overlay, &tx)?;
                depin_sdk_transaction_models::system::validation::verify_transaction_signature(
                    &overlay,
                    &chain.services,
                    &tx,
                    &tx_ctx,
                )?;

                for service in chain.services.services_in_deterministic_order() {
                    if let Some(decorator) = service.as_tx_decorator() {
                        decorator.ante_handle(&mut overlay, &tx, &tx_ctx)?;
                    }
                }

                depin_sdk_transaction_models::system::nonce::bump_nonce(&mut overlay, &tx)?;

                // --- FIX: Simulate the core state transition by applying the payload ---
                chain
                    .transaction_model()
                    .apply_payload(&*chain, &mut overlay, &tx, tx_ctx)
                    .await?;
                // --- END FIX ---

                Ok(())
            }
            .await
            .map_err(|e: TransactionError| e.to_string());

            if check_result.is_err() {
                results.push(check_result);
                while results.len() < initial_tx_count {
                    results.push(Err(
                        "Transaction skipped due to prior failure in batch".to_string()
                    ));
                }
                return Ok(results);
            }

            results.push(check_result);
        }
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
        + 'static,
    // FIX: Add trait bounds required by AppChain
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
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
            .unwrap_or_else(|| vec![0; 32]);
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
        + 'static,
    // FIX: Add trait bounds required by AppChain
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
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
        let state_tree = ctx.workload.state_tree();
        let state = state_tree.read().await;
        let root = depin_sdk_types::app::StateRoot(state.root_commitment().as_ref().to_vec());
        let anchor = root.to_anchor();

        let view = chain.view_at(&anchor).await?;
        let accts = view.validator_set().await?;
        Ok(accts.into_iter().map(|acct| acct.0.to_vec()).collect())
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
        + 'static,
    // FIX: Add trait bounds required by AppChain
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
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
        let set = chain.get_next_validator_set(&ctx.workload).await?;
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
        + 'static,
    // FIX: Add trait bounds required by AppChain
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
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
            .map_err(|_| anyhow!("Invalid context type for GetValidatorSetAtV1"))?;
        let chain = ctx.chain.lock().await;
        let view = chain.view_at(&params.anchor).await?;
        let set = view.validator_set().await?;
        Ok(set)
    }
}
