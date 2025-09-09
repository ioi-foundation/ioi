// Path: crates/validator/src/standard/workload_ipc_server/methods/staking.rs

use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::chain::{AppChain, PublicKey, StakeAmount};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use serde::{Deserialize, Serialize};
use std::{any::Any, collections::BTreeMap, marker::PhantomData, sync::Arc};

// --- staking.getStakes.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetStakesParams {}

pub struct GetStakesV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetStakesV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetStakesV1<CS, ST>
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
    const NAME: &'static str = "staking.getStakes.v1";
    type Params = GetStakesParams;
    type Result = BTreeMap<PublicKey, StakeAmount>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetStakesV1"))?;
        let chain = ctx.chain.lock().await;
        let stakes = chain.get_staked_validators(&ctx.workload).await?;
        Ok(stakes)
    }
}

// --- staking.getNextStakes.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetNextStakesParams {}

pub struct GetNextStakesV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for GetNextStakesV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for GetNextStakesV1<CS, ST>
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
    const NAME: &'static str = "staking.getNextStakes.v1";
    type Params = GetNextStakesParams;
    type Result = BTreeMap<PublicKey, StakeAmount>;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetNextStakesV1"))?;
        let chain = ctx.chain.lock().await;
        let stakes = chain.get_next_staked_validators(&ctx.workload).await?;
        Ok(stakes)
    }
}
