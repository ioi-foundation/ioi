// Path: crates/validator/src/standard/workload_ipc_server/methods/contract.rs

use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    commitment::CommitmentScheme,
    state::StateManager,
    vm::{ExecutionContext, ExecutionOutput},
};
use serde::Deserialize;
use std::{any::Any, collections::HashMap, marker::PhantomData, sync::Arc};

// --- contract.deploy.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct DeployContractParams {
    pub code: Vec<u8>,
    pub sender: Vec<u8>,
}

pub struct DeployContractV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for DeployContractV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for DeployContractV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "contract.deploy.v1";
    type Params = DeployContractParams;
    type Result = (Vec<u8>, HashMap<Vec<u8>, Vec<u8>>);

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for DeployContractV1"))?;
        let result = ctx
            .workload
            .deploy_contract(params.code, params.sender)
            .await?;
        Ok(result)
    }
}

// --- contract.call.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CallContractParams {
    pub address: Vec<u8>,
    pub input_data: Vec<u8>,
    pub context: ExecutionContext,
}

pub struct CallContractV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for CallContractV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for CallContractV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "contract.call.v1";
    type Params = CallContractParams;
    type Result = (ExecutionOutput, HashMap<Vec<u8>, Vec<u8>>);

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for CallContractV1"))?;
        let result = ctx
            .workload
            .call_contract(params.address, params.input_data, params.context)
            .await?;
        Ok(result)
    }
}

// --- contract.query.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QueryContractParams {
    pub address: Vec<u8>,
    pub input_data: Vec<u8>,
    pub context: ExecutionContext,
}

pub struct QueryContractV1<CS, ST> {
    _p: PhantomData<(CS, ST)>,
}
impl<CS, ST> Default for QueryContractV1<CS, ST> {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

#[async_trait::async_trait]
impl<CS, ST> RpcMethod for QueryContractV1<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    const NAME: &'static str = "contract.query.v1";
    type Params = QueryContractParams;
    type Result = ExecutionOutput;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for QueryContractV1"))?;
        let result = ctx
            .workload
            .query_contract(params.address, params.input_data, params.context)
            .await?;
        Ok(result)
    }
}
