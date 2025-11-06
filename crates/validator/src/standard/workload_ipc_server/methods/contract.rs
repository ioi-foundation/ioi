// Path: crates/validator/src/standard/workload_ipc_server/methods/contract.rs

use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    state::StateManager,
    vm::{ExecutionContext, ExecutionOutput},
};
use serde::Deserialize;
use std::{any::Any, collections::HashMap, marker::PhantomData, sync::Arc};

// --- contract.deploy.v1 ---

/// The parameters for the `contract.deploy.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct DeployContractParams {
    /// The WASM bytecode of the contract to deploy.
    pub code: Vec<u8>,
    /// The address of the account deploying the contract.
    pub sender: Vec<u8>,
}

/// The RPC method handler for `contract.deploy.v1`.
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

/// The parameters for the `contract.call.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CallContractParams {
    /// The address of the contract to call.
    pub address: Vec<u8>,
    /// The ABI-encoded input data for the contract function.
    pub input_data: Vec<u8>,
    /// The execution context for the call, including caller and gas limits.
    pub context: ExecutionContext,
}

/// The RPC method handler for `contract.call.v1`.
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
    type Result = (ExecutionOutput, (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>));

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

/// The parameters for the `contract.query.v1` RPC method.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QueryContractParams {
    /// The address of the contract to query.
    pub address: Vec<u8>,
    /// The ABI-encoded input data for the contract function.
    pub input_data: Vec<u8>,
    /// The execution context for the query, including caller and gas limits.
    pub context: ExecutionContext,
}

/// The RPC method handler for `contract.query.v1`.
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
