// Path: crates/validator/src/standard/workload_ipc_server/methods/system.rs

use super::RpcContext;
use crate::standard::workload_ipc_server::router::{RequestContext, RpcMethod};
use anyhow::{anyhow, Result};
use depin_sdk_api::{chain::AppChain, commitment::CommitmentScheme, state::StateManager};
use depin_sdk_services::governance::GovernanceModule;
use depin_sdk_types::{
    app::{read_validator_sets, AccountId, Proposal, ProposalStatus},
    config::WorkloadConfig,
    keys::{GOVERNANCE_PROPOSAL_KEY_PREFIX, VALIDATOR_SET_KEY},
};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

// --- system.getStatus.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetStatusParams {}

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
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    const NAME: &'static str = "system.getStatus.v1";
    type Params = GetStatusParams;
    type Result = depin_sdk_types::app::ChainStatus;

    async fn call(
        &self,
        _req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        _params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for GetStatusV1"))?;
        let chain = ctx.chain.lock().await;
        // FIX: Dereference MutexGuard
        Ok((*chain).status().clone())
    }
}

// --- system.getExpectedModelHash.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetExpectedModelHashParams {}

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
        let json_bytes = state.get(depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH)?;
        let hex_str: String = serde_json::from_slice(&json_bytes.unwrap_or_default())?;
        Ok(hex::decode(hex_str)?)
    }
}

// --- system.checkAndTallyProposals.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CheckAndTallyProposalsParams {
    pub current_height: u64,
}

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
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result> {
        let ctx = shared_ctx
            .downcast::<RpcContext<CS, ST>>()
            .map_err(|_| anyhow!("Invalid context type for CheckAndTallyProposalsV1"))?;
        let state_tree = ctx.workload.state_tree();
        let mut state = state_tree.write().await;
        let governance_module = GovernanceModule::default();
        let proposals_kv = state.prefix_scan(GOVERNANCE_PROPOSAL_KEY_PREFIX)?;
        let mut outcomes = Vec::new();

        for (_key, value_bytes) in proposals_kv {
            if let Ok(proposal) = serde_json::from_slice::<Proposal>(&value_bytes) {
                if proposal.status == ProposalStatus::VotingPeriod
                    && params.current_height > proposal.voting_end_height
                {
                    log::info!("[Workload] Tallying proposal {}", proposal.id);
                    let stakes: BTreeMap<AccountId, u64> = match state.get(VALIDATOR_SET_KEY)? {
                        Some(bytes) => {
                            let sets = read_validator_sets(&bytes)?;
                            sets.current
                                .validators
                                .into_iter()
                                .map(|v| (v.account_id, v.weight as u64))
                                .collect()
                        }
                        _ => BTreeMap::new(),
                    };
                    governance_module
                        .tally_proposal(&mut *state, proposal.id, &stakes)
                        .map_err(|e| anyhow!(e))?;

                    let updated_key = GovernanceModule::proposal_key(proposal.id);
                    if let Some(updated_bytes) = state.get(&updated_key)? {
                        if let Ok(updated_proposal) =
                            serde_json::from_slice::<Proposal>(&updated_bytes)
                        {
                            let outcome_msg = format!(
                                "Proposal {} tallied: {:?}",
                                updated_proposal.id, updated_proposal.status
                            );
                            log::info!("[Workload] {}", outcome_msg);
                            outcomes.push(outcome_msg);
                        }
                    }
                }
            }
        }
        Ok(outcomes)
    }
}

// --- system.callService.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CallServiceParams {
    pub service_id: String,
    pub method_id: String,
    pub params: serde_json::Value,
}

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
        // This is a placeholder for future implementation.
        Ok(serde_json::json!({"status": "not_implemented"}))
    }
}

// --- system.getWorkloadConfig.v1 ---

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetWorkloadConfigParams {}

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

#[derive(Serialize, Deserialize, Debug)]
pub struct GenesisStatus {
    pub ready: bool,
    pub root: Vec<u8>,
    pub chain_id: String,
}

#[derive(Deserialize, Debug)]
pub struct GetGenesisStatusParams {}

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
        let chain = ctx.chain.lock().await;

        match &chain.state.genesis_state {
            depin_sdk_chain::app::GenesisState::Ready { root, chain_id } => Ok(GenesisStatus {
                ready: true,
                root: root.as_ref().to_vec(),
                chain_id: chain_id.to_string(),
            }),
            depin_sdk_chain::app::GenesisState::Pending => Ok(GenesisStatus {
                ready: false,
                root: vec![],
                chain_id: "".to_string(),
            }),
        }
    }
}