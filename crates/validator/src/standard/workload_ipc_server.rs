// Path: crates/validator/src/standard/workload_ipc_server.rs

use anyhow::Result;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::{
    chain::AppChain,
    chain::ChainView, // <--- FIX: Import the trait
    commitment::CommitmentScheme,
    validator::WorkloadContainer,
};
use depin_sdk_chain::Chain;
use depin_sdk_client::{
    ipc::{WorkloadRequest, WorkloadResponse},
    security::SecurityChannel,
};
use depin_sdk_services::governance::{GovernanceModule, Proposal, ProposalStatus};
use depin_sdk_types::app::AccountId;
use depin_sdk_types::keys::{GOVERNANCE_PROPOSAL_KEY_PREFIX, STAKES_KEY_CURRENT};
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::{collections::BTreeMap, sync::Arc};
use tokio::{io::AsyncReadExt, sync::Mutex};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

fn create_ipc_server_config() -> Result<Arc<ServerConfig>> {
    let mut server_params = CertificateParams::new(vec!["workload".to_string()]);
    server_params.subject_alt_names = vec![
        SanType::DnsName("workload".to_string()),
        SanType::IpAddress(Ipv4Addr::LOCALHOST.into()),
    ];
    let server_cert = Certificate::from_params(server_params)?;
    let server_der = server_cert.serialize_der()?;
    let server_key = server_cert.serialize_private_key_der();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_der)],
            PrivateKeyDer::Pkcs8(server_key.into()),
        )?;
    Ok(Arc::new(server_config))
}

pub struct WorkloadIpcServer<ST, CS>
where
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
{
    address: String,
    workload_container: Arc<WorkloadContainer<ST>>,
    chain_arc: Arc<Mutex<Chain<CS, ST>>>,
}

impl<ST, CS> WorkloadIpcServer<ST, CS>
where
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    CS::Commitment: std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
{
    pub async fn new(
        address: String,
        workload_container: Arc<WorkloadContainer<ST>>,
        chain_arc: Arc<Mutex<Chain<CS, ST>>>,
    ) -> Result<Self> {
        Ok(Self {
            address,
            workload_container,
            chain_arc,
        })
    }

    pub async fn run(self) -> Result<()> {
        let ipc_channel = SecurityChannel::new("workload", "orchestration");
        let listener = tokio::net::TcpListener::bind(&self.address).await?;
        log::info!("Workload: IPC server listening on {}", self.address);
        eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", self.address);

        let server_config = create_ipc_server_config()?;
        let acceptor = TlsAcceptor::from(server_config);
        let (stream, _) = listener.accept().await?;
        let mut tls_stream = acceptor.accept(stream).await?;

        let client_id_byte = tls_stream.read_u8().await?;
        log::info!(
            "Workload: Accepted IPC connection from client type: {}",
            client_id_byte
        );

        ipc_channel
            .accept_server_connection(tokio_rustls::TlsStream::Server(tls_stream))
            .await;
        log::info!("Workload: IPC connection established with Orchestration.");

        loop {
            let request_bytes = match ipc_channel.receive().await {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("Workload: IPC receive error: {}. Closing.", e);
                    break;
                }
            };
            let request: WorkloadRequest = serde_json::from_slice(&request_bytes)?;
            log::trace!("Workload: Received request: {:?}", request);

            let response = self.handle_request(request).await?;
            let response_bytes = serde_json::to_vec(&response)?;
            ipc_channel.send(&response_bytes).await?;
        }
        Ok(())
    }

    async fn handle_request(&self, request: WorkloadRequest) -> Result<WorkloadResponse> {
        let response = match request {
            WorkloadRequest::ProcessBlock(block) => {
                let mut chain = self.chain_arc.lock().await;
                let res = chain
                    .process_block(block, &self.workload_container)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::ProcessBlock(res)
            }
            WorkloadRequest::ExecuteTransaction(tx) => {
                // IMPORTANT: This is the mempool pre-check path.
                // It MUST NOT change consensus state and MUST respond quickly.
                // We only run fast, stateless checks here. Stateful checks
                // are performed during block processing.
                let chain = self.chain_arc.lock().await;
                let res = chain
                    .state
                    .transaction_model
                    .validate_stateless(&tx)
                    .map_err(|e| e.to_string());
                log::debug!("Workload IPC: ExecuteTransaction precheck responded.");
                WorkloadResponse::ExecuteTransaction(res)
            }
            WorkloadRequest::GetStatus => {
                let chain = self.chain_arc.lock().await;
                let res = Ok(chain.state.status.clone());
                WorkloadResponse::GetStatus(res)
            }
            WorkloadRequest::GetLastBlockHash => {
                let chain = self.chain_arc.lock().await;
                let hash = chain
                    .state
                    .recent_blocks
                    .last()
                    .map(|b| b.header.hash())
                    .unwrap_or_else(|| vec![0; 32]);
                WorkloadResponse::GetLastBlockHash(Ok(hash))
            }
            WorkloadRequest::GetExpectedModelHash => {
                let handler = async {
                    let state_tree_arc = self.workload_container.state_tree();
                    let state = state_tree_arc.lock().await;
                    match state.get(depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH)? {
                        Some(json_bytes) => {
                            let hex_str: String =
                                serde_json::from_slice(&json_bytes).map_err(|e| {
                                    depin_sdk_types::error::StateError::InvalidValue(format!(
                                        "Failed to deserialize model hash from state JSON: {}",
                                        e
                                    ))
                                })?;
                            hex::decode(hex_str).map_err(|e| {
                                depin_sdk_types::error::StateError::InvalidValue(e.to_string())
                            })
                        }
                        None => Err(depin_sdk_types::error::StateError::KeyNotFound(
                            "STATE_KEY_SEMANTIC_MODEL_HASH not found".to_string(),
                        )),
                    }
                };
                WorkloadResponse::GetExpectedModelHash(handler.await.map_err(|e| e.to_string()))
            }
            WorkloadRequest::GetStakes => {
                let chain = self.chain_arc.lock().await;
                let res = chain
                    .get_staked_validators(&self.workload_container)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::GetStakes(res)
            }
            WorkloadRequest::GetNextStakes => {
                let chain = self.chain_arc.lock().await;
                let res = chain
                    .get_next_staked_validators(&self.workload_container)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::GetNextStakes(res)
            }
            WorkloadRequest::GetAuthoritySet => {
                let chain = self.chain_arc.lock().await;
                // Use the *current* root for a consistent snapshot
                let state_tree_arc = self.workload_container.state_tree();
                let state = state_tree_arc.lock().await;
                let root_bytes = state.root_commitment().as_ref().to_vec();
                let root: [u8; 32] = root_bytes.try_into().unwrap_or([0; 32]);

                let view = chain.view_at(&root).unwrap();
                let res = view
                    .validator_set()
                    .await
                    .map(|accts| {
                        accts
                            .into_iter()
                            .map(|acct| acct.0.to_vec()) // legacy format for header decoration only
                            .collect()
                    })
                    .map_err(|e| e.to_string());
                WorkloadResponse::GetAuthoritySet(res)
            }
            WorkloadRequest::GetValidatorSet => {
                let chain = self.chain_arc.lock().await;
                let res = chain
                    .get_next_validator_set(&self.workload_container)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::GetValidatorSet(res)
            }
            WorkloadRequest::GetStakedValidators => {
                let chain = self.chain_arc.lock().await;
                let res = chain
                    .get_staked_validators(&self.workload_container)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::GetStakedValidators(res)
            }
            WorkloadRequest::GetStateRoot => {
                let state_tree_arc = self.workload_container.state_tree();
                let state = state_tree_arc.lock().await;
                let root = state.root_commitment().as_ref().to_vec();
                WorkloadResponse::GetStateRoot(Ok(root))
            }
            WorkloadRequest::QueryContract {
                address,
                input_data,
                context,
            } => {
                let res = self
                    .workload_container
                    .query_contract(address, input_data, context)
                    .await;
                WorkloadResponse::QueryContract(res.map_err(|e| e.to_string()))
            }
            WorkloadRequest::DeployContract { code, sender } => {
                let res = self
                    .workload_container
                    .deploy_contract(code, sender)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::DeployContract(res)
            }
            WorkloadRequest::CallContract {
                address,
                input_data,
                context,
            } => {
                let res = self
                    .workload_container
                    .call_contract(address, input_data, context)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::CallContract(res)
            }
            WorkloadRequest::CheckAndTallyProposals { current_height } => {
                let state_tree_arc = self.workload_container.state_tree();
                let mut state = state_tree_arc.lock().await;
                let governance_module = GovernanceModule::default();
                let proposals_kv = state.prefix_scan(GOVERNANCE_PROPOSAL_KEY_PREFIX)?;
                let mut outcomes = Vec::new();

                for (_key, value_bytes) in proposals_kv {
                    if let Ok(proposal) = serde_json::from_slice::<Proposal>(&value_bytes) {
                        if proposal.status == ProposalStatus::VotingPeriod
                            && current_height > proposal.voting_end_height
                        {
                            log::info!("[Workload] Tallying proposal {}", proposal.id);
                            // --- FIX START: Use canonical codec and AccountId key for stakes ---
                            let stakes: BTreeMap<AccountId, u64> = match state
                                .get(STAKES_KEY_CURRENT)?
                            {
                                Some(bytes) => depin_sdk_types::codec::from_bytes_canonical(&bytes)
                                    .unwrap_or_default(),
                                _ => BTreeMap::new(),
                            };
                            // --- FIX END ---
                            if let Err(e) =
                                governance_module.tally_proposal(&mut *state, proposal.id, &stakes)
                            {
                                log::error!(
                                    "[Workload] Failed to tally proposal {}: {}",
                                    proposal.id,
                                    e
                                );
                                continue;
                            }
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
                WorkloadResponse::CheckAndTallyProposals(Ok(outcomes))
            }
            WorkloadRequest::PrefixScan(prefix) => {
                let state_tree_arc = self.workload_container.state_tree();
                let state = state_tree_arc.lock().await;
                let res = state.prefix_scan(&prefix).map_err(|e| e.to_string());
                WorkloadResponse::PrefixScan(res)
            }
            WorkloadRequest::QueryRawState(key) => {
                let state_tree_arc = self.workload_container.state_tree();
                let state = state_tree_arc.lock().await;
                let res = state.get(&key).map_err(|e| e.to_string());
                WorkloadResponse::QueryRawState(res)
            }
            _ => WorkloadResponse::CallService(Err("Unsupported service call".to_string())),
        };
        Ok(response)
    }
}
