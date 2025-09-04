// Path: crates/validator/src/standard/workload_ipc_server.rs

use anyhow::Result;
use depin_sdk_api::state::{StateAccessor, StateOverlay};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::{
    chain::AppChain,
    chain::ChainView,
    commitment::CommitmentScheme,
    validator::WorkloadContainer,
};
use depin_sdk_chain::Chain;
use depin_sdk_client::{
    ipc::{WorkloadRequest, WorkloadResponse},
    security::SecurityChannel,
};
use depin_sdk_services::governance::GovernanceModule;
use depin_sdk_types::app::{evidence_id, AccountId, ActiveKeyRecord, Proposal, ProposalStatus};
use depin_sdk_types::codec;
use depin_sdk_types::keys::{
    EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, STAKES_KEY_CURRENT,
};
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
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
        + std::fmt::Debug
        + Clone,
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
            WorkloadRequest::ProcessBlock(mut block) => {
                let mut chain = self.chain_arc.lock().await;

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

                let res = chain
                    .process_block(block, &self.workload_container)
                    .await
                    .map_err(|e| e.to_string());
                WorkloadResponse::ProcessBlock(Box::new(res))
            }
            WorkloadRequest::CheckTransactionsAt { anchor, txs } => {
                let res = async {
                    let chain = self.chain_arc.lock().await;
                    let latest_anchor = chain.state.last_state_root.to_anchor();

                    if anchor != depin_sdk_types::app::StateAnchor::default() && anchor != latest_anchor {
                        return Err("StaleAnchor".to_string());
                    }

                    let base_state_tree = self.workload_container.state_tree();
                    let base_state = base_state_tree.lock().await;
                    let mut overlay = StateOverlay::new(&*base_state);

                    let mut results = Vec::with_capacity(txs.len());

                    for tx in txs {
                        let check_result = async {
                            let status = chain.status().clone();
                            let chain_id = chain.state.chain_id.parse().unwrap_or(1);
                            let ctx = TxContext {
                                block_height: status.height + 1,
                                chain_id,
                                services: &chain.services,
                                simulation: true,
                            };

                            if let depin_sdk_types::app::ChainTransaction::System(sys_tx) = &tx {
                                if let depin_sdk_types::app::SystemPayload::ReportMisbehavior { report } = &sys_tx.payload {
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
                                        return Err(depin_sdk_types::error::TransactionError::Invalid(
                                            "DuplicateEvidence".to_string()
                                        ));
                                    }
                                }
                            }

                            depin_sdk_transaction_models::system::nonce::assert_next_nonce(&overlay, &tx)?;
                            depin_sdk_transaction_models::system::validation::verify_transaction_signature(&overlay, &chain.services, &tx, &ctx)?;

                            for service in chain.services.services_in_deterministic_order() {
                                if let Some(decorator) = service.as_tx_decorator() {
                                    decorator.ante_handle(&mut overlay, &tx, &ctx)?;
                                }
                            }

                            depin_sdk_transaction_models::system::nonce::bump_nonce(&mut overlay, &tx)?;
                            Ok(())
                        }
                        .await
                        .map_err(|e: depin_sdk_types::error::TransactionError| e.to_string());
                        
                        results.push(check_result);
                    }

                    Ok(results)
                }
                .await;

                WorkloadResponse::CheckTransactionsAt(res)
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
                let state_tree_arc = self.workload_container.state_tree();
                let state = state_tree_arc.lock().await;
                let root = depin_sdk_types::app::StateRoot(
                    state.root_commitment().as_ref().to_vec(),
                );
                let anchor = root.to_anchor();

                let view = chain.view_at(&anchor).unwrap();
                let res = view
                    .validator_set()
                    .await
                    .map(|accts| {
                        accts
                            .into_iter()
                            .map(|acct| acct.0.to_vec())
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
                            let stakes: BTreeMap<AccountId, u64> = match state
                                .get(STAKES_KEY_CURRENT)?
                            {
                                Some(bytes) => depin_sdk_types::codec::from_bytes_canonical(&bytes)
                                    .unwrap_or_default(),
                                _ => BTreeMap::new(),
                            };
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
            WorkloadRequest::QueryStateAt { anchor, key } => {
                let val = self.workload_container.get_at(anchor.0, &key).await;
                WorkloadResponse::QueryStateAt(Ok(val))
            }
            WorkloadRequest::GetValidatorSetAt { anchor } => {
                let res: Result<Vec<AccountId>, String> = async {
                    let chain = self.chain_arc.lock().await;
                    let view = chain.view_at(&anchor).map_err(|e| e.to_string())?;
                    view.validator_set().await.map_err(|e| e.to_string())
                }
                .await;
                WorkloadResponse::GetValidatorSetAt(res)
            }
            WorkloadRequest::GetActiveKeyAt { anchor, account_id } => {
                let handler = async {
                    let chain = self.chain_arc.lock().await;
                    let view = chain.view_at(&anchor)?;
                    let record = view.active_consensus_key(&account_id).await;
                    Ok(record)
                };
                let res: Result<Option<ActiveKeyRecord>, String> = handler
                    .await
                    .map_err(|e: depin_sdk_types::error::ChainError| e.to_string());
                WorkloadResponse::GetActiveKeyAt(res)
            }
            WorkloadRequest::CallService { .. } => {
                WorkloadResponse::CheckTransactionsAt(Err("CallService not yet implemented".to_string()))
            }
        };
        Ok(response)
    }
}