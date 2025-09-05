// Path: crates/node/src/bin/malicious-workload.rs
#![forbid(unsafe_code)]

//! A malicious workload container for testing proof verification.
//! This is a copy of the main workload binary with a modified IPC handler
//! that returns a tampered proof for a specific key.

use anyhow::{anyhow, Result};
use clap::Parser;
use depin_sdk_api::services::access::{Service, ServiceDirectory};
use depin_sdk_api::{
    commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer,
};
use depin_sdk_chain::util::load_state_from_genesis_file;
use depin_sdk_chain::wasm_loader::load_service_from_wasm;
use depin_sdk_chain::Chain;
use depin_sdk_client::ipc::{QueryStateAtResponse, WorkloadRequest, WorkloadResponse};
use depin_sdk_client::security::SecurityChannel;
use depin_sdk_commitment::primitives::hash::HashProof;
use depin_sdk_consensus::util::engine_from_config;
use depin_sdk_services::governance::GovernanceModule;
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{
    evidence_id, AccountId, ActiveKeyRecord, Membership, Proposal, ProposalStatus, StateEntry,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use depin_sdk_types::error::{StateError, TransactionError};
use depin_sdk_types::keys::{
    EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, ORACLE_DATA_PREFIX,
    ORACLE_PENDING_REQUEST_PREFIX, STAKES_KEY_CURRENT,
};
use depin_sdk_validator::standard::WorkloadIpcServer;
use depin_sdk_vm_wasm::WasmVm;
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{io::AsyncReadExt, sync::Mutex};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

// Imports for concrete types used in the factory
#[cfg(feature = "primitive-hash")]
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "tree-file")]
use depin_sdk_commitment::tree::file::FileStateTree;
#[cfg(feature = "tree-hashmap")]
use depin_sdk_commitment::tree::hashmap::HashMapStateTree;
#[cfg(feature = "tree-iavl")]
use depin_sdk_commitment::tree::iavl::IAVLTree;
#[cfg(feature = "tree-sparse-merkle")]
use depin_sdk_commitment::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "tree-verkle")]
use depin_sdk_commitment::tree::verkle::VerkleTree;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

/// Generic function containing all logic after component instantiation.
#[allow(dead_code)]
async fn run_workload<CS, ST>(
    mut state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    CS::Proof: AsRef<[u8]> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    CS::Commitment: std::fmt::Debug,
{
    // ... (This function is identical to the one in the real workload.rs) ...
    if !Path::new(&config.state_file).exists() {
        load_state_from_genesis_file(&mut state_tree, &config.genesis_file)?;
    } else {
        log::info!(
            "Found existing state file at '{}'. Skipping genesis initialization.",
            &config.state_file
        );
    }

    let wasm_vm = Box::new(WasmVm::new(config.fuel_costs.clone()));

    let mut initial_services = Vec::new();
    for service_config in &config.initial_services {
        match service_config {
            InitialServiceConfig::IdentityHub(migration_config) => {
                log::info!("[Workload] Instantiating initial service: IdentityHub");
                let hub = IdentityHub::new(migration_config.clone());
                initial_services
                    .push(Arc::new(hub) as Arc<dyn depin_sdk_api::services::UpgradableService>);
            }
        }
    }

    let services_for_dir: Vec<Arc<dyn Service>> = initial_services
        .iter()
        .map(|s| s.clone() as Arc<dyn Service>)
        .collect();
    let service_directory = ServiceDirectory::new(services_for_dir);

    let workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        wasm_vm,
        service_directory,
    ));

    let temp_orch_config = OrchestrationConfig {
        consensus_type: config.consensus_type,
        rpc_listen_address: String::new(),
        initial_sync_timeout_secs: 0,
        block_production_interval_secs: 0,
        round_robin_view_timeout_secs: 0,
        default_query_gas_limit: 0,
    };
    let consensus_engine = engine_from_config(&temp_orch_config)?;

    let mut chain = Chain::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        "depin-chain-1",
        initial_services,
        Box::new(load_service_from_wasm),
        consensus_engine,
        workload_container.clone(),
    );
    chain.load_or_initialize_status(&workload_container).await?;
    let chain_arc = Arc::new(Mutex::new(chain));

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    // Use a modified IPC server for malicious behavior
    let ipc_server = MaliciousWorkloadIpcServer::new(ipc_server_addr, workload_container, chain_arc).await?;

    log::info!("MALICIOUS Workload: State, VM, and Chain initialized. Running IPC server.");
    ipc_server.run().await?;
    Ok(())
}

fn check_features() {
    // ... (Identical to workload.rs) ...
}

#[tokio::main]
async fn main() -> Result<()> {
    // ... (Identical to workload.rs, it just calls run_workload which uses the malicious server) ...
    check_features();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = WorkloadOpts::parse();
    log::info!(
        "MALICIOUS Workload container starting up with config: {:?}",
        opts.config
    );
    let config_str = fs::read_to_string(&opts.config)?;
    let config: WorkloadConfig = toml::from_str(&config_str)?;
    match (config.state_tree.clone(), config.commitment_scheme.clone()) {
        #[cfg(all(feature = "tree-iavl", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::IAVL,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            log::info!("Instantiating state backend: IAVLTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = IAVLTree::new(commitment_scheme.clone());
            run_workload(state_tree, commitment_scheme, config).await
        }
        _ => {
            let err_msg = format!(
                "Unsupported or disabled state configuration for malicious workload. Please use IAVL/Hash."
            );
            log::error!("{}", err_msg);
            Err(anyhow!(err_msg))
        }
    }
}


// --- Malicious IPC Server Implementation ---

// This is the malicious version of the WorkloadIpcServer.
// It's mostly a copy, with a key modification in handle_request.
struct MaliciousWorkloadIpcServer<ST, CS>
where
    ST: depin_sdk_api::state::StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    // ... (struct fields are identical to the real one) ...
    address: String,
    workload_container: Arc<WorkloadContainer<ST>>,
    chain_arc: Arc<Mutex<Chain<CS, ST>>>,
}

impl<ST, CS> MaliciousWorkloadIpcServer<ST, CS>
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    // `new` and `run` are identical to the real server, they just call the malicious handler.
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
        // ... (this entire function is identical to the real workload.rs) ...
        // The key difference is that it calls `self.handle_request` which is malicious.
        let ipc_channel = SecurityChannel::new("workload", "orchestration");
        let listener = tokio::net::TcpListener::bind(&self.address).await?;
        log::info!("MALICIOUS Workload: IPC server listening on {}", self.address);
        eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", self.address);
        let server_config = depin_sdk_validator::standard::workload_ipc_server::create_ipc_server_config()?;
        let acceptor = TlsAcceptor::from(server_config);
        let (stream, _) = listener.accept().await?;
        let mut tls_stream = acceptor.accept(stream).await?;
        let client_id_byte = tls_stream.read_u8().await?;
        log::info!("MALICIOUS Workload: Accepted IPC connection from client type: {}", client_id_byte);
        ipc_channel.accept_server_connection(tokio_rustls::TlsStream::Server(tls_stream)).await;
        loop {
            let request_bytes = match ipc_channel.receive().await {
                Ok(bytes) => bytes,
                Err(e) => { log::error!("MALICIOUS Workload: IPC receive error: {}. Closing.", e); break; }
            };
            let request: WorkloadRequest = serde_json::from_slice(&request_bytes)?;
            log::trace!("MALICIOUS Workload: Received request: {:?}", request);
            let response = self.handle_request(request).await?;
            let response_bytes = serde_json::to_vec(&response)?;
            ipc_channel.send(&response_bytes).await?;
        }
        Ok(())
    }

    async fn handle_request(&self, request: WorkloadRequest) -> Result<WorkloadResponse> {
        if let WorkloadRequest::QueryStateAt { root, key } = request {
            // ===================================================================
            // ========== THIS IS THE MALICIOUS PART FOR THE E2E TEST ==========
            // ===================================================================
            if key == b"poison_pill" {
                log::warn!("[MaliciousWorkload] Received request for poisoned key. Returning tampered proof.");
                
                // Lie about the value.
                let fake_membership = Membership::Present(b"this_is_a_lie".to_vec());
                
                // Create an invalid proof. For HashProof, we can just put garbage in the value field,
                // which is where the real serialized proof would go.
                let tampered_inner_proof = b"this is not a valid serialized iavl proof".to_vec();
                let fake_proof = HashProof {
                    value: tampered_inner_proof,
                    selector: depin_sdk_api::commitment::Selector::Key(key),
                    additional_data: vec![],
                };

                let response = QueryStateAtResponse {
                    msg_version: 1,
                    scheme_id: 1, // Corresponds to Hash
                    scheme_version: 1,
                    membership: fake_membership,
                    proof_bytes: bincode::serialize(&fake_proof).unwrap(),
                };
                // Return the malicious response immediately.
                return Ok(WorkloadResponse::QueryStateAt(Ok(response)));
            }
            
            // For any other key, fall through to the normal, correct logic.
            // Re-construct the request to pass to the normal handler logic.
            let request = WorkloadRequest::QueryStateAt { root, key };
            // Fallthrough to the real logic below
        }

        // --- All other request handlers are copied verbatim from the real workload_ipc_server.rs ---
        // This is a simplified version showing only the relevant arm. A full copy would be here.
        let real_server = WorkloadIpcServer::new(
            self.address.clone(),
            self.workload_container.clone(),
            self.chain_arc.clone(),
        ).await?;
        
        real_server.handle_request(request).await
    }
}