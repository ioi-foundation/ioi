// Path: crates/node/src/bin/malicious-workload.rs
#![forbid(unsafe_code)]

//! A malicious workload container for testing proof verification.
//! This binary intercepts gRPC calls to `QueryStateAt` and returns tampered proofs.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::{
    commitment::CommitmentScheme,
    state::{ProofProvider, StateManager},
};
use ioi_state::primitives::hash::{HashCommitmentScheme, HashProof};
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::Membership;
use ioi_types::codec;
use ioi_types::config::WorkloadConfig;
use ioi_types::keys::VALIDATOR_SET_KEY;

// Import shared setup
use ioi_validator::standard::workload::{
    ipc::{
        grpc_blockchain::{
            ChainControlImpl, ContractControlImpl, StakingControlImpl, StateQueryImpl,
            SystemControlImpl,
        },
        RpcContext,
    },
    setup::setup_workload,
};

// gRPC types
use ioi_ipc::blockchain::chain_control_server::ChainControlServer;
use ioi_ipc::blockchain::contract_control_server::ContractControlServer;
use ioi_ipc::blockchain::staking_control_server::StakingControlServer;
use ioi_ipc::blockchain::state_query_server::{StateQuery, StateQueryServer};
use ioi_ipc::blockchain::system_control_server::SystemControlServer;
use ioi_ipc::blockchain::{
    CheckTransactionsRequest, CheckTransactionsResponse, PrefixScanRequest, PrefixScanResponse,
    QueryRawStateRequest, QueryRawStateResponse, QueryStateAtRequest, QueryStateAtResponse,
};
use tonic::{transport::Server, Request, Response, Status};

use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

// Malicious StateQuery Wrapper
struct MaliciousStateQuery<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    inner: StateQueryImpl<CS, ST>,
}

#[tonic::async_trait]
impl<CS, ST> StateQuery for MaliciousStateQuery<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn query_state_at(
        &self,
        request: Request<QueryStateAtRequest>,
    ) -> Result<Response<QueryStateAtResponse>, Status> {
        let req = request.into_inner();

        // --- INTERCEPTION START ---
        if req.key == VALIDATOR_SET_KEY {
            log::warn!("[MaliciousWorkload] Intercepting VALIDATOR_SET_KEY request. Returning tampered proof.");
            let fake_membership = Membership::Present(b"this_is_a_lie".to_vec());

            // Construct a syntactically valid but cryptographically invalid proof.
            // The Orchestrator should detect this via `verify_proof`.
            let tampered_inner_proof = b"invalid proof data".to_vec();
            // Note: We assume HashProof here because this binary only runs with IAVL/Hash
            let fake_proof = HashProof {
                value: tampered_inner_proof,
                selector: ioi_api::commitment::Selector::Key(req.key),
                additional_data: vec![],
            };

            let proof_bytes = codec::to_bytes_canonical(&fake_proof)
                .map_err(|e| Status::internal(format!("Encode failed: {}", e)))?;

            let response_struct = ioi_api::chain::QueryStateResponse {
                msg_version: 1,
                scheme_id: 1,
                scheme_version: 1,
                membership: fake_membership,
                proof_bytes,
            };

            let response_bytes = codec::to_bytes_canonical(&response_struct)
                .map_err(|e| Status::internal(format!("Encode failed: {}", e)))?;

            return Ok(Response::new(QueryStateAtResponse { response_bytes }));
        }
        // --- INTERCEPTION END ---

        // Fallback to standard implementation
        self.inner.query_state_at(Request::new(req)).await
    }

    // Delegate other methods
    async fn check_transactions(
        &self,
        r: Request<CheckTransactionsRequest>,
    ) -> Result<Response<CheckTransactionsResponse>, Status> {
        self.inner.check_transactions(r).await
    }
    async fn query_raw_state(
        &self,
        r: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        self.inner.query_raw_state(r).await
    }
    async fn prefix_scan(
        &self,
        r: Request<PrefixScanRequest>,
    ) -> Result<Response<PrefixScanResponse>, Status> {
        self.inner.prefix_scan(r).await
    }
}

async fn run_malicious_workload<CS, ST>(
    state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + Debug,
    CS::Proof: serde::Serialize + for<'de> serde::Deserialize<'de> + AsRef<[u8]> + Debug + Clone,
    CS::Commitment: Debug + From<Vec<u8>>,
{
    // 1. Shared Setup
    let (workload_container, machine_arc) =
        setup_workload(state_tree, commitment_scheme, config).await?;

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    let grpc_addr = ipc_server_addr.parse()?;

    // Create Shared Context
    let shared_ctx = Arc::new(RpcContext {
        machine: machine_arc.clone(),
        workload: workload_container.clone(),
        data_plane: None, // No Data Plane for malicious test
    });

    log::info!("MALICIOUS Workload: gRPC Server listening on {}", grpc_addr);
    eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", grpc_addr);

    // Wrap StateQuery
    let state_svc = MaliciousStateQuery {
        inner: StateQueryImpl {
            ctx: shared_ctx.clone(),
        },
    };

    // Standard other services
    let chain_svc = ChainControlImpl {
        ctx: shared_ctx.clone(),
    };
    let contract_svc = ContractControlImpl {
        ctx: shared_ctx.clone(),
    };
    let staking_svc = StakingControlImpl {
        ctx: shared_ctx.clone(),
    };
    let system_svc = SystemControlImpl {
        ctx: shared_ctx.clone(),
    };

    Server::builder()
        .add_service(ChainControlServer::new(chain_svc))
        .add_service(StateQueryServer::new(state_svc)) // Malicious!
        .add_service(ContractControlServer::new(contract_svc))
        .add_service(StakingControlServer::new(staking_svc))
        .add_service(SystemControlServer::new(system_svc))
        .serve(grpc_addr)
        .await?;

    Ok(())
}

fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "state-iavl") {
        enabled_features.push("state-iavl");
    }
    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature. Found: {:?}",
            enabled_features
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
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

    // Force IAVL/Hash as per test requirement
    match (config.state_tree.clone(), config.commitment_scheme.clone()) {
        #[cfg(all(feature = "state-iavl", feature = "commitment-hash"))]
        (ioi_types::config::StateTreeType::IAVL, ioi_types::config::CommitmentSchemeType::Hash) => {
            log::info!("Instantiating state backend: IAVLTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = IAVLTree::new(commitment_scheme.clone());
            run_malicious_workload(state_tree, commitment_scheme, config).await
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