// Path: crates/validator/src/standard/workload/ipc/mod.rs

//! Defines the IPC server implementation for the Workload container.
//!
//! This module implements the gRPC-based Control Plane and Shared Memory Data Plane.
//! It replaces the legacy JSON-RPC implementation.

/// Implements the gRPC services defined in the blockchain protobuf.
pub mod grpc_blockchain;

use anyhow::{anyhow, Result};
use ioi_api::{commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer};
use ioi_client::shmem::DataPlane;
use ioi_execution::ExecutionMachine;

use crate::standard::workload::ipc::grpc_blockchain::{
    ChainControlImpl, ContractControlImpl, StakingControlImpl, StateQueryImpl, SystemControlImpl,
};

use ioi_ipc::blockchain::chain_control_server::ChainControlServer;
use ioi_ipc::blockchain::contract_control_server::ContractControlServer;
use ioi_ipc::blockchain::staking_control_server::StakingControlServer;
use ioi_ipc::blockchain::state_query_server::StateQueryServer;
use ioi_ipc::blockchain::system_control_server::SystemControlServer;

use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Server;

// [FIX] Re-added create_ipc_server_config for Guardian usage
use std::fs::File;
use std::io::BufReader;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

/// The shared, read-only context available to all RPC method handlers.
///
/// It provides safe, concurrent access to the core components of the Workload container,
/// such as the `Chain` instance and the `WorkloadContainer` itself. This struct is generic
/// over the CommitmentScheme (CS) and StateManager (ST) to match the WorkloadIpcServer that creates it.
pub struct RpcContext<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>,
{
    /// A thread-safe handle to the core blockchain state machine.
    pub machine: Arc<Mutex<ExecutionMachine<CS, ST>>>,
    /// A thread-safe handle to the workload container, which manages the VM and state tree.
    pub workload: Arc<WorkloadContainer<ST>>,
    /// [NEW] Access to the shared memory region for zero-copy data transfer.
    /// Optional because it might not be configured in all environments.
    pub data_plane: Option<Arc<DataPlane>>,
}

/// Creates the mTLS server configuration for the IPC server.
/// Used by both Workload (legacy mode) and Guardian.
pub fn create_ipc_server_config(
    ca_cert_path: &str,
    server_cert_path: &str,
    server_key_path: &str,
) -> Result<Arc<ServerConfig>> {
    let ca_cert_file = File::open(ca_cert_path)?;
    let mut reader = BufReader::new(ca_cert_file);
    let ca_certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(ca_certs);

    let server_cert_file = File::open(server_cert_path)?;
    let mut reader = BufReader::new(server_cert_file);
    let server_certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    let server_key_file = File::open(server_key_path)?;
    let mut reader = BufReader::new(server_key_file);
    let server_key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("No private key found in {}", server_key_path))?;

    let client_verifier =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;
    Ok(Arc::new(server_config))
}

/// The main IPC server for the Workload container.
///
/// Handles gRPC requests from the Orchestrator and manages the Data Plane
/// for high-throughput block transfer.
pub struct WorkloadIpcServer<ST, CS>
where
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
{
    address: String,
    workload_container: Arc<WorkloadContainer<ST>>,
    machine_arc: Arc<Mutex<ExecutionMachine<CS, ST>>>,
    data_plane: Option<Arc<DataPlane>>,
}

impl<ST, CS> WorkloadIpcServer<ST, CS>
where
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone
        + std::fmt::Debug,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    CS::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    /// Creates a new `WorkloadIpcServer`.
    ///
    /// This initializes the Shared Memory Data Plane if configured via environment variables.
    pub async fn new(
        address: String,
        workload_container: Arc<WorkloadContainer<ST>>,
        machine_arc: Arc<Mutex<ExecutionMachine<CS, ST>>>,
    ) -> Result<Self> {
        let shmem_id =
            std::env::var("IOI_SHMEM_ID").unwrap_or_else(|_| "ioi_workload_shm_default".into());
        let shmem_size = std::env::var("IOI_SHMEM_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(128 * 1024 * 1024);

        let data_plane = match DataPlane::connect(&shmem_id) {
            Ok(dp) => {
                tracing::info!("Connected to existing Data Plane region: {}", shmem_id);
                Some(Arc::new(dp))
            }
            Err(_) => match DataPlane::create(&shmem_id, shmem_size) {
                Ok(dp) => {
                    tracing::info!(
                        "Created new Data Plane region: {} ({} bytes)",
                        shmem_id,
                        shmem_size
                    );
                    Some(Arc::new(dp))
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize Data Plane '{}': {}. Running in gRPC-only mode.",
                        shmem_id,
                        e
                    );
                    None
                }
            },
        };

        Ok(Self {
            address,
            workload_container,
            machine_arc,
            data_plane,
        })
    }

    /// Runs the gRPC server.
    pub async fn run(self) -> Result<()> {
        let grpc_addr = self.address.parse()?;

        let shared_ctx = Arc::new(RpcContext {
            machine: self.machine_arc.clone(),
            workload: self.workload_container.clone(),
            data_plane: self.data_plane.clone(),
        });

        log::info!("Workload: gRPC Server listening on {}", grpc_addr);
        eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", grpc_addr);

        let chain_svc = ChainControlImpl {
            ctx: shared_ctx.clone(),
        };
        let state_svc = StateQueryImpl {
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
            .add_service(StateQueryServer::new(state_svc))
            .add_service(ContractControlServer::new(contract_svc))
            .add_service(StakingControlServer::new(staking_svc))
            .add_service(SystemControlServer::new(system_svc))
            .serve(grpc_addr)
            .await?;

        Ok(())
    }
}
