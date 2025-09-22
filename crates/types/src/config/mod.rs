// Path: crates/types/src/config/mod.rs

//! Shared configuration structures for core DePIN SDK components.
use crate::app::ChainId;
use crate::service_configs::{GovernanceParams, MigrationConfig};
use serde::{Deserialize, Serialize};

pub mod consensus;
pub use consensus::*;

/// Selects the underlying data structure for the state manager.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum StateTreeType {
    /// An IAVL (Immutable AVL) tree, providing Merkle proofs.
    IAVL,
    /// A Sparse Merkle Tree, suitable for large key spaces.
    SparseMerkle,
    /// A Verkle Tree, offering smaller proof sizes.
    Verkle,
}

/// Selects the cryptographic commitment primitive to use with the state tree.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum CommitmentSchemeType {
    /// Simple SHA-256 hashing.
    Hash,
    /// Pedersen commitments, supporting homomorphic addition.
    Pedersen,
    /// KZG (Kate-Zaverucha-Goldberg) polynomial commitments.
    KZG,
    /// Lattice-based commitments, providing quantum resistance.
    Lattice,
}

/// Defines the fuel (gas) costs for various VM host function calls.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VmFuelCosts {
    /// Base cost for any host function call.
    #[serde(default = "default_fuel_base")]
    pub base_cost: u64,
    /// Per-byte cost for writing to state.
    #[serde(default = "default_fuel_state_set_per_byte")]
    pub state_set_per_byte: u64,
    /// Per-byte cost for reading from state.
    #[serde(default = "default_fuel_state_get_per_byte")]
    pub state_get_per_byte: u64,
}

fn default_fuel_base() -> u64 {
    1000
}
fn default_fuel_state_set_per_byte() -> u64 {
    10
}
fn default_fuel_state_get_per_byte() -> u64 {
    5
}

impl Default for VmFuelCosts {
    fn default() -> Self {
        Self {
            base_cost: default_fuel_base(),
            state_set_per_byte: default_fuel_state_set_per_byte(),
            state_get_per_byte: default_fuel_state_get_per_byte(),
        }
    }
}

/// Enum to represent the configuration of an initial service instantiated at genesis.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "name")]
pub enum InitialServiceConfig {
    /// Configuration for the Identity Hub service.
    IdentityHub(MigrationConfig),
    /// Configuration for the Governance service.
    Governance(GovernanceParams),
}

/// Configuration for the Workload container (`workload.toml`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkloadConfig {
    /// A list of VM identifiers that are enabled (e.g., "WASM").
    pub enabled_vms: Vec<String>,
    /// The type of state tree to use for the state manager.
    pub state_tree: StateTreeType,
    /// The cryptographic commitment scheme to pair with the state tree.
    pub commitment_scheme: CommitmentSchemeType,
    /// The consensus engine type, needed to interpret validator sets correctly.
    pub consensus_type: ConsensusType,
    /// The path to the genesis file for initial state.
    pub genesis_file: String,
    /// The path to the backing file or database for the state tree.
    pub state_file: String,
    /// The path to a pre-computed Structured Reference String (SRS) file, used by KZG.
    #[serde(default)]
    pub srs_file_path: Option<String>,
    /// Defines the fuel costs for VM operations.
    #[serde(default)]
    pub fuel_costs: VmFuelCosts,
    /// A list of services to instantiate at startup.
    #[serde(default)]
    pub initial_services: Vec<InitialServiceConfig>,
    /// The number of recent blocks to preserve from pruning, even if finalized.
    /// Acts as a safety buffer for reorgs. Defaults to 1000.
    #[serde(default = "default_min_finality_depth")]
    pub min_finality_depth: u64,
    /// The number of recent block heights to keep in history for proofs,
    /// regardless of finality. This defines the primary retention window. Defaults to 100_000.
    #[serde(default = "default_keep_recent_heights")]
    pub keep_recent_heights: u64,
}

fn default_min_finality_depth() -> u64 {
    1000
}

fn default_keep_recent_heights() -> u64 {
    100_000
}

fn default_chain_id() -> ChainId {
    ChainId(1)
}

/// Configuration for the RPC server's hardening and DDoS protection layer.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RpcHardeningConfig {
    /// Enables all RPC hardening middleware. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of concurrent in-flight RPC requests.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: u32,
    /// Timeout for a single RPC request in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    /// Per-IP rate limit for `submit_transaction` calls (requests per second).
    #[serde(default = "default_submit_rps")]
    pub submit_rps: u32,
    /// Per-IP burst allowance for `submit_transaction` calls.
    #[serde(default = "default_submit_burst")]
    pub submit_burst: u32,
    /// Per-IP rate limit for all other query calls (requests per second).
    #[serde(default = "default_query_rps")]
    pub query_rps: u32,
    /// Per-IP burst allowance for all other query calls.
    #[serde(default = "default_query_burst")]
    pub query_burst: u32,
    /// A list of trusted proxy IP addresses or CIDR blocks. If a request comes
    /// from a trusted proxy, the `X-Forwarded-For` header is used for rate limiting.
    /// e.g. ["127.0.0.1/32","10.0.0.0/8","172.16.0.0/12"]
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    /// The maximum number of transactions allowed in the mempool.
    #[serde(default = "default_mempool_max")]
    pub mempool_max: usize,
}

fn default_true() -> bool {
    true
}
fn default_max_concurrency() -> u32 {
    1024
}
fn default_timeout_ms() -> u64 {
    2500
}
fn default_max_body_bytes() -> u64 {
    128 * 1024
} // 128 KiB
fn default_submit_rps() -> u32 {
    5
}
fn default_submit_burst() -> u32 {
    10
}
fn default_query_rps() -> u32 {
    20
}
fn default_query_burst() -> u32 {
    40
}
fn default_mempool_max() -> usize {
    50_000
}

impl Default for RpcHardeningConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_concurrency: default_max_concurrency(),
            timeout_ms: default_timeout_ms(),
            max_body_bytes: default_max_body_bytes(),
            submit_rps: default_submit_rps(),
            submit_burst: default_submit_burst(),
            query_rps: default_query_rps(),
            query_burst: default_query_burst(),
            trusted_proxy_cidrs: Vec::new(),
            mempool_max: default_mempool_max(),
        }
    }
}

/// Configuration for the Orchestration container (`orchestration.toml`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OrchestrationConfig {
    /// The unique identifier for the blockchain instance, used in transaction signing.
    #[serde(default = "default_chain_id")]
    pub chain_id: ChainId,
    /// The version of the configuration file schema, for managing future upgrades.
    #[serde(default)]
    pub config_schema_version: u16,
    /// The consensus engine to use (e.g., ProofOfAuthority, ProofOfStake).
    pub consensus_type: ConsensusType,
    /// The network address and port for the JSON-RPC server to listen on.
    pub rpc_listen_address: String,
    /// Hardening and DDoS protection configuration for the RPC server.
    #[serde(default)]
    pub rpc_hardening: RpcHardeningConfig,
    /// The number of seconds to wait for initial peer discovery before assuming genesis node status.
    #[serde(default = "default_sync_timeout_secs")]
    pub initial_sync_timeout_secs: u64,
    /// The interval, in seconds, at which the node attempts to produce a new block if it is the leader.
    #[serde(default = "default_block_production_interval_secs")]
    pub block_production_interval_secs: u64,
    /// The timeout, in seconds, before a node proposes a view change in the RoundRobin BFT consensus engine.
    #[serde(default = "default_round_robin_view_timeout_secs")]
    pub round_robin_view_timeout_secs: u64,
    /// The default gas limit for read-only `query_contract` RPC calls.
    #[serde(default = "default_query_gas_limit")]
    pub default_query_gas_limit: u64,
}

fn default_sync_timeout_secs() -> u64 {
    5
}
fn default_block_production_interval_secs() -> u64 {
    5
}
fn default_round_robin_view_timeout_secs() -> u64 {
    20
}
fn default_query_gas_limit() -> u64 {
    1_000_000_000
}
