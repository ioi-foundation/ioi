// Path: crates/types/src/config/mod.rs

//! Shared configuration structures for core DePIN SDK components.

use crate::service_configs::MigrationConfig;
use serde::{Deserialize, Serialize};

pub mod consensus;
pub use consensus::*;

/// Selects the underlying data structure for the state manager.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum StateTreeType {
    /// A simple, file-backed B-Tree map. Good for development.
    File,
    /// An in-memory HashMap. Volatile but fast for testing.
    HashMap,
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

// Default values for VmFuelCosts
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

/// Enum to represent the configuration of an initial service.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "name")]
pub enum InitialServiceConfig {
    /// Configuration for the Identity Hub service.
    IdentityHub(MigrationConfig),
}

/// Configuration for the Workload container (`workload.toml`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkloadConfig {
    /// A list of VM identifiers that are enabled.
    pub enabled_vms: Vec<String>,
    /// The type of state tree to use for the state manager.
    pub state_tree: StateTreeType,
    /// The cryptographic commitment scheme to pair with the state tree.
    pub commitment_scheme: CommitmentSchemeType,
    /// The consensus engine type. This is needed by the Chain logic to correctly
    /// interpret validator sets (PoS stakes vs PoA authorities).
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
}

/// Configuration for the Orchestration container (`orchestration.toml`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OrchestrationConfig {
    /// The consensus engine to use (e.g., ProofOfAuthority, ProofOfStake).
    pub consensus_type: ConsensusType,
    /// The network address and port for the JSON-RPC server to listen on.
    pub rpc_listen_address: String,
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