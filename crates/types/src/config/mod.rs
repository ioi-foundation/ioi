// Path: crates/types/src/config/mod.rs

//! Shared configuration structures for core IOI Kernel components.
use crate::app::ChainId;
use crate::service_configs::{GovernanceParams, MethodPermission, MigrationConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;

pub mod consensus;
pub use consensus::*;

/// Configuration structures for validator roles and capabilities.
pub mod validator_role;
pub use validator_role::*;

/// Selects the underlying data structure for the state manager.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum StateTreeType {
    /// An IAVL (Immutable AVL) tree, providing Merkle proofs.
    IAVL,
    /// A Sparse Merkle Tree, suitable for large key spaces.
    SparseMerkle,
    /// A Verkle Tree, offering smaller proof sizes.
    Verkle,
    /// A Jellyfish Merkle Tree, optimized for parallel hashing.
    Jellyfish,
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

/// Configuration for the IBC service.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IbcConfig {
    /// A list of enabled light client verifiers by name (e.g., "tendermint-v0.34").
    pub enabled_clients: Vec<String>,
}

/// Configuration for the Oracle service.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OracleParams {
    // Parameters for the oracle can be added here in the future.
}

/// Enum to represent the configuration of an initial service instantiated at genesis.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "name")]
pub enum InitialServiceConfig {
    /// Configuration for the Identity Hub service.
    IdentityHub(MigrationConfig),
    /// Configuration for the Governance service.
    Governance(GovernanceParams),
    /// Configuration for the IBC service.
    Ibc(IbcConfig),
    /// Configuration for the Oracle service.
    Oracle(OracleParams),
}

/// Defines the security policy for a service.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ServicePolicy {
    /// Map of method names to their required permission level.
    pub methods: BTreeMap<String, MethodPermission>,
    /// List of system key prefixes this service is allowed to access.
    pub allowed_system_prefixes: Vec<String>,
}

/// Configuration for Zero-Knowledge Light Clients.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ZkConfig {
    /// Hex-encoded SHA256 hash of the Ethereum Beacon Update verification key.
    /// This acts as the on-chain trust anchor.
    #[serde(default)]
    pub ethereum_beacon_vkey: String,

    /// Optional path to the raw verification key file for the Ethereum Beacon Update circuit.
    /// Required for nodes running with the `ethereum-zk` feature in native verification mode.
    #[serde(default)]
    pub beacon_vk_path: Option<String>,

    /// Hex-encoded SHA256 hash of the State Inclusion verification key.
    /// This acts as the on-chain trust anchor.
    #[serde(default)]
    pub state_inclusion_vkey: String,

    /// Optional path to the raw verification key file for the State Inclusion circuit.
    /// Required for nodes running with the `ethereum-zk` feature in native verification mode.
    #[serde(default)]
    pub state_vk_path: Option<String>,
}

/// Configuration for an AI Inference Runtime.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InferenceConfig {
    /// The provider type: "mock", "local" (e.g. llama.cpp), or "openai" (external).
    #[serde(default = "default_inference_provider")]
    pub provider: String,
    
    /// The base URL for the inference API (required for "local" and "openai").
    pub api_url: Option<String>,
    
    /// The API key (optional, for "openai" or secured local endpoints).
    pub api_key: Option<String>,
    
    /// The model name to request (e.g. "gpt-4", "llama-3-8b").
    pub model_name: Option<String>,

    /// The connector to use for this provider.
    pub connector_ref: Option<String>,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            provider: default_inference_provider(),
            api_url: None,
            api_key: None,
            model_name: None,
            connector_ref: None,
        }
    }
}

fn default_inference_provider() -> String {
    "mock".to_string()
}

/// Configuration for a secure connector.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectorConfig {
    /// Whether the connector is enabled.
    pub enabled: bool,
    /// The filename of the encrypted key in the certs directory (e.g. "openai_primary").
    pub key_ref: String,
}

/// Configuration for the Workload container (`workload.toml`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkloadConfig {
    /// A list of runtime identifiers that are enabled (e.g., "wasm").
    pub runtimes: Vec<String>,
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

    /// Map of service_id to its security policy (ACLs and Namespaces).
    /// Defaults to the standard IOI policy set if omitted.
    #[serde(default = "default_service_policies")]
    pub service_policies: BTreeMap<String, ServicePolicy>,

    /// The number of recent blocks to preserve from pruning, even if finalized.
    /// Acts as a safety buffer for reorgs. Defaults to 1000.
    #[serde(default = "default_min_finality_depth")]
    pub min_finality_depth: u64,
    /// The number of recent block heights to keep in history for proofs,
    /// regardless of finality. This defines the primary retention window. Defaults to 100_000.
    #[serde(default = "default_keep_recent_heights")]
    pub keep_recent_heights: u64,
    /// The size of a state history epoch in blocks for the `redb` backend. Defaults to 50,000.
    #[serde(default = "default_epoch_size")]
    pub epoch_size: u64,
    /// The interval in seconds between garbage collection passes. Defaults to 3600 (1 hour).
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,

    /// Configuration for Zero-Knowledge Light Clients.
    #[serde(default)]
    pub zk_config: ZkConfig,
    
    /// Default Configuration for AI Inference (Legacy Support).
    #[serde(default)]
    pub inference: InferenceConfig,

    /// [NEW] Dedicated Configuration for Fast/Local Inference (The "Reflexes").
    #[serde(default)]
    pub fast_inference: Option<InferenceConfig>,

    /// [NEW] Dedicated Configuration for Reasoning/Cloud Inference (The "Brain").
    #[serde(default)]
    pub reasoning_inference: Option<InferenceConfig>,

    /// Connectors for secure egress.
    #[serde(default)]
    pub connectors: HashMap<String, ConnectorConfig>,
}

impl WorkloadConfig {
    /// Validates the configuration for semantic correctness.
    pub fn validate(&self) -> Result<(), String> {
        let needs_srs = matches!(self.state_tree, StateTreeType::Verkle)
            || matches!(self.commitment_scheme, CommitmentSchemeType::KZG);

        if needs_srs && self.srs_file_path.is_none() {
            return Err("Configuration Error: 'srs_file_path' is required when using Verkle trees or KZG commitments.".to_string());
        }

        if self.epoch_size == 0 {
            return Err("Configuration Error: 'epoch_size' must be greater than 0.".to_string());
        }

        if self.gc_interval_secs == 0 {
            return Err(
                "Configuration Error: 'gc_interval_secs' must be greater than 0.".to_string(),
            );
        }
        
        // Validate legacy inference block if present
        if self.inference.provider != "mock" {
             if self.inference.api_url.is_none() {
                 return Err("Configuration Error: 'api_url' is required for non-mock inference providers.".to_string());
             }
        }

        // Validate new specialized blocks
        if let Some(fast) = &self.fast_inference {
            if fast.provider != "mock" && fast.api_url.is_none() {
                 return Err("Configuration Error: 'fast_inference.api_url' is required.".to_string());
            }
        }
        if let Some(reasoning) = &self.reasoning_inference {
            if reasoning.provider != "mock" && reasoning.api_url.is_none() {
                 return Err("Configuration Error: 'reasoning_inference.api_url' is required.".to_string());
            }
        }

        Ok(())
    }
}

/// Generates the default set of service security policies.
pub fn default_service_policies() -> BTreeMap<String, ServicePolicy> {
    let mut map = BTreeMap::new();

    // Governance
    let mut gov_methods = BTreeMap::new();
    gov_methods.insert("submit_proposal@v1".into(), MethodPermission::User);
    gov_methods.insert("vote@v1".into(), MethodPermission::User);
    gov_methods.insert("stake@v1".into(), MethodPermission::User);
    gov_methods.insert("unstake@v1".into(), MethodPermission::User);
    gov_methods.insert("store_module@v1".into(), MethodPermission::Governance);
    gov_methods.insert("swap_module@v1".into(), MethodPermission::Governance);

    map.insert(
        "governance".to_string(),
        ServicePolicy {
            methods: gov_methods,
            allowed_system_prefixes: vec![
                "system::validators::".to_string(),
                "identity::".to_string(),
                "upgrade::".to_string(),
            ],
        },
    );

    // Identity Hub
    let mut id_methods = BTreeMap::new();
    id_methods.insert("rotate_key@v1".into(), MethodPermission::User);
    id_methods.insert("register_attestation@v1".into(), MethodPermission::User);

    map.insert(
        "identity_hub".to_string(),
        ServicePolicy {
            methods: id_methods,
            allowed_system_prefixes: vec![
                "system::validators::".to_string(),
                "identity::pubkey::".to_string(),
            ],
        },
    );

    // Provider Registry
    let mut prov_methods = BTreeMap::new();
    prov_methods.insert("register@v1".into(), MethodPermission::User);
    prov_methods.insert("heartbeat@v1".into(), MethodPermission::User);
    map.insert(
        "provider_registry".to_string(),
        ServicePolicy {
            methods: prov_methods,
            allowed_system_prefixes: vec![],
        },
    );

    // IBC
    let mut ibc_methods = BTreeMap::new();
    ibc_methods.insert("verify_header@v1".into(), MethodPermission::User);
    ibc_methods.insert("recv_packet@v1".into(), MethodPermission::User);
    ibc_methods.insert("msg_dispatch@v1".into(), MethodPermission::User);
    ibc_methods.insert("submit_header@v1".into(), MethodPermission::User);
    ibc_methods.insert("verify_state@v1".into(), MethodPermission::User);
    ibc_methods.insert("register_verifier@v1".into(), MethodPermission::Governance);

    map.insert(
        "ibc".to_string(),
        ServicePolicy {
            methods: ibc_methods,
            allowed_system_prefixes: vec![],
        },
    );

    // Penalties
    let mut pen_methods = BTreeMap::new();
    pen_methods.insert("report_misbehavior@v1".into(), MethodPermission::User);
    map.insert(
        "penalties".to_string(),
        ServicePolicy {
            methods: pen_methods,
            allowed_system_prefixes: vec![],
        },
    );

    map
}

fn default_min_finality_depth() -> u64 {
    1000
}

fn default_keep_recent_heights() -> u64 {
    100_000
}

fn default_epoch_size() -> u64 {
    50_000
}

fn default_gc_interval_secs() -> u64 {
    3600
}

fn default_chain_id() -> ChainId {
    ChainId(1)
}

/// Configuration for the RPC server's hardening and DDoS protection layer.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RpcHardeningConfig {
    /// If true, enables all RPC hardening middleware.
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
    /// Per-IP rate limit for transaction submission (requests per second).
    #[serde(default = "default_submit_rps")]
    pub submit_rps: u32,
    /// Per-IP burst allowance for transaction submission.
    #[serde(default = "default_submit_burst")]
    pub submit_burst: u32,
    /// Per-IP rate limit for general query calls (requests per second).
    #[serde(default = "default_query_rps")]
    pub query_rps: u32,
    /// Per-IP burst allowance for general query calls.
    #[serde(default = "default_query_burst")]
    pub query_burst: u32,
    /// A list of trusted proxy IP addresses or CIDR blocks.
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
}
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
    /// The unique identifier for the blockchain instance.
    #[serde(default = "default_chain_id")]
    pub chain_id: ChainId,
    /// The version of the configuration file schema.
    #[serde(default)]
    pub config_schema_version: u16,
    /// The functional role of this validator node (Consensus vs Compute).
    #[serde(default)]
    pub validator_role: ValidatorRole,
    /// The consensus engine type.
    pub consensus_type: ConsensusType,
    /// The network address for the JSON-RPC server to listen on.
    pub rpc_listen_address: String,
    /// Configuration for RPC hardening and rate limiting.
    #[serde(default)]
    pub rpc_hardening: RpcHardeningConfig,
    /// Number of seconds to wait for initial peer discovery.
    #[serde(default = "default_sync_timeout_secs")]
    pub initial_sync_timeout_secs: u64,
    /// Interval in seconds at which the node attempts to produce a block.
    #[serde(default = "default_block_production_interval_secs")]
    pub block_production_interval_secs: u64,
    /// Timeout in seconds before proposing a BFT view change.
    #[serde(default = "default_round_robin_view_timeout_secs")]
    pub round_robin_view_timeout_secs: u64,
    /// Default gas limit for read-only contract queries.
    #[serde(default = "default_query_gas_limit")]
    pub default_query_gas_limit: u64,
    /// Optional listen address for the IBC HTTP gateway.
    #[serde(default)]
    pub ibc_gateway_listen_address: Option<String>,

    /// Optional: Path to the quantized GGUF model for the Safety Firewall.
    #[serde(default)]
    pub safety_model_path: Option<String>,
    /// Optional: Path to the tokenizer.json file.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
}

impl OrchestrationConfig {
    /// Validates the configuration for semantic correctness.
    pub fn validate(&self) -> Result<(), String> {
        if self.block_production_interval_secs == 0 {
            return Err(
                "Configuration Error: 'block_production_interval_secs' must be greater than 0."
                    .to_string(),
            );
        }
        Ok(())
    }
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