// Path: crates/types/src/config/mod.rs

//! Shared configuration structures for core IOI Kernel components.
use crate::app::{
    ChainId, FinalityTier, GuardianProductionMode, KeyAuthorityDescriptor, KeyAuthorityKind,
};
use crate::service_configs::{GovernanceParams, MethodPermission, MigrationConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

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

/// Configuration for the guardian registry service.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GuardianRegistryParams {
    /// Whether the guardian registry is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum validator guardian committee size admitted by the registry.
    #[serde(default = "default_min_guardian_committee_size")]
    pub minimum_committee_size: u16,
    /// Minimum witness committee size admitted by the registry.
    #[serde(default = "default_min_witness_committee_size")]
    pub minimum_witness_committee_size: u16,
    /// Minimum distinct provider labels required for a production committee.
    #[serde(default = "default_min_provider_diversity")]
    pub minimum_provider_diversity: u16,
    /// Minimum distinct region labels required for a production committee.
    #[serde(default = "default_min_region_diversity")]
    pub minimum_region_diversity: u16,
    /// Minimum distinct host class labels required for a production committee.
    #[serde(default = "default_min_host_class_diversity")]
    pub minimum_host_class_diversity: u16,
    /// Minimum distinct key-authority classes required for a production committee.
    #[serde(default = "default_min_backend_diversity")]
    pub minimum_backend_diversity: u16,
    /// Production v1 forbids odd-sized majority committees unless a stronger external proof is added.
    #[serde(default = "default_true")]
    pub require_even_committee_sizes: bool,
    /// Require witness or guardian certificates to carry an anchored checkpoint in production policy.
    #[serde(default = "default_true")]
    pub require_checkpoint_anchoring: bool,
    /// Maximum checkpoint staleness admitted by policy.
    #[serde(default = "default_max_checkpoint_staleness_ms")]
    pub max_checkpoint_staleness_ms: u64,
    /// Maximum number of committee members that may be unavailable before the validator is expected to pause.
    #[serde(default = "default_max_committee_outage_members")]
    pub max_committee_outage_members: u16,
    /// Certification strata required for asymptote sealed finality.
    #[serde(default = "default_required_witness_strata")]
    pub asymptote_required_witness_strata: Vec<String>,
    /// Certification strata required after a divergence escalation.
    #[serde(default = "default_escalation_witness_strata")]
    pub asymptote_escalation_witness_strata: Vec<String>,
    /// Finality tier required for high-risk irreversible effects.
    #[serde(default = "default_high_risk_effect_tier")]
    pub asymptote_high_risk_effect_tier: FinalityTier,
    /// Whether accountable faults should trigger validator-set membership
    /// consequences immediately, or remain published evidence only.
    #[serde(default = "default_true")]
    pub apply_accountable_membership_updates: bool,
}

impl Default for GuardianRegistryParams {
    fn default() -> Self {
        Self {
            enabled: false,
            minimum_committee_size: default_min_guardian_committee_size(),
            minimum_witness_committee_size: default_min_witness_committee_size(),
            minimum_provider_diversity: default_min_provider_diversity(),
            minimum_region_diversity: default_min_region_diversity(),
            minimum_host_class_diversity: default_min_host_class_diversity(),
            minimum_backend_diversity: default_min_backend_diversity(),
            require_even_committee_sizes: default_true(),
            require_checkpoint_anchoring: default_true(),
            max_checkpoint_staleness_ms: default_max_checkpoint_staleness_ms(),
            max_committee_outage_members: default_max_committee_outage_members(),
            asymptote_required_witness_strata: default_required_witness_strata(),
            asymptote_escalation_witness_strata: default_escalation_witness_strata(),
            asymptote_high_risk_effect_tier: default_high_risk_effect_tier(),
            apply_accountable_membership_updates: default_true(),
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
    /// Configuration for the IBC service.
    Ibc(IbcConfig),
    /// Configuration for the Oracle service.
    Oracle(OracleParams),
    /// Configuration for the guardian registry service.
    GuardianRegistry(GuardianRegistryParams),
}

/// Static committee member configuration for guardianized deployments.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GuardianCommitteeMemberConfig {
    /// Stable member identifier.
    pub member_id: String,
    /// Optional remote endpoint for the member.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Public key bytes for this member.
    #[serde(default)]
    pub public_key: Vec<u8>,
    /// Optional local private-key material for development / single-host committee tests.
    #[serde(default)]
    pub private_key_path: Option<String>,
    /// Optional provider label for diversity checks.
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional region label for diversity checks.
    #[serde(default)]
    pub region: Option<String>,
    /// Optional host class label for diversity checks.
    #[serde(default)]
    pub host_class: Option<String>,
    /// Optional root authority class for this member.
    #[serde(default)]
    pub key_authority_kind: Option<KeyAuthorityKind>,
}

/// Threshold guardian committee configuration.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GuardianCommitteeConfig {
    /// Threshold required for a committee certificate.
    #[serde(default)]
    pub threshold: u16,
    /// Committee members authorized for this validator.
    #[serde(default)]
    pub members: Vec<GuardianCommitteeMemberConfig>,
    /// Transparency log identifier used by the committee.
    #[serde(default)]
    pub transparency_log_id: String,
}

/// Research-only witness committee configuration hosted by a guardian process.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GuardianWitnessCommitteeConfig {
    /// Stable witness committee identifier.
    #[serde(default)]
    pub committee_id: String,
    /// Stable certification stratum represented by this witness committee.
    #[serde(default)]
    pub stratum_id: String,
    /// Witness committee epoch.
    #[serde(default)]
    pub epoch: u64,
    /// Threshold required for a witness certificate.
    #[serde(default)]
    pub threshold: u16,
    /// Witness committee members.
    #[serde(default)]
    pub members: Vec<GuardianCommitteeMemberConfig>,
    /// Transparency log identifier used by the witness committee.
    #[serde(default)]
    pub transparency_log_id: String,
    /// Optional policy hash override for the witness committee.
    #[serde(default)]
    pub policy_hash: Option<[u8; 32]>,
}

/// Guardian hardening profile for the runtime worker.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GuardianHardeningConfig {
    /// Mount the worker root filesystem as read-only.
    #[serde(default = "default_true")]
    pub read_only_rootfs: bool,
    /// Disallow interactive shells inside the worker image.
    #[serde(default = "default_true")]
    pub no_shell: bool,
    /// Disallow runtime dynamic library loading.
    #[serde(default = "default_true")]
    pub no_dynamic_loading: bool,
    /// Use tmpfs for scratch data rather than persistent disks.
    #[serde(default = "default_true")]
    pub tmpfs_scratch: bool,
    /// Require measured boot / runtime measurement on startup.
    #[serde(default = "default_true")]
    pub measured_boot_required: bool,
    /// Attempt to lock sensitive pages in memory.
    #[serde(default = "default_true")]
    pub memory_locking: bool,
    /// Optional seccomp profile path or identifier.
    #[serde(default)]
    pub seccomp_profile: Option<String>,
}

impl Default for GuardianHardeningConfig {
    fn default() -> Self {
        Self {
            read_only_rootfs: default_true(),
            no_shell: default_true(),
            no_dynamic_loading: default_true(),
            tmpfs_scratch: default_true(),
            measured_boot_required: default_true(),
            memory_locking: default_true(),
            seccomp_profile: None,
        }
    }
}

/// Transparency-log configuration for guardianized receipts and checkpoints.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GuardianTransparencyLogConfig {
    /// Stable log identifier.
    #[serde(default)]
    pub log_id: String,
    /// Optional endpoint for the witness log.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Optional protobuf-encoded libp2p Ed25519 keypair used to sign checkpoints.
    #[serde(default)]
    pub signing_key_path: Option<String>,
    /// Whether an anchored checkpoint is mandatory for production effects.
    #[serde(default)]
    pub required: bool,
}

/// Attestation verifier policy.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GuardianVerifierPolicyConfig {
    /// Enabled verifier identifiers in priority order.
    #[serde(default)]
    pub enabled_verifiers: Vec<String>,
    /// Whether structural fallback is permitted.
    #[serde(default = "default_true")]
    pub allow_structural_fallback: bool,
    /// Explicitly allowed TLS server names for secure egress when non-empty.
    #[serde(default)]
    pub tls_allowed_server_names: Vec<String>,
    /// Optional custom root CA PEM files to trust for secure egress.
    #[serde(default)]
    pub tls_allowed_root_pem_paths: Vec<String>,
    /// Optional SHA-256 pins for the peer leaf certificate.
    #[serde(default)]
    pub tls_pinned_leaf_certificate_sha256: Vec<String>,
    /// Transcript schema version expected for secure egress receipts.
    #[serde(default = "default_tls_transcript_version")]
    pub tls_transcript_version: u32,
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
    /// The filename of the encrypted key in the certs directory (e.g. "openai_primary.key").
    pub key_ref: String,
    /// Optional endpoint or region override.
    pub region: Option<String>,
}

/// Global MCP execution mode for the workload.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpMode {
    /// No MCP servers may be configured or started.
    #[default]
    Disabled,
    /// Development-only MCP mode. Allows unverified servers for local iteration.
    Development,
    /// Production MCP mode. Requires pinned/integrity-checked, contained servers.
    Production,
}

/// Trust tier for an MCP server entry.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpServerTier {
    /// First-party or formally audited server artifact.
    Audited,
    /// Pinned and verified server artifact (integrity checked, not fully audited).
    Verified,
    /// Unverified plugin/server intended only for explicit development workflows.
    #[default]
    Unverified,
}

/// Source class for MCP server artifacts.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpServerSource {
    /// Local binary installed on the host.
    #[default]
    LocalBin,
    /// Vendored artifact shipped with the runtime/deployment bundle.
    Vendored,
    /// Package-manager resolved artifact (for example `npx`, `pipx`, `uvx`).
    PackageManager,
}

/// Containment mode for MCP server processes.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpContainmentMode {
    /// Strict containment expected (no ambient authority by default).
    #[default]
    Strict,
    /// Explicitly uncontained development mode.
    DeveloperUnconfined,
}

/// Integrity pinning metadata for MCP server artifacts.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct McpIntegrityConfig {
    /// Human-readable pinned version label (e.g., "1.4.2").
    #[serde(default)]
    pub version: Option<String>,
    /// Hex-encoded SHA-256 of the executable artifact to run.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Optional lockfile hash for package-manager based sources.
    #[serde(default)]
    pub lockfile_sha256: Option<String>,
}

/// Runtime containment contract for MCP server subprocesses.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpContainmentConfig {
    /// Containment mode to apply at launch.
    #[serde(default)]
    pub mode: McpContainmentMode,
    /// Whether outbound network egress is allowed.
    #[serde(default)]
    pub allow_network_egress: bool,
    /// Whether the server can spawn child processes.
    #[serde(default)]
    pub allow_child_processes: bool,
    /// Workspace root used for path-scoped operations and process cwd.
    #[serde(default)]
    pub workspace_root: Option<String>,
}

impl Default for McpContainmentConfig {
    fn default() -> Self {
        Self {
            mode: McpContainmentMode::Strict,
            allow_network_egress: false,
            allow_child_processes: false,
            workspace_root: None,
        }
    }
}

/// Configuration for an external MCP server process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpConfigEntry {
    /// The executable command to run (e.g., "node", "python").
    pub command: String,
    /// Arguments to pass to the command (e.g., ["index.js"]).
    pub args: Vec<String>,
    /// Environment variables for the process.
    /// Values starting with "env:" (e.g. "env:STRIPE_SECRET") will be resolved
    /// from the Guardian's secure vault at runtime.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Trust tier for admission and runtime policy checks.
    #[serde(default)]
    pub tier: McpServerTier,
    /// Artifact/source class used for supply-chain policy.
    #[serde(default)]
    pub source: McpServerSource,
    /// Integrity pins for deterministic artifact identity.
    #[serde(default)]
    pub integrity: McpIntegrityConfig,
    /// Containment contract for subprocess runtime boundaries.
    #[serde(default)]
    pub containment: McpContainmentConfig,
    /// Optional explicit allowlist of raw MCP tool names (`tools/list` names).
    /// If empty, all tools are eligible in development mode.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
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

    /// Dedicated Configuration for Fast/Local Inference (The "Reflexes").
    #[serde(default)]
    pub fast_inference: Option<InferenceConfig>,

    /// Dedicated Configuration for Reasoning/Cloud Inference (The "Brain").
    #[serde(default)]
    pub reasoning_inference: Option<InferenceConfig>,

    /// Connectors for secure egress (internal drivers).
    /// Used by both Inference (OpenAI) and Provisioning (AWS, Akash).
    ///
    /// Example:
    /// [connectors.aws_primary]
    /// enabled = true
    /// key_ref = "aws_access"
    /// region = "us-east-1"
    #[serde(default)]
    pub connectors: HashMap<String, ConnectorConfig>,

    /// Configuration for external MCP servers to spawn.
    /// Key is the logical server name (e.g. "filesystem"), Value contains execution details.
    #[serde(default)]
    pub mcp_servers: HashMap<String, McpConfigEntry>,
    /// Global MCP execution mode.
    #[serde(default)]
    pub mcp_mode: McpMode,
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
        if self.inference.provider != "mock" && self.inference.api_url.is_none() {
            return Err(
                "Configuration Error: 'api_url' is required for non-mock inference providers."
                    .to_string(),
            );
        }

        // Validate new specialized blocks
        if let Some(fast) = &self.fast_inference {
            if fast.provider != "mock" && fast.api_url.is_none() {
                return Err(
                    "Configuration Error: 'fast_inference.api_url' is required.".to_string()
                );
            }
        }
        if let Some(reasoning) = &self.reasoning_inference {
            if reasoning.provider != "mock" && reasoning.api_url.is_none() {
                return Err(
                    "Configuration Error: 'reasoning_inference.api_url' is required.".to_string(),
                );
            }
        }

        if self.mcp_mode == McpMode::Disabled && !self.mcp_servers.is_empty() {
            return Err(
                "Configuration Error: 'mcp_servers' requires 'mcp_mode' to be 'development' or 'production'."
                    .to_string(),
            );
        }
        if self.mcp_mode == McpMode::Production && !cfg!(target_os = "linux") {
            return Err(
                "Configuration Error: mcp_mode=production is currently supported only on Linux (strict containment requirement)."
                    .to_string(),
            );
        }

        let installer_commands = ["npx", "npm", "pnpm", "yarn", "bunx", "pipx", "uvx"];
        for (name, server) in &self.mcp_servers {
            if server.command.trim().is_empty() {
                return Err(format!(
                    "Configuration Error: mcp_servers.{} has an empty command.",
                    name
                ));
            }

            if let Some(sha) = server.integrity.sha256.as_deref() {
                let is_sha256 = sha.len() == 64 && sha.chars().all(|ch| ch.is_ascii_hexdigit());
                if !is_sha256 {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{}.integrity.sha256 must be 64 hex characters.",
                        name
                    ));
                }
            }
            if server
                .allowed_tools
                .iter()
                .any(|tool| tool.trim().is_empty())
            {
                return Err(format!(
                    "Configuration Error: mcp_servers.{}.allowed_tools cannot contain empty entries.",
                    name
                ));
            }
            let mut dedupe = HashSet::new();
            for tool in &server.allowed_tools {
                let normalized = tool.trim().to_string();
                if !dedupe.insert(normalized.clone()) {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{}.allowed_tools contains duplicate entry '{}'.",
                        name, normalized
                    ));
                }
            }

            let command_base = std::path::Path::new(server.command.trim())
                .file_name()
                .and_then(|part| part.to_str())
                .unwrap_or(server.command.trim())
                .to_ascii_lowercase();
            let uses_installer = server.source == McpServerSource::PackageManager
                || installer_commands
                    .iter()
                    .any(|candidate| command_base == *candidate);

            if self.mcp_mode != McpMode::Development && uses_installer {
                return Err(format!(
                    "Configuration Error: mcp_servers.{} uses installer-style command '{}' but mcp_mode is not development.",
                    name, server.command
                ));
            }

            if self.mcp_mode == McpMode::Production {
                if server.allowed_tools.is_empty() {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{}.allowed_tools is required in production mode.",
                        name
                    ));
                }
                if server.tier == McpServerTier::Unverified {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{} tier 'unverified' is not allowed in production mode.",
                        name
                    ));
                }
                if server
                    .integrity
                    .version
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{}.integrity.version is required in production mode.",
                        name
                    ));
                }
                if server
                    .integrity
                    .sha256
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{}.integrity.sha256 is required in production mode.",
                        name
                    ));
                }
                if server.containment.mode != McpContainmentMode::Strict {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{} must use strict containment in production mode.",
                        name
                    ));
                }
                if server
                    .containment
                    .workspace_root
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!(
                        "Configuration Error: mcp_servers.{}.containment.workspace_root is required in production mode.",
                        name
                    ));
                }
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

    // Guardian Registry
    let mut guardian_methods = BTreeMap::new();
    guardian_methods.insert(
        "register_guardian_transparency_log@v1".into(),
        MethodPermission::Governance,
    );
    guardian_methods.insert(
        "register_guardian_committee@v1".into(),
        MethodPermission::User,
    );
    guardian_methods.insert(
        "publish_measurement_profile@v1".into(),
        MethodPermission::Governance,
    );
    guardian_methods.insert(
        "anchor_guardian_checkpoint@v1".into(),
        MethodPermission::User,
    );
    guardian_methods.insert(
        "report_guardian_equivocation@v1".into(),
        MethodPermission::User,
    );
    map.insert(
        "guardian_registry".to_string(),
        ServicePolicy {
            methods: guardian_methods,
            allowed_system_prefixes: vec![
                "guardian::committee::".to_string(),
                "guardian::measurement::".to_string(),
                "guardian::log::".to_string(),
                "guardian::checkpoint::".to_string(),
            ],
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

    // [NEW] Market Service
    let mut market_methods = BTreeMap::new();
    market_methods.insert("publish_asset@v1".into(), MethodPermission::User);
    market_methods.insert("purchase_license@v1".into(), MethodPermission::User);
    market_methods.insert("request_compute@v1".into(), MethodPermission::User);
    market_methods.insert("settle_compute@v1".into(), MethodPermission::User);
    market_methods.insert("deploy_agent@v1".into(), MethodPermission::User);

    map.insert(
        "market".to_string(),
        ServicePolicy {
            methods: market_methods,
            allowed_system_prefixes: vec![],
        },
    );

    // Wallet Network
    let mut wallet_methods = BTreeMap::new();
    for method in [
        "configure_control_root@v1",
        "register_client@v1",
        "revoke_client@v1",
        "get_client@v1",
        "list_clients@v1",
        "issue_session_grant@v1",
        "store_secret_record@v1",
        "connector_auth_upsert@v1",
        "connector_auth_get@v1",
        "connector_auth_list@v1",
        "connector_auth_export@v1",
        "connector_auth_import@v1",
        "upsert_policy_rule@v1",
        "mail_connector_upsert@v1",
        "mail_connector_get@v1",
        "mail_connector_ensure_binding@v1",
        "open_channel_init@v1",
        "open_channel_try@v1",
        "open_channel_ack@v1",
        "open_channel_confirm@v1",
        "issue_session_lease@v1",
        "mail_read_latest@v1",
        "mail_list_recent@v1",
        "mailbox_total_count@v1",
        "mail_delete_spam@v1",
        "mail_reply@v1",
        "commit_receipt_root@v1",
        "close_channel@v1",
        "record_secret_injection_request@v1",
        "grant_secret_injection@v1",
        "record_interception@v1",
        "record_approval@v1",
        "consume_approval_token@v1",
        "panic_stop@v1",
    ] {
        wallet_methods.insert(method.to_string(), MethodPermission::User);
    }
    map.insert(
        "wallet_network".to_string(),
        ServicePolicy {
            methods: wallet_methods,
            allowed_system_prefixes: vec![],
        },
    );

    // Desktop Agent
    let mut desktop_agent_methods = BTreeMap::new();
    for method in [
        "start@v1",
        "resume@v1",
        "step@v1",
        "post_message@v1",
        "delete_session@v1",
    ] {
        desktop_agent_methods.insert(method.to_string(), MethodPermission::User);
    }
    map.insert(
        "desktop_agent".to_string(),
        ServicePolicy {
            methods: desktop_agent_methods,
            // Required for namespaced desktop-agent state to discover active service tools
            // and to bridge wallet-network connector state for mail capability execution.
            allowed_system_prefixes: vec![
                "upgrade::active::".to_string(),
                "_service_data::wallet_network::".to_string(),
            ],
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
    /// Safety mode for the Aft Fault Tolerance family.
    #[serde(default)]
    pub aft_safety_mode: AftSafetyMode,
    /// Guardianized signing / deployment profile.
    #[serde(default)]
    pub guardian_production_mode: GuardianProductionMode,
    /// Authority handle used for guardianized signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_authority: Option<KeyAuthorityDescriptor>,
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
    2
}
fn default_query_gas_limit() -> u64 {
    1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::default_service_policies;

    #[test]
    fn wallet_network_policy_exposes_policy_rule_upsert() {
        let policies = default_service_policies();
        let wallet = policies
            .get("wallet_network")
            .expect("wallet_network service policy should exist");

        assert!(
            wallet.methods.contains_key("upsert_policy_rule@v1"),
            "wallet_network ActiveServiceMeta must advertise upsert_policy_rule@v1",
        );
    }
}

fn default_tls_transcript_version() -> u32 {
    1
}
fn default_min_guardian_committee_size() -> u16 {
    4
}
fn default_min_witness_committee_size() -> u16 {
    4
}
fn default_min_provider_diversity() -> u16 {
    2
}
fn default_min_region_diversity() -> u16 {
    2
}
fn default_min_host_class_diversity() -> u16 {
    2
}
fn default_min_backend_diversity() -> u16 {
    2
}
fn default_max_checkpoint_staleness_ms() -> u64 {
    120_000
}
fn default_max_committee_outage_members() -> u16 {
    1
}
fn default_required_witness_strata() -> Vec<String> {
    vec!["stratum-a".to_string(), "stratum-b".to_string()]
}
fn default_escalation_witness_strata() -> Vec<String> {
    vec![
        "stratum-a".to_string(),
        "stratum-b".to_string(),
        "stratum-c".to_string(),
    ]
}
fn default_high_risk_effect_tier() -> FinalityTier {
    FinalityTier::SealedFinal
}
