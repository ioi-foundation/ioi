// Path: crates/types/src/app/agentic/market.rs

use crate::app::AccountId;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use super::knowledge::{LensManifest, StaticKnowledgeChunk};

/// The classification of the intelligence asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum AssetType {
    /// A single executable capability (e.g., "Stripe Login").
    Skill,
    /// An autonomous worker with persona, tools, and policy (e.g., "Invoice Analyst").
    Agent,
    /// A coordinated graph of agents (e.g., "Finance Department").
    Swarm,
}

/// A tradeable unit of intelligence.
/// Wraps the specific manifest type for polymorphic storage in the Market Registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum IntelligenceAsset {
    /// A single executable capability (e.g., "Stripe Login").
    Skill(SkillManifest),
    /// An autonomous worker with persona, tools, and policy (e.g., "Invoice Analyst").
    Agent(AgentManifest),
    /// A coordinated graph of agents (e.g., "Finance Department").
    Swarm(SwarmManifest),
}

/// Represents a listing for a single atomic capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SkillManifest {
    /// Unique hash of the AgentMacro (definition + steps) stored in SCS.
    pub skill_hash: [u8; 32],
    /// Human-readable name (e.g. "Stripe Login v2").
    pub name: String,
    /// Detailed description of capabilities.
    pub description: String,
    /// The author/developer of this skill.
    pub author: AccountId,
    /// Price per license in Labor Gas (IOI Tokens).
    pub price: u64,
    /// Semantic tags for discovery (e.g. ["finance", "browser"]).
    pub tags: Vec<String>,
    /// Minimum compatible Kernel ABI version.
    pub min_kernel_version: u32,
    /// Version string (e.g., "1.0.2").
    pub version: String,
}

/// Defines the execution environment required by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum RuntimeEnvironment {
    /// Standard IOI Sandbox (WASM + Native Drivers). Safe, fast, zero-setup.
    Native,
    /// A custom Docker container image.
    /// Used for agents needing specific system libs (ffmpeg, python-pandas).
    Docker {
        /// The Content Identifier (CID) of the tarball/image on Filecoin/IPFS.
        image_cid: String,
        /// SHA-256 hash of the uncompressed image for verification.
        image_hash: [u8; 32],
        /// Entrypoint command.
        entrypoint: Vec<String>,
        /// Environment variables required (keys only, values from Vault).
        required_env_vars: Vec<String>,
    },
    /// A Unikernel or VM image (e.g. Firecracker).
    Unikernel {
        /// The Content Identifier (CID) of the kernel image.
        kernel_cid: String,
        /// The Content Identifier (CID) of the initrd (optional).
        initrd_cid: Option<String>,
    },
}

/// Hardware requirements for the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ResourceRequirements {
    /// Minimum VRAM in GB (for local models).
    pub min_vram_gb: u32,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// Number of vCPUs.
    pub min_cpus: u32,
    /// Network access requirements ("none", "public", "p2p-only").
    pub network_access: String,
    /// Preferred provider type (e.g. "akash", "aws", "any").
    pub provider_preference: String,
}

/// Represents a listing for a fully configured autonomous worker.
/// Includes definitions for "Service-as-a-Software" distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AgentManifest {
    /// The human-readable name of the agent.
    pub name: String,
    /// A description of the agent's purpose and capabilities.
    pub description: String,
    /// The "Persona" or System Prompt template.
    pub system_prompt: String,
    /// Recommended model class (e.g., "gpt-4-turbo", "llama-3-70b").
    pub model_selector: String,
    /// List of Skill hashes this agent comes equipped with.
    pub skills: Vec<[u8; 32]>,

    // Runtime & Resources
    /// Defines HOW this agent runs (WASM vs Docker).
    pub runtime: RuntimeEnvironment,
    /// Defines WHERE this agent can run (Hardware constraints).
    pub resources: ResourceRequirements,

    /// Hash of the default safety policy (Firewall rules).
    pub default_policy_hash: [u8; 32],
    /// The author of this agent configuration.
    pub author: AccountId,
    /// Licensing fee (e.g., Hourly rate or One-time fee).
    pub price: u64,
    /// Semantic tags for discovery.
    pub tags: Vec<String>,
    /// The version string of the agent manifest.
    pub version: String,

    /// Structured static knowledge injected into context every turn.
    #[serde(default)]
    pub static_knowledge: Vec<StaticKnowledgeChunk>,

    // [UPDATED] Service-as-a-Software Configuration
    
    /// If true, the agent binary contains an embedded web app in `embedded_assets/`.
    #[serde(default)]
    pub has_embedded_app: bool,
    
    /// The default route to navigate to on start (e.g. "/dashboard").
    pub app_entrypoint: Option<String>,
    
    /// List of typed lens configurations for interacting with the embedded app or external tools.
    #[serde(default)]
    pub custom_lenses: Vec<LensManifest>, 
    
    /// Commitment to the UI assets (Merkle Root of embedded_assets folder).
    /// Calculated at pack time to ensure UI integrity.
    #[serde(default)]
    pub ui_assets_root: [u8; 32],
}

/// Represents a listing for a coordinated team of agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SwarmManifest {
    /// The human-readable name of the swarm.
    pub name: String,
    /// A description of the swarm's collective purpose.
    pub description: String,
    /// The agents that make up this swarm.
    /// Key: Role Name (e.g. "Manager"), Value: AgentManifest Hash.
    pub roster: Vec<(String, [u8; 32])>,
    /// The delegation graph (Adjacency List).
    /// e.g. ("Manager", "Researcher"), ("Manager", "Writer")
    pub delegation_flow: Vec<(String, String)>,
    /// The author/developer of this swarm configuration.
    pub author: AccountId,
    /// Licensing fee for the swarm.
    pub price: u64,
    /// Semantic tags for discovery.
    pub tags: Vec<String>,
    /// The version string of the swarm manifest.
    pub version: String,
}

/// Proof of purchase for a specific intelligence asset.
/// Required by the Kernel to load a remote skill or agent into the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AssetLicense {
    /// The unique hash of the asset being licensed.
    pub asset_hash: [u8; 32],
    /// The type of asset (Skill, Agent, Swarm).
    pub asset_type: AssetType,
    /// The account that purchased the license.
    pub licensee: AccountId,
    /// The block height when the license was purchased.
    pub purchase_height: u64,
    /// Expiry block height (0 = Permanent/Lifetime).
    pub expiry: u64,
}