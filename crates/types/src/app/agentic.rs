// Path: crates/types/src/app/agentic.rs
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use crate::app::action::ApprovalToken; // [NEW] Import

/// The cryptographic proof that a distributed committee converged on a specific meaning.
/// This forms the "Proof of Meaning" verified by Type A (Consensus) validators.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeCertificate {
    /// The SHA-256 hash of the Canonical JSON output (RFC 8785).
    /// This is the "Intent Hash" that represents the agreed-upon semantic result.
    pub intent_hash: [u8; 32],

    /// The unique ID of the DIM (Distributed Inference Mesh) committee assigned to this task.
    pub committee_id: u64,

    /// The epoch in which this inference occurred.
    pub epoch: u64,

    /// The hash of the Model Snapshot used for inference.
    /// Ensures all committee members used the exact same model weights.
    pub model_snapshot_id: [u8; 32],

    /// The aggregated BLS signature of the quorum (>= 2/3 of committee weight).
    /// This aggregates the individual signatures of the Compute Validators.
    pub aggregated_signature: Vec<u8>,

    /// A bitfield representing which committee members contributed to the signature.
    /// Used to reconstruct the aggregate public key for verification.
    pub signers_bitfield: Vec<u8>,

    /// [NEW] Optional ZK Proof of Inference Correctness.
    /// If present, this replaces the need for a committee quorum in some contexts,
    /// or acts as a fraud proof.
    pub zk_proof: Option<Vec<u8>>,
}

/// The type of data being redacted from a Context Slice.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RedactionType {
    /// Personally Identifiable Information (e.g., Email, Phone).
    Pii,
    /// High-entropy secrets (e.g., API Keys, Private Keys).
    Secret,
    /// Custom pattern match (e.g., proprietary project names).
    Custom(String),
}

/// A specific redaction applied to a text segment.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RedactionEntry {
    /// Start byte index in the original UTF-8 buffer.
    pub start_index: u32,
    /// End byte index in the original UTF-8 buffer.
    pub end_index: u32,
    /// The type of data removed.
    pub redaction_type: RedactionType,
    /// SHA-256 hash of the original redacted content.
    /// Allows verifying that the rehydrated data matches the original scrubbed data.
    pub original_hash: [u8; 32],
}

/// A map of all redactions applied to a `ContextSlice`.
/// Used by the Orchestrator to "rehydrate" responses or verify the integrity of the scrubbing process.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RedactionMap {
    /// A chronological list of redactions applied to the source text.
    pub entries: Vec<RedactionEntry>,
}

/// Represents a tool definition compatible with LLM function calling schemas (e.g. OpenAI/Anthropic).
/// This allows the Kernel to project on-chain services as tools into the model's context window.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct LlmToolDefinition {
    /// The name of the function to be called.
    /// Typically namespaced, e.g., "browser__navigate" or "calculator__add".
    pub name: String,

    /// A description of what the function does, used by the model to decide when to call it.
    pub description: String,

    /// The parameters the function accepts, described as a JSON Schema string.
    pub parameters: String,
}

/// Defines the configuration for a single inference request, including tool availability.
#[derive(Serialize, Deserialize, Debug, Clone, Default, Encode, Decode)]
pub struct InferenceOptions {
    /// The list of tools available for the model to call during this inference generation.
    #[serde(default)]
    pub tools: Vec<LlmToolDefinition>,

    /// Controls randomness in output generation.
    pub temperature: f32,
}

/// A structured representation of an Agent Skill following the agentskills.io standard.
/// This represents Procedural Memory (Know-How) stored in the Substrate.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentSkill {
    /// Unique identifier (e.g., "webapp-testing"). From YAML frontmatter.
    pub name: String,
    /// Detailed description for semantic search/recall. From YAML frontmatter.
    pub description: String,
    /// The raw Markdown content containing instructions and examples.
    pub content: String,
    /// Optional list of relative paths to auxiliary resources (scripts, templates) in the skill folder.
    #[serde(default)]
    pub resources: Vec<String>,
}

/// A debug trace of a single agent step.
/// This is the "Black Box Recording" used to debug failures.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct StepTrace {
    /// The unique session ID this step belongs to.
    pub session_id: [u8; 32],
    /// The sequence number of this step.
    pub step_index: u32,
    /// The SHA-256 hash of the visual context (screenshot) seen by the agent.
    pub visual_hash: [u8; 32],
    /// The full, constructed prompt sent to the LLM (including injected skills).
    pub full_prompt: String,
    /// The raw string output received from the LLM.
    pub raw_output: String,
    /// Whether the action was successfully parsed and executed.
    pub success: bool,
    /// Error message if the step failed.
    pub error: Option<String>,
    /// UNIX timestamp of this step.
    pub timestamp: u64,
}

/// Parameters for resuming a paused agent session.
#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    /// The ID of the session to resume.
    pub session_id: [u8; 32],
    /// Optional approval token to unblock a gated action.
    /// If provided, this token authorizes the action that caused the pause.
    pub approval_token: Option<ApprovalToken>, 
}