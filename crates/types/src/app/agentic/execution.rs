// Path: crates/types/src/app/agentic/execution.rs

use crate::app::action::{ApprovalAuthority, ApprovalGrant};
use crate::app::ActionRequest;
use crate::app::{CanonicalCollapseObject, FinalityTier, SealedFinalityProof};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

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

/// Represents a single message in an agent's conversation history.
/// This provides a structured, queryable format for Chat Mode and Context hydration.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct ChatMessage {
    /// The entity that generated the message: "user", "agent", "system", "tool".
    pub role: String,

    /// The text content of the message (input prompt, thought, or tool output).
    /// Note: mapped to `text` in some UI contexts.
    #[serde(alias = "content")]
    pub content: String,

    /// UNIX timestamp (milliseconds) when the message was created.
    pub timestamp: u64,

    /// Optional: The hash of the specific execution trace step this message corresponds to.
    /// This allows linking the conversation view back to the high-resolution Audit Log.
    pub trace_hash: Option<[u8; 32]>,
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

/// Structure for a "Learned Skill" (Macro).
/// This is the executable logic that backs a dynamic LlmToolDefinition.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Encode, Decode)]
pub struct AgentMacro {
    /// The definition of the tool (interface).
    pub definition: LlmToolDefinition,

    /// The sequence of atomic actions to execute when this tool is called.
    /// The `params` in these requests are templates (e.g. "{{url}}") that are interpolated
    /// with the arguments provided by the LLM at runtime.
    pub steps: Vec<ActionRequest>,

    /// The hash of the session/trace that generated this skill (Provenance).
    pub source_trace_hash: [u8; 32],

    /// The fitness score of this skill (Evolutionary quality).
    pub fitness: f32,
}

/// Lifecycle state for an executable skill record.
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
)]
pub enum SkillLifecycleState {
    /// Newly synthesized skill that has not yet cleared validation thresholds.
    #[default]
    Candidate,
    /// Skill that has demonstrated enough successful usage to be eligible at runtime.
    Validated,
    /// Skill that has cleared promotion benchmarks and can publish human-facing docs.
    Promoted,
    /// Skill that regressed below acceptable quality and should no longer be used.
    Deprecated,
}

/// Provenance class for how a skill entered the system.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, Encode, Decode)]
pub enum SkillSourceType {
    /// Skill synthesized from an observed successful agent trace.
    Trace,
    /// Skill synthesized specifically to recover from a failure trace.
    Recovery,
    /// Skill synthesized from parsed video evidence.
    Video,
    /// Skill synthesized from transcript-only evidence.
    Transcript,
    /// Skill synthesized from a structured web procedure.
    WebProcedure,
    /// Skill imported directly by a human or market package.
    #[default]
    Imported,
    /// Skill synthesized from an explicitly labeled human demonstration.
    HumanDemonstration,
}

/// Mutable benchmark snapshot used to decide whether a skill can be promoted.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Encode, Decode)]
pub struct SkillBenchmarkReport {
    /// Number of sessions or benchmark runs contributing to this report.
    pub sample_size: u32,
    /// Success rate in basis points (0 - 10_000).
    pub success_rate_bps: u32,
    /// Fraction of runs requiring explicit user intervention, in basis points.
    pub intervention_rate_bps: u32,
    /// Fraction of runs that triggered policy incidents, in basis points.
    pub policy_incident_rate_bps: u32,
    /// Moving average of Labor Gas cost across the measured runs.
    pub avg_cost: u64,
    /// Moving average latency in milliseconds, if available.
    pub avg_latency_ms: u64,
    /// Whether the current report satisfies the promotion gate.
    pub passed: bool,
    /// Last block height used to refresh this report.
    pub last_evaluated_height: u64,
}

/// Publication metadata for a generated human-facing skill document.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Encode, Decode)]
pub struct SkillPublicationInfo {
    /// Version string for the deterministic doc generator.
    pub generator_version: String,
    /// Last wall-clock timestamp (ms) when the doc artifact was generated.
    pub generated_at: u64,
    /// Hash of the generated markdown artifact.
    pub doc_hash: [u8; 32],
    /// Relative path where the generated doc should live when exported.
    pub relative_path: String,
    /// Whether the current generated doc is known to be stale relative to the macro hash.
    pub stale: bool,
}

/// Canonical mutable record for a learned executable skill.
///
/// The wrapped `AgentMacro` remains the executable source of truth for behavior.
/// The surrounding record tracks lifecycle, provenance, evaluation, and publication state.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SkillRecord {
    /// Canonical hash of the serialized `AgentMacro`.
    pub skill_hash: [u8; 32],
    /// Archival memory record id where the immutable macro payload is stored.
    pub archival_record_id: i64,
    /// Executable macro body used at runtime.
    pub macro_body: AgentMacro,
    /// Mutable lifecycle state.
    #[serde(default)]
    pub lifecycle_state: SkillLifecycleState,
    /// Provenance class for how this skill entered the system.
    #[serde(default)]
    pub source_type: SkillSourceType,
    /// Source session id, when the skill originated from a session.
    pub source_session_id: Option<[u8; 32]>,
    /// Canonical hash of normalized external evidence, when applicable.
    pub source_evidence_hash: Option<[u8; 32]>,
    /// Latest benchmark snapshot.
    pub benchmark: Option<SkillBenchmarkReport>,
    /// Publication metadata, populated after deterministic doc generation.
    pub publication: Option<SkillPublicationInfo>,
    /// Creation timestamp in ms.
    pub created_at: u64,
    /// Last update timestamp in ms.
    pub updated_at: u64,
}

/// Aggregate skill catalog index used by UI/CLI clients that can only query exact keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Encode, Decode)]
pub struct SkillCatalogIndex {
    /// Canonical skill hashes that belong to this catalog view.
    pub skills: Vec<[u8; 32]>,
}

/// Human-facing, generated skill document derived from a promoted executable skill.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PublishedSkillDoc {
    /// Canonical hash of the executable macro this doc describes.
    pub skill_hash: [u8; 32],
    /// Stable display name, usually matching the tool name.
    pub name: String,
    /// Markdown body of the generated doc.
    pub markdown: String,
    /// Generator version used to create the doc.
    pub generator_version: String,
    /// Generation timestamp in ms.
    pub generated_at: u64,
    /// Provenance trace hash carried through from the macro.
    pub source_trace_hash: [u8; 32],
    /// Canonical hash of normalized external evidence, when applicable.
    pub source_evidence_hash: Option<[u8; 32]>,
    /// Lifecycle state of the source skill at generation time.
    pub lifecycle_state: SkillLifecycleState,
    /// Hash of the generated markdown bytes.
    pub doc_hash: [u8; 32],
    /// Relative export path for this generated doc.
    pub relative_path: String,
    /// Whether the doc is stale relative to the current promoted macro.
    pub stale: bool,
}

/// Normalized external evidence that can be turned into a candidate executable skill.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ExternalSkillEvidence {
    /// Source class of the evidence.
    #[serde(default)]
    pub source_type: SkillSourceType,
    /// Optional canonical source URI (e.g. YouTube URL, tutorial URL).
    pub source_uri: Option<String>,
    /// Optional human-friendly title.
    pub title: Option<String>,
    /// Deterministically normalized procedure text.
    pub normalized_procedure: String,
    /// Optional structured hints produced by an extractor.
    pub structured_hints_json: Option<String>,
    /// Session id associated with the extraction, if applicable.
    pub source_session_id: Option<[u8; 32]>,
    /// Source trace hash, if the evidence was derived from a prior trace.
    pub source_trace_hash: Option<[u8; 32]>,
}

/// Tracks the longitudinal performance of a specific skill (Macro).
/// Stored in state as `skills::stats::{skill_hash}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Encode, Decode)]
pub struct SkillStats {
    /// Total number of times this skill has been expanded/executed.
    pub uses: u32,
    /// Number of sessions where this skill was used and the session succeeded.
    pub successes: u32,
    /// Number of sessions where this skill was used and the session failed.
    pub failures: u32,
    /// Moving average of Labor Gas cost per execution.
    pub avg_cost: u64,
    /// The last block height this skill was used.
    pub last_used_height: u64,
}

impl SkillStats {
    /// Returns a reliability score between 0.0 and 1.0.
    /// Uses Laplace smoothing to handle low sample sizes (starts at 0.5).
    pub fn reliability(&self) -> f32 {
        let s = self.successes as f32;
        let n = self.uses as f32;
        // Laplace smoothing: (s + 1) / (n + 2)
        (s + 1.0) / (n + 2.0)
    }

    /// Returns success rate in basis points (0 - 10_000).
    pub fn success_rate_bps(&self) -> u32 {
        if self.uses == 0 {
            return 0;
        }
        ((self.successes as u64 * 10_000) / self.uses as u64) as u32
    }
}

/// Defines the configuration for a single inference request, including tool availability.
#[derive(Serialize, Deserialize, Debug, Clone, Default, Encode, Decode)]
pub struct InferenceOptions {
    /// The list of tools available for the model to call during this inference generation.
    #[serde(default)]
    pub tools: Vec<LlmToolDefinition>,

    /// Controls randomness in output generation.
    pub temperature: f32,

    /// Enforce valid JSON output (e.g., OpenAI "json_object" mode).
    /// This ensures the model output can be parsed even if it includes Chain-of-Thought
    /// embedded within JSON fields (e.g., "thought": "...").
    #[serde(default)]
    pub json_mode: bool,

    /// The maximum number of tokens to generate in the completion.
    #[serde(default)]
    pub max_tokens: u32,

    /// Optional renderer-native stop sequences used to bound direct document authoring.
    #[serde(default)]
    pub stop_sequences: Vec<String>,

    /// Minimum finality tier required for any externalized effect generated by this inference.
    #[serde(default)]
    pub required_finality_tier: FinalityTier,

    /// Optional sealed finality proof authorizing stronger egress.
    #[serde(default)]
    pub sealed_finality_proof: Option<SealedFinalityProof>,

    /// Optional protocol-wide canonical collapse object bound to a sealed effect.
    #[serde(default)]
    pub canonical_collapse_object: Option<CanonicalCollapseObject>,
}

/// Legacy human-facing skill content following the agentskills.io-style schema.
///
/// Runtime execution should prefer `SkillRecord` + `AgentMacro`.
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
/// This is the "Black Box Recording" used to debug failures and drive evolution.
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

    // [NEW] Evolutionary Fields (The Reward Signal)
    /// The economic cost (Labor Gas) incurred for this specific step.
    pub cost_incurred: u64,
    /// A semantic success score (0.0 - 1.0) derived by the Evaluator/Verifier.
    /// This score determines if the agent survives or is deprecated.
    pub fitness_score: Option<f32>,

    /// [NEW] The hash of the Skill (Macro) that generated this step, if applicable.
    /// This links execution back to the specific version of the learned behavior.
    pub skill_hash: Option<[u8; 32]>,

    /// UNIX timestamp of this step.
    pub timestamp: u64,
}

/// Parameters for resuming a paused agent session.
#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    /// The ID of the session to resume.
    pub session_id: [u8; 32],
    /// Optional canonical approval grant to unblock a gated action.
    /// This is the authoritative approval artifact for constitutional resume flows.
    pub approval_grant: Option<ApprovalGrant>,
}

/// Parameters for registering an approval authority with the runtime.
#[derive(Encode, Decode)]
pub struct RegisterApprovalAuthorityParams {
    /// Authority artifact to persist under the runtime namespace.
    pub authority: ApprovalAuthority,
}

/// Parameters for revoking a previously registered approval authority.
#[derive(Encode, Decode)]
pub struct RevokeApprovalAuthorityParams {
    /// Authority identifier to revoke.
    pub authority_id: [u8; 32],
}
