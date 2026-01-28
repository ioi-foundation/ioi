// Path: crates/types/src/app/agentic.rs
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use crate::app::action::ApprovalToken; 
use schemars::JsonSchema; 

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
    pub steps: Vec<crate::app::ActionRequest>,
    
    /// The hash of the session/trace that generated this skill (Provenance).
    pub source_trace_hash: [u8; 32],
    
    /// The fitness score of this skill (Evolutionary quality).
    pub fitness: f32,
}

/// Defines the configuration for a single inference request, including tool availability.
#[derive(Serialize, Deserialize, Debug, Clone, Default, Encode, Decode)]
pub struct InferenceOptions {
    /// The list of tools available for the model to call during this inference generation.
    #[serde(default)]
    pub tools: Vec<LlmToolDefinition>,

    /// Controls randomness in output generation.
    pub temperature: f32,

    /// [NEW] Enforce valid JSON output (e.g., OpenAI "json_object" mode).
    /// This ensures the model output can be parsed even if it includes Chain-of-Thought
    /// embedded within JSON fields (e.g., "thought": "...").
    #[serde(default)]
    pub json_mode: bool,
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

/// [NEW] Configuration for the "Law" (Firewall) of an agent.
/// Defines the hard constraints and liabilities.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, Default)]
pub struct FirewallPolicy {
    /// Maximum USD spend per execution (converted to tokens).
    pub budget_cap: f64,
    /// List of allowed DNS domains (e.g. "*.stripe.com").
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    /// If true, execution halts for "Hold to Sign".
    pub require_human_gate: bool,
    /// Data egress policy ("none", "masked", "zero-knowledge").
    pub privacy_level: Option<String>,
}

/// A structured, immutable fact extracted from an agent's thought or observation.
/// Used for the "Canonical Semantic Model" RAG system.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct SemanticFact {
    /// The subject of the fact (e.g., "user_budget").
    pub subject: String,
    /// The relationship (e.g., "is_limited_to").
    pub predicate: String,
    /// The value/object (e.g., "50_USD").
    pub object: String,
    // Note: We don't store context_hash here typically, as the Fact is embedded *into* the Index
    // which points to the Frame.
}

// -----------------------------------------------------------------------------
// [NEW] Type-Safe Agent Tools (Phase 4)
// -----------------------------------------------------------------------------

/// The single source of truth for all Agent Capabilities.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "name", content = "arguments", rename_all = "snake_case")]
pub enum AgentTool {
    /// Meta-tool for computer control (Claude 3.5 Sonnet style)
    #[serde(rename = "computer")]
    Computer(ComputerAction),

    /// Writes content to a file.
    #[serde(rename = "filesystem__write_file")]
    FsWrite { 
        /// Path to the file.
        path: String, 
        /// Content to write.
        content: String 
    },

    /// Reads content from a file.
    #[serde(rename = "filesystem__read_file")]
    FsRead { 
        /// Path to the file.
        path: String 
    },
    
    /// Lists directory contents.
    #[serde(rename = "filesystem__list_directory")]
    FsList { 
        /// Path to the directory.
        path: String 
    },

    /// Executes a system command.
    #[serde(rename = "sys__exec")]
    SysExec { 
        /// Command to execute.
        command: String, 
        /// Arguments for the command.
        #[serde(default)]
        args: Vec<String>, 
        /// Whether to detach the process.
        #[serde(default)]
        detach: bool 
    },

    /// Navigates the browser to a URL.
    #[serde(rename = "browser__navigate")]
    BrowserNavigate { 
        /// URL to navigate to.
        url: String 
    },

    /// Extracts content from the browser.
    #[serde(rename = "browser__extract")]
    BrowserExtract,

    /// Clicks an element in the browser.
    #[serde(rename = "browser__click")]
    BrowserClick { 
        /// CSS selector of element to click.
        selector: String 
    },

    /// Legacy GUI click tool.
    #[serde(rename = "gui__click")]
    GuiClick { 
        /// X coordinate.
        x: u32, 
        /// Y coordinate.
        y: u32, 
        /// Mouse button (left/right/middle).
        button: Option<String> 
    },

    /// Legacy GUI typing tool.
    #[serde(rename = "gui__type")]
    GuiType { 
        /// Text to type.
        text: String 
    },

    /// Sends a reply in the chat.
    #[serde(rename = "chat__reply")]
    ChatReply { 
        /// Message content.
        message: String 
    },
    
    /// Meta Tool: Delegates a task to a sub-agent.
    #[serde(rename = "agent__delegate")]
    AgentDelegate { 
        /// Goal for the sub-agent.
        goal: String, 
        /// Budget allocated.
        budget: u64 
    },
    
    /// Meta Tool: Awaits result from a sub-agent.
    #[serde(rename = "agent__await_result")]
    AgentAwait { 
        /// Session ID of the child agent.
        child_session_id_hex: String 
    },
    
    /// Meta Tool: Pauses execution.
    #[serde(rename = "agent__pause")]
    AgentPause { 
        /// Reason for pausing.
        reason: String 
    },
    
    /// Meta Tool: Completes the task.
    #[serde(rename = "agent__complete")]
    AgentComplete { 
        /// Final result description.
        result: String 
    },
    
    /// Commerce Tool: Initiates a checkout.
    #[serde(rename = "commerce__checkout")]
    CommerceCheckout { 
        /// Merchant URL.
        merchant_url: String, 
        /// Items to purchase.
        items: Vec<CommerceItem>,
        /// Total amount.
        total_amount: f64,
        /// Currency code.
        currency: String,
        /// Buyer email address.
        buyer_email: Option<String>
    },

    /// Catch-all for dynamic/unknown tools (e.g. MCP extensions) not yet strictly typed
    #[serde(untagged)]
    Dynamic(serde_json::Value),
}

/// An item in a commerce transaction.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct CommerceItem {
    /// Item ID.
    pub id: String,
    /// Quantity.
    pub quantity: u32,
}

/// Actions available via the Computer meta-tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ComputerAction {
    /// Type text.
    #[serde(rename = "type")]
    Type { 
        /// Text to type.
        text: String 
    },
    
    /// Press a key.
    #[serde(rename = "key")]
    Key { 
        /// Key name.
        text: String 
    },

    /// Move mouse cursor.
    MouseMove { 
        /// Coordinates [x, y].
        coordinate: [u32; 2] 
    },
    
    /// Click left mouse button.
    LeftClick,
    
    /// Click and drag.
    LeftClickDrag { 
        /// Coordinates [x, y].
        coordinate: [u32; 2] 
    },
    
    /// Take a screenshot.
    Screenshot,
    
    /// Get cursor position.
    CursorPosition,
}

/// Trait to map high-level tools to Kernel Security Scopes
impl AgentTool {
    /// Maps the tool to its corresponding `ActionTarget` for policy enforcement.
    pub fn target(&self) -> crate::app::ActionTarget {
        match self {
            AgentTool::FsWrite { .. } => crate::app::ActionTarget::FsWrite,
            AgentTool::FsRead { .. } | AgentTool::FsList { .. } => crate::app::ActionTarget::FsRead,
            
            AgentTool::SysExec { .. } => crate::app::ActionTarget::SysExec,
            
            AgentTool::BrowserNavigate { .. } => crate::app::ActionTarget::BrowserNavigate,
            AgentTool::BrowserExtract => crate::app::ActionTarget::BrowserExtract,
            AgentTool::BrowserClick { .. } => crate::app::ActionTarget::Custom("browser::click".into()), // Not a standard target yet

            AgentTool::GuiClick { .. } => crate::app::ActionTarget::GuiClick,
            AgentTool::GuiType { .. } => crate::app::ActionTarget::GuiType,
            
            // [FIX] Changed from "chat::reply" to "chat__reply" to match policy rule
            AgentTool::ChatReply { .. } => crate::app::ActionTarget::Custom("chat__reply".into()),

            AgentTool::Computer(action) => match action {
                ComputerAction::Type { .. } | ComputerAction::Key { .. } => crate::app::ActionTarget::GuiType,
                ComputerAction::MouseMove { .. } => crate::app::ActionTarget::GuiMouseMove,
                ComputerAction::LeftClick => crate::app::ActionTarget::GuiClick,
                ComputerAction::LeftClickDrag { .. } => crate::app::ActionTarget::GuiClick, 
                ComputerAction::Screenshot => crate::app::ActionTarget::GuiScreenshot,
                ComputerAction::CursorPosition => crate::app::ActionTarget::Custom("computer::cursor".into()),
            },
            
            AgentTool::CommerceCheckout { .. } => crate::app::ActionTarget::CommerceCheckout,

            // Meta-tools map to custom targets
            AgentTool::AgentDelegate { .. } => crate::app::ActionTarget::Custom("agent__delegate".into()),
            AgentTool::AgentAwait { .. } => crate::app::ActionTarget::Custom("agent__await_result".into()),
            AgentTool::AgentPause { .. } => crate::app::ActionTarget::Custom("agent__pause".into()),
            AgentTool::AgentComplete { .. } => crate::app::ActionTarget::Custom("agent__complete".into()),
            
            AgentTool::Dynamic(val) => {
                 // Try to infer name if possible, else unknown
                 if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                     crate::app::ActionTarget::Custom(name.to_string())
                 } else {
                     crate::app::ActionTarget::Custom("unknown".into())
                 }
            }
        }
    }
}