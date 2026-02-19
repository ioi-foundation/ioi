// Path: crates/services/src/agentic/desktop/types.rs

use ioi_types::app::action::ApprovalToken;
use ioi_types::app::agentic::ResolvedIntentState;
use ioi_types::app::ActionRequest;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::VecDeque;

pub const MAX_COMMAND_HISTORY: usize = 20;
pub const MAX_PROMPT_HISTORY: usize = 5;
pub const COMMAND_HISTORY_SANITIZED_PLACEHOLDER: &str = "[REDACTED_PII]";
pub const MESSAGE_SANITIZED_PLACEHOLDER: &str = "[REDACTED_PII]";
pub const DEFAULT_MESSAGE_REDACTION_VERSION: &str = "v1";
pub const DEFAULT_MESSAGE_PRIVACY_POLICY_ID: &str = "desktop-agent/default";
pub const DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct InteractionTarget {
    pub app_hint: Option<String>,
    pub title_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum ToolCallStatus {
    Pending,
    Approved,
    Executed(String),
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed(Option<String>),
    Failed(String),
    Paused(String),
    Terminated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub enum AgentMode {
    #[default]
    Agent,
    Chat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub enum ExecutionTier {
    #[default]
    DomHeadless,
    VisualBackground,
    VisualForeground,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SwarmContext {
    pub swarm_id: [u8; 32],
    pub role: String,
    pub allowed_delegates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PendingSearchReadSummary {
    pub url: String,
    pub title: Option<String>,
    pub excerpt: String,
}

fn default_pending_search_min_sources() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PendingSearchCompletion {
    pub query: String,
    pub url: String,
    pub started_step: u32,
    pub started_at_ms: u64,
    pub deadline_ms: u64,
    pub candidate_urls: Vec<String>,
    #[serde(default)]
    pub candidate_source_hints: Vec<PendingSearchReadSummary>,
    pub attempted_urls: Vec<String>,
    pub blocked_urls: Vec<String>,
    pub successful_reads: Vec<PendingSearchReadSummary>,
    #[serde(default = "default_pending_search_min_sources")]
    pub min_sources: u32,
}

impl Default for PendingSearchReadSummary {
    fn default() -> Self {
        Self {
            url: String::new(),
            title: None,
            excerpt: String::new(),
        }
    }
}

impl Default for PendingSearchCompletion {
    fn default() -> Self {
        Self {
            query: String::new(),
            url: String::new(),
            started_step: 0,
            started_at_ms: 0,
            deadline_ms: 0,
            candidate_urls: Vec::new(),
            candidate_source_hints: Vec::new(),
            attempted_urls: Vec::new(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources: default_pending_search_min_sources(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct CommandExecution {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timestamp_ms: u64,
    pub step_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct MessagePrivacyMetadata {
    #[serde(default)]
    pub redaction_version: String,
    #[serde(default)]
    pub sensitive_fields_mask: Vec<String>,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub policy_version: String,
    #[serde(default)]
    pub scrubbed_for_model_hash: Option<String>,
}

impl Default for MessagePrivacyMetadata {
    fn default() -> Self {
        Self {
            redaction_version: String::new(),
            sensitive_fields_mask: Vec::new(),
            policy_id: String::new(),
            policy_version: String::new(),
            scrubbed_for_model_hash: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RecordedMessage {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub trace_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub raw_content: String,
    #[serde(default)]
    pub scrubbed_for_model: String,
    #[serde(default)]
    pub scrubbed_for_scs: String,

    #[serde(default)]
    pub raw_reference: Option<String>,

    #[serde(default)]
    pub privacy_metadata: MessagePrivacyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentState {
    pub session_id: [u8; 32],
    pub goal: String,

    // [REMOVED] pub history: Vec<ChatMessage>,
    pub transcript_root: [u8; 32],

    pub status: AgentStatus,
    pub step_count: u32,
    pub max_steps: u32,
    pub last_action_type: Option<String>,
    pub parent_session_id: Option<[u8; 32]>,
    pub child_session_ids: Vec<[u8; 32]>,
    pub budget: u64,
    pub tokens_used: u64,
    pub consecutive_failures: u8,
    pub pending_approval: Option<ApprovalToken>,
    pub pending_tool_call: Option<String>,

    // [NEW] Canonical Resume State
    // Stores the exact JCS bytes of the AgentTool that was intercepted.
    #[serde(default)]
    pub pending_tool_jcs: Option<Vec<u8>>,

    // The hash of the tool JCS, which must match the ApprovalToken.
    #[serde(default)]
    pub pending_tool_hash: Option<[u8; 32]>,

    // The visual context hash active when the action was intercepted.
    #[serde(default)]
    pub pending_visual_hash: Option<[u8; 32]>,

    #[serde(default)]
    pub recent_actions: Vec<String>,
    #[serde(default)]
    pub mode: AgentMode,
    #[serde(default)]
    pub current_tier: ExecutionTier,
    #[serde(default)]
    pub last_screen_phash: Option<[u8; 32]>,
    #[serde(default)]
    pub execution_queue: Vec<ActionRequest>,

    #[serde(default)]
    pub pending_search_completion: Option<PendingSearchCompletion>,

    #[serde(default)]
    pub active_skill_hash: Option<[u8; 32]>,

    #[serde(default)]
    pub tool_execution_log: BTreeMap<String, ToolCallStatus>,

    #[serde(default)]
    pub visual_som_map: Option<BTreeMap<u32, (i32, i32, i32, i32)>>,

    // [NEW] Map SoM ID -> Semantic Element ID (e.g. 7 -> "btn_calculator_7")
    // This allows upgrading ephemeral numeric IDs to robust semantic lookups on resume.
    #[serde(default)]
    pub visual_semantic_map: Option<BTreeMap<u32, String>>,

    #[serde(default)]
    pub swarm_context: Option<SwarmContext>,

    #[serde(default)]
    pub target: Option<InteractionTarget>,

    /// Global resolver output used by step/action/incident routing.
    #[serde(default)]
    pub resolved_intent: Option<ResolvedIntentState>,

    /// True when the session is paused waiting for intent clarification.
    #[serde(default)]
    pub awaiting_intent_clarification: bool,

    /// Persistent working directory used by `sys__exec`.
    #[serde(default = "default_working_directory")]
    pub working_directory: String,

    #[serde(default)]
    pub command_history: VecDeque<CommandExecution>,

    // [NEW] The name of the Application Lens used during the last perception step.
    // Required to re-resolve element IDs (e.g. "btn_submit") to coordinates during execution.
    #[serde(default)]
    pub active_lens: Option<String>,
}

fn default_working_directory() -> String {
    ".".to_string()
}

#[derive(Encode, Decode)]
pub struct StartAgentParams {
    pub session_id: [u8; 32],
    pub goal: String,
    pub max_steps: u32,
    pub parent_session_id: Option<[u8; 32]>,
    pub initial_budget: u64,
    pub mode: AgentMode,
}

#[derive(Encode, Decode)]
pub struct StepAgentParams {
    pub session_id: [u8; 32],
}

#[derive(Encode, Decode)]
pub struct PostMessageParams {
    pub session_id: [u8; 32],
    pub role: String,
    pub content: String,
}

#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    pub session_id: [u8; 32],
    pub approval_token: Option<ApprovalToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SessionSummary {
    pub session_id: [u8; 32],
    pub title: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SessionResult {
    pub session_id: [u8; 32],
    pub result: String,
    pub cost_incurred: u64,
    pub success: bool,
    pub timestamp: u64,
}
