// Path: crates/services/src/agentic/desktop/types.rs

use ioi_types::app::action::ApprovalToken;
use ioi_types::app::ActionRequest;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap; // [FIX] Added BTreeMap for deterministic codec

// [NEW] Track status of tool calls to enforce idempotency.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum ToolCallStatus {
    Pending,
    Approved,
    Executed(String), // Result hash or summary
    Failed(String),
}

// [FIX] Removed Copy trait because String fields are not Copy
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed(Option<String>),
    Failed(String),
    Paused(String),
}

// [NEW] Define Agent Mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub enum AgentMode {
    #[default]
    Agent, // Default: Uses tools, autonomous
    Chat,  // Chat only: No tools, conversational
}

// [NEW] Execution Tiers for Hybrid Architecture (Progressive Escalation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub enum ExecutionTier {
    #[default]
    DomHeadless,      // Level 1: Fast, text-based (DOM + Selectors)
    VisualBackground, // Level 2: Visual, but non-interruptive (Tab Screenshot + Synthetic Click)
    VisualForeground, // Level 3: Full OS Control (Monitor Screenshot + Physical Mouse)
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentState {
    pub session_id: [u8; 32],
    pub goal: String,
    
    // [REMOVED] pub history: Vec<ChatMessage>,

    /// The cryptographic commitment to the conversation history stored in SCS.
    /// This is the hash of the most recent Frame added to this session.
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
    #[serde(default)]
    pub recent_actions: Vec<String>,
    
    // [NEW] Track the mode in state
    #[serde(default)]
    pub mode: AgentMode,
    
    // [NEW] Track the current execution tier (Escalation level)
    #[serde(default)]
    pub current_tier: ExecutionTier,

    // [NEW] Visual Interlock State
    // Stores the perceptual hash of the screen state from the *previous* step (Thought Phase).
    // The Executor uses this to verify the screen hasn't changed before executing a click (Action Phase).
    // This prevents TOCTOU (Time-of-Check Time-of-Use) attacks or race conditions (popups).
    #[serde(default)]
    pub last_screen_phash: Option<[u8; 32]>,

    // [NEW] Queue for multi-step macro execution.
    // Drained FIFO (First-In, First-Out).
    // This allows a single "Skill Tool Call" to expand into multiple atomic system actions
    // that are executed sequentially over multiple ticks/blocks, subject to individual policy checks.
    #[serde(default)]
    pub execution_queue: Vec<ActionRequest>,

    // [NEW] Track status of tool calls to enforce idempotency.
    // Key: Hex(RequestHash)
    #[serde(default)]
    pub tool_execution_log: BTreeMap<String, ToolCallStatus>,
}

#[derive(Encode, Decode)]
pub struct StartAgentParams {
    pub session_id: [u8; 32],
    pub goal: String,
    pub max_steps: u32,
    pub parent_session_id: Option<[u8; 32]>,
    pub initial_budget: u64,
    // [NEW] Allow specifying mode at start
    pub mode: AgentMode,
}

#[derive(Encode, Decode)]
pub struct StepAgentParams {
    pub session_id: [u8; 32],
    // [FIX] Removed optional user input, now handled via PostMessageParams
}

// [NEW] Params for posting a message to the session (Inbox Pattern)
#[derive(Encode, Decode)]
pub struct PostMessageParams {
    pub session_id: [u8; 32],
    pub role: String, // "user"
    pub content: String,
}

#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    pub session_id: [u8; 32],
    pub approval_token: Option<ApprovalToken>,
}

// [NEW] Struct for persistent session history index
// Used by the backend to display the sidebar list without hydrating full state
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SessionSummary {
    pub session_id: [u8; 32],
    pub title: String,
    pub timestamp: u64,
}