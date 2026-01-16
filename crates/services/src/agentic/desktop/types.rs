use ioi_types::app::action::ApprovalToken;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed(Option<String>),
    Failed(String),
    Paused(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentState {
    pub session_id: [u8; 32],
    pub goal: String,
    pub history: Vec<String>,
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
}

#[derive(Encode, Decode)]
pub struct StartAgentParams {
    pub session_id: [u8; 32],
    pub goal: String,
    pub max_steps: u32,
    pub parent_session_id: Option<[u8; 32]>,
    pub initial_budget: u64,
}

#[derive(Encode, Decode)]
pub struct StepAgentParams {
    pub session_id: [u8; 32],
}

#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    pub session_id: [u8; 32],
    pub approval_token: Option<ApprovalToken>,
}