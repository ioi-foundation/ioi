use super::*;

mod apply_post_execution_guards;
mod execute_tool_phase;
mod finalize_action_processing;

pub(super) use apply_post_execution_guards::apply_post_execution_guards;
pub(super) use execute_tool_phase::execute_tool_phase;
pub(crate) use execute_tool_phase::{
    emit_completion_gate_status_event, emit_execution_contract_receipt_event,
    emit_execution_contract_receipt_event_with_observation, record_non_command_success_receipts,
    resolved_intent_id,
};
pub(super) use finalize_action_processing::finalize_action_processing;

pub(super) struct ActionProcessingState {
    pub policy_decision: String,
    pub action_payload: serde_json::Value,
    pub intent_hash: String,
    pub retry_intent_hash: Option<String>,
    pub success: bool,
    pub error_msg: Option<String>,
    pub is_gated: bool,
    pub is_lifecycle_action: bool,
    pub current_tool_name: String,
    pub history_entry: Option<String>,
    pub action_output: Option<String>,
    pub trace_visual_hash: Option<[u8; 32]>,
    pub executed_tool_jcs: Option<Vec<u8>>,
    pub failure_class: Option<FailureClass>,
    pub stop_condition_hit: bool,
    pub escalation_path: Option<String>,
    pub remediation_queued: bool,
    pub verification_checks: Vec<String>,
    pub awaiting_sudo_password: bool,
    pub awaiting_clarification: bool,
    pub command_probe_completed: bool,
    pub invalid_tool_call_fail_fast: bool,
    pub invalid_tool_call_bootstrap_web: bool,
    pub invalid_tool_call_fail_fast_mailbox: bool,
    pub terminal_chat_reply_output: Option<String>,
}

impl ActionProcessingState {
    pub fn new(raw_tool_output: &str) -> Self {
        Self {
            policy_decision: "allowed".to_string(),
            action_payload: json!({
                "raw_tool_output": raw_tool_output,
            }),
            intent_hash: "unknown".to_string(),
            retry_intent_hash: None,
            success: false,
            error_msg: None,
            is_gated: false,
            is_lifecycle_action: false,
            current_tool_name: "unknown".to_string(),
            history_entry: None,
            action_output: None,
            trace_visual_hash: None,
            executed_tool_jcs: None,
            failure_class: None,
            stop_condition_hit: false,
            escalation_path: None,
            remediation_queued: false,
            verification_checks: Vec::new(),
            awaiting_sudo_password: false,
            awaiting_clarification: false,
            command_probe_completed: false,
            invalid_tool_call_fail_fast: false,
            invalid_tool_call_bootstrap_web: false,
            invalid_tool_call_fail_fast_mailbox: false,
            terminal_chat_reply_output: None,
        }
    }
}

pub(super) struct ExecuteToolPhaseContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub call_context: ServiceCallContext<'a>,
    pub tool: AgentTool,
    pub tool_args: serde_json::Value,
    pub rules: &'a ActionRules,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub final_visual_phash: [u8; 32],
    pub req_hash_hex: String,
    pub tool_call_result: String,
    pub pre_state_summary: RoutingStateSummary,
}

pub(super) struct ApplyPostExecutionGuardsContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub tool_call_result: String,
    pub final_visual_phash: [u8; 32],
}

pub(super) struct FinalizeActionProcessingContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub strategy_used: String,
    pub tool_call_result: String,
    pub final_visual_phash: [u8; 32],
    pub key: Vec<u8>,
    pub routing_decision: TierRoutingDecision,
    pub pre_state_summary: RoutingStateSummary,
    pub tool_version: &'static str,
}
