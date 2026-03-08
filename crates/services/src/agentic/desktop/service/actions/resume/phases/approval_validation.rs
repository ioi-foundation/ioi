use super::super::*;
use ioi_api::vm::drivers::os::OsDriver;
use std::sync::Arc;

pub(crate) struct ApprovalValidationPhaseData {
    pub tool_jcs: Vec<u8>,
    pub tool_hash: [u8; 32],
    pub tool: AgentTool,
    pub tool_name: String,
    pub action_json: String,
    pub intent_hash: String,
    pub retry_intent_hash: String,
    pub command_scope: bool,
    pub rules: ActionRules,
    pub scoped_exception_override_hash: Option<[u8; 32]>,
    pub explicit_pii_deny: bool,
    pub pii_request_present: bool,
    pub os_driver: Arc<dyn OsDriver>,
    pub pending_vhash: [u8; 32],
}

pub(crate) async fn run_approval_validation_phase(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_timestamp_ns: u64,
    routing_decision: &TierRoutingDecision,
    pre_state_step_index: u32,
    verification_checks: &mut Vec<String>,
) -> Result<ApprovalValidationPhaseData, TransactionError> {
    let tool_jcs = agent_state
        .pending_tool_jcs
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing pending_tool_jcs".into()))?
        .clone();
    let tool_hash = agent_state
        .pending_tool_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_tool_hash".into(),
        ))?;

    let tool: AgentTool = serde_json::from_slice(&tool_jcs)
        .map_err(|e| TransactionError::Serialization(format!("Corrupt pending tool: {}", e)))?;
    let (tool_name, tool_args) = canonical_tool_identity(&tool);
    let action_json = serde_json::to_string(&tool).unwrap_or_else(|_| "{}".to_string());
    let intent_hash = canonical_intent_hash(
        &tool_name,
        &tool_args,
        routing_decision.tier,
        pre_state_step_index,
        env!("CARGO_PKG_VERSION"),
    );
    let retry_intent_hash = canonical_retry_intent_hash(
        &tool_name,
        &tool_args,
        routing_decision.tier,
        env!("CARGO_PKG_VERSION"),
    );
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    if let Some(route_label) = capability_route_label(&tool, &tool_name) {
        verification_checks.push(format!("capability_route_selected={}", route_label));
        if command_scope {
            record_provider_selection_receipts(
                &mut agent_state.tool_execution_log,
                verification_checks,
                &tool_name,
                &route_label,
            );
        }
    }
    if is_command_execution_provider_tool(&tool) {
        if agent_state.command_history.is_empty() {
            verification_checks.push("capability_execution_phase=discovery".to_string());
            if command_scope {
                mark_execution_receipt(&mut agent_state.tool_execution_log, "host_discovery");
                verification_checks.push(receipt_marker("host_discovery"));
            }
        }
        verification_checks.push("capability_execution_phase=execution".to_string());
    }

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let mut rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let block_timestamp_ms = block_timestamp_ns / 1_000_000;
    let block_timestamp_secs = block_timestamp_ns / 1_000_000_000;
    let incident_state = load_incident_state(state, &session_id)?;
    let pending_gate_hash = incident_state
        .as_ref()
        .and_then(|incident| incident.pending_gate.as_ref())
        .and_then(|pending| hashing::parse_hash_hex(&pending.request_hash));
    let expected_request_hash = resolve_expected_request_hash(pending_gate_hash, tool_hash);
    let request_key = pii::review::request(&expected_request_hash);
    let pii_request: Option<PiiReviewRequest> = state
        .get(&request_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok());

    let approval = approvals::validate_and_apply(
        service,
        state,
        agent_state,
        session_id,
        &tool,
        expected_request_hash,
        pii_request.as_ref(),
        block_timestamp_ms,
        block_timestamp_secs,
        &mut rules,
        verification_checks,
    )
    .await?;
    let scoped_exception_override_hash = approval.scoped_exception_override_hash;
    let explicit_pii_deny = approval.explicit_pii_deny;

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;
    let pending_vhash = agent_state
        .pending_visual_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_visual_hash".into(),
        ))?;

    Ok(ApprovalValidationPhaseData {
        tool_jcs,
        tool_hash,
        tool,
        tool_name,
        action_json,
        intent_hash,
        retry_intent_hash,
        command_scope,
        rules,
        scoped_exception_override_hash,
        explicit_pii_deny,
        pii_request_present: pii_request.is_some(),
        os_driver,
        pending_vhash,
    })
}
