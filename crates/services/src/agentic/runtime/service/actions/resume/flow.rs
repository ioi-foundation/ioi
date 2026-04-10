use super::phases::{
    run_approval_validation_phase, run_execution_timer_phase, run_lifecycle_status_phase,
    run_visual_prechecks_phase, ExecutionTimerPhaseContext, ExecutionTimerPhaseData,
    LifecycleStatusPhaseContext, VisualPrecheckPhaseContext, VisualPrecheckPhaseData,
    VisualPrecheckPhaseResult,
};
use super::*;

pub(super) struct ResumePendingActionFlowContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub call_context: ServiceCallContext<'a>,
}

pub(super) async fn resume_pending_action_flow(
    ctx: ResumePendingActionFlowContext<'_, '_>,
) -> Result<(), TransactionError> {
    let ResumePendingActionFlowContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        block_timestamp_ns,
        call_context,
    } = ctx;

    let pre_state_summary = build_state_summary(agent_state);
    let routing_decision = TierRoutingDecision {
        tier: agent_state.current_tier,
        reason_code: "resume_preserve_tier",
        source_failure: latest_failure_class(agent_state),
    };
    let mut policy_decision = "approved".to_string();
    let mut verification_checks = Vec::new();

    let approval = run_approval_validation_phase(
        service,
        state,
        agent_state,
        session_id,
        block_timestamp_ns,
        &routing_decision,
        pre_state_summary.step_index,
        &mut verification_checks,
    )
    .await?;

    let tool_jcs = approval.tool_jcs;
    let tool_hash = approval.tool_hash;
    let tool = approval.tool;
    let tool_name = approval.tool_name;
    let action_json = approval.action_json;
    let intent_hash = approval.intent_hash;
    let retry_intent_hash = approval.retry_intent_hash;
    let command_scope = approval.command_scope;
    let rules = approval.rules;
    let scoped_exception_override_hash = approval.scoped_exception_override_hash;
    let explicit_pii_deny = approval.explicit_pii_deny;
    let pii_request_present = approval.pii_request_present;
    let os_driver = approval.os_driver;
    let pending_vhash = approval.pending_vhash;

    let visual_result = run_visual_prechecks_phase(VisualPrecheckPhaseContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        pending_vhash,
        tool: &tool,
        os_driver: &os_driver,
        explicit_pii_deny,
        pii_request_present,
        verification_checks: &mut verification_checks,
    })
    .await?;

    let VisualPrecheckPhaseData {
        precheck_error,
        log_visual_hash,
    } = match visual_result {
        VisualPrecheckPhaseResult::Continue(data) => data,
        VisualPrecheckPhaseResult::EarlyReturn => return Ok(()),
    };

    let execution = run_execution_timer_phase(ExecutionTimerPhaseContext {
        service,
        state,
        agent_state,
        os_driver: &os_driver,
        tool,
        rules: &rules,
        session_id,
        tool_hash,
        pending_vhash,
        scoped_exception_override_hash,
        precheck_error,
        log_visual_hash,
        command_scope,
        step_index: pre_state_summary.step_index,
        block_height,
        call_context,
        verification_checks: &mut verification_checks,
        policy_decision: &mut policy_decision,
    })
    .await;

    let ExecutionTimerPhaseData {
        tool,
        success,
        out,
        err,
        log_visual_hash,
    } = execution;

    run_lifecycle_status_phase(LifecycleStatusPhaseContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        pre_state_summary,
        routing_decision,
        policy_decision,
        verification_checks: &mut verification_checks,
        tool,
        tool_name,
        tool_jcs,
        tool_hash,
        pending_vhash,
        action_json,
        intent_hash,
        retry_intent_hash,
        rules,
        command_scope,
        success,
        out,
        err,
        log_visual_hash,
    })
    .await
}
