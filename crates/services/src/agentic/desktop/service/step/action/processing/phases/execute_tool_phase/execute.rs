use super::contracts::{bootstrap_contract, duplicate_execution_state};
use super::duplicate::{handle_duplicate_command_execution, DuplicateExecutionContext};
use super::pending_approval::{handle_pending_approval, PendingApprovalContext};
use super::precheck::run_execution_prechecks;
use super::rrsa::{record_rrsa_action_evidence, RrsaContext};
use super::success_path::{handle_execution_success, ExecutionSuccessContext};
use super::timeout::execute_tool_with_optional_timeout;
use super::timer_contract::{
    prepare_timer_contract, restore_pending_visual_context, TimerContractContext,
};
use super::*;

pub(crate) async fn execute_tool_phase(
    ctx: ExecuteToolPhaseContext<'_, '_>,
    state_in: ActionProcessingState,
) -> Result<ActionProcessingState, TransactionError> {
    let ExecuteToolPhaseContext {
        service,
        state,
        agent_state,
        call_context,
        tool,
        tool_args,
        rules,
        session_id,
        block_height,
        block_timestamp_ns,
        final_visual_phash,
        req_hash_hex,
        tool_call_result,
        pre_state_summary,
    } = ctx;

    let ActionProcessingState {
        mut policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        mut success,
        mut error_msg,
        mut is_gated,
        mut is_lifecycle_action,
        mut current_tool_name,
        mut history_entry,
        mut action_output,
        mut trace_visual_hash,
        executed_tool_jcs,
        failure_class,
        stop_condition_hit,
        escalation_path,
        remediation_queued,
        mut verification_checks,
        awaiting_sudo_password,
        awaiting_clarification,
        mut command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let mut tool = tool;
    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;
    let action_fingerprint = retry_intent_hash.clone().unwrap_or_default();
    let bootstrap = bootstrap_contract(
        service,
        agent_state,
        &tool,
        &current_tool_name,
        session_id,
        pre_state_summary.step_index,
        &mut verification_checks,
    );
    let command_scope = bootstrap.command_scope;
    let resolved_intent_id = bootstrap.resolved_intent_id;
    let mut synthesized_payload_hash = bootstrap.synthesized_payload_hash;
    let route_label = bootstrap.route_label;
    if agent_state.consecutive_failures > 0 {
        verification_checks.push("determinism_recovery_retry=true".to_string());
        verification_checks.push(format!(
            "determinism_recovery_reason=consecutive_failures={}",
            agent_state.consecutive_failures
        ));
    }
    let (duplicate_command_execution, matching_command_history_entry) = duplicate_execution_state(
        agent_state,
        &tool,
        command_scope,
        pre_state_summary.step_index,
        &action_fingerprint,
        &mut verification_checks,
    );
    if duplicate_command_execution {
        let duplicate_outcome = handle_duplicate_command_execution(DuplicateExecutionContext {
            service,
            agent_state,
            rules,
            tool: &tool,
            matching_command_history_entry,
            command_scope,
            action_fingerprint: &action_fingerprint,
            session_id,
            step_index: pre_state_summary.step_index,
            resolved_intent_id: &resolved_intent_id,
            verification_checks: &mut verification_checks,
        });
        success = duplicate_outcome.success;
        error_msg = duplicate_outcome.error_msg;
        history_entry = duplicate_outcome.history_entry;
        action_output = duplicate_outcome.action_output;
        terminal_chat_reply_output = duplicate_outcome.terminal_chat_reply_output;
        is_lifecycle_action = duplicate_outcome.is_lifecycle_action;
    } else {
        if run_execution_prechecks(
            service,
            agent_state,
            &tool,
            &current_tool_name,
            command_scope,
            &req_hash_hex,
            session_id,
            pre_state_summary.step_index,
            &resolved_intent_id,
            route_label.as_deref(),
            synthesized_payload_hash.clone(),
            &mut verification_checks,
            &mut policy_decision,
            &mut success,
            &mut error_msg,
            &mut history_entry,
            &mut action_output,
        ) {
            let timer_contract = prepare_timer_contract(TimerContractContext {
                service,
                agent_state,
                tool,
                command_scope,
                req_hash_hex: &req_hash_hex,
                session_id,
                step_index: pre_state_summary.step_index,
                resolved_intent_id: &resolved_intent_id,
                verification_checks: &mut verification_checks,
                synthesized_payload_hash,
            });
            tool = timer_contract.tool;
            synthesized_payload_hash = timer_contract.synthesized_payload_hash;
            let should_execute_tool = timer_contract.should_execute_tool;
            if let Some(synth_error) = timer_contract.pre_execution_error {
                success = false;
                error_msg = Some(synth_error.clone());
                history_entry = Some(synth_error.clone());
                action_output = Some(synth_error);
            }

            restore_pending_visual_context(service, agent_state).await;

            if should_execute_tool {
                match execute_tool_with_optional_timeout(
                    service,
                    state,
                    call_context,
                    agent_state,
                    tool.clone(),
                    &current_tool_name,
                    session_id,
                    final_visual_phash,
                    &rules,
                    &os_driver,
                )
                .await
                {
                    Ok(execution_result) => {
                        handle_execution_success(ExecutionSuccessContext {
                            service,
                            state,
                            agent_state,
                            rules,
                            tool: &tool,
                            tool_args: &tool_args,
                            session_id,
                            block_height,
                            block_timestamp_ns,
                            step_index: pre_state_summary.step_index,
                            resolved_intent_id: &resolved_intent_id,
                            synthesized_payload_hash: synthesized_payload_hash.clone(),
                            command_scope,
                            req_hash_hex: &req_hash_hex,
                            retry_intent_hash: retry_intent_hash.as_deref(),
                            success: &mut success,
                            error_msg: &mut error_msg,
                            history_entry: &mut history_entry,
                            action_output: &mut action_output,
                            trace_visual_hash: &mut trace_visual_hash,
                            is_lifecycle_action: &mut is_lifecycle_action,
                            current_tool_name: &mut current_tool_name,
                            terminal_chat_reply_output: &mut terminal_chat_reply_output,
                            verification_checks: &mut verification_checks,
                            command_probe_completed: &mut command_probe_completed,
                            execution_result,
                        })
                        .await?;
                        if let Err(rrsa_error) = record_rrsa_action_evidence(RrsaContext {
                            service,
                            agent_state,
                            tool: &tool,
                            tool_args: &tool_args,
                            session_id,
                            step_index: pre_state_summary.step_index,
                            resolved_intent_id: &resolved_intent_id,
                            synthesized_payload_hash: synthesized_payload_hash.clone(),
                            req_hash_hex: req_hash_hex.as_str(),
                            policy_decision: policy_decision.as_str(),
                            success,
                            error_msg: error_msg.as_deref(),
                            history_entry: history_entry.as_deref(),
                            trace_visual_hash,
                            verification_checks: &mut verification_checks,
                        }) {
                            let msg = format!(
                                "ERROR_CLASS=ActionEnforceability RRSA contract unmet. {}",
                                rrsa_error
                            );
                            success = false;
                            error_msg = Some(msg.clone());
                            history_entry = Some(msg.clone());
                            action_output = Some(msg);
                        }
                    }
                    Err(TransactionError::PendingApproval(h)) => {
                        let pending_approval = handle_pending_approval(PendingApprovalContext {
                            service,
                            state,
                            agent_state,
                            rules,
                            session_id,
                            block_height,
                            block_timestamp_ns,
                            final_visual_phash,
                            current_tool_name: &current_tool_name,
                            tool: &tool,
                            tool_call_result: &tool_call_result,
                            retry_intent_hash: retry_intent_hash.as_deref(),
                            intent_hash: intent_hash.as_str(),
                            approval_hash_hex: &h,
                            verification_checks: &mut verification_checks,
                        })
                        .await?;
                        policy_decision = pending_approval.policy_decision;
                        success = pending_approval.success;
                        error_msg = pending_approval.error_msg;
                        is_gated = pending_approval.is_gated;
                        is_lifecycle_action = pending_approval.is_lifecycle_action;
                    }
                    Err(e) => {
                        success = false;
                        let msg = e.to_string();
                        if msg.to_lowercase().contains("blocked by policy") {
                            policy_decision = "denied".to_string();
                        }
                        error_msg = Some(msg.clone());
                        if !req_hash_hex.is_empty() {
                            agent_state
                                .tool_execution_log
                                .insert(req_hash_hex.clone(), ToolCallStatus::Failed(msg));
                        }
                    }
                }
            }
        }
    }

    Ok(ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        success,
        error_msg,
        is_gated,
        is_lifecycle_action,
        current_tool_name,
        history_entry,
        action_output,
        trace_visual_hash,
        executed_tool_jcs,
        failure_class,
        stop_condition_hit,
        escalation_path,
        remediation_queued,
        verification_checks,
        awaiting_sudo_password,
        awaiting_clarification,
        command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        terminal_chat_reply_output,
    })
}
