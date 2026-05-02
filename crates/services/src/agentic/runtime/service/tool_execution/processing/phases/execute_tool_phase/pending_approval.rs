use super::*;

pub(super) struct PendingApprovalContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub final_visual_phash: [u8; 32],
    pub current_tool_name: &'a str,
    pub tool: &'a AgentTool,
    pub tool_call_result: &'a str,
    pub retry_intent_hash: Option<&'a str>,
    pub intent_hash: &'a str,
    pub approval_hash_hex: &'a str,
    pub verification_checks: &'a mut Vec<String>,
}

pub(super) struct PendingApprovalOutcome {
    pub policy_decision: String,
    pub success: bool,
    pub error_msg: Option<String>,
    pub is_gated: bool,
    pub is_lifecycle_action: bool,
}

pub(super) async fn handle_pending_approval(
    ctx: PendingApprovalContext<'_, '_>,
) -> Result<PendingApprovalOutcome, TransactionError> {
    let PendingApprovalContext {
        service,
        state,
        agent_state,
        rules,
        session_id,
        block_height,
        block_timestamp_ns,
        final_visual_phash,
        current_tool_name,
        tool,
        tool_call_result,
        retry_intent_hash,
        intent_hash,
        approval_hash_hex,
        verification_checks,
    } = ctx;

    let mut policy_decision = "require_approval".to_string();
    let success;
    let mut error_msg = None;
    let mut is_gated = true;
    let mut is_lifecycle_action = true;

    let tool_jcs =
        serde_jcs::to_vec(tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
        TransactionError::Invalid(format!(
            "Failed to hash pending approval tool payload: {}",
            e
        ))
    })?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(tool_hash_bytes.as_ref());

    let action_fingerprint = sha256(&tool_jcs)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new());
    let effective_rules = crate::agentic::policy::augment_workspace_filesystem_policy(
        rules,
        Some(agent_state.working_directory.as_str()),
    );
    let policy_hash_bytes = serde_jcs::to_vec(&effective_rules)
        .ok()
        .and_then(|canonical| sha256(&canonical).ok())
        .ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=DeterminismBoundary Failed to hash pending approval policy"
                    .to_string(),
            )
        })?;
    let mut policy_hash = [0u8; 32];
    policy_hash.copy_from_slice(policy_hash_bytes.as_ref());
    state.insert(
        &crate::agentic::runtime::keys::get_approval_policy_hash_key(&session_id, &hash_arr),
        &policy_hash,
    )?;
    let root_retry_hash = retry_intent_hash.unwrap_or(intent_hash);
    if let Ok(bytes) = hex::decode(approval_hash_hex) {
        if bytes.len() == 32 {
            let mut decision_hash = [0u8; 32];
            decision_hash.copy_from_slice(&bytes);
            if let Some(request) = build_pii_review_request_for_tool(
                service,
                rules,
                session_id,
                tool,
                decision_hash,
                block_timestamp_ns / 1_000_000,
            )
            .await?
            {
                persist_pii_review_request(state, &request)?;
                emit_pii_review_requested(service, &request);
            }
        }
    }
    let incident_before = load_incident_state(state, &session_id)?;
    let incident_stage_before = incident_before
        .as_ref()
        .map(|incident| incident.stage.clone())
        .unwrap_or_else(|| "None".to_string());

    let approval_directive = register_pending_approval(
        state,
        rules,
        agent_state,
        session_id,
        root_retry_hash,
        current_tool_name,
        &tool_jcs,
        &action_fingerprint,
        approval_hash_hex,
    )?;
    let incident_after = load_incident_state(state, &session_id)?;
    let incident_stage_after = incident_after
        .as_ref()
        .map(|incident| incident.stage.clone())
        .unwrap_or_else(|| "None".to_string());
    verification_checks.push(format!(
        "approval_suppressed_single_pending={}",
        matches!(
            approval_directive,
            ApprovalDirective::SuppressDuplicatePrompt
        )
    ));
    verification_checks.push(format!(
        "incident_id_stable={}",
        match (incident_before.as_ref(), incident_after.as_ref()) {
            (Some(before), Some(after)) => before.incident_id == after.incident_id,
            _ => true,
        }
    ));
    verification_checks.push(format!("incident_stage_before={}", incident_stage_before));
    verification_checks.push(format!("incident_stage_after={}", incident_stage_after));

    agent_state.pending_tool_jcs = Some(tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    agent_state.pending_request_nonce = Some(agent_state.step_count as u64);
    agent_state.pending_visual_hash = Some(final_visual_phash);
    agent_state.pending_tool_call = Some(tool_call_result.to_string());
    agent_state.last_screen_phash = Some(final_visual_phash);
    agent_state.status = AgentStatus::Paused(
        install_approval_pause_message(tool).unwrap_or_else(|| "Waiting for approval".to_string()),
    );

    if let Some(incident_state) = load_incident_state(state, &session_id)? {
        if incident_state.active {
            log::info!(
                "incident.approval_intercepted session={} incident_id={} root_tool={} gated_tool={}",
                hex::encode(&session_id[..4]),
                incident_state.incident_id,
                incident_state.root_tool_name,
                current_tool_name
            );
        }
    }

    match approval_directive {
        ApprovalDirective::PromptUser => {
            let msg = format!(
                "System: Action halted by Agency Firewall (Hash: {}). Requesting authorization.",
                approval_hash_hex
            );
            let sys_msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: msg,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &sys_msg, block_height)
                .await?;
            success = true;
        }
        ApprovalDirective::SuppressDuplicatePrompt => {
            let sys_msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content:
                    "System: Approval already pending for this incident/action. Waiting for your decision."
                        .to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &sys_msg, block_height)
                .await?;
            success = true;
        }
        ApprovalDirective::PauseLoop => {
            policy_decision = "denied".to_string();
            success = false;
            let loop_msg = format!(
                "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                approval_hash_hex
            );
            error_msg = Some(loop_msg.clone());
            agent_state.status = AgentStatus::Paused(
                "Approval loop detected for the same incident/action. Automatic retries paused."
                    .to_string(),
            );
            let sys_msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: format!(
                    "System: {} Please approve, deny, or change policy settings.",
                    loop_msg
                ),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &sys_msg, block_height)
                .await?;
            is_gated = true;
            is_lifecycle_action = true;
        }
    }

    Ok(PendingApprovalOutcome {
        policy_decision,
        success,
        error_msg,
        is_gated,
        is_lifecycle_action,
    })
}

fn install_approval_pause_message(tool: &AgentTool) -> Option<String> {
    let summary = install_resolution_summary_for_tool(tool)?;
    let display = summary.display_name.as_deref().unwrap_or("software");
    let manager = summary.manager.as_deref().unwrap_or("auto");
    let source_kind = summary.source_kind.as_deref().unwrap_or("resolved_source");
    if summary.stage == "unresolved" {
        return Some(format!(
            "Install source unresolved: {} ({})",
            display, source_kind
        ));
    }
    Some(format!(
        "Awaiting install approval: {} via {} ({})",
        display, manager, source_kind
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::execution::system::software_install_plan_ref_for_request;
    use ioi_types::app::agentic::SoftwareInstallRequestFrame;

    fn software_install_execute_plan_tool(
        target_text: &str,
        manager_preference: Option<&str>,
    ) -> AgentTool {
        let request = SoftwareInstallRequestFrame {
            target_text: target_text.to_string(),
            target_kind: None,
            manager_preference: manager_preference.map(str::to_string),
            launch_after_install: None,
            provenance: Some("test".to_string()),
        };
        AgentTool::SoftwareInstallExecutePlan {
            plan_ref: software_install_plan_ref_for_request(&request),
        }
    }

    #[test]
    fn pending_install_approval_status_uses_resolution_summary() {
        let tool = software_install_execute_plan_tool("generic tool", Some("apt"));

        assert_eq!(
            install_approval_pause_message(&tool).as_deref(),
            Some("Awaiting install approval: generic tool via apt-get (package_manager)")
        );
    }

    #[test]
    fn pending_unknown_install_status_is_resolution_blocker() {
        let tool = software_install_execute_plan_tool("snorflepaint", Some("auto"));

        assert_eq!(
            install_approval_pause_message(&tool).as_deref(),
            Some("Install source unresolved: snorflepaint (unknown_target)")
        );
    }
}
