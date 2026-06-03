use super::super::file_observation::record_file_read_observation;
use super::*;
use crate::agentic::runtime::connectors::{
    connector_id_for_tool_name, connector_success_condition_verifier_bindings,
};
use crate::agentic::runtime::service::tool_execution::command_contract::contract_requires_success_condition_with_rules;
use crate::agentic::runtime::trajectory::{
    workspace_change_record_from_tool, WorkspaceChangeRecord,
};

fn record_browser_marker_receipt(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    evidence: &str,
) {
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        key,
        evidence.to_string(),
    );
    verification_checks.push(execution_evidence_key(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        key,
        true,
        evidence,
        None,
        None,
        synthesized_payload_hash,
    );
}

fn record_browser_marker_postcondition(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    evidence: &str,
) {
    record_success_condition(&mut agent_state.tool_execution_log, key);
    verification_checks.push(success_condition_key(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        key,
        true,
        evidence,
        None,
        None,
        synthesized_payload_hash,
    );
}

pub(super) fn workspace_edit_receipt_details(
    tool: &AgentTool,
    step_index: u32,
) -> Option<(String, String)> {
    match tool {
        AgentTool::FsWrite { path, .. } => {
            let tool_name = "file__write";
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some((
                tool_name.to_string(),
                format!("step={step_index};tool={tool_name};path={path}"),
            ))
        }
        AgentTool::FsPatch { path, .. } => {
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some((
                "file__edit".to_string(),
                format!("step={step_index};tool=file__edit;path={path}"),
            ))
        }
        AgentTool::FsMultiPatch { path, .. } => {
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some((
                "file__multi_edit".to_string(),
                format!("step={step_index};tool=file__multi_edit;path={path}"),
            ))
        }
        _ => None,
    }
}

pub(super) fn workspace_read_receipt_details(tool: &AgentTool, step_index: u32) -> Option<String> {
    match tool {
        AgentTool::FsRead { path } => {
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some(format!("step={step_index};tool=file__read;path={path}"))
        }
        AgentTool::FsView { path, .. } => {
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some(format!("step={step_index};tool=file__view;path={path}"))
        }
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            let path = path.trim();
            let regex = regex.trim();
            if path.is_empty() || regex.is_empty() {
                return None;
            }
            let file_pattern = file_pattern
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("*");
            Some(format!(
                "step={step_index};tool=file__search;path={path};regex={regex};file_pattern={file_pattern}"
            ))
        }
        _ => None,
    }
}

pub(crate) fn workspace_change_lifecycle_receipt_details(
    tool: &AgentTool,
    history_entry: Option<&str>,
) -> Option<(&'static str, &'static str, String)> {
    let (receipt_name, tool_name) = match tool {
        AgentTool::WorkspaceChangeStatus { .. } => {
            ("workspace_change_status", "workspace_change__status")
        }
        AgentTool::WorkspaceChangeAccept { .. } => {
            ("workspace_change_accepted", "workspace_change__accept")
        }
        AgentTool::WorkspaceChangeReject { .. } => {
            ("workspace_change_rejected", "workspace_change__reject")
        }
        AgentTool::WorkspaceChangeRollback { .. } => {
            ("workspace_change_rolled_back", "workspace_change__rollback")
        }
        _ => return None,
    };
    let evidence = history_entry?.trim();
    if evidence.is_empty() {
        return None;
    }
    if matches!(
        tool,
        AgentTool::WorkspaceChangeAccept { .. }
            | AgentTool::WorkspaceChangeReject { .. }
            | AgentTool::WorkspaceChangeRollback { .. }
    ) && serde_json::from_str::<WorkspaceChangeRecord>(evidence).is_err()
    {
        return None;
    }
    Some((receipt_name, tool_name, evidence.to_string()))
}

fn install_resolution_receipt_evidence(verification_checks: &[String]) -> Option<String> {
    let mut fields = verification_checks
        .iter()
        .map(|check| check.trim())
        .filter_map(|check| check.strip_prefix("software_install."))
        .filter(|field| !field.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    (!fields.is_empty()).then(|| fields.join(";"))
}

fn install_approval_receipt_evidence(agent_state: &AgentState) -> Option<String> {
    let grant = agent_state.pending_approval.as_ref()?;
    let grant_ref = grant
        .artifact_hash()
        .map(|hash| format!("sha256:{}", hex::encode(hash)))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    Some(format!(
        "approval_grant_ref={};request_hash=sha256:{};policy_hash=sha256:{};authority_id=sha256:{}",
        grant_ref,
        hex::encode(grant.request_hash),
        hex::encode(grant.policy_hash),
        hex::encode(grant.authority_id)
    ))
}

pub(super) fn record_install_success_contract_receipts(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    history_entry: Option<&str>,
) {
    if let Some(evidence) = install_resolution_receipt_evidence(verification_checks) {
        record_execution_evidence_with_value(
            &mut agent_state.tool_execution_log,
            "install_resolution",
            evidence.clone(),
        );
        verification_checks.push(execution_evidence_key("install_resolution"));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "resolution",
            "install_resolution",
            true,
            &evidence,
            Some("install_resolver"),
            Some("resolved"),
            Some("software_install_resolution"),
            None,
            Some("software.install.execute".to_string()),
            synthesized_payload_hash.clone(),
        );
    }

    if let Some(evidence) = install_approval_receipt_evidence(agent_state) {
        record_execution_evidence_with_value(
            &mut agent_state.tool_execution_log,
            "approval",
            evidence.clone(),
        );
        verification_checks.push(execution_evidence_key("approval"));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "approval",
            "approval",
            true,
            &evidence,
            Some("approval_grant"),
            Some("approved"),
            Some("signed_approval"),
            None,
            Some("agency_firewall".to_string()),
            synthesized_payload_hash.clone(),
        );
    }

    let verification_evidence = format!(
        "verified_local_app_available=true;tool_output_chars={}",
        history_entry
            .map(|entry| entry.chars().count())
            .unwrap_or(0)
    );
    record_success_condition(
        &mut agent_state.tool_execution_log,
        "verified_local_app_available",
    );
    verification_checks.push(success_condition_key("verified_local_app_available"));
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        "verified_local_app_available",
        true,
        &verification_evidence,
        Some("install_verifier"),
        Some("true"),
        Some("bool"),
        None,
        Some("software.install.execute".to_string()),
        synthesized_payload_hash,
    );
}

pub(super) fn record_workspace_read_receipt(
    agent_state: &mut AgentState,
    tool: &AgentTool,
    step_index: u32,
) {
    let Some(evidence) = workspace_read_receipt_details(tool, step_index) else {
        return;
    };
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        evidence.clone(),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read",
        evidence.clone(),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "file_context",
        evidence,
    );
    record_file_read_observation(
        &mut agent_state.tool_execution_log,
        &agent_state.working_directory,
        tool,
        step_index,
    );
}

pub(super) fn record_workspace_edit_receipt(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    tool: &AgentTool,
) {
    let Some((tool_name, evidence)) = workspace_edit_receipt_details(tool, step_index) else {
        return;
    };

    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_edit_applied",
        evidence.clone(),
    );
    if let Some(change_record) = workspace_change_record_from_tool(
        tool,
        "applied",
        agent_state
            .pending_tool_hash
            .map(|hash| format!("pending_tool_hash:{}", hex::encode(hash)))
            .or_else(|| {
                synthesized_payload_hash
                    .clone()
                    .map(|hash| format!("payload_hash:{hash}"))
            }),
        Some(evidence.clone()),
    ) {
        if let Ok(change_evidence) = serde_json::to_string(&change_record) {
            record_execution_evidence_with_value(
                &mut agent_state.tool_execution_log,
                "workspace_change_applied",
                change_evidence.clone(),
            );
            verification_checks.push(execution_evidence_key("workspace_change_applied"));
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "execution",
                "workspace_change_applied",
                true,
                &change_evidence,
                None,
                Some(tool_name.clone()),
                synthesized_payload_hash.clone(),
            );
        }
    }
    verification_checks.push(execution_evidence_key("workspace_edit_applied"));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        "workspace_edit_applied",
        true,
        &evidence,
        None,
        Some(tool_name),
        synthesized_payload_hash,
    );
}

pub(super) fn record_workspace_change_lifecycle_receipt(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    tool: &AgentTool,
    history_entry: Option<&str>,
) {
    let Some((receipt_name, tool_name, evidence)) =
        workspace_change_lifecycle_receipt_details(tool, history_entry)
    else {
        return;
    };
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        receipt_name,
        evidence.clone(),
    );
    verification_checks.push(execution_evidence_key(receipt_name));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        receipt_name,
        true,
        &evidence,
        None,
        Some(tool_name.to_string()),
        synthesized_payload_hash,
    );
}

fn parse_find_text_found(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("result")
        .and_then(|result| result.get("found"))
        .and_then(|found| found.as_bool())
}

fn parse_selection_non_empty(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("selection")
        .and_then(|selection| selection.get("selected_text"))
        .and_then(|selected_text| selected_text.as_str())
        .map(|selected_text| !selected_text.is_empty())
}

fn parse_key_is_chord(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("key")
        .and_then(|key| key.get("is_chord"))
        .and_then(|is_chord| is_chord.as_bool())
}

fn parse_clipboard_text_length(history_entry: Option<&str>) -> Option<u64> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("clipboard")
        .and_then(|clipboard| clipboard.get("text_length"))
        .and_then(|text_length| text_length.as_u64())
}

fn parse_wait_condition_met(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("wait")
        .and_then(|wait| wait.get("met"))
        .and_then(|met| met.as_bool())
}

fn compact_browser_receipt_evidence(history_entry: Option<&str>) -> String {
    let raw = history_entry
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .unwrap_or("browser_action_success=true");

    let normalized = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| serde_jcs::to_vec(&value).ok())
        .unwrap_or_else(|| raw.as_bytes().to_vec());

    sha256(&normalized)
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string())
}

pub(super) fn record_browser_success_markers(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    history_entry: Option<&str>,
    trace_visual_hash: Option<[u8; 32]>,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
) {
    let evidence = compact_browser_receipt_evidence(history_entry);

    match tool {
        AgentTool::BrowserHover { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_hover",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_pointer_target_acquired",
                "browser_pointer_target_acquired=true",
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_hover_applied",
                "browser_hover_applied=true",
            );
        }
        AgentTool::BrowserMoveMouse { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_pointer_move",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_pointer_position_updated",
                "browser_pointer_position_updated=true",
            );
        }
        AgentTool::BrowserMouseDown { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_mouse_down",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_pointer_pressed",
                "browser_pointer_pressed=true",
            );
        }
        AgentTool::BrowserMouseUp { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_mouse_up",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_pointer_released",
                "browser_pointer_released=true",
            );
        }
        AgentTool::BrowserSelectText { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_text_selection",
                evidence.as_str(),
            );
            if parse_selection_non_empty(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_text_selected",
                    "browser_text_selected=true",
                );
            }
        }
        AgentTool::BrowserKey { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_key_input",
                evidence.as_str(),
            );
            if parse_key_is_chord(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_key_chord_applied",
                    "browser_key_chord_applied=true",
                );
            }
        }
        AgentTool::BrowserCopySelection {} => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_clipboard_copy",
                evidence.as_str(),
            );
            if parse_clipboard_text_length(history_entry).unwrap_or(0) > 0 {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_clipboard_populated",
                    "browser_clipboard_populated=true",
                );
            }
        }
        AgentTool::BrowserPasteClipboard { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_clipboard_paste",
                evidence.as_str(),
            );
            if parse_clipboard_text_length(history_entry).unwrap_or(0) > 0 {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_clipboard_inserted",
                    "browser_clipboard_inserted=true",
                );
            }
        }
        AgentTool::BrowserUploadFile { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_upload_file",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_file_attached",
                "browser_file_attached=true",
            );
        }
        AgentTool::BrowserSelectDropdown { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_dropdown_selected",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_dropdown_selection_applied",
                "browser_dropdown_selection_applied=true",
            );
        }
        AgentTool::BrowserGoBack { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_history_back",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_navigation_changed",
                "browser_navigation_changed=true",
            );
        }
        AgentTool::BrowserWait { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_wait",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_wait_completed",
                "browser_wait_completed=true",
            );
            if parse_wait_condition_met(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    None,
                    "browser_wait_condition_met",
                    "browser_wait_condition_met=true",
                );
            }
        }
        AgentTool::BrowserTabSwitch { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_tab_switch",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_active_tab_selected",
                "browser_active_tab_selected=true",
            );
        }
        AgentTool::BrowserTabClose { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_tab_close",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_tab_closed",
                "browser_tab_closed=true",
            );
        }
        AgentTool::BrowserFindText { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_find_text",
                evidence.as_str(),
            );
            if parse_find_text_found(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_text_found",
                    "browser_text_found=true",
                );
            }
        }
        AgentTool::BrowserCanvasSummary { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_canvas_summary",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_canvas_observation",
                "browser_canvas_observation=true",
            );
        }
        AgentTool::BrowserScreenshot { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_screenshot",
                evidence.as_str(),
            );
            if trace_visual_hash.is_some() {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_visual_observation",
                    "browser_visual_observation=true",
                );
            }
        }
        AgentTool::BrowserDropdownOptions { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_dropdown_options",
                evidence.as_str(),
            );
        }
        AgentTool::BrowserTabList {} => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_tab_list",
                evidence.as_str(),
            );
        }
        _ => {}
    }
}

async fn verify_non_command_success_conditions(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    current_tool_name: &str,
    tool_args: &serde_json::Value,
    history_entry: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), String> {
    if agent_state.resolved_intent.is_none() {
        return Ok(());
    }
    if !contract_requires_success_condition_with_rules(agent_state, rules, "mail.reply.completed") {
        return Ok(());
    }
    let connector_id = agent_state
        .resolved_intent
        .as_ref()
        .and_then(|resolved| resolved.provider_selection.as_ref())
        .and_then(|selection| selection.selected_connector_id.as_deref())
        .or_else(|| connector_id_for_tool_name(current_tool_name))
        .ok_or_else(|| {
            "ERROR_CLASS=GroundingMissing Postcondition verification requires a selected connector."
                .to_string()
        })?;
    let verifier = connector_success_condition_verifier_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=VerificationMissing No postcondition verifier is registered for connector '{}'.",
                connector_id
            )
        })?;
    let history_entry = history_entry.ok_or_else(|| {
        "ERROR_CLASS=VerificationMissing Postcondition verification requires structured tool output."
            .to_string()
    })?;
    let Some(proof) = (verifier.verify)(agent_state, current_tool_name, tool_args, history_entry)
        .await
        .map_err(|error| format!("ERROR_CLASS=PostconditionFailed {}", error))?
    else {
        return Err(
            "ERROR_CLASS=VerificationMissing Connector verifier returned no postcondition proof."
                .to_string(),
        );
    };

    for evidence in proof.evidence {
        record_success_condition(&mut agent_state.tool_execution_log, &evidence.key);
        verification_checks.push(success_condition_key(&evidence.key));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "verification",
            &evidence.key,
            true,
            &evidence.evidence,
            Some("connector_verifier"),
            evidence.observed_value.as_deref(),
            evidence.evidence_type.as_deref(),
            None,
            evidence.provider_id,
            synthesized_payload_hash.clone(),
        );
    }

    Ok(())
}

pub(crate) async fn record_non_command_success_receipts(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    current_tool_name: &str,
    tool_args: &serde_json::Value,
    history_entry: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), String> {
    record_execution_evidence(&mut agent_state.tool_execution_log, "execution");
    verification_checks.push(execution_evidence_key("execution"));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        "execution",
        true,
        "execution_invocation_completed=true",
        None,
        None,
        synthesized_payload_hash.clone(),
    );

    verify_non_command_success_conditions(
        service,
        agent_state,
        rules,
        current_tool_name,
        tool_args,
        history_entry,
        session_id,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash.clone(),
        verification_checks,
    )
    .await?;

    record_execution_evidence(&mut agent_state.tool_execution_log, "verification");
    verification_checks.push(execution_evidence_key("verification"));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        "verification",
        true,
        "verification_receipt_recorded=true",
        None,
        None,
        synthesized_payload_hash,
    );

    Ok(())
}
