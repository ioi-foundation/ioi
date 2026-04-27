use crate::agentic::runtime::service::step::action::{
    emit_execution_contract_receipt_event, execution_evidence_key_for,
    record_execution_evidence_for_value, RuntimeEvidence,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use ioi_types::app::agentic::AgentTool;

fn queue_workspace_read_receipt(step_index: u32, tool: &AgentTool) -> Option<String> {
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
        _ => None,
    }
}

fn queue_workspace_edit_receipt(step_index: u32, tool: &AgentTool) -> Option<(String, String)> {
    match tool {
        AgentTool::FsWrite {
            path, line_number, ..
        } => {
            let tool_name = if line_number.is_some() {
                "file__replace_line"
            } else {
                "file__write"
            };
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some((
                tool_name.to_string(),
                format!("step={step_index};tool={tool_name};path={path}"),
            ))
        }
        _ => None,
    }
}

pub(super) fn record_queue_workspace_success_receipts(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    verification_checks: &mut Vec<String>,
) {
    if let Some(evidence) = queue_workspace_read_receipt(step_index, tool) {
        record_execution_evidence_for_value(
            &mut agent_state.tool_execution_log,
            RuntimeEvidence::WorkspaceReadObserved,
            evidence.clone(),
        );
        verification_checks.push(execution_evidence_key_for(
            RuntimeEvidence::WorkspaceReadObserved,
        ));
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            RuntimeEvidence::WorkspaceReadObserved.as_str(),
            true,
            &evidence,
            None,
            Some("file__read".to_string()),
            None,
        );
    }

    if let Some((tool_name, evidence)) = queue_workspace_edit_receipt(step_index, tool) {
        record_execution_evidence_for_value(
            &mut agent_state.tool_execution_log,
            RuntimeEvidence::WorkspaceEditApplied,
            evidence.clone(),
        );
        verification_checks.push(execution_evidence_key_for(
            RuntimeEvidence::WorkspaceEditApplied,
        ));
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            RuntimeEvidence::WorkspaceEditApplied.as_str(),
            true,
            &evidence,
            None,
            Some(tool_name),
            None,
        );
    }
}
