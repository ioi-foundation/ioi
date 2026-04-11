use crate::agentic::runtime::keys::get_incident_key;
use crate::agentic::runtime::middleware;
use crate::agentic::runtime::service::step::incident::IncidentState;
use crate::agentic::runtime::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(super) const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

fn pending_install_available(agent_state: &AgentState) -> bool {
    agent_state
        .pending_tool_jcs
        .as_ref()
        .and_then(|raw| serde_json::from_slice::<AgentTool>(raw).ok())
        .map(|tool| matches!(tool, AgentTool::SysInstallPackage { .. }))
        .unwrap_or(false)
}

pub(super) fn is_waiting_for_sudo_password(status: &AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Paused(reason) if reason.eq_ignore_ascii_case("Waiting for sudo password")
    )
}

pub(super) fn status_mentions_sudo_password(status: &AgentStatus) -> bool {
    match status {
        AgentStatus::Paused(reason) | AgentStatus::Failed(reason) => {
            let lower = reason.to_ascii_lowercase();
            lower.contains("sudo password") || lower.contains("administrative privileges")
        }
        _ => false,
    }
}

pub(super) fn incident_waiting_for_sudo_password(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let incident_key = get_incident_key(&session_id);
    let Some(incident_bytes) = state.get(&incident_key)? else {
        return Ok(false);
    };
    let incident: IncidentState = codec::from_bytes_canonical(&incident_bytes)?;
    Ok(incident
        .resolution_action
        .eq_ignore_ascii_case("wait_for_sudo_password"))
}

fn restore_pending_install_from_tool_call(
    agent_state: &mut AgentState,
) -> Result<bool, TransactionError> {
    if agent_state.pending_tool_jcs.is_some() {
        return Ok(true);
    }
    let Some(raw) = agent_state.pending_tool_call.as_deref() else {
        return Ok(false);
    };
    let parsed = match middleware::normalize_tool_call(raw) {
        Ok(tool) => tool,
        Err(_) => return Ok(false),
    };
    if !matches!(parsed, AgentTool::SysInstallPackage { .. }) {
        return Ok(false);
    }

    let tool_jcs = serde_jcs::to_vec(&parsed).map_err(|e| {
        TransactionError::Serialization(format!("Failed to encode pending install tool: {}", e))
    })?;
    let hash_bytes = sha256(&tool_jcs).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes.as_ref());

    agent_state.pending_tool_jcs = Some(tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    if agent_state.pending_visual_hash.is_none() {
        agent_state.pending_visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    }
    agent_state.pending_approval = None;
    Ok(true)
}

pub(super) fn maybe_restore_pending_install_from_incident(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    agent_state: &mut AgentState,
) -> Result<(), TransactionError> {
    if pending_install_available(agent_state) {
        return Ok(());
    }

    // A prior approval or recovery pass can leave stale non-install pending metadata
    // behind. Drop it so sudo retry resume can reconstruct the canonical install tool.
    if agent_state.pending_tool_jcs.is_some() {
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
    }

    if restore_pending_install_from_tool_call(agent_state)? {
        return Ok(());
    }

    let incident_key = get_incident_key(&session_id);
    let Some(incident_bytes) = state.get(&incident_key)? else {
        return Ok(());
    };
    let incident: IncidentState = codec::from_bytes_canonical(&incident_bytes)?;
    let waiting_for_sudo = incident
        .resolution_action
        .eq_ignore_ascii_case("wait_for_sudo_password");
    let is_install_root = incident
        .root_tool_name
        .eq_ignore_ascii_case("package__install")
        || incident
            .root_tool_name
            .eq_ignore_ascii_case("sys::install_package")
        || incident.root_tool_name.ends_with("install_package");
    if !waiting_for_sudo || !is_install_root || incident.root_tool_jcs.is_empty() {
        return Ok(());
    }

    let hash_bytes =
        sha256(&incident.root_tool_jcs).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes.as_ref());
    agent_state.pending_tool_jcs = Some(incident.root_tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    agent_state.pending_tool_call = agent_state
        .pending_tool_jcs
        .as_ref()
        .and_then(|raw| String::from_utf8(raw.clone()).ok());
    if agent_state.pending_visual_hash.is_none() {
        agent_state.pending_visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    }
    agent_state.pending_approval = None;
    agent_state.execution_queue.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::keys::get_incident_key;
    use crate::agentic::runtime::service::step::anti_loop::FailureClass;
    use crate::agentic::runtime::service::step::incident::IncidentState;
    use crate::agentic::runtime::service::step::ontology::{
        GateState, IncidentStage, IntentClass, StrategyName, StrategyNode,
    };
    use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use ioi_api::state::{StateAccess, StateScanIter};
    use ioi_types::app::ActionRequest;
    use ioi_types::error::StateError;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            for key in deletes {
                self.delete(key)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let items = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| {
                    Ok((
                        Arc::<[u8]>::from(key.clone().into_boxed_slice()),
                        Arc::<[u8]>::from(value.clone().into_boxed_slice()),
                    ))
                })
                .collect::<Vec<_>>();
            Ok(Box::new(items.into_iter()))
        }
    }

    fn test_agent_state(session_id: [u8; 32]) -> AgentState {
        AgentState {
            session_id,
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Paused("Waiting for sudo password".to_string()),
            step_count: 3,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: Some(
                serde_json::to_string(&AgentTool::SysExec {
                    command: "echo".to_string(),
                    args: vec!["stale".to_string()],
                    stdin: None,
                    detach: false,
                })
                .expect("stale tool json"),
            ),
            pending_tool_jcs: Some(
                serde_jcs::to_vec(&AgentTool::SysExec {
                    command: "echo".to_string(),
                    args: vec!["stale".to_string()],
                    stdin: None,
                    detach: false,
                })
                .expect("stale tool jcs"),
            ),
            pending_tool_hash: Some([1u8; 32]),
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: Some([4u8; 32]),
            execution_queue: vec![ActionRequest {
                target: ioi_types::app::ActionTarget::SysExec,
                params: vec![],
                context: ioi_types::app::ActionContext {
                    agent_id: "desktop_agent".to_string(),
                    session_id: Some(session_id),
                    window_id: None,
                },
                nonce: 7,
            }],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn sudo_retry_restores_install_from_incident_when_pending_tool_is_stale() {
        let session_id = [7u8; 32];
        let install_tool = AgentTool::SysInstallPackage {
            package: "sl".to_string(),
            manager: Some("apt-get".to_string()),
        };
        let install_jcs = serde_jcs::to_vec(&install_tool).expect("install tool jcs");
        let incident = IncidentState {
            active: true,
            incident_id: "incident-test".to_string(),
            root_retry_hash: "retry-hash".to_string(),
            root_tool_jcs: install_jcs.clone(),
            root_tool_name: "package__install".to_string(),
            intent_class: IntentClass::InstallDependency.as_str().to_string(),
            root_failure_class: FailureClass::PermissionOrApprovalRequired
                .as_str()
                .to_string(),
            root_error: Some("sudo: a password is required".to_string()),
            stage: IncidentStage::PausedForUser.as_str().to_string(),
            strategy_name: StrategyName::InstallRecovery.as_str().to_string(),
            strategy_cursor: StrategyNode::PauseForUser.as_str().to_string(),
            visited_node_fingerprints: vec![],
            pending_gate: None,
            gate_state: GateState::Cleared.as_str().to_string(),
            resolution_action: "wait_for_sudo_password".to_string(),
            transitions_used: 0,
            max_transitions: 3,
            started_step: 3,
            pending_remedy_fingerprint: None,
            pending_remedy_tool_jcs: None,
            retry_enqueued: false,
        };

        let incident_key = get_incident_key(&session_id);
        let mut state = MockState {
            data: BTreeMap::from([(
                incident_key,
                codec::to_bytes_canonical(&incident).expect("incident bytes"),
            )]),
        };
        let mut agent_state = test_agent_state(session_id);

        maybe_restore_pending_install_from_incident(&mut state, session_id, &mut agent_state)
            .expect("restore pending install");

        assert_eq!(agent_state.pending_tool_jcs, Some(install_jcs));
        let restored_call = agent_state
            .pending_tool_call
            .clone()
            .expect("restored pending tool call");
        let restored_json: serde_json::Value =
            serde_json::from_str(&restored_call).expect("restored tool call json");
        assert_eq!(restored_json["name"], "package__install");
        assert_eq!(restored_json["arguments"]["package"], "sl");
        assert_eq!(restored_json["arguments"]["manager"], "apt-get");
        assert_eq!(agent_state.pending_visual_hash, Some([4u8; 32]));
        assert!(agent_state.execution_queue.is_empty());
    }
}
