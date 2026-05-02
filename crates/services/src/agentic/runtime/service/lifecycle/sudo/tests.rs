use super::*;
use crate::agentic::runtime::execution::system::software_install_plan_ref_for_request;
use crate::agentic::runtime::keys::get_incident_key;
use crate::agentic::runtime::service::decision_loop::ontology::{
    GateState, IncidentStage, IntentClass, StrategyName, StrategyNode,
};
use crate::agentic::runtime::service::recovery::anti_loop::FailureClass;
use crate::agentic::runtime::service::recovery::incident::IncidentState;
use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use ioi_api::state::{StateAccess, StateScanIter};
use ioi_types::app::agentic::{AgentTool, SoftwareInstallRequestFrame};
use ioi_types::app::ActionRequest;
use ioi_types::error::StateError;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

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
                wait_ms_before_async: None,
                detach: false,
            })
            .expect("stale tool json"),
        ),
        pending_tool_jcs: Some(
            serde_jcs::to_vec(&AgentTool::SysExec {
                command: "echo".to_string(),
                args: vec!["stale".to_string()],
                stdin: None,
                wait_ms_before_async: None,
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
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
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
    let install_tool = software_install_execute_plan_tool("sl", Some("apt-get"));
    let install_jcs = serde_jcs::to_vec(&install_tool).expect("install tool jcs");
    let incident = IncidentState {
        active: true,
        incident_id: "incident-test".to_string(),
        root_retry_hash: "retry-hash".to_string(),
        root_tool_jcs: install_jcs.clone(),
        root_tool_name: "software_install__execute_plan".to_string(),
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
    assert_eq!(restored_json["name"], "software_install__execute_plan");
    assert!(restored_json["arguments"]["plan_ref"]
        .as_str()
        .is_some_and(|value| value.starts_with("software-install-plan:v1:")));
    assert_eq!(agent_state.pending_visual_hash, Some([4u8; 32]));
    assert!(agent_state.execution_queue.is_empty());
}
