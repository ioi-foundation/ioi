use super::*;
use crate::agentic::runtime::execution::system::software_install_plan_ref_for_request;
use crate::agentic::runtime::service::tool_execution::command_contract::{
    PROVIDER_SELECTION_COMMIT_EVIDENCE, VERIFICATION_COMMIT_EVIDENCE,
};
use crate::agentic::runtime::service::tool_execution::{
    execution_evidence_key, record_success_condition,
};
use crate::agentic::runtime::types::{AgentMode, ExecutionTier, ToolCallStatus};
use async_trait::async_trait;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{
    AgentTool, CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    SoftwareInstallRequestFrame,
};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent, RoutingStateSummary};
use ioi_types::error::{StateError, VmError};
use serde_json::json;
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

#[derive(Debug, Default, Clone)]
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

    fn prefix_scan(&self, prefix: &[u8]) -> Result<ioi_api::state::StateScanIter<'_>, StateError> {
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

struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

fn mail_reply_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "mail.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("mail.reply")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: String::new(),
        embedding_model_version: String::new(),
        similarity_function_id: String::new(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: String::new(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn agent_state_with_mail_reply() -> AgentState {
    AgentState {
        session_id: [4u8; 32],
        goal: "send the email".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 10,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::default(),
        current_tier: ExecutionTier::default(),
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(mail_reply_resolved_intent()),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

fn automation_monitor_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "automation.monitor".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("automation.monitor.install")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: String::new(),
        embedding_model_version: String::new(),
        similarity_function_id: String::new(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: String::new(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn install_dependency_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "command.exec.install_dependency".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("command.exec.install_dependency")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: String::new(),
        embedding_model_version: String::new(),
        similarity_function_id: String::new(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: String::new(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn agent_state_with_automation_monitor() -> AgentState {
    AgentState {
        session_id: [7u8; 32],
        goal: "Monitor Hacker News and notify me whenever a post about Web4 or post-quantum cryptography hits the front page.".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 10,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::default(),
        current_tier: ExecutionTier::default(),
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(automation_monitor_resolved_intent()),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

fn agent_state_with_install_dependency() -> AgentState {
    AgentState {
        session_id: [9u8; 32],
        goal: "install cowsay".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 10,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::default(),
        current_tier: ExecutionTier::default(),
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(install_dependency_resolved_intent()),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

fn build_resume_test_service() -> RuntimeAgentService {
    let (tx, _rx) = tokio::sync::broadcast::channel(32);
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
    RuntimeAgentService::new(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        inference,
    )
    .with_memory_runtime(Arc::new(
        MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
    ))
    .with_event_sender(tx)
}

#[test]
fn terminalizes_mail_reply_resume_when_intent_is_mail_reply() {
    let agent_state = agent_state_with_mail_reply();
    assert!(should_terminalize_mail_reply_intent(
        &agent_state,
        "connector__google__gmail_send_email"
    ));
}

#[test]
fn terminalizes_mail_reply_resume_when_only_fallback_provider_actions_remain() {
    let mut agent_state = agent_state_with_mail_reply();
    agent_state.resolved_intent = None;
    agent_state
        .execution_queue
        .push(ioi_types::app::ActionRequest {
            target: ioi_types::app::ActionTarget::Custom(
                "connector__google__gmail_draft_email".to_string(),
            ),
            params: vec![],
            context: ioi_types::app::ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(agent_state.session_id),
                window_id: None,
            },
            nonce: 0,
        });

    assert!(should_terminalize_mail_reply_intent(
        &agent_state,
        "connector__google__gmail_send_email"
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn approved_automation_monitor_resume_terminalizes_instead_of_looping() {
    let service = build_resume_test_service();
    let mut receiver = service
        .event_sender
        .as_ref()
        .expect("event sender")
        .subscribe();
    let mut state = MockState::default();
    let mut agent_state = agent_state_with_automation_monitor();
    let tool = AgentTool::AutomationCreateMonitor {
        title: Some("Hacker News Monitor for Web4 and Post-Quantum Cryptography".to_string()),
        description: Some(
            "Monitor Hacker News for posts about Web4 and post-quantum cryptography.".to_string(),
        ),
        keywords: vec!["Web4".to_string(), "post-quantum cryptography".to_string()],
        interval_seconds: Some(300),
        source_prompt: Some(agent_state.goal.clone()),
    };
    let tool_jcs = serde_jcs::to_vec(&tool).expect("tool jcs");
    let output = concat!(
        "Scheduled workflow: Hacker News Monitor for Web4 and Post-Quantum Cryptography\n",
        "Workflow ID: monitor_hacker_news_cc9364be12aa\n",
        "Poll interval: 300 seconds\n",
        "Source: https://news.ycombinator.com/\n",
        "Keywords: post-quantum cryptography, web4\n",
        "Artifact path: ./ioi-data/automation/artifacts/monitor_hacker_news_cc9364be12aa.json"
    )
    .to_string();
    let mut verification_checks = Vec::new();
    let session_id = agent_state.session_id;
    let current_tier = agent_state.current_tier;
    agent_state.tool_execution_log.insert(
        execution_evidence_key("host_discovery"),
        ToolCallStatus::Executed("/home/test".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key("provider_selection"),
        ToolCallStatus::Executed("automation.monitor.install".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key(PROVIDER_SELECTION_COMMIT_EVIDENCE),
        ToolCallStatus::Executed("sha256:provider-selection".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key("execution"),
        ToolCallStatus::Executed("monitor__create".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key("verification"),
        ToolCallStatus::Executed("automation_monitor_install=true".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key(VERIFICATION_COMMIT_EVIDENCE),
        ToolCallStatus::Executed("sha256:verification".to_string()),
    );
    record_success_condition(&mut agent_state.tool_execution_log, "execution_artifact");

    run_lifecycle_status_phase(LifecycleStatusPhaseContext {
        service: &service,
        state: &mut state,
        agent_state: &mut agent_state,
        session_id,
        block_height: 1,
        pre_state_summary: RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "tool_first".to_string(),
            step_index: 0,
            consecutive_failures: 0,
            target_hint: None,
        },
        routing_decision: TierRoutingDecision {
            tier: current_tier,
            reason_code: "resume_test",
            source_failure: None,
        },
        policy_decision: "approved".to_string(),
        verification_checks: &mut verification_checks,
        tool,
        tool_name: "monitor__create".to_string(),
        tool_jcs,
        tool_hash: [0u8; 32],
        pending_vhash: [0u8; 32],
        action_json: json!({
            "name": "monitor__create",
            "arguments": {
                "interval_seconds": 300,
                "keywords": ["Web4", "post-quantum cryptography"],
            }
        })
        .to_string(),
        intent_hash: "intent-hash".to_string(),
        retry_intent_hash: "retry-intent-hash".to_string(),
        rules: ActionRules::default(),
        command_scope: true,
        success: true,
        out: Some(output.clone()),
        err: None,
        log_visual_hash: [0u8; 32],
    })
    .await
    .expect("resume lifecycle status");

    assert!(matches!(
        agent_state.status,
        AgentStatus::Completed(Some(ref summary)) if summary == &output
    ));
    assert!(agent_state.execution_queue.is_empty());

    let mut saw_chat_reply = false;
    let mut saw_running_automation_result = false;
    while let Ok(event) = receiver.try_recv() {
        if let KernelEvent::AgentActionResult {
            tool_name,
            agent_status,
            ..
        } = event
        {
            if tool_name == "chat__reply" && agent_status == "Completed" {
                saw_chat_reply = true;
            }
            if tool_name == "monitor__create" && agent_status == "Running" {
                saw_running_automation_result = true;
            }
        }
    }

    assert!(saw_chat_reply);
    assert!(!saw_running_automation_result);
}

#[tokio::test(flavor = "current_thread")]
async fn approved_install_resume_terminalizes_instead_of_looping() {
    let service = build_resume_test_service();
    let mut receiver = service
        .event_sender
        .as_ref()
        .expect("event sender")
        .subscribe();
    let mut state = MockState::default();
    let mut agent_state = agent_state_with_install_dependency();
    let tool = software_install_execute_plan_tool("cowsay", Some("apt"));
    let plan_ref = match &tool {
        AgentTool::SoftwareInstallExecutePlan { plan_ref } => plan_ref.clone(),
        _ => unreachable!("test helper returns a software install execute-plan tool"),
    };
    let tool_jcs = serde_jcs::to_vec(&tool).expect("tool jcs");
    let output = "Installed 'cowsay' via 'apt-get' (sudo-password)".to_string();
    let mut verification_checks = Vec::new();
    let session_id = agent_state.session_id;
    let current_tier = agent_state.current_tier;
    agent_state.tool_execution_log.insert(
        execution_evidence_key("host_discovery"),
        ToolCallStatus::Executed("/home/test".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key("provider_selection"),
        ToolCallStatus::Executed("command.exec.install_dependency".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key(PROVIDER_SELECTION_COMMIT_EVIDENCE),
        ToolCallStatus::Executed("sha256:provider-selection".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key("execution"),
        ToolCallStatus::Executed("software_install__execute_plan".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key("verification"),
        ToolCallStatus::Executed("install_package_success=true".to_string()),
    );
    agent_state.tool_execution_log.insert(
        execution_evidence_key(VERIFICATION_COMMIT_EVIDENCE),
        ToolCallStatus::Executed("sha256:verification".to_string()),
    );
    record_success_condition(&mut agent_state.tool_execution_log, "execution_artifact");

    run_lifecycle_status_phase(LifecycleStatusPhaseContext {
        service: &service,
        state: &mut state,
        agent_state: &mut agent_state,
        session_id,
        block_height: 1,
        pre_state_summary: RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "tool_first".to_string(),
            step_index: 0,
            consecutive_failures: 0,
            target_hint: None,
        },
        routing_decision: TierRoutingDecision {
            tier: current_tier,
            reason_code: "resume_test",
            source_failure: None,
        },
        policy_decision: "approved".to_string(),
        verification_checks: &mut verification_checks,
        tool,
        tool_name: "software_install__execute_plan".to_string(),
        tool_jcs,
        tool_hash: [0u8; 32],
        pending_vhash: [0u8; 32],
        action_json: json!({
            "name": "software_install__execute_plan",
            "arguments": {
                "plan_ref": plan_ref,
            }
        })
        .to_string(),
        intent_hash: "intent-hash".to_string(),
        retry_intent_hash: "retry-intent-hash".to_string(),
        rules: ActionRules::default(),
        command_scope: true,
        success: true,
        out: Some(output.clone()),
        err: None,
        log_visual_hash: [0u8; 32],
    })
    .await
    .expect("resume lifecycle status");

    assert!(matches!(
        agent_state.status,
        AgentStatus::Completed(Some(ref summary)) if summary == &output
    ));
    assert!(agent_state.execution_queue.is_empty());

    let mut saw_chat_reply = false;
    let mut saw_running_install_result = false;
    while let Ok(event) = receiver.try_recv() {
        if let KernelEvent::AgentActionResult {
            tool_name,
            agent_status,
            ..
        } = event
        {
            if tool_name == "chat__reply" && agent_status == "Completed" {
                saw_chat_reply = true;
            }
            if tool_name == "software_install__execute_plan" && agent_status == "Running" {
                saw_running_install_result = true;
            }
        }
    }

    assert!(saw_chat_reply);
    assert!(!saw_running_install_result);
}
