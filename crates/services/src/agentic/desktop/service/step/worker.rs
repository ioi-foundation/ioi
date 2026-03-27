use crate::agentic::desktop::keys::get_state_key;
use crate::agentic::desktop::service::lifecycle::load_worker_assignment;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::desktop::utils::persist_agent_state;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use ioi_types::error::TransactionError;

#[derive(Debug, Clone)]
pub struct WorkerExecutionResult {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub attempts: u8,
}

pub async fn execute_worker_step(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    rules: &ActionRules,
    worker_session_id: [u8; 32],
    tool: AgentTool,
    max_retries: u8,
) -> Result<WorkerExecutionResult, TransactionError> {
    let key = get_state_key(&worker_session_id);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "Worker session not found: {}",
            hex::encode(worker_session_id)
        ))
    })?;
    let mut worker_state: AgentState = codec::from_bytes_canonical(&bytes)?;
    let os_driver = service.os_driver.clone();
    let worker_assignment =
        load_worker_assignment(state, worker_session_id).map_err(TransactionError::Invalid)?;

    let mut output: Option<String> = None;
    let mut error: Option<String> = None;
    let mut success = false;
    let mut attempts: u8 = 0;

    if let Some(assignment) = worker_assignment.as_ref() {
        let tool_name = tool.name_string();
        if !assignment.allowed_tools.is_empty()
            && !assignment
                .allowed_tools
                .iter()
                .any(|allowed| allowed == &tool_name)
        {
            let failure = format!(
                "ERROR_CLASS=PolicyBlocked Worker playbook disallows tool '{}'. Allowed tools: {}.",
                tool_name,
                assignment.allowed_tools.join(", ")
            );
            worker_state.step_count = worker_state.step_count.saturating_add(1);
            worker_state.status = AgentStatus::Failed(failure.clone());
            persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;
            return Ok(WorkerExecutionResult {
                success: false,
                output: None,
                error: Some(failure),
                attempts: 0,
            });
        }
    }

    // A delegated worker must never stay Running because of infrastructure gaps.
    // If no OS driver is configured, mark this worker failed and return a terminal result
    // so the parent planner can complete deterministically instead of retry-spawning.
    let Some(os_driver) = os_driver else {
        worker_state.step_count = worker_state.step_count.saturating_add(1);
        worker_state.status = AgentStatus::Failed("OS driver missing".to_string());
        persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;
        return Ok(WorkerExecutionResult {
            success: false,
            output: None,
            error: Some("OS driver missing".to_string()),
            attempts: 0,
        });
    };

    for attempt in 0..=max_retries {
        attempts = attempt.saturating_add(1);
        match service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool.clone(),
                worker_session_id,
                worker_state.step_count,
                worker_state.last_screen_phash.unwrap_or([0u8; 32]),
                rules,
                &worker_state,
                &os_driver,
                None,
            )
            .await
        {
            Ok((step_success, history_entry, step_error, _step_visual_hash)) => {
                output = history_entry;
                error = step_error;
                if step_success {
                    success = true;
                    break;
                }
            }
            Err(err) => {
                error = Some(err.to_string());
            }
        }
        worker_state.consecutive_failures = worker_state.consecutive_failures.saturating_add(1);
    }

    worker_state.step_count = worker_state.step_count.saturating_add(1);
    worker_state.status = if success {
        AgentStatus::Completed(output.clone())
    } else {
        AgentStatus::Failed(
            error
                .clone()
                .unwrap_or_else(|| "worker step failed".to_string()),
        )
    };
    persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;

    Ok(WorkerExecutionResult {
        success,
        output,
        error,
        attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::execute_worker_step;
    use crate::agentic::desktop::keys::get_state_key;
    use crate::agentic::desktop::service::lifecycle::{
        persist_worker_assignment, resolve_worker_assignment,
    };
    use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use crate::agentic::rules::ActionRules;
    use async_trait::async_trait;
    use image::{ImageBuffer, ImageFormat, Rgba};
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateAccess;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::{AccountId, ChainId, ContextSlice};
    use ioi_types::codec;
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, HashMap};
    use std::io::Cursor;
    use std::sync::Arc;

    #[derive(Clone)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
            img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
            let mut bytes = Vec::new();
            img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
                .map_err(|e| VmError::HostError(format!("mock PNG encode failed: {}", e)))?;
            Ok(bytes)
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            self.capture_screen(None).await
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Ok("<root/>".to_string())
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ContextSlice, VmError> {
            Ok(ContextSlice {
                slice_id: [0u8; 32],
                frame_id: 0,
                chunks: vec![b"<root/>".to_vec()],
                mhnsw_root: [0u8; 32],
                traversal_proof: None,
                intent_id: [0u8; 32],
            })
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_worker_state(session_id: [u8; 32]) -> AgentState {
        AgentState {
            session_id,
            goal: "Inspect host environment and available timer surfaces".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 4,
            last_action_type: None,
            parent_session_id: Some([9u8; 32]),
            child_session_ids: Vec::new(),
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
            pending_search_completion: None,
            planner_state: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_os_driver_marks_worker_failed_instead_of_leaving_running() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let runtime = Arc::new(MockInferenceRuntime);
        let mut service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime,
        );
        service.os_driver = None;

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let worker_session_id = [0x11; 32];
        let key = get_state_key(&worker_session_id);
        let worker_state = build_worker_state(worker_session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");

        let services_dir = ServiceDirectory::new(vec![]);
        let call_context = ServiceCallContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(0),
            signer_account_id: AccountId::default(),
            services: &services_dir,
            simulation: false,
            is_internal: false,
        };

        let result = execute_worker_step(
            &service,
            &mut state,
            call_context,
            &ActionRules::default(),
            worker_session_id,
            ioi_types::app::agentic::AgentTool::OsLaunchApp {
                app_name: "calculator".to_string(),
            },
            1,
        )
        .await
        .expect("worker execution should return terminal result");

        assert!(!result.success);
        assert_eq!(result.attempts, 0);
        assert_eq!(result.error.as_deref(), Some("OS driver missing"));

        let bytes = state
            .get(&key)
            .expect("state get")
            .expect("worker state should exist");
        let updated: AgentState = codec::from_bytes_canonical(&bytes).expect("decode worker state");
        assert!(matches!(updated.status, AgentStatus::Failed(_)));
        assert_eq!(updated.step_count, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verifier_playbook_blocks_disallowed_worker_tool_execution() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let runtime = Arc::new(MockInferenceRuntime);
        let mut service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime,
        );
        service.os_driver = None;

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let worker_session_id = [0x22; 32];
        let key = get_state_key(&worker_session_id);
        let worker_state = build_worker_state(worker_session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        let assignment = resolve_worker_assignment(
            worker_session_id,
            1,
            90,
            "Verify whether the receipt proves the claimed postcondition.",
            None,
            Some("verifier"),
            Some("postcondition_audit"),
            None,
            None,
            None,
            None,
        );
        persist_worker_assignment(&mut state, worker_session_id, &assignment)
            .expect("persist worker assignment");

        let services_dir = ServiceDirectory::new(vec![]);
        let call_context = ServiceCallContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(0),
            signer_account_id: AccountId::default(),
            services: &services_dir,
            simulation: false,
            is_internal: false,
        };

        let result = execute_worker_step(
            &service,
            &mut state,
            call_context,
            &ActionRules::default(),
            worker_session_id,
            ioi_types::app::agentic::AgentTool::Dynamic(serde_json::json!({
                "tool_name": "model__responses",
                "input": [{ "role": "user", "content": "audit the receipt" }]
            })),
            assignment.max_retries,
        )
        .await
        .expect("worker execution should return terminal result");

        assert!(!result.success);
        assert_eq!(result.attempts, 0);
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Worker playbook disallows tool 'model__responses'"));
    }
}
