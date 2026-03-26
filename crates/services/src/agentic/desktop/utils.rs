// Path: crates/services/src/agentic/desktop/utils.rs

use crate::agentic::desktop::keys::{get_state_key, TRACE_PREFIX};
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;

use image::load_from_memory; // [FIX] Added missing import
use image_hasher::{HashAlg, HasherConfig};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AGENT_STATE_CHECKPOINT_NAME: &str = "desktop.agent_state.v1";

/// Helper to get a string representation of the agent status for event emission.
fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

pub fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32], TransactionError> {
    let img = load_from_memory(image_bytes)
        .map_err(|e| TransactionError::Invalid(format!("Image decode failed: {}", e)))?;
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let hash = hasher.hash_image(&img);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
    Ok(out)
}

pub fn persist_agent_state(
    state: &mut dyn StateAccess,
    key: &[u8],
    agent_state: &AgentState,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
) -> Result<(), TransactionError> {
    let bytes = codec::to_bytes_canonical(agent_state)?;
    state.insert(key, &bytes)?;

    if let Some(memory_runtime) = memory_runtime {
        memory_runtime
            .upsert_checkpoint_blob(agent_state.session_id, AGENT_STATE_CHECKPOINT_NAME, &bytes)
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "Failed to persist agent-state checkpoint: {}",
                    error
                ))
            })?;
    }

    Ok(())
}

pub fn delete_agent_state_checkpoint(
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(memory_runtime) = memory_runtime else {
        return Ok(());
    };

    memory_runtime
        .delete_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "Failed to delete agent-state checkpoint: {}",
                error
            ))
        })?;
    Ok(())
}

pub fn load_agent_state_checkpoint(
    memory_runtime: &MemoryRuntime,
    session_id: [u8; 32],
) -> Result<Option<AgentState>, TransactionError> {
    let Some(bytes) = memory_runtime
        .load_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
        .map_err(|error| {
            TransactionError::Invalid(format!("Failed to load agent-state checkpoint: {}", error))
        })?
    else {
        return Ok(None);
    };

    let agent_state = codec::from_bytes_canonical::<AgentState>(&bytes).map_err(|error| {
        TransactionError::Invalid(format!(
            "Failed to decode agent-state checkpoint: {}",
            error
        ))
    })?;

    if agent_state.session_id != session_id {
        return Err(TransactionError::Invalid(
            "Agent-state checkpoint session mismatch".to_string(),
        ));
    }

    Ok(Some(agent_state))
}

pub fn await_child_session_status_for_inspection(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let child_session_id = parse_child_session_id_hex(child_session_id_hex)?;
    let child_state = if let Some(memory_runtime) = memory_runtime {
        match load_agent_state_checkpoint(memory_runtime.as_ref(), child_session_id) {
            Ok(Some(agent_state)) => agent_state,
            Ok(None) => load_agent_state_from_state(state, child_session_id, child_session_id_hex)?,
            Err(error) => {
                return Err(format!(
                    "ERROR_CLASS=UnexpectedState Failed to load child session '{}' from runtime checkpoint: {}",
                    child_session_id_hex, error
                ));
            }
        }
    } else {
        load_agent_state_from_state(state, child_session_id, child_session_id_hex)?
    };

    match child_state.status {
        AgentStatus::Running | AgentStatus::Idle => Ok("Running".to_string()),
        AgentStatus::Paused(reason) => Ok(format!("Running (paused: {})", reason)),
        AgentStatus::Completed(Some(result)) => Ok(result),
        AgentStatus::Completed(None) => Ok("Completed".to_string()),
        AgentStatus::Failed(reason) => Err(format!(
            "ERROR_CLASS=UnexpectedState Child agent failed: {}",
            reason
        )),
        AgentStatus::Terminated => {
            Err("ERROR_CLASS=UnexpectedState Child agent terminated.".to_string())
        }
    }
}

fn load_agent_state_from_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    let key = get_state_key(&session_id);
    let bytes = state
        .get(&key)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Child state lookup failed: {}",
                error
            )
        })?
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
                child_session_id_hex
            )
        })?;

    codec::from_bytes_canonical::<AgentState>(&bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to decode child session '{}': {}",
            child_session_id_hex, error
        )
    })
}

fn parse_child_session_id_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|error| {
        format!(
            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}': {}",
            input, error
        )
    })?;
    if bytes.len() != 32 {
        return Err(format!(
            "ERROR_CLASS=ToolUnavailable child_session_id_hex '{}' must be 32 bytes (got {}).",
            input,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn goto_trace_log(
    agent_state: &mut AgentState,
    state: &mut dyn StateAccess,
    key: &[u8],
    session_id: [u8; 32],
    visual_hash_arr: [u8; 32],
    user_prompt: String,
    output_str: String,
    action_success: bool,
    action_error: Option<String>,
    action_type: String,
    event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
    skill_hash: Option<[u8; 32]>,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
) -> Result<(), TransactionError> {
    let trace = StepTrace {
        session_id,
        step_index: agent_state.step_count,
        visual_hash: visual_hash_arr,
        full_prompt: user_prompt,
        raw_output: output_str,
        success: action_success,
        error: action_error.clone(),
        cost_incurred: 0,
        fitness_score: None,
        skill_hash,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let trace_key = [
        TRACE_PREFIX,
        session_id.as_slice(),
        &agent_state.step_count.to_le_bytes(),
    ]
    .concat();
    state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

    if let Some(tx) = &event_sender {
        let event = KernelEvent::AgentStep(trace.clone());
        let _ = tx.send(event);
    }

    if let Some(_e) = action_error {
        agent_state.consecutive_failures += 1;
    } else {
        agent_state.consecutive_failures = 0;
    }

    agent_state.last_action_type = Some(action_type);

    if agent_state.step_count >= agent_state.max_steps
        && agent_state.status == AgentStatus::Running
        && agent_state.pending_search_completion.is_none()
    {
        agent_state.status = AgentStatus::Completed(None);

        if let Some(tx) = &event_sender {
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: "system::max_steps_reached".to_string(),
                output: "Max steps reached. Task completed.".to_string(),
                error_class: None,
                agent_status: get_status_str(&agent_state.status),
            });
        }
    }

    persist_agent_state(state, key, agent_state, memory_runtime)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        await_child_session_status_for_inspection, delete_agent_state_checkpoint, get_state_key,
        load_agent_state_checkpoint, persist_agent_state, AGENT_STATE_CHECKPOINT_NAME,
    };
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use ioi_api::state::{StateAccess, StateScanIter};
    use ioi_memory::MemoryRuntime;
    use ioi_types::codec;
    use ioi_types::error::StateError;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    #[derive(Default)]
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
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    fn test_agent_state(session_id: [u8; 32]) -> AgentState {
        AgentState {
            session_id,
            goal: "checkpoint me".to_string(),
            transcript_root: [7u8; 32],
            status: AgentStatus::Running,
            step_count: 3,
            max_steps: 16,
            last_action_type: Some("click".to_string()),
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 2,
            tokens_used: 0,
            consecutive_failures: 1,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
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
    fn persist_agent_state_mirrors_runtime_checkpoint_blob() {
        let session_id = [9u8; 32];
        let checkpoint_key = b"agent::state::test".to_vec();
        let agent_state = test_agent_state(session_id);
        let expected_bytes = codec::to_bytes_canonical(&agent_state).expect("encode agent state");
        let mut state = MockState::default();
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

        persist_agent_state(&mut state, &checkpoint_key, &agent_state, Some(&runtime))
            .expect("persist agent state");

        assert_eq!(
            state.get(&checkpoint_key).expect("state get"),
            Some(expected_bytes.clone())
        );
        assert_eq!(
            runtime
                .load_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
                .expect("load checkpoint"),
            Some(expected_bytes),
        );
    }

    #[test]
    fn delete_agent_state_checkpoint_removes_runtime_blob() {
        let session_id = [4u8; 32];
        let checkpoint_key = b"agent::state::test".to_vec();
        let agent_state = test_agent_state(session_id);
        let mut state = MockState::default();
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

        persist_agent_state(&mut state, &checkpoint_key, &agent_state, Some(&runtime))
            .expect("persist agent state");
        delete_agent_state_checkpoint(Some(&runtime), session_id)
            .expect("delete agent state checkpoint");

        assert_eq!(
            runtime
                .load_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
                .expect("load checkpoint"),
            None,
        );
    }

    #[test]
    fn load_agent_state_checkpoint_decodes_runtime_blob() {
        let session_id = [6u8; 32];
        let checkpoint_key = b"agent::state::test".to_vec();
        let agent_state = test_agent_state(session_id);
        let mut state = MockState::default();
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

        persist_agent_state(&mut state, &checkpoint_key, &agent_state, Some(&runtime))
            .expect("persist agent state");

        let loaded: Option<AgentState> = load_agent_state_checkpoint(runtime.as_ref(), session_id)
            .expect("load agent state checkpoint");

        let loaded = loaded.expect("agent state present");
        assert_eq!(loaded.session_id, agent_state.session_id);
        assert_eq!(loaded.goal, agent_state.goal);
        assert_eq!(loaded.step_count, agent_state.step_count);
        assert_eq!(loaded.max_steps, agent_state.max_steps);
    }

    #[test]
    fn await_child_session_status_prefers_runtime_checkpoint() {
        let session_id = [8u8; 32];
        let checkpoint_key = get_state_key(&session_id);
        let mut runtime_state = test_agent_state(session_id);
        runtime_state.status = AgentStatus::Completed(Some("All done".to_string()));
        let mut stale_state = test_agent_state(session_id);
        stale_state.status = AgentStatus::Running;
        let stale_bytes = codec::to_bytes_canonical(&stale_state).expect("encode stale state");
        let mut state = MockState::default();
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

        state
            .insert(&checkpoint_key, &stale_bytes)
            .expect("insert stale raw state");
        persist_agent_state(&mut state, &checkpoint_key, &runtime_state, Some(&runtime))
            .expect("persist runtime-backed state");

        let status = await_child_session_status_for_inspection(
            &state,
            Some(&runtime),
            &hex::encode(session_id),
        )
        .expect("await child session status");

        assert_eq!(status, "All done");
    }

    #[test]
    fn await_child_session_status_falls_back_to_raw_state_when_checkpoint_missing() {
        let session_id = [5u8; 32];
        let checkpoint_key = get_state_key(&session_id);
        let mut child_state = test_agent_state(session_id);
        child_state.status = AgentStatus::Paused("Waiting".to_string());
        let child_bytes = codec::to_bytes_canonical(&child_state).expect("encode child state");
        let mut state = MockState::default();
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

        state
            .insert(&checkpoint_key, &child_bytes)
            .expect("insert raw child state");

        let status = await_child_session_status_for_inspection(
            &state,
            Some(&runtime),
            &hex::encode(session_id),
        )
        .expect("await child session status");

        assert_eq!(status, "Running (paused: Waiting)");
    }
}
