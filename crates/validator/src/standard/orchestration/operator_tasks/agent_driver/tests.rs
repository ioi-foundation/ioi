use super::*;
use async_trait::async_trait;
use ioi_api::app::{Block, ChainStatus};
use ioi_api::chain::QueryStateResponse;
use ioi_services::agentic::runtime::types::ExecutionTier;
use ioi_services::agentic::runtime::AgentMode;
use ioi_types::app::{StateAnchor, StateRoot};
use ioi_types::error::ChainError;
use std::any::Any;
use std::collections::VecDeque;
use tokio::sync::Mutex;

#[derive(Debug, Default)]
struct StaticStateWorkloadClient {
    raw_state: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
}

#[async_trait]
impl WorkloadClientApi for StaticStateWorkloadClient {
    async fn process_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_blocks_range(
        &self,
        _since: u64,
        _max_blocks: u32,
        _max_bytes: u32,
    ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_block_by_height(
        &self,
        _height: u64,
    ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> std::result::Result<QueryStateResponse, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn query_raw_state(
        &self,
        key: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
        Ok(self.raw_state.lock().await.get(key).cloned())
    }

    async fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Ok(self
            .raw_state
            .lock()
            .await
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn get_staked_validators(
        &self,
    ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn update_block_header(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(), ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn test_agent_state(session_id: [u8; 32]) -> AgentState {
    AgentState {
        session_id,
        goal: "test local driver".to_string(),
        transcript_root: [7u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 4,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 100,
        tokens_used: 0,
        consecutive_failures: 0,
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
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
        execution_ledger: Default::default(),
    }
}

#[tokio::test]
async fn driver_falls_back_to_raw_state_when_runtime_checkpoint_missing() {
    let session_id = [0x5Au8; 32];
    let agent_state = test_agent_state(session_id);
    let raw_state_bytes = codec::to_bytes_canonical(&agent_state).expect("encode agent state");
    let state_key = [
        service_namespace_prefix("desktop_agent"),
        b"agent::state::".to_vec(),
        session_id.to_vec(),
    ]
    .concat();

    let workload_client = std::sync::Arc::new(StaticStateWorkloadClient::default());
    workload_client
        .raw_state
        .lock()
        .await
        .insert(state_key, raw_state_bytes);

    let tx_pool_ref = std::sync::Arc::new(crate::standard::orchestration::mempool::Mempool::new());
    let local_keypair = libp2p::identity::Keypair::generate_ed25519();
    let our_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::ED25519,
            &local_keypair.public().encode_protobuf(),
        )
        .expect("account id"),
    );
    let nonce_manager = std::sync::Arc::new(TokioMutex::new(BTreeMap::new()));
    let (consensus_kick_tx, mut consensus_kick_rx) = tokio::sync::mpsc::unbounded_channel();
    let memory_runtime = Some(std::sync::Arc::new(
        MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
    ));

    let work_performed = run_agent_driver_task_with_handles(
        workload_client,
        tx_pool_ref.clone(),
        local_keypair,
        ioi_types::app::ChainId(0),
        nonce_manager,
        consensus_kick_tx,
        memory_runtime,
    )
    .await
    .expect("run agent driver");

    assert!(work_performed);
    assert!(tx_pool_ref.contains_account(&our_account_id));
    assert!(consensus_kick_rx.try_recv().is_ok());
}
