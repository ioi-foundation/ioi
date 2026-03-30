use super::*;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::desktop::utils::load_agent_state_checkpoint;

fn parse_session_id_from_state_key(state_key: &[u8], full_scan_prefix: &[u8]) -> Option<[u8; 32]> {
    let suffix = state_key.strip_prefix(full_scan_prefix)?;
    let session_bytes = suffix.get(..32)?;
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(session_bytes);
    Some(session_id)
}

fn decode_agent_state_bytes(bytes: &[u8], key_suffix: &str, source: &str) -> Option<AgentState> {
    match decode_state_value(bytes) {
        Ok(state) => Some(state),
        Err(error) => {
            tracing::warn!(
                target: "agent_driver",
                "Failed to decode agent state from {} for key {}: {}",
                source,
                key_suffix,
                error
            );
            None
        }
    }
}

fn load_agent_state_from_runtime_or_scan(
    memory_runtime: Option<&std::sync::Arc<MemoryRuntime>>,
    session_id: [u8; 32],
    scan_value: &[u8],
    key_suffix: &str,
) -> Option<AgentState> {
    if let Some(memory_runtime) = memory_runtime {
        match load_agent_state_checkpoint(memory_runtime.as_ref(), session_id) {
            Ok(Some(state)) => return Some(state),
            Ok(None) => {
                tracing::debug!(
                    target: "agent_driver",
                    "Runtime checkpoint missing for agent {}; falling back to scanned raw state",
                    key_suffix
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "agent_driver",
                    "Failed to load runtime agent state for key {}; falling back to scanned raw state: {}",
                    key_suffix,
                    error
                );
            }
        }
    }

    decode_agent_state_bytes(scan_value, key_suffix, "prefix scan")
}

async fn refresh_agent_state_from_runtime_or_chain(
    workload_client: &std::sync::Arc<dyn WorkloadClientApi>,
    memory_runtime: Option<&std::sync::Arc<MemoryRuntime>>,
    state_key: &[u8],
    session_id: [u8; 32],
    key_suffix: &str,
) -> Option<AgentState> {
    if let Some(memory_runtime) = memory_runtime {
        match load_agent_state_checkpoint(memory_runtime.as_ref(), session_id) {
            Ok(Some(state)) => return Some(state),
            Ok(None) => {
                tracing::debug!(
                    target: "agent_driver",
                    "Refresh checkpoint missing for agent {}; falling back to chain state",
                    key_suffix
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "agent_driver",
                    "Failed to refresh runtime agent state for key {}; falling back to chain state: {}",
                    key_suffix,
                    error
                );
            }
        }
    }

    match workload_client.query_raw_state(state_key).await {
        Ok(Some(bytes)) => decode_agent_state_bytes(&bytes, key_suffix, "query_raw_state"),
        Ok(None) => {
            tracing::debug!(
                target: "agent_driver",
                "Refreshed agent state disappeared for key {}",
                key_suffix
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                target: "agent_driver",
                "Failed to refresh agent state for key {}: {}",
                key_suffix,
                error
            );
            None
        }
    }
}

/// Scans running desktop-agent sessions and submits `step@v1` transactions
/// using detached context handles without holding the main context mutex.
pub async fn run_agent_driver_task_with_handles(
    workload_client: std::sync::Arc<dyn WorkloadClientApi>,
    tx_pool_ref: std::sync::Arc<crate::standard::orchestration::mempool::Mempool>,
    local_keypair: libp2p::identity::Keypair,
    chain_id: ioi_types::app::ChainId,
    nonce_manager: std::sync::Arc<TokioMutex<BTreeMap<AccountId, u64>>>,
    consensus_kick_tx: tokio::sync::mpsc::UnboundedSender<()>,
    memory_runtime: Option<std::sync::Arc<MemoryRuntime>>,
) -> Result<bool> {
    let mut work_performed = false;

    // 1. Scan for agent states
    // The canonical prefix for AgentState is b"agent::state::"
    const AGENT_STATE_PREFIX_RAW: &[u8] = b"agent::state::";

    // Use the fully namespaced key prefix for the desktop agent service.
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let full_scan_prefix = [ns_prefix.as_slice(), AGENT_STATE_PREFIX_RAW].concat();

    let kvs = match workload_client.prefix_scan(&full_scan_prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(target: "agent_driver", "Prefix scan failed: {}", e);
            return Ok(false);
        }
    };

    if kvs.is_empty() {
        tracing::debug!(target: "agent_driver", "No agent states found under prefix.");
        return Ok(false);
    }
    tracing::debug!(
        target: "agent_driver",
        "Found {} agent state entries",
        kvs.len()
    );

    let our_pk = local_keypair.public().encode_protobuf();
    let our_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &our_pk,
    )?);

    // 2. Identify Running Agents
    for (state_key, val_bytes) in kvs {
        let Some(session_id) =
            parse_session_id_from_state_key(state_key.as_slice(), full_scan_prefix.as_slice())
        else {
            tracing::warn!(
                target: "agent_driver",
                "Skipping agent state entry with malformed session suffix"
            );
            continue;
        };

        let key_suffix = hex::encode(&session_id[..4]);
        let Some(state) = load_agent_state_from_runtime_or_scan(
            memory_runtime.as_ref(),
            session_id,
            &val_bytes,
            &key_suffix,
        ) else {
            continue;
        };

        tracing::debug!(
            target: "agent_driver",
            "Agent {} status {:?} step_count {}",
            hex::encode(&state.session_id[..4]),
            state.status,
            state.step_count
        );

        if state.status == AgentStatus::Running {
            // 3. Check Mempool for Pending Step (Debounce)
            // If the mempool already has a transaction for this signer, we wait.
            // This prevents spam loops when the agent is blocked by policy or waiting for a block commit.
            if tx_pool_ref.contains_account(&our_account_id) {
                continue;
            }

            // Refresh the session immediately before dispatch. The initial prefix scan can race
            // with a just-committed step result, which otherwise causes stale Running snapshots
            // to submit an extra follow-up step after the session already completed/cleared queue.
            let Some(latest_state) = refresh_agent_state_from_runtime_or_chain(
                &workload_client,
                memory_runtime.as_ref(),
                &state_key,
                session_id,
                &key_suffix,
            )
            .await
            else {
                continue;
            };

            if latest_state.status != AgentStatus::Running {
                tracing::debug!(
                    target: "agent_driver",
                    "Skipping stale running snapshot for agent {}; refreshed status is {:?}",
                    hex::encode(&state.session_id[..4]),
                    latest_state.status
                );
                continue;
            }

            // 4. Construct Step Transaction
            let params = StepAgentParams {
                session_id: latest_state.session_id,
            };

            let payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "step@v1".to_string(),
                params: codec::to_bytes_canonical(&params).unwrap(),
            };

            // Get next nonce
            // Use nonce-manager plus committed-state reconciliation.
            // This keeps auto-step submissions aligned with reserved nonces.
            let (nonce, committed_nonce_state) = {
                // 1. Get state nonce
                let nonce_key = [
                    ioi_types::keys::ACCOUNT_NONCE_PREFIX,
                    our_account_id.as_ref(),
                ]
                .concat();

                let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
                    Ok(Some(b)) => decode_account_nonce(&b),
                    _ => 0,
                };

                // 2. Sync with Manager
                let mut nm = nonce_manager.lock().await;
                let entry = nm.entry(our_account_id).or_insert(0);

                // Fast-forward if state is ahead
                if *entry < state_nonce {
                    *entry = state_nonce;
                }

                let use_nonce = *entry;
                // Increment to reserve
                *entry += 1;

                (use_nonce, state_nonce)
            };

            tracing::info!(
                target: "agent_driver",
                "Submitting step for session {} with nonce {}",
                hex::encode(&latest_state.session_id[..4]),
                nonce
            );

            let mut sys_tx = SystemTransaction {
                header: SignHeader {
                    account_id: our_account_id,
                    nonce,
                    chain_id,
                    tx_version: 1,
                    session_auth: None,
                },
                payload,
                signature_proof: SignatureProof::default(),
            };

            // Normalize transaction-signing serialization failures into anyhow.
            let sign_bytes = sys_tx
                .to_sign_bytes()
                .map_err(|e| anyhow!("Failed to serialize tx: {}", e))?;

            let signature = local_keypair.sign(&sign_bytes)?;

            sys_tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: our_pk.clone(),
                signature,
            };

            let tx = ChainTransaction::System(Box::new(sys_tx));
            let tx_hash = tx.hash()?;

            // 5. Submit to Mempool
            // We use the pool directly to skip gRPC overhead, as we are the node itself.
            let res = tx_pool_ref.add(
                tx,
                tx_hash,
                Some((our_account_id, nonce)),
                committed_nonce_state,
            );

            match res {
                crate::standard::orchestration::mempool::AddResult::Rejected(reason) => {
                    tracing::warn!(target: "agent_driver", "Step tx rejected by mempool (Nonce: {}): {}", nonce, reason);
                }
                crate::standard::orchestration::mempool::AddResult::Known => {
                    tracing::debug!(
                        target: "agent_driver",
                        "Step tx already present in mempool (nonce={})",
                        nonce
                    );
                }
                crate::standard::orchestration::mempool::AddResult::Ready => {
                    // Wake consensus
                    let _ = consensus_kick_tx.send(());

                    tracing::info!(
                        target: "agent_driver",
                        "Auto-stepping agent session {} (Step {} | Nonce {})",
                        hex::encode(&latest_state.session_id[0..4]),
                        latest_state.step_count,
                        nonce
                    );
                    work_performed = true;
                }
                crate::standard::orchestration::mempool::AddResult::Future => {
                    tracing::warn!(
                        target: "agent_driver",
                        "Step tx queued as future (nonce={} committed_nonce_state={}); waiting for nonce gap to close.",
                        nonce,
                        committed_nonce_state
                    );
                    work_performed = true;
                }
            }
        } else {
            tracing::debug!(
                target: "agent_driver",
                "Agent {} not running; status {:?}",
                hex::encode(&state.session_id[..4]),
                state.status
            );
        }
    }

    Ok(work_performed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::app::{Block, ChainStatus};
    use ioi_api::chain::QueryStateResponse;
    use ioi_services::agentic::desktop::types::ExecutionTier;
    use ioi_services::agentic::desktop::AgentMode;
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
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
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

        let tx_pool_ref =
            std::sync::Arc::new(crate::standard::orchestration::mempool::Mempool::new());
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
}

/// Runs the background task for the Agent driver.
/// Scans for active agents and triggers steps if needed.
/// Returns `true` if any agent action was taken, allowing the main loop to speed up.
pub async fn run_agent_driver_task<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Result<bool>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    run_agent_driver_task_with_handles(
        context.view_resolver.workload_client().clone(),
        context.tx_pool_ref.clone(),
        context.local_keypair.clone(),
        context.chain_id,
        context.nonce_manager.clone(),
        context.consensus_kick_tx.clone(),
        context.memory_runtime.clone(),
    )
    .await
}
