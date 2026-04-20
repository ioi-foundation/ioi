use super::*;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::utils::load_agent_state_checkpoint;

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
#[path = "agent_driver/tests.rs"]
mod tests;

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
