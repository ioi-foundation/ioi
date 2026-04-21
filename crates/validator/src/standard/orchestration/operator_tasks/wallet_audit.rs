use super::*;

/// Streams firewall interception events and persists them as signed
/// `wallet_network::record_interception@v1` service calls.
pub async fn run_wallet_network_audit_bridge_task<CS, ST, CE, V>(
    context_arc: std::sync::Arc<TokioMutex<MainLoopContext<CS, ST, CE, V>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
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
    let (
        mut event_rx,
        workload_client,
        tx_pool,
        consensus_kick_tx,
        nonce_manager,
        keypair,
        chain_id,
    ) = {
        let ctx = context_arc.lock().await;
        (
            ctx.event_broadcaster.subscribe(),
            ctx.view_resolver.workload_client().clone(),
            ctx.tx_pool_ref.clone(),
            ctx.consensus_kick_tx.clone(),
            ctx.nonce_manager.clone(),
            ctx.local_keypair.clone(),
            ctx.chain_id,
        )
    };

    let mut seen_request_hashes: LruCache<[u8; 32], ()> =
        LruCache::new(NonZeroUsize::new(4096).expect("non-zero"));

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                let event = match event {
                    Ok(value) => value,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(target: "wallet_network", "wallet audit bridge lagged by {} events", skipped);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                let KernelEvent::FirewallInterception {
                    verdict,
                    target,
                    request_hash,
                    session_id,
                } = event else {
                    continue;
                };

                if verdict != "REQUIRE_APPROVAL" && verdict != "BLOCK" {
                    continue;
                }
                if seen_request_hashes.get(&request_hash).is_some() {
                    continue;
                }

                let reason = match verdict.as_str() {
                    "REQUIRE_APPROVAL" => "manual approval required",
                    "BLOCK" => "blocked by active policy rules",
                    _ => "policy interception",
                };
                let interception = WalletInterceptionContext {
                    session_id,
                    request_hash,
                    target: ActionTarget::Custom(target),
                    policy_hash: [0xAB; 32],
                    value_usd_micros: None,
                    reason: reason.to_string(),
                    intercepted_at_ms: now_unix_ms(),
                };

                match submit_wallet_interception_record(
                    &workload_client,
                    &tx_pool,
                    &consensus_kick_tx,
                    &nonce_manager,
                    &keypair,
                    chain_id,
                    interception,
                )
                .await
                {
                    Ok(()) => {
                        seen_request_hashes.put(request_hash, ());
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "wallet_network",
                            "failed to persist interception {}: {}",
                            hex::encode(request_hash),
                            err
                        );
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}
