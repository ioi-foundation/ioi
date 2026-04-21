use super::*;
use ioi_ipc::public::{SubmissionStatus, TxStatus};
use ioi_networking::libp2p::SwarmCommand;
use ioi_tx::system::validation::verify_stateless_signature;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use std::collections::HashSet;
use std::time::Instant;

fn tx_account_nonce(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
        ChainTransaction::Settlement(s) => Some((s.header.account_id, s.header.nonce)),
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
        },
        _ => None,
    }
}

fn requires_ingestion_semantic_screening(tx: &ChainTransaction) -> bool {
    let ChainTransaction::System(sys) = tx else {
        return false;
    };

    matches!(
        &sys.payload,
        ioi_types::app::SystemPayload::CallService { service_id, .. }
            if matches!(service_id.as_str(), "agentic" | "desktop_agent" | "compute_market")
    )
}

fn relay_fanout() -> usize {
    std::env::var("IOI_AFT_TX_RELAY_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn leader_accounts_for_upcoming_heights(
    local_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 1..=steps {
        let target_height = local_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }
    leaders
}

fn dispatch_swarm_command(sender: &tokio::sync::mpsc::Sender<SwarmCommand>, command: SwarmCommand) {
    match sender.try_send(command) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(command)) => {
            let sender = sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(command).await;
            });
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn fast_admit_mempool_limit() -> usize {
    std::env::var("IOI_RPC_FAST_ADMIT_MAX_MEMPOOL")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(512)
}

impl<CS, ST, CE, V> PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    pub(super) async fn handle_submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let tx_bytes = req.transaction_bytes;
        let ctx_arc = self.get_context().await?;
        let tx_status_cache = {
            let ctx = ctx_arc.lock().await;
            ctx.tx_status_cache.clone()
        };

        let tx_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tx_bytes)
            .map_err(|e| Status::invalid_argument(format!("Hashing failed: {}", e)))?;
        let tx_hash_hex = hex::encode(tx_hash_bytes);

        let decoded_tx = match codec::from_bytes_canonical::<ChainTransaction>(&tx_bytes) {
            Ok(tx) => tx,
            Err(error) => {
                let mut cache = tx_status_cache.lock().await;
                cache.put(
                    tx_hash_hex,
                    TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some(format!("Failed to decode transaction: {}", error)),
                        block_height: None,
                    },
                );
                return Err(Status::invalid_argument(format!(
                    "Failed to decode transaction: {}",
                    error
                )));
            }
        };

        if let Err(error) = verify_stateless_signature(&decoded_tx) {
            let mut cache = tx_status_cache.lock().await;
            cache.put(
                tx_hash_hex,
                TxStatusEntry {
                    status: TxStatus::Rejected,
                    error: Some(format!("Invalid signature: {}", error)),
                    block_height: None,
                },
            );
            return Err(Status::invalid_argument(format!(
                "Invalid signature: {}",
                error
            )));
        }

        if let Some((account_id, nonce)) = tx_account_nonce(&decoded_tx) {
            {
                let next_nonce = nonce.saturating_add(1);
                let nonce_manager = {
                    let ctx = ctx_arc.lock().await;
                    ctx.nonce_manager.clone()
                };
                let mut guard = nonce_manager.lock().await;
                let entry = guard.entry(account_id).or_insert(0);
                if *entry < next_nonce {
                    *entry = next_nonce;
                }
            }
        };

        {
            let mut cache = tx_status_cache.lock().await;
            cache.put(
                tx_hash_hex.clone(),
                TxStatusEntry {
                    status: TxStatus::Pending,
                    error: None,
                    block_height: None,
                },
            );
        }

        {
            let tx = decoded_tx;
            let tx_info = tx_account_nonce(&tx);
            let tx_hash = tx.hash().unwrap_or(tx_hash_bytes);

            let (
                tx_pool_ref,
                swarm_commander,
                consensus_kick_tx,
                receipt_map,
                local_keypair,
                last_committed_block,
                peer_accounts_ref,
                consensus_kick_scheduled,
                workload_client,
            ) = {
                let ctx = ctx_arc.lock().await;
                (
                    ctx.tx_pool_ref.clone(),
                    ctx.swarm_commander.clone(),
                    ctx.consensus_kick_tx.clone(),
                    ctx.receipt_map.clone(),
                    ctx.local_keypair.clone(),
                    ctx.last_committed_block.clone(),
                    ctx.peer_accounts_ref.clone(),
                    ctx.consensus_kick_scheduled.clone(),
                    ctx.view_resolver.workload_client().clone(),
                )
            };

            let local_account_id = AccountId(
                account_id_from_key_material(
                    SignatureSuite::ED25519,
                    &local_keypair.public().encode_protobuf(),
                )
                .unwrap_or_default(),
            );

            let leader_peers = if let Some(block) = last_committed_block.as_ref() {
                let leader_accounts = leader_accounts_for_upcoming_heights(
                    block.header.height,
                    &block.header.validator_set,
                    relay_fanout(),
                );
                let peers = peer_accounts_ref.lock().await;
                leader_accounts
                    .into_iter()
                    .filter(|leader_account_id| *leader_account_id != local_account_id)
                    .filter_map(|leader_account_id| {
                        peers.iter().find_map(|(peer_id, account_id)| {
                            (*account_id == leader_account_id).then_some(*peer_id)
                        })
                    })
                    .collect::<Vec<_>>()
            } else {
                // Clean-start admission runs before we have a committed tip. Avoid a workload
                // state lookup per transaction on that path; generic publish is sufficient until
                // the first committed block gives us a concrete leader schedule to target.
                Vec::new()
            };

            let requires_semantic_screening = requires_ingestion_semantic_screening(&tx);
            let should_fast_admit = {
                let limit = fast_admit_mempool_limit();
                limit > 0 && tx_pool_ref.len() < limit && !requires_semantic_screening
            };

            let committed_nonce_state = if let Some((account_id, _)) = tx_info.as_ref() {
                let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
                match workload_client.query_raw_state(&nonce_key).await {
                    Ok(Some(bytes)) => codec::from_bytes_canonical::<u64>(&bytes).unwrap_or(0),
                    _ => 0,
                }
            } else {
                0
            };

            let fast_admit = if should_fast_admit {
                Some(tx_pool_ref.add(tx, tx_hash, tx_info, committed_nonce_state))
            } else {
                None
            };

            if let Some(result) = fast_admit.as_ref() {
                if matches!(
                    result,
                    crate::standard::orchestration::mempool::AddResult::Rejected(_)
                ) {
                    // Fall through to the ingestion worker.
                } else {
                    if !matches!(
                        result,
                        crate::standard::orchestration::mempool::AddResult::Known
                    ) {
                        metrics().inc_mempool_transactions_added();
                    }
                    metrics().set_mempool_size(tx_pool_ref.len() as f64);
                    {
                        let mut receipts = receipt_map.lock().await;
                        receipts.put(tx_hash, tx_hash_hex.clone());
                    }

                    {
                        let mut cache = tx_status_cache.lock().await;
                        cache.put(
                            tx_hash_hex.clone(),
                            TxStatusEntry {
                                status: TxStatus::InMempool,
                                error: None,
                                block_height: None,
                            },
                        );
                    }

                    if !matches!(
                        result,
                        crate::standard::orchestration::mempool::AddResult::Known
                    ) {
                        // RPC ingress may land on a non-leader in a sparse topology. Always
                        // publish the transaction so connected peers can forward it, then
                        // opportunistically relay directly to upcoming leaders for lower latency
                        // when those links exist.
                        dispatch_swarm_command(
                            &swarm_commander,
                            SwarmCommand::PublishTransaction(tx_bytes.clone()),
                        );
                        for peer in leader_peers {
                            dispatch_swarm_command(
                                &swarm_commander,
                                SwarmCommand::RelayTransactionToPeer {
                                    peer,
                                    data: tx_bytes.clone(),
                                },
                            );
                        }
                        crate::standard::orchestration::schedule_consensus_kick(
                            &consensus_kick_tx,
                            &consensus_kick_scheduled,
                        );
                    }

                    metrics().inc_requests_total("submit_transaction", 200);
                    metrics().observe_request_duration(
                        "submit_transaction",
                        start.elapsed().as_secs_f64(),
                    );

                    tracing::debug!(
                        target: "rpc",
                        "Received transaction via gRPC. Hash: {}",
                        tx_hash_hex
                    );

                    return Ok(Response::new(SubmitTransactionResponse {
                        tx_hash: tx_hash_hex,
                        status: SubmissionStatus::Accepted as i32,
                        approval_reason: String::new(),
                    }));
                }
            }
        }

        match self.tx_ingest_tx.try_send((tx_hash_bytes, tx_bytes)) {
            Ok(_) => {
                metrics().inc_requests_total("submit_transaction", 200);
                metrics()
                    .observe_request_duration("submit_transaction", start.elapsed().as_secs_f64());

                tracing::debug!(
                    target: "rpc",
                    "Received transaction via gRPC. Hash: {}",
                    tx_hash_hex
                );

                Ok(Response::new(SubmitTransactionResponse {
                    tx_hash: tx_hash_hex,
                    status: SubmissionStatus::Accepted as i32,
                    approval_reason: String::new(),
                }))
            }
            Err(_) => {
                metrics().inc_requests_total("submit_transaction", 503);
                let mut cache = tx_status_cache.lock().await;
                cache.put(
                    tx_hash_hex,
                    TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some("Ingestion queue full".into()),
                        block_height: None,
                    },
                );

                Err(Status::resource_exhausted("Ingestion queue full"))
            }
        }
    }

    pub(super) async fn handle_get_transaction_status(
        &self,
        request: Request<GetTransactionStatusRequest>,
    ) -> Result<Response<GetTransactionStatusResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;
        let tx_status_cache = {
            let ctx = ctx_arc.lock().await;
            ctx.tx_status_cache.clone()
        };
        let mut cache = tx_status_cache.lock().await;
        if let Some(entry) = cache.get(&req.tx_hash) {
            Ok(Response::new(GetTransactionStatusResponse {
                status: entry.status as i32,
                error_message: entry.error.clone().unwrap_or_default(),
                block_height: entry.block_height.unwrap_or(0),
            }))
        } else {
            Ok(Response::new(GetTransactionStatusResponse {
                status: TxStatus::Unknown as i32,
                error_message: "Transaction not found".into(),
                block_height: 0,
            }))
        }
    }

    pub(super) async fn handle_draft_transaction(
        &self,
        request: Request<DraftTransactionRequest>,
    ) -> Result<Response<DraftTransactionResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;

        let (
            chain_id,
            inference_runtime,
            keypair,
            nonce_manager,
            workload_client,
            account_id_bytes,
        ) = {
            let ctx = ctx_arc.lock().await;
            let account_id = account_id_from_key_material(
                SignatureSuite::ED25519,
                &ctx.local_keypair.public().encode_protobuf(),
            )
            .unwrap_or_default();

            (
                ctx.chain_id,
                ctx.inference_runtime.clone(),
                ctx.local_keypair.clone(),
                ctx.nonce_manager.clone(),
                ctx.view_resolver.workload_client().clone(),
                account_id,
            )
        };

        let account_id = AccountId(account_id_bytes);
        let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();

        let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(b)) => codec::from_bytes_canonical::<u64>(&b).unwrap_or(0),
            _ => 0,
        };

        let nonce = {
            let mut guard = nonce_manager.lock().await;
            let entry = guard.entry(account_id).or_insert(0);

            if *entry < state_nonce {
                *entry = state_nonce;
            }

            let use_nonce = *entry;
            *entry += 1;

            use_nonce
        };

        let resolver = IntentResolver::new(inference_runtime);
        let address_book = std::collections::HashMap::new();

        let tx_bytes = resolver
            .resolve_intent(&req.intent, chain_id, nonce, &address_book)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut tx: ChainTransaction = codec::from_bytes_canonical(&tx_bytes)
            .map_err(|e| Status::internal(format!("Failed to deserialize draft: {}", e)))?;

        let signer_pk_bytes = keypair.public().encode_protobuf();
        let signer_account_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &signer_pk_bytes)
                .map_err(|e| Status::internal(e.to_string()))?,
        );

        let signed_tx_bytes = match &mut tx {
            ChainTransaction::Settlement(s) => {
                s.header.account_id = signer_account_id;
                let sign_bytes = s.to_sign_bytes().map_err(Status::internal)?;
                let sig = keypair
                    .sign(&sign_bytes)
                    .map_err(|e| Status::internal(e.to_string()))?;
                s.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
                    public_key: signer_pk_bytes,
                    signature: sig,
                };
                codec::to_bytes_canonical(&tx).map_err(Status::internal)?
            }
            ChainTransaction::System(s) => {
                s.header.account_id = signer_account_id;
                let sign_bytes = s.to_sign_bytes().map_err(Status::internal)?;
                let sig = keypair
                    .sign(&sign_bytes)
                    .map_err(|e| Status::internal(e.to_string()))?;
                s.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
                    public_key: signer_pk_bytes,
                    signature: sig,
                };
                codec::to_bytes_canonical(&tx).map_err(Status::internal)?
            }
            _ => {
                return Err(Status::unimplemented(
                    "Auto-signing not supported for this transaction type",
                ))
            }
        };

        Ok(Response::new(DraftTransactionResponse {
            transaction_bytes: signed_tx_bytes,
            summary_markdown: format!(
                "**Action:** Execute `{}` (Auto-Signed, Nonce {})",
                req.intent, nonce
            ),
            required_capabilities: vec!["wallet::sign".into()],
        }))
    }
}

#[cfg(test)]
#[path = "tx_handlers/tests.rs"]
mod tests;
