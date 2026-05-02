use crate::metrics::rpc_metrics as metrics;
use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::mempool::{AddResult, Mempool};
use ioi_api::chain::WorkloadClientApi;
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::{AccountId, ChainTransaction, StateAnchor};
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::standard::orchestration::ingestion::types::ProcessedTx;
use ioi_client::WorkloadClient;

fn relay_fanout() -> usize {
    std::env::var("IOI_AFT_TX_RELAY_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(2)
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
    let mut seen = std::collections::HashSet::new();
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

fn dispatch_swarm_command(sender: &mpsc::Sender<SwarmCommand>, command: SwarmCommand) {
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

fn is_desktop_agent_step(tx: &ChainTransaction) -> bool {
    let ChainTransaction::System(system) = tx else {
        return false;
    };
    let ioi_types::app::SystemPayload::CallService {
        service_id, method, ..
    } = &system.payload;
    service_id == "desktop_agent" && method == "step@v1"
}

pub(crate) async fn finalize_valid_transactions(
    workload_client: &Arc<WorkloadClient>,
    tx_pool: &Arc<Mempool>,
    swarm_sender: &mpsc::Sender<SwarmCommand>,
    peer_accounts_ref: &Arc<Mutex<HashMap<PeerId, AccountId>>>,
    local_account_id: AccountId,
    status_cache: &Arc<tokio::sync::Mutex<lru::LruCache<String, TxStatusEntry>>>,
    receipt_map: &Arc<tokio::sync::Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>,
    nonce_cache: &mut lru::LruCache<ioi_types::app::AccountId, u64>,
    semantically_valid_indices: &[usize],
    processed_batch: &[ProcessedTx],
    anchor: StateAnchor,
    current_tip_height: u64,
    current_validator_set: &[Vec<u8>],
    expected_ts: u64,
) -> bool {
    let mut ordered_check_indices = semantically_valid_indices.to_vec();
    ordered_check_indices.sort_by(|left_idx, right_idx| {
        let left = &processed_batch[*left_idx];
        let right = &processed_batch[*right_idx];

        match (left.account_id, right.account_id) {
            (Some(left_account), Some(right_account)) => left_account
                .cmp(&right_account)
                .then_with(|| left.nonce.unwrap_or(0).cmp(&right.nonce.unwrap_or(0)))
                .then_with(|| left_idx.cmp(right_idx)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left_idx.cmp(right_idx),
        }
    });

    let txs_to_check: Vec<ChainTransaction> = ordered_check_indices
        .iter()
        .map(|&i| processed_batch[i].tx.clone())
        .collect();

    let check_results = match workload_client
        .check_transactions_at(anchor, expected_ts, txs_to_check)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(target: "ingestion", "Validation IPC failed: {}", e);
            return false;
        }
    };

    let mut status_guard = status_cache.lock().await;
    let mut receipt_guard = receipt_map.lock().await;
    let mut accepted_count = 0;
    let (leader_peer_targets, leader_peers) =
        if current_tip_height == 0 || current_validator_set.is_empty() {
            // Before the first committed tip exists, keep admission cheap and rely on generic publish
            // rather than fetching validator set state to derive targeted relays.
            (0, Vec::new())
        } else {
            let leader_accounts = leader_accounts_for_upcoming_heights(
                current_tip_height,
                current_validator_set,
                relay_fanout(),
            );
            let leader_peer_targets = leader_accounts
                .iter()
                .filter(|account_id| **account_id != local_account_id)
                .count();
            let peers = peer_accounts_ref.lock().await;
            let leader_peers = leader_accounts
                .into_iter()
                .filter(|account_id| *account_id != local_account_id)
                .filter_map(|leader_account_id| {
                    peers.iter().find_map(|(peer_id, account_id)| {
                        (*account_id == leader_account_id).then_some(*peer_id)
                    })
                })
                .collect::<Vec<_>>();
            (leader_peer_targets, leader_peers)
        };

    for (res_idx, result) in check_results.into_iter().enumerate() {
        let original_idx = ordered_check_indices[res_idx];
        let p_tx = &processed_batch[original_idx];

        let is_approval_error = if let Err(e) = &result {
            e.contains("Approval required for request")
        } else {
            false
        };

        let validation_ok = result.is_ok() || is_approval_error;

        if validation_ok {
            let receipt_already_present = receipt_guard.peek(&p_tx.canonical_hash).is_some();
            let readmit_after_operator_pause =
                receipt_already_present && is_desktop_agent_step(&p_tx.tx) && !is_approval_error;
            if readmit_after_operator_pause {
                receipt_guard.pop(&p_tx.canonical_hash);
                tx_pool.remove_by_hash(&p_tx.canonical_hash);
                if let (Some(account_id), Some(nonce)) = (p_tx.account_id, p_tx.nonce) {
                    tx_pool.remove_by_account_nonce(&account_id, nonce);
                }
            } else if receipt_already_present {
                accepted_count += 1;
                status_guard.put(
                    p_tx.receipt_hash_hex.clone(),
                    TxStatusEntry {
                        status: TxStatus::InMempool,
                        error: None,
                        block_height: None,
                    },
                );
                continue;
            }

            let tx_info = p_tx.account_id.map(|acc| (acc, p_tx.nonce.unwrap()));
            let committed_nonce = p_tx
                .account_id
                .and_then(|acc| nonce_cache.get(&acc).copied())
                .unwrap_or(0);
            let committed_nonce = if readmit_after_operator_pause {
                p_tx.nonce
                    .map(|nonce| committed_nonce.max(nonce))
                    .unwrap_or(committed_nonce)
            } else {
                committed_nonce
            };

            let add_result = tx_pool.add(
                p_tx.tx.clone(),
                p_tx.canonical_hash,
                tx_info,
                committed_nonce,
            );

            match add_result {
                AddResult::Ready | AddResult::Future | AddResult::Known => {
                    accepted_count += 1;
                    if !matches!(add_result, AddResult::Known) {
                        metrics().inc_mempool_transactions_added();
                        if let Ok(tx_bytes) = ioi_types::codec::to_bytes_canonical(&p_tx.tx) {
                            dispatch_swarm_command(
                                swarm_sender,
                                SwarmCommand::PublishTransaction(tx_bytes.clone()),
                            );
                            for peer in &leader_peers {
                                dispatch_swarm_command(
                                    swarm_sender,
                                    SwarmCommand::RelayTransactionToPeer {
                                        peer: *peer,
                                        data: tx_bytes.clone(),
                                    },
                                );
                            }
                            if leader_peers.len() < leader_peer_targets {
                                tracing::debug!(
                                    target: "ingestion",
                                    expected_leader_peers = leader_peer_targets,
                                    resolved_leader_peers = leader_peers.len(),
                                    "Leader-aware relay fell back to generic publish for unresolved peers."
                                );
                            }
                        }
                    }
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::InMempool,
                            error: None,
                            block_height: None,
                        },
                    );
                    receipt_guard.put(p_tx.canonical_hash, p_tx.receipt_hash_hex.clone());

                    tracing::debug!(
                        target: "ingestion",
                        "Added transaction to mempool: {}",
                        p_tx.receipt_hash_hex
                    );
                }
                AddResult::Rejected(r) => {
                    tracing::warn!(
                        target: "ingestion",
                        "Mempool rejected transaction {}: {}",
                        p_tx.receipt_hash_hex,
                        r
                    );
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::Rejected,
                            error: Some(format!("Mempool: {}", r)),
                            block_height: None,
                        },
                    );
                }
            }
        } else {
            let e = result.unwrap_err();
            tx_pool.remove_by_hash(&p_tx.canonical_hash);
            let _ = receipt_guard.pop(&p_tx.canonical_hash);
            tracing::warn!(
                target: "ingestion",
                "Validation failed for transaction {}: {}",
                p_tx.receipt_hash_hex,
                e
            );
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: TxStatus::Rejected,
                    error: Some(format!("Validation: {}", e)),
                    block_height: None,
                },
            );
        }
    }

    metrics().set_mempool_size(tx_pool.len() as f64);
    accepted_count > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        ChainId, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    };

    fn system_call(service_id: &str, method: &str) -> ChainTransaction {
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([3u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: service_id.to_string(),
                method: method.to_string(),
                params: Vec::new(),
            },
            signature_proof: SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: Vec::new(),
                signature: Vec::new(),
            },
        }))
    }

    #[test]
    fn ingestion_readmission_identifies_only_desktop_agent_step() {
        assert!(is_desktop_agent_step(&system_call(
            "desktop_agent",
            "step@v1"
        )));
        assert!(!is_desktop_agent_step(&system_call(
            "desktop_agent",
            "start@v1"
        )));
        assert!(!is_desktop_agent_step(&system_call("agentic", "step@v1")));
    }
}
