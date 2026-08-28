// Path: crates/cli/src/testing/rpc.rs

use anyhow::{anyhow, Result};
use ioi_ipc::blockchain::{GetStatusRequest, GetStatusResponse, QueryRawStateRequest}; // [FIX] Added GetStatusResponse
use ioi_ipc::public::public_api_client::PublicApiClient;
// [FIX] Removed unused imports
use ioi_ipc::public::{
    GetBlockByHeightRequest, GetTransactionStatusRequest, SubmitTransactionRequest, TxStatus,
};
use ioi_types::{
    app::{Block, ChainTransaction, Proposal, StateEntry, StateRoot},
    codec,
    keys::{EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, QUARANTINED_VALIDATORS_KEY},
};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::Channel;

// How many retries for transient RPC decode/transport glitches
const RPC_RETRY_MAX: usize = 5;
const RPC_RETRY_BASE_MS: u64 = 80;

/// The fixed interval between committed-status polls.
///
/// Every commit-wait measurement taken on this path is quantized to this
/// interval, so a profile that reports the wait must also report the quantum
/// rather than presenting the sampled figure as an exact latency.
const COMMIT_POLL_INTERVAL_MS: u64 = 500;

/// A wall-clock observation of one submission through [`submit_transaction`].
///
/// These are measurements of the very path `submit_transaction` already walks.
/// Producing them changes no admission, commitment, or status truth, and no
/// field here is ever substituted for a value the chain did not report.
#[derive(Debug, Clone)]
pub struct SubmissionProfile {
    /// The hash the RPC admitted the transaction under.
    pub tx_hash: String,
    /// Wall time of the `submit_transaction` RPC call itself.
    pub admission_ms: u128,
    /// Wall time from the end of admission until the status read COMMITTED.
    pub commit_wait_ms: u128,
    /// How many `get_transaction_status` polls that wait issued.
    pub commit_poll_count: u64,
    /// The interval those polls quantize `commit_wait_ms` to.
    pub commit_poll_interval_ms: u64,
    /// The EXACT block height the validator recorded for this transaction.
    ///
    /// `None` when the status cache published no height. A caller must report
    /// that absence; the chain tip is a different fact and is never a
    /// substitute for it.
    pub committed_height: Option<u64>,
}

/// Connects to the public gRPC API.
async fn connect(rpc_addr: &str) -> Result<PublicApiClient<Channel>> {
    let url = if rpc_addr.starts_with("http") {
        rpc_addr.to_string()
    } else {
        format!("http://{}", rpc_addr)
    };

    PublicApiClient::connect(url)
        .await
        .map_err(|e| anyhow!("Failed to connect to public gRPC: {}", e))
}

/// Robust get_block_by_height:
/// - Retries transient -32000 decode/network errors
/// - Treats future/hemi-available heights as Ok(None)
pub async fn get_block_by_height_resilient(
    rpc_addr: &str,
    height: u64,
) -> Result<Option<Block<ChainTransaction>>> {
    let mut attempt = 0usize;
    loop {
        match get_block_by_height(rpc_addr, height).await {
            Ok(opt) => return Ok(opt), // Found (Some) or cleanly NotFound (None)
            Err(e) => {
                let msg = e.to_string();
                // Check for Tonic/gRPC transport errors
                if msg.contains("transport error")
                    || msg.contains("unavailable")
                    || msg.contains("h2")
                {
                    attempt += 1;
                    if attempt >= RPC_RETRY_MAX {
                        return Ok(None);
                    }
                    sleep(Duration::from_millis(RPC_RETRY_BASE_MS * attempt as u64)).await;
                    continue;
                }
                return Err(anyhow!(e));
            }
        }
    }
}

/// Return latest known chain tip by probing upwards.
pub async fn tip_height_resilient(rpc_addr: &str) -> Result<u64> {
    let mut h = 0u64;
    loop {
        let next = h + 1;
        match get_block_by_height_resilient(rpc_addr, next).await? {
            Some(_) => h = next,
            None => return Ok(h),
        }
    }
}

/// Submits a transaction and waits for the next block to be produced.
pub async fn submit_transaction_and_get_block(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<Block<ChainTransaction>> {
    let initial_height = get_chain_height(rpc_addr).await?;
    let target_height = initial_height + 1;

    submit_transaction_no_wait(rpc_addr, tx).await?;

    super::assert::wait_for_height(rpc_addr, target_height, Duration::from_secs(60)).await?;

    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(b)) = get_block_by_height_resilient(rpc_addr, target_height).await {
            return Ok(b);
        }
        if start.elapsed() > Duration::from_secs(10) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(anyhow!(
        "Block {} committed but not found in store after polling",
        target_height
    ))
}

/// Submits a transaction via gRPC without waiting for inclusion.
pub async fn submit_transaction_no_wait(rpc_addr: &str, tx: &ChainTransaction) -> Result<String> {
    let mut client = connect(rpc_addr).await?;

    let tx_bytes =
        codec::to_bytes_canonical(tx).map_err(|e| anyhow!("Serialization failed: {}", e))?;

    let request = tonic::Request::new(SubmitTransactionRequest {
        transaction_bytes: tx_bytes,
    });

    let response = client.submit_transaction(request).await?;
    let tx_hash = response.into_inner().tx_hash;

    log::info!("submit_transaction: accepted -> hash: {}", tx_hash);
    Ok(tx_hash)
}

/// Submits a transaction and waits for it to be COMMITTED.
/// Returns error if the transaction is Rejected or times out.
pub async fn submit_transaction(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<()> {
    submit_transaction_profiled(rpc_addr, tx).await.map(|_| ())
}

/// The single implementation behind [`submit_transaction`], additionally
/// returning what it observed about its own timing.
///
/// [`submit_transaction`] delegates here so there is exactly ONE submission
/// path: a profiled copy that could drift from the path the soak actually
/// walks would measure a different journey than the one under test.
pub async fn submit_transaction_profiled(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<SubmissionProfile> {
    let admission_started = std::time::Instant::now();
    let tx_hash = submit_transaction_no_wait(rpc_addr, tx).await?;
    let admission_ms = admission_started.elapsed().as_millis();
    let mut commit_poll_count = 0u64;
    let mut committed_height = None;

    // Poll for status. Long held journeys against the debug wallet fixture
    // legitimately commit slowly as the chain deepens; callers opt into a
    // longer wait without changing the default for everyone else.
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(
        std::env::var("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(10, 900),
    );

    let mut client = connect(rpc_addr).await?;

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for tx {} to commit", tx_hash));
        }

        let req = tonic::Request::new(GetTransactionStatusRequest {
            tx_hash: tx_hash.clone(),
        });

        commit_poll_count += 1;
        match client.get_transaction_status(req).await {
            Ok(resp) => {
                let r = resp.into_inner();
                match TxStatus::try_from(r.status).unwrap_or(TxStatus::Unknown) {
                    TxStatus::Committed => {
                        // The status cache publishes the exact including height
                        // on commit. A zero means it published none; that
                        // absence is carried forward as absence.
                        if r.block_height > 0 {
                            committed_height = Some(r.block_height);
                        }
                        return Ok(SubmissionProfile {
                            tx_hash,
                            admission_ms,
                            commit_wait_ms: start.elapsed().as_millis(),
                            commit_poll_count,
                            commit_poll_interval_ms: COMMIT_POLL_INTERVAL_MS,
                            committed_height,
                        });
                    }
                    TxStatus::Rejected => {
                        return Err(anyhow!("Transaction rejected: {}", r.error_message));
                    }
                    _ => { /* Pending/InMempool, continue waiting */ }
                }
            }
            Err(_) => {
                // Ignore transient gRPC errors during polling
            }
        }

        sleep(Duration::from_millis(COMMIT_POLL_INTERVAL_MS)).await;
    }
}

/// Queries a raw key from the workload state via Public gRPC.
pub async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut client = connect(rpc_addr).await?;
    let req = QueryRawStateRequest { key: key.to_vec() };
    let response = client.query_raw_state(req).await?.into_inner();

    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

/// Gets the current chain height from the state.
pub async fn get_chain_height(rpc_addr: &str) -> Result<u64> {
    let mut client = connect(rpc_addr).await?;
    let req = GetStatusRequest {};
    let status = client.get_status(req).await?.into_inner();
    Ok(status.height)
}

// [NEW] Get full status
pub async fn get_status(rpc_addr: &str) -> Result<GetStatusResponse> {
    let mut client = connect(rpc_addr).await?;
    let req = GetStatusRequest {};
    let status = client.get_status(req).await?.into_inner();
    Ok(status)
}

/// Gets the latest on-chain UNIX timestamp (seconds).
pub async fn get_chain_timestamp(rpc_addr: &str) -> Result<u64> {
    let mut client = connect(rpc_addr).await?;
    let req = GetStatusRequest {};
    let status = client.get_status(req).await?.into_inner();
    Ok(status.latest_timestamp)
}

/// Gets the current set of quarantined validators for PoA.
pub async fn get_quarantined_set(rpc_addr: &str) -> Result<BTreeSet<ioi_types::app::AccountId>> {
    let bytes_opt = query_state_key(rpc_addr, QUARANTINED_VALIDATORS_KEY).await?;
    if let Some(bytes) = bytes_opt {
        codec::from_bytes_canonical(&bytes)
            .map_err(|e| anyhow!("Failed to decode quarantined set: {}", e))
    } else {
        Ok(BTreeSet::new())
    }
}

/// Gets a governance proposal by its ID.
pub async fn get_proposal(rpc_addr: &str, id: u64) -> Result<Option<Proposal>> {
    let key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &id.to_le_bytes()].concat();
    let bytes_opt = query_state_key(rpc_addr, &key).await?;
    if let Some(bytes) = bytes_opt {
        codec::from_bytes_canonical(&bytes).map_err(|e| anyhow!("Failed to decode proposal: {}", e))
    } else {
        Ok(None)
    }
}

/// Checks if a contract's code exists at a given address.
pub async fn get_contract_code(rpc_addr: &str, address: &[u8]) -> Result<Option<Vec<u8>>> {
    let key = [b"contract_code::", address].concat();
    let state_entry_bytes_opt = query_state_key(rpc_addr, &key).await?;
    if let Some(state_entry_bytes) = state_entry_bytes_opt {
        let entry: StateEntry = codec::from_bytes_canonical(&state_entry_bytes)
            .map_err(|e| anyhow!("StateEntry decode failed: {}", e))?;
        Ok(Some(entry.value))
    } else {
        Ok(None)
    }
}

/// Gets the current set of processed evidence IDs.
pub async fn get_evidence_set(rpc_addr: &str) -> Result<BTreeSet<[u8; 32]>> {
    let bytes_opt = query_state_key(rpc_addr, EVIDENCE_REGISTRY_KEY).await?;
    if let Some(bytes) = bytes_opt {
        codec::from_bytes_canonical(&bytes)
            .map_err(|e| anyhow!("Failed to decode evidence set: {}", e))
    } else {
        Ok(BTreeSet::new())
    }
}

/// Queries the block header for a specific, committed block height using gRPC.
pub async fn get_block_by_height(
    rpc_addr: &str,
    height: u64,
) -> Result<Option<Block<ChainTransaction>>> {
    let mut client = connect(rpc_addr).await?;
    let req = GetBlockByHeightRequest { height };
    // The server returns empty bytes if not found.
    let response = client.get_block_by_height(req).await?.into_inner();

    if response.block_bytes.is_empty() {
        Ok(None)
    } else {
        let block = codec::from_bytes_canonical(&response.block_bytes)
            .map_err(|e| anyhow!("Failed to decode block: {}", e))?;
        Ok(Some(block))
    }
}

/// Queries a raw key from the workload state against a specific historical root via RPC.
pub async fn query_state_key_at_root(
    rpc_addr: &str,
    root: &StateRoot,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut client = connect(rpc_addr).await?;

    let req = ioi_ipc::blockchain::QueryStateAtRequest {
        root: root.0.clone(),
        key: key.to_vec(),
    };

    let response = client.query_state(req).await?.into_inner();

    // [FIX] Manually map the String error from codec to anyhow::Error
    let qs_resp: ioi_api::chain::QueryStateResponse =
        codec::from_bytes_canonical(&response.response_bytes)
            .map_err(|e| anyhow!("Failed to decode QueryStateResponse: {}", e))?;

    Ok(qs_resp.membership.into_option())
}
