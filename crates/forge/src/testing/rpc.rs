// Path: crates/forge/src/testing/rpc.rs

use anyhow::{anyhow, Result};
use ioi_ipc::blockchain::{GetStatusRequest, QueryRawStateRequest};
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetBlockByHeightRequest, SubmitTransactionRequest};
use ioi_types::{
    app::{Block, ChainStatus, ChainTransaction, Membership, Proposal, StateEntry, StateRoot},
    codec,
    keys::{
        EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, QUARANTINED_VALIDATORS_KEY,
        STATUS_KEY,
    },
};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::Channel;

// How many retries for transient RPC decode/transport glitches
const RPC_RETRY_MAX: usize = 5;
const RPC_RETRY_BASE_MS: u64 = 80;

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

/// Submits a transaction and waits for inclusion (Legacy wrapper).
pub async fn submit_transaction(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<()> {
    let initial_height = get_chain_height(rpc_addr).await.unwrap_or(0);
    let _tx_hash = submit_transaction_no_wait(rpc_addr, tx).await?;
    super::assert::wait_for_height(rpc_addr, initial_height + 1, Duration::from_secs(60)).await?;
    Ok(())
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
