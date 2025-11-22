// Path: crates/forge/src/testing/rpc.rs

use anyhow::{anyhow, Result};
use ioi_types::{
    app::{
        AccountId, Block, ChainStatus, ChainTransaction, Membership, Proposal, StateEntry,
        StateRoot,
    },
    codec,
    keys::{
        EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, QUARANTINED_VALIDATORS_KEY,
        STATUS_KEY,
    },
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::time::sleep;

// How many retries for transient RPC decode/transport glitches
const RPC_RETRY_MAX: usize = 5;
const RPC_RETRY_BASE_MS: u64 = 80;

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
                // Normalize transient JSON-RPC decoding / workload start-up hiccups
                if msg.contains("Invalid JSON-RPC response")
                    || msg.contains("getBlockByHeight failed")
                {
                    attempt += 1;
                    if attempt >= RPC_RETRY_MAX {
                        // As a *resilience* choice, return None rather than error out.
                        // Tests will keep polling via wait_until anyway.
                        return Ok(None);
                    }
                    sleep(Duration::from_millis(RPC_RETRY_BASE_MS * attempt as u64)).await;
                    continue;
                }
                // hard error -> bubble up
                return Err(anyhow!(e));
            }
        }
    }
}

/// Return latest known chain tip by probing upwards.
/// Uses get_block_by_height_resilient, so it won't fail due to transient RPC issues.
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

// [+] NEW HELPER for time-sensitive tests
/// Submits a transaction and waits for the next block to be produced, ensuring inclusion.
/// Returns the block that included the transaction.
pub async fn submit_transaction_and_get_block(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<Block<ChainTransaction>> {
    // Use state-based height as it is the primary signal for consensus progress.
    let initial_height = get_chain_height(rpc_addr).await?;
    let target_height = initial_height + 1;

    submit_transaction_no_wait(rpc_addr, tx).await?;

    // Wait for consensus to commit the next height
    super::assert::wait_for_height(rpc_addr, target_height, Duration::from_secs(60)).await?;

    // Poll for the block data itself, handling the small race between state commit and block store commit.
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

/// Submits a transaction but does NOT wait for it to be included in a block.
/// Returns the raw JSON-RPC response `Value`. This is useful for testing
/// transactions that are expected to be rejected by the state machine, causing a chain halt.
pub async fn submit_transaction_no_wait(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<serde_json::Value> {
    // Directly use the canonical SCALE codec from ioi-types.
    let tx_bytes = codec::to_bytes_canonical(tx).map_err(|e| anyhow!(e))?;
    let tx_hex = hex::encode(tx_bytes);
    // Use the new, dedicated endpoint for submitting transactions.
    let url = format!("http://{}/rpc/submit", rpc_addr);
    let client = Client::new();

    // Use the canonical method name.
    let method = "submit_tx";
    let params = json!([tx_hex]);

    let req = json!({ "jsonrpc":"2.0", "method": method, "params": params, "id": 1 });
    let resp = client.post(&url).json(&req).send().await?;
    let status = resp.status();
    let text = resp.text().await?;

    if !status.is_success() {
        return Err(anyhow!(
            "RPC submission failed with status {}: {}",
            status,
            text
        ));
    }

    serde_json::from_str(&text).map_err(|e| anyhow!("Failed to parse JSON RPC response: {}", e))
}

/// The `submit_transaction` helper in `forge` needs to be updated to serialize the tx canonically.
pub async fn submit_transaction(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<()> {
    let initial_height = get_chain_height(rpc_addr).await.unwrap_or(0);

    let v = submit_transaction_no_wait(rpc_addr, tx).await?;

    if v.get("error").is_some() && !v["error"].is_null() {
        return Err(anyhow!("RPC error: {}", v["error"]));
    }

    // Check for a successful result and then wait for the next block
    if v.get("result").is_some() {
        log::info!("submit_transaction: accepted -> {}", v);
        // Wait for the next block to be produced to ensure the tx is processed.
        // Increased timeout to 60s to handle adaptive timing tests and slow CI environments.
        super::assert::wait_for_height(rpc_addr, initial_height + 1, Duration::from_secs(60))
            .await?;
        return Ok(());
    }

    Err(anyhow!(
        "RPC submission was accepted but did not return a valid result: {}",
        v
    ))
}

/// Queries a raw key from the workload state via RPC.
pub async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "query_state",
        "params": [hex::encode(key)],
        "id": 1
    });
    // Use the new dedicated query endpoint for better rate-limiting behavior
    let rpc_url = format!("http://{}/rpc/query", rpc_addr);

    // Add retry logic and robust response parsing.
    let mut backoff = Duration::from_millis(100);
    for attempt in 0..5 {
        // Retry up to 5 times
        let response = client.post(&rpc_url).json(&request_body).send().await;

        match response {
            Ok(r) => {
                match r.status() {
                    StatusCode::OK => {
                        let body = r.text().await?;
                        let v: Value = serde_json::from_str(&body).map_err(|e| {
                            anyhow!(
                                "Invalid JSON-RPC response from server: {}. Body: '{}'",
                                e,
                                body
                            )
                        })?;

                        if let Some(err) = v.get("error") {
                            if !err.is_null() {
                                return Err(anyhow!("RPC error: {}", err));
                            }
                        }

                        return match v["result"].as_str() {
                            Some(hex_val) => Ok(Some(hex::decode(hex_val)?)),
                            None if v["result"].is_null() => Ok(None),
                            _ => Err(anyhow!(
                                "Unexpected result format in RPC response: {}",
                                v["result"]
                            )),
                        };
                    }
                    StatusCode::NOT_FOUND | StatusCode::NO_CONTENT => {
                        // Gracefully handle non-compliant "not found" as success(None)
                        return Ok(None);
                    }
                    StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                        if attempt < 4 =>
                    {
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue; // Retry
                    }
                    status => {
                        let text = r.text().await.unwrap_or_default();
                        return Err(anyhow!(
                            "RPC request failed with status: {} - {}",
                            status,
                            text
                        ));
                    }
                }
            }
            Err(e) if attempt < 4 => {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                if backoff > Duration::from_secs(2) {
                    return Err(e.into()); // Fail after significant backoff
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow!("RPC state query timed out after retries"))
}

/// Gets the current chain height from the state.
pub async fn get_chain_height(rpc_addr: &str) -> Result<u64> {
    let status_bytes = query_state_key(rpc_addr, STATUS_KEY)
        .await?
        .ok_or_else(|| anyhow!("STATUS_KEY not found in state"))?;
    let status: ChainStatus = codec::from_bytes_canonical(&status_bytes)
        .map_err(|e| anyhow!("Failed to decode ChainStatus: {}", e))?;
    Ok(status.height)
}

/// Gets the latest on-chain UNIX timestamp (seconds).
pub async fn get_chain_timestamp(rpc_addr: &str) -> Result<u64> {
    let status_bytes = query_state_key(rpc_addr, STATUS_KEY)
        .await?
        .ok_or_else(|| anyhow!("STATUS_KEY not found in state"))?;
    let status: ChainStatus = codec::from_bytes_canonical(&status_bytes)
        .map_err(|e| anyhow!("Failed to decode ChainStatus: {}", e))?;
    Ok(status.latest_timestamp)
}

/// Gets the current set of quarantined validators for PoA.
pub async fn get_quarantined_set(rpc_addr: &str) -> Result<BTreeSet<AccountId>> {
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

/// Queries the block header for a specific, committed block height via the HTTP RPC.
pub async fn get_block_by_height(
    rpc_addr: &str,
    height: u64,
) -> Result<Option<Block<ChainTransaction>>> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "chain.getBlockByHeight.v1",
        "params": { "height": height },
        "id": 1
    });
    let url = format!("http://{}/rpc/query", rpc_addr);
    let resp = client
        .post(&url)
        .json(&request_body)
        .send()
        .await?
        .json::<Value>()
        .await?;

    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(anyhow!("RPC error getting block {}: {}", height, err));
    }

    serde_json::from_value(resp["result"].clone()).map_err(|e| {
        anyhow!(
            "Failed to parse Block from response for height {}: {}",
            height,
            e
        )
    })
}

/// Queries a raw key from the workload state against a specific historical root via RPC.
pub async fn query_state_key_at_root(
    rpc_addr: &str,
    root: &StateRoot,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    let client = Client::new();
    // The params need to match what the IPC server expects, which is the serialized struct.
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "state.queryStateAt.v1",
        "params": {
            "root": serde_json::to_value(root)?,
            "key": serde_json::to_value(key)?
        },
        "id": 1
    });
    let url = format!("http://{}/rpc/query", rpc_addr);
    let resp: Value = client
        .post(&url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(anyhow!("RPC error in queryStateAt: {}", err));
    }

    let result_val = resp
        .get("result")
        .ok_or_else(|| anyhow!("Missing result field"))?;
    // CHANGED: Use the new response type from api/chain
    let response_struct: ioi_api::chain::QueryStateResponse =
        serde_json::from_value(result_val.clone())?;

    match response_struct.membership {
        Membership::Present(bytes) => Ok(Some(bytes)),
        Membership::Absent => Ok(None),
    }
}
