// Path: crates/forge/src/testing/rpc.rs

use anyhow::{anyhow, Result};
use depin_sdk_types::keys::{
    EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
};
use depin_sdk_types::{
    app::{AccountId, ChainStatus, Proposal, StateEntry},
    codec,
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

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

/// The `submit_transaction` helper in `forge` needs to be updated to serialize the tx canonically.
pub async fn submit_transaction(
    rpc_addr: &str,
    tx: &depin_sdk_types::app::ChainTransaction,
) -> Result<()> {
    // Directly use the canonical SCALE codec from depin-sdk-types.
    let tx_bytes = codec::to_bytes_canonical(tx);
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

    let v: serde_json::Value = serde_json::from_str(&text)?;

    if v.get("error").is_some() && !v["error"].is_null() {
        return Err(anyhow!("RPC error: {}", v["error"]));
    }

    // Check for a successful result
    if v.get("result").is_some() {
        log::info!("submit_transaction: {} accepted -> {}", method, text);
        return Ok(());
    }

    Err(anyhow!(
        "RPC submission was accepted but did not return a valid result: {}",
        text
    ))
}

/// Gets the current chain height from the state.
pub async fn get_chain_height(rpc_addr: &str) -> Result<u64> {
    let status_bytes = query_state_key(rpc_addr, STATUS_KEY)
        .await?
        .ok_or_else(|| anyhow!("STATUS_KEY not found in state"))?;
    let status: ChainStatus =
        codec::from_bytes_canonical(&status_bytes).map_err(anyhow::Error::msg)?;
    Ok(status.height)
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
        let entry: StateEntry =
            codec::from_bytes_canonical(&state_entry_bytes).map_err(anyhow::Error::msg)?;
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
