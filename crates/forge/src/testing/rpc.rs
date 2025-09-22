// Path: crates/forge/src/testing/rpc.rs

use anyhow::{anyhow, Result};
use depin_sdk_types::app::{AccountId, ChainStatus, Proposal};
use depin_sdk_types::codec;
use depin_sdk_types::keys::{
    EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
};
use reqwest::Client;
use serde_json::json;
use std::collections::BTreeSet;

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
    let response: serde_json::Value = client
        .post(&rpc_url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;

    if let Some(error) = response.get("error") {
        if !error.is_null() {
            return Err(anyhow!("RPC error: {}", error));
        }
    }
    match response["result"].as_str() {
        Some(hex_val) if !hex_val.is_empty() => Ok(Some(hex::decode(hex_val)?)),
        _ => Ok(None),
    }
}

/// Gets the current chain height from the state.
pub async fn get_chain_height(rpc_addr: &str) -> Result<u64> {
    let status_bytes = query_state_key(rpc_addr, STATUS_KEY)
        .await?
        .ok_or_else(|| anyhow!("STATUS_KEY not found in state"))?;
    let status: ChainStatus = serde_json::from_slice(&status_bytes)?;
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
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("Failed to decode proposal: {}", e))
    } else {
        Ok(None)
    }
}

/// Checks if a contract's code exists at a given address.
pub async fn get_contract_code(rpc_addr: &str, address: &[u8]) -> Result<Option<Vec<u8>>> {
    let key = [b"contract_code::", address].concat();
    let state_entry_bytes_opt = query_state_key(rpc_addr, &key).await?;
    if let Some(state_entry_bytes) = state_entry_bytes_opt {
        let entry: depin_sdk_types::app::StateEntry = serde_json::from_slice(&state_entry_bytes)?;
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
