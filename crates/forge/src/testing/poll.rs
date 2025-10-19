// Path: crates/forge/src/testing/poll.rs

use anyhow::{anyhow, Result};
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_client::WorkloadClient;
use depin_sdk_types::{
    app::{AccountId, Proposal, ProposalStatus, StateEntry},
    codec,
    keys::{
        GOVERNANCE_PROPOSAL_KEY_PREFIX, ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX,
        QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
    },
};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use super::rpc::{get_chain_height, get_quarantined_set, query_state_key};
use crate::testing::rpc::get_contract_code;

/// Generic polling function that waits for an async condition to be met.
pub async fn wait_for<F, Fut, T>(
    description: &str,
    interval: Duration,
    timeout: Duration,
    mut condition: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let start = Instant::now();
    loop {
        match condition().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => { /* continue polling */ }
            Err(e) => {
                // Don't fail immediately on transient RPC errors, let the timeout handle it.
                log::trace!(
                    "Polling for '{}' received transient error: {}",
                    description,
                    e
                );
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for {}", description));
        }
        sleep(interval).await;
    }
}

/// Waits for the chain to reach a specific block height.
pub async fn wait_for_height(rpc_addr: &str, target_height: u64, timeout: Duration) -> Result<()> {
    wait_for(
        &format!("height to reach {}", target_height),
        Duration::from_millis(500),
        timeout,
        || async move {
            let current_height = get_chain_height(rpc_addr).await?;
            if current_height >= target_height {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

/// Waits for a specific account to have a specific stake amount by polling the *next* validator set.
pub async fn wait_for_stake_to_be(
    client: &WorkloadClient,
    staker_account_id: &AccountId,
    target_stake: u64,
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!(
            "stake for account {}... to be {}",
            hex::encode(staker_account_id.as_ref()),
            target_stake
        ),
        Duration::from_millis(500),
        timeout,
        || async {
            let stakes = client
                .get_next_staked_validators()
                .await
                .map_err(|e: String| anyhow!(e))?;
            let current_stake = stakes.get(staker_account_id).copied().unwrap_or(0);
            if current_stake == target_stake {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

/// Waits for an account's quarantine status to be a specific value.
pub async fn wait_for_quarantine_status(
    rpc_addr: &str,
    account_id: &AccountId,
    is_quarantined: bool,
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!(
            "quarantine status for {} to be {}",
            hex::encode(account_id.as_ref()),
            is_quarantined
        ),
        Duration::from_millis(500),
        timeout,
        || async move {
            let set = get_quarantined_set(rpc_addr).await?;
            if set.contains(account_id) == is_quarantined {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

/// Waits for a governance proposal to be confirmed as passed in the state.
/// This function is robust against RPC rate limiting and minor changes in the `ProposalStatus` enum.
pub async fn confirm_proposal_passed_state(
    rpc_addr: &str,
    proposal_id: u64,
    timeout: Duration,
) -> Result<()> {
    let proposal_key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &proposal_id.to_le_bytes()].concat();

    wait_for(
        &format!("proposal {} to be passed", proposal_id),
        Duration::from_millis(250),
        timeout,
        || async {
            // Query the state to find the proposal and check its status.
            if let Some(bytes) = query_state_key(rpc_addr, &proposal_key).await? {
                let entry: StateEntry = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| anyhow!("StateEntry decode failed: {}", e))?;
                let proposal: Proposal = codec::from_bytes_canonical(&entry.value)
                    .map_err(|e| anyhow!("Proposal decode failed: {}", e))?;

                // This check is tolerant to the exact "passed" state representation.
                if is_passed_like(&proposal.status) {
                    return Ok(Some(()));
                }
            }
            Ok(None)
        },
    )
    .await
}

/// A tolerant predicate that checks if a proposal status is considered "passed".
/// It handles both the direct `Passed` state and a potential future `Closed` state.
fn is_passed_like(status: &ProposalStatus) -> bool {
    matches!(status, ProposalStatus::Passed)
    // If your governance logic had a `Closed` state, you would add it here:
    // `|| matches!(status, ProposalStatus::Closed { outcome: Outcome::Passed, .. })`
}

/// Waits for a contract to be deployed at a specific address.
pub async fn wait_for_contract_deployment(
    rpc_addr: &str,
    address: &[u8],
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!("contract deployment at {}", hex::encode(address)),
        Duration::from_millis(500),
        timeout,
        || async move {
            if get_contract_code(rpc_addr, address).await?.is_some() {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

/// Waits for an evidence ID to be present in the evidence registry.
pub async fn wait_for_evidence(
    rpc_addr: &str,
    evidence_id: &[u8; 32],
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!("evidence ID {}", hex::encode(evidence_id)),
        Duration::from_millis(500),
        timeout,
        || async move {
            let set = super::rpc::get_evidence_set(rpc_addr).await?;
            if set.contains(evidence_id) {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

/// Waits for an oracle request to appear in the "pending" state on-chain.
pub async fn wait_for_pending_oracle_request(
    rpc_addr: &str,
    request_id: u64,
    timeout: Duration,
) -> Result<()> {
    let key = [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();

    wait_for(
        &format!("pending oracle request for id {}", request_id),
        Duration::from_millis(500),
        timeout,
        || async {
            if query_state_key(rpc_addr, &key).await?.is_some() {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

/// A generic polling utility that waits until an async condition returns true.
pub async fn wait_until<F, Fut>(
    timeout: Duration,
    interval: Duration,
    mut condition: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let start = Instant::now();
    loop {
        match condition().await {
            Ok(true) => return Ok(()),
            Ok(false) => { /* continue polling */ }
            Err(e) => {
                log::trace!("Polling condition returned transient error: {}", e);
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for condition"));
        }
        sleep(interval).await;
    }
}

/// Waits for oracle data for a specific request ID to be finalized and present in the state.
pub async fn wait_for_oracle_data(
    rpc_addr: &str,
    request_id: u64,
    expected_value: &[u8],
    timeout: Duration,
) -> Result<()> {
    let key = [ORACLE_DATA_PREFIX, &request_id.to_le_bytes()].concat();

    wait_for(
        &format!("oracle data for request_id {} to be finalized", request_id),
        Duration::from_millis(500),
        timeout,
        || async {
            if let Some(bytes) = query_state_key(rpc_addr, &key).await? {
                // The value stored is a StateEntry containing the final data.
                let entry: StateEntry = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| anyhow!("StateEntry decode failed: {}", e))?;
                if entry.value == expected_value {
                    return Ok(Some(())); // Success!
                }
            }
            Ok(None) // Continue polling
        },
    )
    .await
}
