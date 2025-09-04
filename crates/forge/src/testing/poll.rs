// Path: crates/forge/src/testing/poll.rs

use super::rpc::{
    get_chain_height, get_contract_code, get_evidence_set, get_proposal, get_quarantined_set,
    get_stake,
};
use anyhow::{anyhow, Result};
use depin_sdk_types::app::{AccountId, ProposalStatus};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::time::sleep;

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
                log::trace!("Polling for '{}' received transient error: {}", description, e);
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

/// Waits for a specific account to have a specific stake amount.
pub async fn wait_for_stake_to_be(
    rpc_addr: &str,
    account_id: &AccountId,
    target_stake: u64,
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!(
            "stake for account {} to be {}",
            hex::encode(account_id.as_ref()),
            target_stake
        ),
        Duration::from_millis(500),
        timeout,
        || async move {
            let current_stake = get_stake(rpc_addr, account_id).await?.unwrap_or(0);
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

/// Waits for a governance proposal to reach a specific status.
pub async fn wait_for_proposal_status(
    rpc_addr: &str,
    id: u64,
    target_status: ProposalStatus,
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!("proposal {} to reach status {:?}", id, target_status),
        Duration::from_millis(500),
        timeout,
        || async move {
            if let Some(proposal) = get_proposal(rpc_addr, id).await? {
                if proposal.status == target_status {
                    return Ok(Some(()));
                }
            }
            Ok(None)
        },
    )
    .await
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
            let set = get_evidence_set(rpc_addr).await?;
            if set.contains(evidence_id) {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}