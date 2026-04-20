use anyhow::{anyhow, Result};
use ioi_api::app::{Block, ChainStatus, ChainTransaction};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::consensus::{CanonicalCollapseContinuityVerifier, ConsensusEngine};
use ioi_types::app::{
    aft_canonical_collapse_object_key, canonical_collapse_commitment,
    canonical_collapse_continuity_public_inputs, canonical_collapse_eq_on_header_surface,
    derive_canonical_collapse_object, derive_canonical_collapse_object_with_previous,
    verify_canonical_collapse_continuity, CanonicalCollapseContinuityProofSystem,
    CanonicalCollapseObject,
};
use ioi_types::codec;
use ioi_types::config::ConsensusType;
use std::sync::Arc;
use tokio::sync::Mutex;
use zk_driver_succinct::SuccinctDriver;

fn header_carries_aft_external_finality(block: &Block<ChainTransaction>) -> bool {
    let header = &block.header;
    !header.signature.is_empty()
        || header.guardian_certificate.is_some()
        || header.sealed_finality_proof.is_some()
        || header.canonical_order_certificate.is_some()
        || header.oracle_counter != 0
        || header.oracle_trace_hash != [0u8; 32]
}

fn header_carries_materialized_execution(block: &Block<ChainTransaction>) -> bool {
    let header = &block.header;
    header.timestamp_ms > 0
        || !header.state_root.0.is_empty()
        || !header.transactions_root.is_empty()
        || header.gas_used > 0
}

pub(crate) fn maybe_derive_persisted_canonical_collapse_object(
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !header_carries_aft_external_finality(block) || !header_carries_materialized_execution(block)
    {
        return Ok(None);
    }

    let collapse =
        derive_canonical_collapse_object(&block.header, &block.transactions).map_err(|error| {
            anyhow!(
                "failed to derive canonical collapse object for height {}: {error}",
                block.header.height
            )
        })?;
    Ok(Some(collapse))
}

pub(crate) async fn load_persisted_aft_canonical_collapse_object(
    workload_client: &dyn WorkloadClientApi,
    height: u64,
) -> Result<Option<CanonicalCollapseObject>> {
    let Some(raw) = workload_client
        .query_raw_state(&aft_canonical_collapse_object_key(height))
        .await
        .map_err(|error| {
            anyhow!("failed to load canonical collapse object from workload state: {error}")
        })?
    else {
        return Ok(None);
    };

    codec::from_bytes_canonical(&raw)
        .map(Some)
        .map_err(|error| anyhow!("failed to decode persisted canonical collapse object: {error}"))
}

pub(crate) async fn derive_expected_aft_canonical_collapse_for_block(
    workload_client: &dyn WorkloadClientApi,
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !header_carries_aft_external_finality(block) || !header_carries_materialized_execution(block)
    {
        return Ok(None);
    }

    let previous = if block.header.height <= 1 {
        None
    } else {
        load_persisted_aft_canonical_collapse_object(workload_client, block.header.height - 1)
            .await?
    };
    if let Some(previous) = previous.as_ref() {
        verify_canonical_collapse_backend(previous)?;
    }

    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        previous.as_ref(),
    )
    .map_err(|error| {
        anyhow!(
            "failed to derive canonical collapse object for height {}: {error}",
            block.header.height
        )
    })?;
    verify_canonical_collapse_continuity(&collapse, previous.as_ref()).map_err(|error| {
        anyhow!(
            "derived canonical collapse continuity verification failed for height {}: {}",
            block.header.height,
            error
        )
    })?;
    verify_canonical_collapse_backend(&collapse)?;
    Ok(Some(collapse))
}

pub(crate) async fn resolve_live_aft_canonical_collapse_for_block(
    consensus_type: ConsensusType,
    workload_client: &dyn WorkloadClientApi,
    previous_live_collapse: Option<&CanonicalCollapseObject>,
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !matches!(consensus_type, ConsensusType::Aft) {
        return Ok(None);
    }
    if !header_carries_aft_external_finality(block) || !header_carries_materialized_execution(block)
    {
        return Ok(None);
    }

    let previous = if block.header.height <= 1 {
        None
    } else {
        let persisted_previous =
            load_persisted_aft_canonical_collapse_object(workload_client, block.header.height - 1)
                .await?;
        let previous = match (previous_live_collapse.cloned(), persisted_previous) {
            (_, Some(persisted_previous)) => {
                verify_persisted_aft_canonical_collapse_chain(workload_client, &persisted_previous)
                    .await?;
                Some(persisted_previous)
            }
            (Some(previous_live), None) => {
                verify_canonical_collapse_backend(&previous_live)?;
                Some(previous_live)
            }
            (None, None) => {
                return Err(anyhow!(
                    "missing previous canonical collapse object for height {}",
                    block.header.height
                ));
            }
        };
        previous
    };

    let derived = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        previous.as_ref(),
    )
    .map_err(|error| {
        anyhow!(
            "failed to derive canonical collapse object for height {}: {error}",
            block.header.height
        )
    })?;
    verify_canonical_collapse_continuity(&derived, previous.as_ref()).map_err(|error| {
        anyhow!(
            "derived canonical collapse continuity verification failed for height {}: {}",
            block.header.height,
            error
        )
    })?;
    verify_canonical_collapse_backend(&derived)?;

    if let Some(persisted) =
        load_persisted_aft_canonical_collapse_object(workload_client, block.header.height).await?
    {
        verify_persisted_aft_canonical_collapse_chain(workload_client, &persisted).await?;
        if !canonical_collapse_eq_on_header_surface(&persisted, &derived) {
            return Err(anyhow!(
                "persisted canonical collapse object does not match committed block surface at height {}",
                block.header.height
            ));
        }
        Ok(Some(persisted))
    } else {
        Ok(Some(derived))
    }
}

pub(crate) async fn observe_live_committed_chain_through_block<CE>(
    consensus_engine_ref: &Arc<Mutex<CE>>,
    consensus_type: ConsensusType,
    workload_client: &dyn WorkloadClientApi,
    tip_block: &Block<ChainTransaction>,
) -> Result<bool>
where
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    let target_height = tip_block.header.height;
    if target_height == 0 {
        return Ok(false);
    }

    let mut start_height = target_height;
    if matches!(consensus_type, ConsensusType::Aft) && target_height > 1 {
        for height in 1..target_height {
            let known = consensus_engine_ref
                .lock()
                .await
                .canonical_collapse_for_committed_height(height);
            let Some(known) = known else {
                start_height = height;
                break;
            };

            let Some(persisted) =
                load_persisted_aft_canonical_collapse_object(workload_client, height).await?
            else {
                continue;
            };
            verify_persisted_aft_canonical_collapse_chain(workload_client, &persisted).await?;

            if canonical_collapse_commitment(&known) != canonical_collapse_commitment(&persisted) {
                start_height = height;
                break;
            }
        }
    }

    let mut previous_live_collapse = if start_height <= 1 {
        None
    } else {
        consensus_engine_ref
            .lock()
            .await
            .canonical_collapse_for_committed_height(start_height - 1)
    };

    for height in start_height..=target_height {
        let block = match workload_client
            .get_block_by_height(height)
            .await
            .map_err(|error| {
                anyhow!(
                    "failed to load committed block {height} for live consensus hydration: {error}"
                )
            })? {
            Some(block) => block,
            None if height == target_height => tip_block.clone(),
            None => {
                return Err(anyhow!(
                    "missing committed ancestor block {height} for live consensus hydration"
                ));
            }
        };
        let committed_collapse = resolve_live_aft_canonical_collapse_for_block(
            consensus_type,
            workload_client,
            previous_live_collapse.as_ref(),
            &block,
        )
        .await?;
        let accepted = consensus_engine_ref
            .lock()
            .await
            .observe_committed_block(&block.header, committed_collapse.as_ref());
        if !accepted {
            return Ok(false);
        }
        previous_live_collapse = committed_collapse;
    }

    Ok(true)
}

pub(crate) async fn require_persisted_aft_canonical_collapse_for_block(
    workload_client: &dyn WorkloadClientApi,
    block: &Block<ChainTransaction>,
) -> Result<CanonicalCollapseObject> {
    let expected = derive_expected_aft_canonical_collapse_for_block(workload_client, block)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "AFT durable-state advancement requires a materialized canonical collapse object for height {}",
                block.header.height
            )
        })?;

    let Some(persisted) =
        load_persisted_aft_canonical_collapse_object(workload_client, block.header.height).await?
    else {
        return Err(anyhow!(
            "missing persisted canonical collapse object for AFT height {}",
            block.header.height
        ));
    };
    verify_persisted_aft_canonical_collapse_chain(workload_client, &persisted).await?;
    if !canonical_collapse_eq_on_header_surface(&persisted, &expected) {
        return Err(anyhow!(
            "persisted canonical collapse object does not match committed block surface at height {}",
            block.header.height
        ));
    }

    Ok(persisted)
}

pub(crate) async fn require_persisted_aft_canonical_collapse_if_needed(
    consensus_type: ConsensusType,
    workload_client: &dyn WorkloadClientApi,
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !matches!(consensus_type, ConsensusType::Aft) {
        return Ok(None);
    }

    require_persisted_aft_canonical_collapse_for_block(workload_client, block)
        .await
        .map(Some)
}

pub(crate) fn collapse_backed_aft_status<'a>(
    base: &ChainStatus,
    blocks_desc: impl IntoIterator<Item = &'a Block<ChainTransaction>>,
) -> ChainStatus {
    for block in blocks_desc {
        if maybe_derive_persisted_canonical_collapse_object(block)
            .ok()
            .flatten()
            .is_some()
        {
            let mut durable = base.clone();
            durable.height = block.header.height;
            durable.set_latest_timestamp_ms(block.header.timestamp_ms_or_legacy());
            return durable;
        }
    }

    let mut durable = base.clone();
    durable.height = 0;
    durable.set_latest_timestamp_ms(0);
    durable
}

fn verify_canonical_collapse_backend(collapse: &CanonicalCollapseObject) -> Result<()> {
    let proof = &collapse.continuity_recursive_proof;
    match proof.proof_system {
        CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(()),
        CanonicalCollapseContinuityProofSystem::SuccinctSp1V1 => {
            let public_inputs = canonical_collapse_continuity_public_inputs(
                &proof.commitment,
                proof.previous_canonical_collapse_commitment_hash,
                proof.payload_hash,
                proof.previous_recursive_proof_hash,
            );
            SuccinctDriver::default()
                .verify_canonical_collapse_continuity(
                    proof.proof_system,
                    &proof.proof_bytes,
                    &public_inputs,
                )
                .map_err(|error| {
                    anyhow!(
                        "canonical collapse continuity backend verification failed for height {}: {}",
                        collapse.height,
                        error
                    )
                })
        }
    }
}

async fn verify_persisted_aft_canonical_collapse_chain(
    workload_client: &dyn WorkloadClientApi,
    collapse: &CanonicalCollapseObject,
) -> Result<()> {
    let mut chain = Vec::new();
    let mut current = collapse.clone();
    loop {
        chain.push(current.clone());
        if current.height <= 1 {
            break;
        }
        current = load_persisted_aft_canonical_collapse_object(workload_client, current.height - 1)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "missing persisted canonical collapse object for height {}",
                    current.height - 1
                )
            })?;
    }
    chain.reverse();
    let mut previous: Option<&CanonicalCollapseObject> = None;
    for current in &chain {
        verify_canonical_collapse_continuity(current, previous).map_err(|error| {
            anyhow!(
                "persisted canonical collapse continuity verification failed for height {}: {}",
                current.height,
                error
            )
        })?;
        verify_canonical_collapse_backend(current)?;
        previous = Some(current);
    }
    Ok(())
}

#[cfg(test)]
#[path = "aft_collapse/tests.rs"]
mod tests;
