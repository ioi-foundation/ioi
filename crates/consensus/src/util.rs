// Path: crates/consensus/src/util.rs
use crate::Consensus;
use anyhow::Result;
use ioi_types::app::ChainTransaction;
use ioi_types::config::{ConsensusType, OrchestrationConfig};

pub fn engine_from_config(config: &OrchestrationConfig) -> Result<Consensus<ChainTransaction>> {
    match config.consensus_type {
        ConsensusType::ProofOfStake => proof_of_stake_engine(),
        ConsensusType::ProofOfAuthority => proof_of_authority_engine(),
        ConsensusType::Aft => {
            aft_engine(config.aft_safety_mode, config.round_robin_view_timeout_secs)
        }
    }
}

#[cfg(feature = "pos")]
fn proof_of_stake_engine() -> Result<Consensus<ChainTransaction>> {
    use crate::proof_of_stake::ProofOfStakeEngine;

    log::info!("Using ProofOfStake consensus engine.");
    Ok(Consensus::ProofOfStake(ProofOfStakeEngine::new()))
}

#[cfg(not(feature = "pos"))]
fn proof_of_stake_engine() -> Result<Consensus<ChainTransaction>> {
    Err(anyhow::anyhow!(
        "Node configured for ProofOfStake, but not compiled with the 'consensus-pos' feature."
    ))
}

#[cfg(feature = "poa")]
fn proof_of_authority_engine() -> Result<Consensus<ChainTransaction>> {
    use crate::proof_of_authority::ProofOfAuthorityEngine;

    log::info!("Using ProofOfAuthority consensus engine.");
    Ok(Consensus::ProofOfAuthority(ProofOfAuthorityEngine::new()))
}

#[cfg(not(feature = "poa"))]
fn proof_of_authority_engine() -> Result<Consensus<ChainTransaction>> {
    Err(anyhow::anyhow!(
        "Node configured for ProofOfAuthority, but not compiled with the 'consensus-poa' feature."
    ))
}

#[cfg(feature = "aft")]
fn aft_engine(
    mode: ioi_types::config::AftSafetyMode,
    view_timeout_secs: u64,
) -> Result<Consensus<ChainTransaction>> {
    use crate::aft::AftEngine;
    use std::time::Duration;

    let view_timeout = std::env::var("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(view_timeout_secs.max(1)));

    log::info!("Using Aft Fault Tolerance consensus engine.");
    Ok(Consensus::Aft(AftEngine::with_view_timeout(
        mode,
        view_timeout,
    )))
}

#[cfg(not(feature = "aft"))]
fn aft_engine(
    _mode: ioi_types::config::AftSafetyMode,
    _view_timeout_secs: u64,
) -> Result<Consensus<ChainTransaction>> {
    Err(anyhow::anyhow!(
        "Node configured for Aft consensus, but not compiled with the 'consensus-aft' feature."
    ))
}
