// Path: crates/consensus/src/util.rs
use crate::Consensus;
use anyhow::Result;
use ioi_types::app::ChainTransaction;
use ioi_types::config::{ConsensusType, OrchestrationConfig};

pub fn engine_from_config(config: &OrchestrationConfig) -> Result<Consensus<ChainTransaction>> {
    match config.consensus_type {
        ConsensusType::ProofOfStake => proof_of_stake_engine(),
        ConsensusType::ProofOfAuthority => proof_of_authority_engine(),
        ConsensusType::Convergent => convergent_engine(config.convergent_safety_mode),
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

#[cfg(feature = "convergent")]
fn convergent_engine(
    mode: ioi_types::config::ConvergentSafetyMode,
) -> Result<Consensus<ChainTransaction>> {
    use crate::convergent::ConvergentEngine;

    log::info!("Using Convergent Fault Tolerance consensus engine.");
    Ok(Consensus::Convergent(ConvergentEngine::new(mode)))
}

#[cfg(not(feature = "convergent"))]
fn convergent_engine(
    _mode: ioi_types::config::ConvergentSafetyMode,
) -> Result<Consensus<ChainTransaction>> {
    Err(anyhow::anyhow!(
        "Node configured for Convergent consensus, but not compiled with the 'consensus-convergent' feature."
    ))
}
