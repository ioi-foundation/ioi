// Path: crates/consensus/src/util.rs
use crate::Consensus;
use anyhow::Result;
use ioi_types::app::ChainTransaction;
use ioi_types::config::{ConsensusType, OrchestrationConfig};

pub fn engine_from_config(config: &OrchestrationConfig) -> Result<Consensus<ChainTransaction>> {
    match config.consensus_type {
        ConsensusType::ProofOfStake => proof_of_stake_engine(),
        ConsensusType::ProofOfAuthority => proof_of_authority_engine(),
        ConsensusType::Admft => lft_engine(),
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

#[cfg(feature = "admft")]
fn lft_engine() -> Result<Consensus<ChainTransaction>> {
    use crate::lft::LftEngine;

    log::info!("Using A-DMFT Lazarus consensus engine.");
    Ok(Consensus::Lft(LftEngine::new()))
}

#[cfg(not(feature = "admft"))]
fn lft_engine() -> Result<Consensus<ChainTransaction>> {
    Err(anyhow::anyhow!(
        "Node configured for Admft, but not compiled with the 'consensus-admft' feature."
    ))
}
