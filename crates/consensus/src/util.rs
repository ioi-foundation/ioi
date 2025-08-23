// Path: crates/consensus/src/util.rs
//! Utility functions for the consensus crate.

use crate::Consensus;
use anyhow::Result;
use cfg_if::cfg_if;
use depin_sdk_types::app::ChainTransaction;
use depin_sdk_types::config::ConsensusType;

/// Creates a concrete consensus engine instance based on the configuration enum.
pub fn engine_from_config(config_type: &ConsensusType) -> Result<Consensus<ChainTransaction>> {
    // --- FIX START: Move the Ok() wrapper inside each match arm ---
    match config_type {
        ConsensusType::ProofOfStake => {
            cfg_if! {
                if #[cfg(feature = "pos")] {
                    use crate::proof_of_stake::ProofOfStakeEngine;
                    log::info!("Using ProofOfStake consensus engine.");
                    Ok(Consensus::ProofOfStake(ProofOfStakeEngine::new()))
                } else {
                    Err(anyhow::anyhow!("Node configured for ProofOfStake, but not compiled with the 'consensus-pos' feature."))
                }
            }
        }
        ConsensusType::ProofOfAuthority => {
            cfg_if! {
                if #[cfg(feature = "poa")] {
                    use crate::proof_of_authority::ProofOfAuthorityEngine;
                    log::info!("Using ProofOfAuthority consensus engine.");
                    Ok(Consensus::ProofOfAuthority(ProofOfAuthorityEngine::new()))
                } else {
                    Err(anyhow::anyhow!("Node configured for ProofOfAuthority, but not compiled with the 'consensus-poa' feature."))
                }
            }
        }
    }
    // --- FIX END: The Ok(engine) line is removed from here ---
}
