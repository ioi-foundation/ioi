// Path: crates/consensus/src/util.rs
//! Utility functions for the consensus crate.

use crate::Consensus;
use anyhow::Result;
use cfg_if::cfg_if;
use ioi_types::app::ChainTransaction;
use ioi_types::config::{ConsensusType, OrchestrationConfig};

/// Creates a concrete consensus engine instance based on the configuration enum.
pub fn engine_from_config(config: &OrchestrationConfig) -> Result<Consensus<ChainTransaction>> {
    match &config.consensus_type {
        ConsensusType::ProofOfStake => {
            cfg_if! {
                if #[cfg(feature = "pos")] {
                    use crate::proof_of_stake::ProofOfStakeEngine;
                    log::info!("Using ProofOfStake consensus engine.");
                    Ok(Consensus::ProofOfStake(ProofOfStakeEngine::new()))
                } else {
                    Err(anyhow::anyhow!("Node configured for ProofOfStake, but not compiled with the 'pos' feature."))
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
                    Err(anyhow::anyhow!("Node configured for ProofOfAuthority, but not compiled with the 'poa' feature."))
                }
            }
        }
        // This pattern allows adding new consensus types that might require config.
        // Example for RoundRobin:
        #[allow(unreachable_patterns)] // This is okay as it depends on features
        ConsensusType::ProofOfAuthority => {
            cfg_if! {
                if #[cfg(feature = "round-robin")] {
                    use crate::round_robin::RoundRobinBftEngine;
                    use std::time::Duration;
                    log::info!("Using RoundRobinBft consensus engine.");
                    let timeout = Duration::from_secs(config.round_robin_view_timeout_secs);
                    Ok(Consensus::RoundRobin(Box::new(RoundRobinBftEngine::new(timeout))))
                } else {
                     Err(anyhow::anyhow!("Node configured for RoundRobinBFT, but not compiled with the 'round-robin' feature."))
                }
            }
        }
    }
}
