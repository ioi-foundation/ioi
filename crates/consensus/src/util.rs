// Path: crates/consensus/src/util.rs
use crate::{AdmftEngine, Consensus};
use anyhow::Result;
use ioi_types::app::ChainTransaction;
use ioi_types::config::OrchestrationConfig;

pub fn engine_from_config(_config: &OrchestrationConfig) -> Result<Consensus<ChainTransaction>> {
    // A-DMFT is now the unified engine for both PoA and PoS configurations.
    log::info!("Initializing A-DMFT Consensus Engine (Guardian-Rooted).");
    Ok(Consensus::Admft(AdmftEngine::new()))
}
