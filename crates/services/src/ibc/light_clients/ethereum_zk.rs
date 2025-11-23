// Path: crates/services/src/ibc/light_clients/ethereum_zk.rs

use async_trait::async_trait;
use ioi_api::error::CoreError;
use ioi_api::ibc::{IbcZkVerifier, LightClient, VerifyCtx};
use ioi_types::ibc::{Finality, Header, InclusionProof};
use std::sync::Arc;
use zk_driver_succinct::{config::SuccinctDriverConfig, SuccinctDriver};

/// A light client verifier for Ethereum that uses a ZK driver.
#[derive(Clone)]
pub struct EthereumZkLightClient {
    chain_id: String,
    // The driver performs the actual ZK verification (SimulatedGroth16 or real SP1).
    zk_driver: Arc<dyn IbcZkVerifier>,
}

impl EthereumZkLightClient {
    /// Create a new client with a specific driver configuration.
    pub fn new(chain_id: String, config: SuccinctDriverConfig) -> Self {
        Self {
            chain_id,
            zk_driver: Arc::new(SuccinctDriver::new(config)),
        }
    }

    /// Create a new client with default (mock) configuration.
    /// Useful for tests that don't care about specific vkeys.
    pub fn new_mock(chain_id: String) -> Self {
        Self {
            chain_id,
            zk_driver: Arc::new(SuccinctDriver::new_mock()),
        }
    }
}

#[async_trait]
impl LightClient for EthereumZkLightClient {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    async fn verify_header(
        &self,
        header: &Header,
        finality: &Finality,
        _ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError> {
        // 1. Extract fields based on types
        let (eth_header, update_ssz) = match (header, finality) {
            (Header::Ethereum(h), Finality::EthereumBeaconUpdate { update_ssz }) => (h, update_ssz),
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header/finality type for EthereumZkVerifier".into(),
                ))
            }
        };

        // 2. Delegate to the ZK driver.
        // In the simulation, the public input is the state root we are committing to.
        let public_inputs = eth_header.state_root.to_vec();

        self.zk_driver
            .verify_beacon_update(update_ssz, &public_inputs)
            .map_err(|e| CoreError::Custom(format!("ZK Beacon verification failed: {}", e)))?;

        log::info!(
            "[EthereumZkVerifier] Verified beacon update for chain {} at root 0x{}",
            self.chain_id,
            hex::encode(eth_header.state_root)
        );

        Ok(())
    }

    async fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        header: &Header,
        _ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError> {
        // 1. Extract the trusted root from the header.
        let eth_header = match header {
            Header::Ethereum(h) => h,
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header type for EthereumZkVerifier".into(),
                ))
            }
        };

        // 2. Delegate to ZK driver.
        match proof {
            InclusionProof::Evm {
                scheme,
                proof_bytes,
            } => {
                self.zk_driver
                    .verify_state_inclusion(*scheme, proof_bytes, eth_header.state_root)
                    .map_err(|e| {
                        CoreError::Custom(format!("ZK State Inclusion verification failed: {}", e))
                    })?;
                Ok(())
            }
            _ => Err(CoreError::Custom(
                "Invalid proof type for EthereumZkVerifier".into(),
            )),
        }
    }

    async fn latest_verified_height(&self) -> u64 {
        // Stateless verifier; actual height tracking is in the service registry state.
        0
    }
}
