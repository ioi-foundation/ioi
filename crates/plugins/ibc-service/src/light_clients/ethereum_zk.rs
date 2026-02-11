// Path: crates/services/src/ibc/light_clients/ethereum_zk.rs

use async_trait::async_trait;
use ioi_api::error::CoreError;
use ioi_api::ibc::{IbcZkVerifier, LightClient, VerifyCtx};
use ioi_types::ibc::{Finality, Header, InclusionProof};
use std::sync::Arc;
use zk_driver_succinct::BeaconPublicInputs;
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
        let (eth_header, update_ssz) = match (header, finality) {
            (Header::Ethereum(h), Finality::EthereumBeaconUpdate { update_ssz }) => (h, update_ssz),
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header/finality type for EthereumZkVerifier".into(),
                ))
            }
        };

        // 1. Construct Canonical Public Inputs
        let inputs = BeaconPublicInputs {
            // TODO: Retrieve the trusted previous state root from the client store
            // to enforce continuity of the beacon chain.
            previous_state_root: [0u8; 32],
            new_state_root: eth_header.state_root,
            // TODO: Extract the slot number from the Ethereum header.
            slot: 0,
        };

        // 2. Serialize Inputs using bincode
        let public_inputs_bytes = bincode::serialize(&inputs)
            .map_err(|e| CoreError::Custom(format!("Failed to serialize public inputs: {}", e)))?;

        // 3. Delegate to the ZK driver.
        self.zk_driver
            .verify_beacon_update(update_ssz, &public_inputs_bytes)
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
        let eth_header = match header {
            Header::Ethereum(h) => h,
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header type for EthereumZkVerifier".into(),
                ))
            }
        };

        match proof {
            InclusionProof::Evm {
                scheme,
                proof_bytes,
            } => {
                // We pass the proof bytes directly. The driver constructs the
                // canonical public inputs (containing the root) internally.
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
