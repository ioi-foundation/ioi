// attestation.rs - Container attestation implementation

use crate::chain::ChainState;
use crate::crypto::{CryptoProvider, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Attestation data structure that follows chain's signature evolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAttestation {
    /// Container identifier
    pub container_id: ContainerId,

    /// Merkle root of measured binaries and memory
    pub merkle_root: MerkleRoot,

    /// Challenge nonce from Guardian
    pub nonce: Vec<u8>,

    /// Timestamp of attestation
    pub timestamp: Timestamp,

    /// Public key for verification (format depends on current scheme)
    pub public_key: Vec<u8>,

    /// Signature over (nonce || merkle_root || timestamp)
    /// Uses the chain's current signature scheme
    pub signature: Vec<u8>,

    /// Metadata about the attestation
    pub metadata: AttestationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMetadata {
    /// Which signature scheme was used (for verification)
    pub signature_scheme: SignatureScheme,

    /// Container version
    pub container_version: String,

    /// Additional measurements
    pub extended_measurements: HashMap<String, Vec<u8>>,
}

/// Attestation manager that handles the protocol
pub struct AttestationManager {
    /// Reference to chain state for current signature scheme
    chain_state: Arc<ChainState>,

    /// Cryptographic provider
    crypto_provider: Arc<CryptoProvider>,

    /// Container's key pair (format depends on current scheme)
    key_pair: Arc<RwLock<KeyPair>>,

    /// Configuration
    config: AttestationConfig,

    /// Attestation history for monitoring
    history: RwLock<AttestationHistory>,
}

impl AttestationManager {
    /// Creates attestation using current chain signature scheme
    pub async fn create_attestation(
        &self,
        nonce: &[u8],
        measurements: &ContainerMeasurements,
    ) -> Result<ContainerAttestation, AttestationError> {
        // Get current signature scheme from chain
        let current_scheme = self
            .chain_state
            .get_active_signature_scheme()
            .await
            .map_err(|e| AttestationError::ChainStateError(e))?;

        // Build merkle root from measurements
        let merkle_root = self.compute_merkle_root(measurements)?;

        // Create attestation message
        let timestamp = current_time();
        let message = self.build_attestation_message(nonce, &merkle_root, timestamp)?;

        // Sign using current scheme
        let key_pair = self.key_pair.read().await;
        let (signature, public_key) = match current_scheme {
            SignatureScheme::Ed25519 => {
                let sig = self
                    .crypto_provider
                    .sign_ed25519(&key_pair.ed25519()?, &message)?;
                let pk = key_pair.ed25519()?.public_key();
                (sig, pk)
            }
            SignatureScheme::Dilithium2 => {
                let sig = self
                    .crypto_provider
                    .sign_dilithium2(&key_pair.dilithium2()?, &message)?;
                let pk = key_pair.dilithium2()?.public_key();
                (sig, pk)
            }
            SignatureScheme::Falcon512 => {
                let sig = self
                    .crypto_provider
                    .sign_falcon512(&key_pair.falcon512()?, &message)?;
                let pk = key_pair.falcon512()?.public_key();
                (sig, pk)
            }
            // Add other schemes as needed
            _ => return Err(AttestationError::UnsupportedScheme(current_scheme)),
        };

        // Create attestation
        let attestation = ContainerAttestation {
            container_id: self.get_container_id(),
            merkle_root,
            nonce: nonce.to_vec(),
            timestamp,
            public_key,
            signature,
            metadata: AttestationMetadata {
                signature_scheme: current_scheme,
                container_version: self.get_container_version(),
                extended_measurements: measurements.extended.clone(),
            },
        };

        // Record in history
        self.history.write().await.record_attestation(&attestation);

        Ok(attestation)
    }

    /// Handles key rotation when chain signature scheme changes
    pub async fn handle_signature_rotation(
        &self,
        new_scheme: SignatureScheme,
    ) -> Result<(), RotationError> {
        info!(
            "Rotating attestation keys to {:?} following chain rotation",
            new_scheme
        );

        // Generate new key pair for the scheme
        let new_key_pair = match new_scheme {
            SignatureScheme::Ed25519 => KeyPair::generate_ed25519(&mut self.crypto_provider.rng())?,
            SignatureScheme::Dilithium2 => {
                KeyPair::generate_dilithium2(&mut self.crypto_provider.rng())?
            }
            SignatureScheme::Falcon512 => {
                KeyPair::generate_falcon512(&mut self.crypto_provider.rng())?
            }
            _ => return Err(RotationError::UnsupportedScheme(new_scheme)),
        };

        // Atomic key replacement
        let mut key_pair = self.key_pair.write().await;
        *key_pair = new_key_pair;

        // Notify Guardian of key rotation
        self.notify_guardian_of_rotation(new_scheme).await?;

        Ok(())
    }

    /// Builds the attestation message to be signed
    fn build_attestation_message(
        &self,
        nonce: &[u8],
        merkle_root: &MerkleRoot,
        timestamp: Timestamp,
    ) -> Result<Vec<u8>, AttestationError> {
        let mut message = Vec::new();
        message.extend_from_slice(nonce);
        message.extend_from_slice(merkle_root.as_bytes());
        message.extend_from_slice(&timestamp.to_be_bytes());
        Ok(message)
    }

    /// Monitors chain for signature scheme changes
    pub async fn monitor_scheme_changes(&self) -> Result<(), Error> {
        let mut current_scheme = self.chain_state.get_active_signature_scheme().await?;

        loop {
            // Check every block for scheme changes
            tokio::time::sleep(self.config.scheme_check_interval).await;

            let new_scheme = self.chain_state.get_active_signature_scheme().await?;
            if new_scheme != current_scheme {
                info!(
                    "Detected signature scheme change: {:?} -> {:?}",
                    current_scheme, new_scheme
                );

                // Handle rotation
                self.handle_signature_rotation(new_scheme).await?;
                current_scheme = new_scheme;
            }
        }
    }
}

/// Guardian-side attestation verifier
pub struct AttestationVerifier {
    chain_state: Arc<ChainState>,
    crypto_provider: Arc<CryptoProvider>,
    config: AttestationConfig,
    container_registry: Arc<ContainerRegistry>,
}

impl AttestationVerifier {
    /// Verifies attestation using the scheme it was created with
    pub async fn verify_attestation(
        &self,
        attestation: &ContainerAttestation,
    ) -> Result<(), AttestationError> {
        // Verify timestamp freshness
        let now = current_time();
        let age = now.saturating_sub(attestation.timestamp);
        if age > self.config.max_attestation_age {
            return Err(AttestationError::StaleAttestation { age });
        }

        // Check clock skew
        if attestation.timestamp > now + self.config.max_clock_skew {
            return Err(AttestationError::ClockSkew);
        }

        // Verify container is registered
        let container_info = self
            .container_registry
            .get(&attestation.container_id)
            .await
            .ok_or(AttestationError::UnknownContainer)?;

        // Build message for verification
        let message = self.build_attestation_message(
            &attestation.nonce,
            &attestation.merkle_root,
            attestation.timestamp,
        )?;

        // Verify signature using the scheme specified in metadata
        match attestation.metadata.signature_scheme {
            SignatureScheme::Ed25519 => {
                self.crypto_provider.verify_ed25519(
                    &attestation.public_key,
                    &message,
                    &attestation.signature,
                )?;
            }
            SignatureScheme::Dilithium2 => {
                self.crypto_provider.verify_dilithium2(
                    &attestation.public_key,
                    &message,
                    &attestation.signature,
                )?;
            }
            SignatureScheme::Falcon512 => {
                self.crypto_provider.verify_falcon512(
                    &attestation.public_key,
                    &message,
                    &attestation.signature,
                )?;
            }
            _ => {
                return Err(AttestationError::UnsupportedScheme(
                    attestation.metadata.signature_scheme,
                ))
            }
        }

        // Verify merkle root matches expected manifest
        self.verify_merkle_root_integrity(
            &attestation.merkle_root,
            &container_info.expected_manifest,
        )?;

        Ok(())
    }

    /// Batch verification for efficiency when possible
    pub async fn verify_attestation_batch(
        &self,
        attestations: &[ContainerAttestation],
    ) -> Result<Vec<Result<(), AttestationError>>, Error> {
        // Group by signature scheme for batch verification
        let mut by_scheme: HashMap<SignatureScheme, Vec<&ContainerAttestation>> = HashMap::new();

        for attestation in attestations {
            by_scheme
                .entry(attestation.metadata.signature_scheme)
                .or_default()
                .push(attestation);
        }

        let mut results = Vec::with_capacity(attestations.len());

        // Batch verify each scheme group
        for (scheme, group) in by_scheme {
            match scheme {
                SignatureScheme::Ed25519 => {
                    // Ed25519 supports efficient batch verification
                    let batch_results = self.batch_verify_ed25519(group).await?;
                    results.extend(batch_results);
                }
                _ => {
                    // Other schemes: verify individually
                    for attestation in group {
                        results.push(self.verify_attestation(attestation).await);
                    }
                }
            }
        }

        Ok(results)
    }
}

/// Attestation monitoring and health tracking
#[derive(Debug)]
pub struct AttestationHealth {
    pub success_rate: f64,
    pub average_latency: Duration,
    pub failed_containers: Vec<ContainerId>,
    pub last_rotation: Option<(SignatureScheme, Timestamp)>,
}

impl AttestationManager {
    /// Gets current attestation health metrics
    pub async fn get_health(&self) -> AttestationHealth {
        let history = self.history.read().await;

        AttestationHealth {
            success_rate: history.calculate_success_rate(),
            average_latency: history.calculate_average_latency(),
            failed_containers: history.get_failed_containers(),
            last_rotation: history.get_last_rotation(),
        }
    }
}

/// Errors specific to attestation
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Unsupported signature scheme: {0:?}")]
    UnsupportedScheme(SignatureScheme),

    #[error("Stale attestation (age: {age:?})")]
    StaleAttestation { age: Duration },

    #[error("Clock skew detected")]
    ClockSkew,

    #[error("Unknown container")]
    UnknownContainer,

    #[error("Merkle root mismatch")]
    MerkleRootMismatch,

    #[error("Chain state error: {0}")]
    ChainStateError(#[from] ChainStateError),

    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_follows_chain_rotation() {
        // Setup
        let chain_state = Arc::new(mock_chain_state());
        let crypto_provider = Arc::new(CryptoProvider::new());
        let manager = AttestationManager::new(chain_state.clone(), crypto_provider);

        // Initially using Ed25519
        chain_state
            .set_active_scheme(SignatureScheme::Ed25519)
            .await;

        // Create attestation with Ed25519
        let attestation1 = manager
            .create_attestation(b"nonce1", &measurements())
            .await?;
        assert_eq!(
            attestation1.metadata.signature_scheme,
            SignatureScheme::Ed25519
        );

        // Chain rotates to Dilithium2
        chain_state
            .set_active_scheme(SignatureScheme::Dilithium2)
            .await;
        manager
            .handle_signature_rotation(SignatureScheme::Dilithium2)
            .await?;

        // New attestation uses Dilithium2
        let attestation2 = manager
            .create_attestation(b"nonce2", &measurements())
            .await?;
        assert_eq!(
            attestation2.metadata.signature_scheme,
            SignatureScheme::Dilithium2
        );

        // Both attestations can be verified
        let verifier = AttestationVerifier::new(chain_state, crypto_provider);
        verifier.verify_attestation(&attestation1).await?;
        verifier.verify_attestation(&attestation2).await?;
    }
}
