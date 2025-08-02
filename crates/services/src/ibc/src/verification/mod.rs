//! IBC verification utilities

use depin_sdk_api::commitment::{ProofContext, Selector};
use depin_sdk_api::ibc::{LightClient, UniversalProofFormat};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry for light clients
pub struct LightClientRegistry {
    /// Map from chain ID to light client instance
    clients: HashMap<String, Arc<dyn LightClient>>,
}

impl LightClientRegistry {
    /// Create a new light client registry
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Register a light client
    pub fn register(&mut self, chain_id: &str, client: Arc<dyn LightClient>) {
        self.clients.insert(chain_id.to_string(), client);
    }

    /// Get a light client by chain ID
    pub fn get(&self, chain_id: &str) -> Option<Arc<dyn LightClient>> {
        self.clients.get(chain_id).cloned()
    }

    /// Verify a proof against a specific chain
    pub fn verify(
        &self,
        chain_id: &str,
        commitment: &[u8],
        proof: &[u8],
        selector: &Selector,
        value: &[u8],
        context: Option<&ProofContext>,
    ) -> bool {
        if let Some(client) = self.get(chain_id) {
            // Extract key bytes from selector
            let key_bytes = match selector {
                Selector::Key(key) => key.as_slice(),
                Selector::Position(pos) => {
                    // Convert position to bytes if needed
                    // For now just use empty slice or could use position as bytes
                    &[]
                }
                // Handle other selector types
                _ => &[],
            };

            client.verify_native_proof(commitment, proof, key_bytes, value)
        } else {
            false
        }
    }

    /// Verify a universal proof against a specific chain
    pub fn verify_universal(
        &self,
        chain_id: &str,
        commitment: &[u8],
        proof: &UniversalProofFormat,
        value: &[u8],
        context: Option<&ProofContext>,
    ) -> bool {
        if let Some(client) = self.get(chain_id) {
            client.verify_universal_proof(commitment, proof, &proof.key, value)
        } else {
            false
        }
    }

    /// List all registered chain IDs
    pub fn chain_ids(&self) -> Vec<String> {
        self.clients.keys().cloned().collect()
    }
}

/// Proof verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Proof verified successfully
    Success,
    /// Proof verification failed
    Failure(String),
    /// Chain not found
    ChainNotFound(String),
    /// Unsupported proof format
    UnsupportedProofFormat,
    /// Invalid selector
    InvalidSelector(String),
    /// Missing or invalid context
    InvalidContext(String),
}

/// Cross-chain proof verifier
pub struct CrossChainVerifier {
    /// Light client registry
    registry: LightClientRegistry,
    /// Trusted commitments by chain ID and height
    commitments: HashMap<String, HashMap<u64, Vec<u8>>>,
    /// Cached proof contexts by chain ID
    contexts: HashMap<String, ProofContext>,
}

impl CrossChainVerifier {
    /// Create a new cross-chain proof verifier
    pub fn new(registry: LightClientRegistry) -> Self {
        Self {
            registry,
            commitments: HashMap::new(),
            contexts: HashMap::new(),
        }
    }

    /// Add a trusted commitment
    pub fn add_trusted_commitment(&mut self, chain_id: &str, height: u64, commitment: Vec<u8>) {
        let chain_commitments = self
            .commitments
            .entry(chain_id.to_string())
            .or_insert_with(HashMap::new);

        chain_commitments.insert(height, commitment);
    }

    /// Add a proof context for a chain
    pub fn add_context(&mut self, chain_id: &str, context: ProofContext) {
        self.contexts.insert(chain_id.to_string(), context);
    }

    /// Get proof context for a chain
    pub fn get_context(&self, chain_id: &str) -> Option<&ProofContext> {
        self.contexts.get(chain_id)
    }

    /// Get the latest height for a chain
    pub fn latest_height(&self, chain_id: &str) -> Option<u64> {
        self.commitments
            .get(chain_id)
            .and_then(|commitments| commitments.keys().max().copied())
    }

    /// Get the commitment at a specific height
    pub fn get_commitment(&self, chain_id: &str, height: u64) -> Option<&[u8]> {
        self.commitments
            .get(chain_id)
            .and_then(|commitments| commitments.get(&height))
            .map(|c| c.as_slice())
    }

    /// Verify a proof against the latest commitment for a chain
    pub fn verify_proof(
        &self,
        chain_id: &str,
        proof: &[u8],
        selector: &Selector,
        value: &[u8],
    ) -> VerificationResult {
        // Get the latest height
        let height = match self.latest_height(chain_id) {
            Some(h) => h,
            None => return VerificationResult::ChainNotFound(chain_id.to_string()),
        };

        // Get the commitment at that height
        let commitment = match self.get_commitment(chain_id, height) {
            Some(c) => c,
            None => {
                return VerificationResult::Failure(format!(
                    "No commitment found for chain {} at height {}",
                    chain_id, height
                ))
            }
        };

        // Get the context for the chain
        let context = self.get_context(chain_id);

        // Verify the proof
        if self
            .registry
            .verify(chain_id, commitment, proof, selector, value, context)
        {
            VerificationResult::Success
        } else {
            VerificationResult::Failure(format!(
                "Proof verification failed for chain {} at height {}",
                chain_id, height
            ))
        }
    }

    /// Verify a universal proof against the latest commitment for a chain
    pub fn verify_universal_proof(
        &self,
        chain_id: &str,
        proof: &UniversalProofFormat,
        value: &[u8],
    ) -> VerificationResult {
        // Get the latest height
        let height = match self.latest_height(chain_id) {
            Some(h) => h,
            None => return VerificationResult::ChainNotFound(chain_id.to_string()),
        };

        // Get the commitment at that height
        let commitment = match self.get_commitment(chain_id, height) {
            Some(c) => c,
            None => {
                return VerificationResult::Failure(format!(
                    "No commitment found for chain {} at height {}",
                    chain_id, height
                ))
            }
        };

        // Get the context for the chain
        let context = self.get_context(chain_id);

        // Verify the proof
        if self
            .registry
            .verify_universal(chain_id, commitment, proof, value, context)
        {
            VerificationResult::Success
        } else {
            VerificationResult::Failure(format!(
                "Proof verification failed for chain {} at height {}",
                chain_id, height
            ))
        }
    }

    /// List all registered chain IDs
    pub fn chain_ids(&self) -> Vec<String> {
        self.registry.chain_ids()
    }

    /// Create verification context for a chain
    pub fn create_context(&self, chain_id: &str, height: Option<u64>) -> ProofContext {
        let mut context = ProofContext::new();

        // Add chain ID to context
        context.add_data("chain_id", chain_id.as_bytes().to_vec());

        // Add height to context if specified
        if let Some(h) = height {
            context.add_data("height", h.to_le_bytes().to_vec());
        } else if let Some(h) = self.latest_height(chain_id) {
            context.add_data("height", h.to_le_bytes().to_vec());
        }

        context
    }
}
