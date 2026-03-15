use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_crypto::sign::guardian_log::{
    canonical_log_leaf_hash, checkpoint_root_from_leaf_hashes, checkpoint_signing_payload,
};
use ioi_types::app::{
    GuardianLogCheckpoint, GuardianLogProof, GuardianTransparencyLogDescriptor, SignatureSuite,
};
use libp2p::identity::Keypair;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Append-only witness log used for guardian receipts and checkpoints.
#[async_trait]
pub trait TransparencyLog: Send + Sync {
    /// Appends an entry and returns the current checkpoint.
    async fn append(&self, entry: &[u8]) -> Result<GuardianLogCheckpoint>;

    /// Returns the descriptor needed to verify signed checkpoints from this log.
    fn descriptor(&self) -> GuardianTransparencyLogDescriptor;
}

/// In-memory witness log for development and compatibility profiles.
#[derive(Debug, Clone)]
pub struct MemoryTransparencyLog {
    log_id: String,
    signer: Arc<Keypair>,
    leaf_hashes: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl MemoryTransparencyLog {
    /// Creates an in-memory witness log with the provided logical identifier and signer.
    pub fn new(log_id: impl Into<String>, signer: Keypair) -> Self {
        Self {
            log_id: log_id.into(),
            signer: Arc::new(signer),
            leaf_hashes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Creates an in-memory witness log with a freshly generated development signer.
    pub fn ephemeral(log_id: impl Into<String>) -> Self {
        Self::new(log_id, Keypair::generate_ed25519())
    }
}

#[async_trait]
impl TransparencyLog for MemoryTransparencyLog {
    async fn append(&self, entry: &[u8]) -> Result<GuardianLogCheckpoint> {
        let leaf_hash = canonical_log_leaf_hash(entry).map_err(|e| anyhow!(e.to_string()))?;
        let mut leaf_hashes = self.leaf_hashes.lock().await;
        leaf_hashes.push(leaf_hash);
        let tree_size = leaf_hashes.len() as u64;
        let extension_leaf_hashes = leaf_hashes.clone();
        let root_hash = checkpoint_root_from_leaf_hashes(&extension_leaf_hashes)
            .map_err(|e| anyhow!(e.to_string()))?;
        let mut checkpoint = GuardianLogCheckpoint {
            log_id: self.log_id.clone(),
            tree_size,
            root_hash,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!(e.to_string()))?
                .as_millis() as u64,
            signature: Vec::new(),
            proof: Some(GuardianLogProof {
                base_tree_size: 0,
                leaf_index: tree_size.saturating_sub(1),
                leaf_hash,
                extension_leaf_hashes,
            }),
        };
        let payload =
            checkpoint_signing_payload(&checkpoint).map_err(|e| anyhow!(e.to_string()))?;
        checkpoint.signature = self
            .signer
            .sign(&payload)
            .map_err(|e| anyhow!("failed to sign transparency checkpoint: {e}"))?;
        Ok(checkpoint)
    }

    fn descriptor(&self) -> GuardianTransparencyLogDescriptor {
        GuardianTransparencyLogDescriptor {
            log_id: self.log_id.clone(),
            signature_suite: SignatureSuite::ED25519,
            public_key: self.signer.public().encode_protobuf(),
        }
    }
}
