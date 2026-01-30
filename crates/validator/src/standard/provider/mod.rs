// Path: crates/validator/src/standard/provider/mod.rs

//! The Compute Provider module.
//!
//! This module implements the logic for "Type B" validators (Compute Providers)
//! that offer hardware resources (CPU/GPU) to the network.

/// The HTTP API server for the provider.
pub mod server;

use anyhow::{anyhow, Result};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_crypto::algorithms::hash::sha256;
// [FIX] Removed unused import Ed25519KeyPair
use ioi_services::market::JobTicket;
use ioi_types::codec;
// [FIX] Use crate-relative path instead of package name
use crate::common::LocalSigner;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

// [FIX] Define the Receipt Data structure here to match the client's expectation
// This mirrors the struct in `operator_tasks.rs`
/// Data returned to the client upon successful provisioning.
#[derive(serde::Serialize)]
pub struct ProvisioningReceiptData {
    /// The unique ID of the provisioned instance.
    pub instance_id: String,
    /// The public URI where the instance is reachable.
    pub endpoint_uri: String,
    /// The lease identifier for resource tracking.
    pub lease_id: String,
    /// The provider's cryptographic signature over the receipt data.
    pub signature: String, // Hex encoded
}

/// The brain of the Compute Provider.
/// Manages resource allocation and job acceptance.
pub struct ProviderController {
    /// The identity key used to sign receipts.
    signer: Arc<LocalSigner>,
    /// The public endpoint where this provider is reachable (e.g. https://provider.io)
    public_endpoint: String,
    /// Internal map of active jobs (Mock resource manager for MVP).
    active_jobs: Arc<Mutex<std::collections::HashMap<String, JobTicket>>>,
}

impl ProviderController {
    /// Creates a new `ProviderController`.
    ///
    /// # Arguments
    /// * `signer` - The local signer used to authenticate receipts.
    /// * `public_endpoint` - The base URL where this provider's services are exposed.
    pub fn new(signer: Arc<LocalSigner>, public_endpoint: String) -> Self {
        Self {
            signer,
            public_endpoint,
            active_jobs: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Handles a request to provision a new compute instance.
    pub async fn handle_provision_request(
        &self,
        ticket: JobTicket,
        _ticket_root: [u8; 32],
    ) -> Result<ProvisioningReceiptData> {
        log::info!(
            "Provider: Received provisioning request for Job {}",
            ticket.request_id
        );

        // 1. Validation (Simplified for MVP)
        // In prod: Verify ticket signature, check user balance on-chain, check resource availability.
        // Here we assume the router has done basic filtering.

        // 2. Resource Allocation (Mock)
        // In prod: Call Docker/Kubernetes/Libvirt to spawn the container.
        let instance_id = Uuid::new_v4().to_string();
        let lease_id = Uuid::new_v4().to_string();
        
        // Mock endpoint for the specific instance (e.g. a reverse proxy path)
        let instance_uri = format!("{}/instances/{}", self.public_endpoint, instance_id);

        // 3. Construct Receipt Payload
        // We must sign exactly what the client expects:
        // Domain || TicketRoot || InstanceID || Hash(URI) || Expiry || Hash(Lease)
        
        // Re-calculate ticket root to ensure integrity
        let ticket_bytes = codec::to_bytes_canonical(&ticket).map_err(|e| anyhow!(e))?;
        let computed_root = sha256(&ticket_bytes)?;
        
        // Define domain separator (Must match client)
        // [FIX] Prefix unused variable
        let _domain = b"IOI_DCPP_PROVIDER_ACK_V1"; 
        
        let endpoint_hash = sha256(instance_uri.as_bytes())?;
        let lease_hash = sha256(lease_id.as_bytes())?;
        
        // Manual SCALE encoding of the fields:
        // ticket_root (32) + instance_id (vec) + endpoint_hash (32) + expiry (u64) + lease_hash (32)
        let mut payload_vec = Vec::new();
        payload_vec.extend_from_slice(&computed_root);
        parity_scale_codec::Encode::encode_to(&instance_id.as_bytes().to_vec(), &mut payload_vec);
        payload_vec.extend_from_slice(&endpoint_hash);
        payload_vec.extend_from_slice(&ticket.expiry_height.to_le_bytes()); // SCALE uses LE for u64
        payload_vec.extend_from_slice(&lease_hash);
        
        self.active_jobs.lock().await.insert(instance_id.clone(), ticket);

        Ok(ProvisioningReceiptData {
            instance_id,
            endpoint_uri: instance_uri,
            lease_id,
            signature: String::new(), // Will be filled by caller or we sign here if we update args
        })
    }
    
    /// Provisions a resource, signing the receipt with the provided domain context.
    ///
    /// # Arguments
    /// * `ticket` - The job ticket containing specifications.
    /// * `domain` - The domain separator (including chain ID and genesis hash) for replay protection.
    pub async fn provision_with_domain(
        &self,
        ticket: JobTicket,
        domain: Vec<u8>,
    ) -> Result<ProvisioningReceiptData> {
         let mut receipt = self.handle_provision_request(ticket.clone(), [0;32]).await?;
         
         // Re-construct payload to sign
         // (Duplicated logic from above - in refactor we'd share the struct)
         let ticket_bytes = codec::to_bytes_canonical(&ticket).map_err(|e| anyhow!(e))?;
         let computed_root = sha256(&ticket_bytes)?;
         
         let endpoint_hash = sha256(receipt.endpoint_uri.as_bytes())?;
         let lease_hash = sha256(receipt.lease_id.as_bytes())?;
         
         #[derive(parity_scale_codec::Encode)]
        struct ProviderAckPayload {
            ticket_root: [u8; 32],
            instance_id: Vec<u8>,
            endpoint_uri_hash: [u8; 32],
            expiry_height: u64,
            lease_id_hash: [u8; 32],
        }
        let ack_payload = ProviderAckPayload {
            ticket_root: computed_root.try_into().unwrap(),
            instance_id: receipt.instance_id.as_bytes().to_vec(),
            endpoint_uri_hash: endpoint_hash.try_into().unwrap(),
            expiry_height: ticket.expiry_height,
            lease_id_hash: lease_hash.try_into().unwrap(),
        };
        let payload_bytes = codec::to_bytes_canonical(&ack_payload).map_err(|e| anyhow!(e))?;
        
        let mut signing_input = domain;
        signing_input.extend_from_slice(&payload_bytes);
        
        // Sign
        let sig_bytes = self.signer.keypair.private_key().sign(&signing_input)?.to_bytes();
        receipt.signature = hex::encode(sig_bytes);
        
        Ok(receipt)
    }
}