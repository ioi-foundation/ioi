// Path: crates/services/src/market/licensing.rs

use anyhow::{anyhow, Result};
use ioi_api::chain::WorkloadClientApi; // [FIX] Import trait for query_state_at
use ioi_api::state::Verifier;
use ioi_client::WorkloadClient;
use ioi_state::tree::iavl::verifier::IAVLHashVerifier;
use ioi_types::app::agentic::AssetLicense;
use ioi_types::app::{AccountId, Membership};
use ioi_types::codec;

pub struct LicenseVerifier {
    rpc_url: String,
    trusted_root: [u8; 32],
}

impl LicenseVerifier {
    pub fn new(rpc_url: String, trusted_root: [u8; 32]) -> Self {
        Self {
            rpc_url,
            trusted_root,
        }
    }

    /// Verifies license ownership using a Merkle Proof.
    pub async fn verify_license(&self, user: AccountId, asset_hash: [u8; 32]) -> Result<bool> {
        let client = WorkloadClient::new(&self.rpc_url, "", "", "").await?;

        let license_key = [b"market::license::", user.as_ref(), b"::", &asset_hash].concat();

        // 1. Request Proof for the License Key
        let root = ioi_types::app::StateRoot(self.trusted_root.to_vec());
        let response = client.query_state_at(root, &license_key).await?;

        // 2. Local Verification
        let verifier = IAVLHashVerifier::default();
        let commitment = verifier.commitment_from_bytes(&self.trusted_root)?;

        // [FIX] Explicitly map codec string error to anyhow::Error
        let proof = codec::from_bytes_canonical(&response.proof_bytes)
            .map_err(|e| anyhow!("Codec error: {}", e))?;

        verifier
            .verify(&commitment, &proof, &license_key, &response.membership)
            .map_err(|e| anyhow!("License proof verification failed: {}", e))?;

        // 3. Check Content
        if let Membership::Present(bytes) = response.membership {
            if let Ok(license) = codec::from_bytes_canonical::<AssetLicense>(&bytes) {
                if license.expiry == 0 {
                    return Ok(true);
                }
                let status = client.get_status().await?;
                return Ok(status.height < license.expiry);
            }
        }

        Ok(false)
    }
}
