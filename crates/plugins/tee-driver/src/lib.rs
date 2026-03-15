use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_types::app::wallet_network::GuardianAttestation;

/// Verifier abstraction for guardian / TEE attestation evidence.
#[async_trait]
pub trait GuardianAttestationVerifier: Send + Sync {
    fn verifier_id(&self) -> &'static str;
    async fn verify(&self, attestation: &GuardianAttestation) -> Result<()>;
}

/// Stub hardware quote verifier.
#[derive(Debug, Default)]
pub struct TeeDriverVerifier;

#[async_trait]
impl GuardianAttestationVerifier for TeeDriverVerifier {
    fn verifier_id(&self) -> &'static str {
        "tee_driver"
    }

    async fn verify(&self, attestation: &GuardianAttestation) -> Result<()> {
        let evidence = attestation
            .evidence
            .as_ref()
            .ok_or_else(|| anyhow!("tee_driver requires evidence"))?;
        if evidence.evidence.is_empty() {
            return Err(anyhow!("tee_driver requires non-empty quote evidence"));
        }
        Ok(())
    }
}

/// Software guardian verifier backed by committee/log policy.
#[derive(Debug, Default)]
pub struct SoftwareGuardianVerifier;

#[async_trait]
impl GuardianAttestationVerifier for SoftwareGuardianVerifier {
    fn verifier_id(&self) -> &'static str {
        "software_guardian"
    }

    async fn verify(&self, attestation: &GuardianAttestation) -> Result<()> {
        let evidence = attestation
            .evidence
            .as_ref()
            .ok_or_else(|| anyhow!("software_guardian requires evidence"))?;
        if evidence.manifest_hash == [0u8; 32] || evidence.measurement_root == [0u8; 32] {
            return Err(anyhow!(
                "software_guardian requires manifest and measurement roots"
            ));
        }
        Ok(())
    }
}
