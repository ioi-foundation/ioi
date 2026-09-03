//! FIPS 205 terminal-seal verification shared by runtimes and offline tools.
//!
//! Authority begins at the supplied configuration manifest or predecessor
//! commitment. A public key carried by a share never authenticates itself.

use ioi_types::app::{SealKeyManifestV1, SealShareV2};
use slh_dsa::signature::Verifier;
use slh_dsa::{Sha2_128s, Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};

/// Verify one v2 share after its current key matches the caller's exact
/// enrolled or predecessor-provided commitment.
pub fn verify_seal_share_v2(
    share: &SealShareV2,
    expected_key_commitment: [u8; 32],
) -> Result<(), String> {
    share.verify_anchor(expected_key_commitment)?;
    let public_key =
        SlhDsaVerifyingKey::<Sha2_128s>::try_from(share.current_key.public_key.as_slice())
            .map_err(|_| "invalid SLH-DSA-SHA2-128s public key".to_string())?;
    let signature = SlhDsaSignature::<Sha2_128s>::try_from(share.signature.as_slice())
        .map_err(|_| "invalid SLH-DSA-SHA2-128s signature encoding".to_string())?;
    public_key
        .verify(&share.signing_bytes()?, &signature)
        .map_err(|_| "SLH-DSA terminal signature verification failed".to_string())
}

/// Verify an initial v2 share only through the configuration-owned manifest.
pub fn verify_initial_seal_share_v2(
    share: &SealShareV2,
    manifest: &SealKeyManifestV1,
) -> Result<(), String> {
    let enrolled = manifest.initial_key_for_scope(&share.current_key.scope)?;
    if enrolled.initial_key != share.current_key {
        return Err("initial terminal key binding differs from the enrolled manifest".into());
    }
    verify_seal_share_v2(share, enrolled.initial_key_commitment)
}
