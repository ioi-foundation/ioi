use ioi_types::app::SignatureSuite;
use ioi_types::error::ConsensusError;
use libp2p::identity::PublicKey;
use tracing::warn;

/// Verifies the block producer's signature against the oracle-anchored payload.
pub(crate) fn verify_signature(
    preimage: &[u8],
    public_key: &[u8],
    _suite: SignatureSuite,
    signature: &[u8],
    oracle_counter: u64,
    oracle_trace: &[u8; 32],
) -> Result<(), ConsensusError> {
    let pk = PublicKey::try_decode_protobuf(public_key)
        .map_err(|_e| ConsensusError::InvalidSignature)?;

    let header_hash = ioi_crypto::algorithms::hash::sha256(preimage).map_err(|e| {
        warn!("Failed to hash header preimage: {}", e);
        ConsensusError::InvalidSignature
    })?;

    let mut signed_payload = Vec::with_capacity(32 + 8 + 32);
    signed_payload.extend_from_slice(&header_hash);
    signed_payload.extend_from_slice(&oracle_counter.to_be_bytes());
    signed_payload.extend_from_slice(oracle_trace);

    if pk.verify(&signed_payload, signature) {
        Ok(())
    } else {
        Err(ConsensusError::InvalidSignature)
    }
}
