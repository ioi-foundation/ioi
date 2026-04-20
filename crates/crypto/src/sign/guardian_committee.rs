use crate::algorithms::hash::sha256;
use crate::error::CryptoError;
use crate::sign::bls::{
    aggregate_signatures, verify_aggregate_fast, BlsPrivateKey, BlsPublicKey, BlsSignature,
};
use ioi_api::crypto::{SerializableKey, SigningKey};
use ioi_types::app::{
    GuardianCommitteeManifest, GuardianDecision, GuardianQuorumCertificate,
    GuardianWitnessCertificate, GuardianWitnessCommitteeManifest, GuardianWitnessStatement,
};
use ioi_types::codec;
use std::collections::BTreeSet;

fn normalized_manifest_for_hash(manifest: &GuardianCommitteeManifest) -> GuardianCommitteeManifest {
    let mut normalized = manifest.clone();
    for member in &mut normalized.members {
        member.endpoint = None;
    }
    normalized
}

fn normalized_witness_manifest_for_hash(
    manifest: &GuardianWitnessCommitteeManifest,
) -> GuardianWitnessCommitteeManifest {
    let mut normalized = manifest.clone();
    for member in &mut normalized.members {
        member.endpoint = None;
    }
    normalized
}

/// Hashes the canonical guardian committee manifest encoding.
pub fn canonical_manifest_hash(
    manifest: &GuardianCommitteeManifest,
) -> Result<[u8; 32], CryptoError> {
    // Endpoints are operational routing metadata and must not affect committee identity.
    let normalized = normalized_manifest_for_hash(manifest);
    let bytes =
        codec::to_bytes_canonical(&normalized).map_err(|e| CryptoError::Custom(e.to_string()))?;
    sha256(&bytes)
}

/// Hashes the canonical guardian decision encoding.
pub fn canonical_decision_hash(decision: &GuardianDecision) -> Result<[u8; 32], CryptoError> {
    let bytes =
        codec::to_bytes_canonical(decision).map_err(|e| CryptoError::Custom(e.to_string()))?;
    sha256(&bytes)
}

/// Hashes the canonical experimental witness committee manifest encoding.
pub fn canonical_witness_manifest_hash(
    manifest: &GuardianWitnessCommitteeManifest,
) -> Result<[u8; 32], CryptoError> {
    let normalized = normalized_witness_manifest_for_hash(manifest);
    let bytes =
        codec::to_bytes_canonical(&normalized).map_err(|e| CryptoError::Custom(e.to_string()))?;
    sha256(&bytes)
}

/// Hashes the canonical experimental witness statement encoding.
pub fn canonical_witness_statement_hash(
    statement: &GuardianWitnessStatement,
) -> Result<[u8; 32], CryptoError> {
    let bytes =
        codec::to_bytes_canonical(statement).map_err(|e| CryptoError::Custom(e.to_string()))?;
    sha256(&bytes)
}

/// Encodes a sorted signer set into the canonical committee bitfield format.
pub fn encode_signers_bitfield(
    committee_len: usize,
    signer_indexes: &[usize],
) -> Result<Vec<u8>, CryptoError> {
    let mut seen = BTreeSet::new();
    let mut bitfield = vec![0u8; committee_len.div_ceil(8)];

    for signer_index in signer_indexes {
        if *signer_index >= committee_len {
            return Err(CryptoError::InvalidInput(format!(
                "signer index {} is outside committee of size {}",
                signer_index, committee_len
            )));
        }
        if !seen.insert(*signer_index) {
            return Err(CryptoError::InvalidInput(format!(
                "duplicate signer index {}",
                signer_index
            )));
        }
        bitfield[*signer_index / 8] |= 1u8 << (*signer_index % 8);
    }

    Ok(bitfield)
}

/// Decodes the canonical committee signer bitfield.
pub fn decode_signers_bitfield(
    committee_len: usize,
    signers_bitfield: &[u8],
) -> Result<Vec<usize>, CryptoError> {
    let expected_len = committee_len.div_ceil(8);
    if signers_bitfield.len() != expected_len {
        return Err(CryptoError::InvalidInput(format!(
            "invalid signer bitfield length: expected {}, got {}",
            expected_len,
            signers_bitfield.len()
        )));
    }

    let mut indexes = Vec::new();
    for index in 0..committee_len {
        let byte = signers_bitfield[index / 8];
        if ((byte >> (index % 8)) & 1u8) == 1 {
            indexes.push(index);
        }
    }

    for padding_index in committee_len..(expected_len * 8) {
        let byte = signers_bitfield[padding_index / 8];
        if ((byte >> (padding_index % 8)) & 1u8) == 1 {
            return Err(CryptoError::InvalidInput(
                "signer bitfield has non-zero padding bits".into(),
            ));
        }
    }

    Ok(indexes)
}

/// Aggregates committee signatures for a canonical decision hash.
pub fn aggregate_member_signatures(
    member_signatures: &[(usize, BlsSignature)],
    committee_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let signer_indexes: Vec<usize> = member_signatures.iter().map(|(index, _)| *index).collect();
    let signatures: Vec<BlsSignature> = member_signatures
        .iter()
        .map(|(_, signature)| signature.clone())
        .collect();

    let bitfield = encode_signers_bitfield(committee_len, &signer_indexes)?;
    let aggregated_signature = aggregate_signatures(&signatures)?.to_bytes();

    Ok((bitfield, aggregated_signature))
}

/// Verifies a quorum certificate against its manifest and canonical decision payload.
pub fn verify_quorum_certificate(
    manifest: &GuardianCommitteeManifest,
    decision: &GuardianDecision,
    certificate: &GuardianQuorumCertificate,
) -> Result<(), CryptoError> {
    let manifest_hash = canonical_manifest_hash(manifest)?;
    if certificate.manifest_hash != manifest_hash {
        return Err(CryptoError::InvalidInput(
            "guardian certificate manifest hash mismatch".into(),
        ));
    }
    if certificate.epoch != manifest.epoch {
        return Err(CryptoError::InvalidInput(
            "guardian certificate epoch mismatch".into(),
        ));
    }

    let decision_hash = canonical_decision_hash(decision)?;
    if certificate.decision_hash != decision_hash {
        return Err(CryptoError::InvalidInput(
            "guardian certificate decision hash mismatch".into(),
        ));
    }

    if certificate.measurement_root != decision.measurement_root {
        return Err(CryptoError::InvalidInput(
            "guardian certificate measurement root mismatch".into(),
        ));
    }

    let signer_indexes =
        decode_signers_bitfield(manifest.members.len(), &certificate.signers_bitfield)?;
    if signer_indexes.len() < usize::from(manifest.threshold) {
        return Err(CryptoError::InvalidInput(format!(
            "guardian certificate threshold not met: {} < {}",
            signer_indexes.len(),
            manifest.threshold
        )));
    }

    let mut public_keys = Vec::with_capacity(signer_indexes.len());
    for signer_index in signer_indexes {
        let member = manifest.members.get(signer_index).ok_or_else(|| {
            CryptoError::InvalidInput("guardian certificate signer outside committee".into())
        })?;
        public_keys.push(BlsPublicKey::from_bytes(&member.public_key)?);
    }

    let aggregated_signature = BlsSignature::from_bytes(&certificate.aggregated_signature)?;
    if !verify_aggregate_fast(
        &public_keys,
        &certificate.decision_hash,
        &aggregated_signature,
    )? {
        return Err(CryptoError::VerificationFailed);
    }

    Ok(())
}

/// Verifies a research-only witness certificate against its manifest and canonical witness statement.
pub fn verify_witness_certificate(
    manifest: &GuardianWitnessCommitteeManifest,
    statement: &GuardianWitnessStatement,
    certificate: &GuardianWitnessCertificate,
) -> Result<(), CryptoError> {
    let manifest_hash = canonical_witness_manifest_hash(manifest)?;
    if certificate.manifest_hash != manifest_hash {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate manifest hash mismatch".into(),
        ));
    }
    if certificate.epoch != manifest.epoch {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate epoch mismatch".into(),
        ));
    }
    if certificate.recovery_binding != statement.recovery_binding {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate recovery binding mismatch".into(),
        ));
    }

    let statement_hash = canonical_witness_statement_hash(statement)?;
    if certificate.statement_hash != statement_hash {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate statement hash mismatch".into(),
        ));
    }

    let signer_indexes =
        decode_signers_bitfield(manifest.members.len(), &certificate.signers_bitfield)?;
    if signer_indexes.len() < usize::from(manifest.threshold) {
        return Err(CryptoError::InvalidInput(format!(
            "guardian witness certificate threshold not met: {} < {}",
            signer_indexes.len(),
            manifest.threshold
        )));
    }

    let mut public_keys = Vec::with_capacity(signer_indexes.len());
    for signer_index in signer_indexes {
        let member = manifest.members.get(signer_index).ok_or_else(|| {
            CryptoError::InvalidInput(
                "guardian witness certificate signer outside committee".into(),
            )
        })?;
        public_keys.push(BlsPublicKey::from_bytes(&member.public_key)?);
    }

    let aggregated_signature = BlsSignature::from_bytes(&certificate.aggregated_signature)?;
    if !verify_aggregate_fast(
        &public_keys,
        &certificate.statement_hash,
        &aggregated_signature,
    )? {
        return Err(CryptoError::VerificationFailed);
    }

    Ok(())
}

/// Signs a guardian decision hash with the specified committee members and returns a certificate.
pub fn sign_decision_with_members(
    manifest: &GuardianCommitteeManifest,
    decision: &GuardianDecision,
    counter: u64,
    trace_hash: [u8; 32],
    signer_keys: &[(usize, BlsPrivateKey)],
) -> Result<GuardianQuorumCertificate, CryptoError> {
    if signer_keys.len() < usize::from(manifest.threshold) {
        return Err(CryptoError::InvalidInput(format!(
            "insufficient local signers for threshold {}",
            manifest.threshold
        )));
    }

    let decision_hash = canonical_decision_hash(decision)?;
    let member_signatures = signer_keys
        .iter()
        .map(|(index, key)| {
            key.sign(&decision_hash)
                .map(|signature| (*index, signature))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (signers_bitfield, aggregated_signature) =
        aggregate_member_signatures(&member_signatures, manifest.members.len())?;

    Ok(GuardianQuorumCertificate {
        manifest_hash: canonical_manifest_hash(manifest)?,
        epoch: manifest.epoch,
        decision_hash,
        counter,
        trace_hash,
        measurement_root: decision.measurement_root,
        signers_bitfield,
        aggregated_signature,
        log_checkpoint: None,
        experimental_witness_certificate: None,
    })
}

/// Signs a research-only witness statement with the specified witness committee members.
pub fn sign_witness_statement_with_members(
    manifest: &GuardianWitnessCommitteeManifest,
    statement: &GuardianWitnessStatement,
    signer_keys: &[(usize, BlsPrivateKey)],
) -> Result<GuardianWitnessCertificate, CryptoError> {
    if signer_keys.len() < usize::from(manifest.threshold) {
        return Err(CryptoError::InvalidInput(format!(
            "insufficient local witness signers for threshold {}",
            manifest.threshold
        )));
    }

    let statement_hash = canonical_witness_statement_hash(statement)?;
    let member_signatures = signer_keys
        .iter()
        .map(|(index, key)| {
            key.sign(&statement_hash)
                .map(|signature| (*index, signature))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (signers_bitfield, aggregated_signature) =
        aggregate_member_signatures(&member_signatures, manifest.members.len())?;

    Ok(GuardianWitnessCertificate {
        manifest_hash: canonical_witness_manifest_hash(manifest)?,
        stratum_id: manifest.stratum_id.clone(),
        epoch: manifest.epoch,
        statement_hash,
        signers_bitfield,
        aggregated_signature,
        reassignment_depth: 0,
        recovery_binding: statement.recovery_binding.clone(),
        log_checkpoint: None,
    })
}

#[cfg(test)]
#[path = "guardian_committee/tests.rs"]
mod tests;
