use crate::SuccinctDriver;
use ioi_api::consensus::CanonicalCollapseContinuityVerifier;
use ioi_types::app::{
    canonical_collapse_succinct_mock_proof_bytes, CanonicalCollapseCommitment,
    CanonicalCollapseContinuityProofSystem, CanonicalCollapseContinuityPublicInputs,
};

fn sample_public_inputs() -> CanonicalCollapseContinuityPublicInputs {
    CanonicalCollapseContinuityPublicInputs {
        commitment: CanonicalCollapseCommitment {
            height: 7,
            continuity_accumulator_hash: [0x11; 32],
            resulting_state_root_hash: [0x22; 32],
        },
        previous_canonical_collapse_commitment_hash: [0x33; 32],
        payload_hash: [0x44; 32],
        previous_recursive_proof_hash: [0x55; 32],
    }
}

#[test]
fn mock_continuity_verifier_accepts_valid_succinct_proof() {
    let driver = SuccinctDriver::new_mock();
    let inputs = sample_public_inputs();
    let proof = canonical_collapse_succinct_mock_proof_bytes(&inputs).expect("mock proof");

    driver
        .verify_canonical_collapse_continuity(
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1,
            &proof,
            &inputs,
        )
        .expect("succinct continuity proof should verify");
}

#[test]
fn mock_continuity_verifier_rejects_mutated_succinct_proof() {
    let driver = SuccinctDriver::new_mock();
    let inputs = sample_public_inputs();
    let mut proof = canonical_collapse_succinct_mock_proof_bytes(&inputs).expect("mock proof");
    proof[0] ^= 0xFF;

    let result = driver.verify_canonical_collapse_continuity(
        CanonicalCollapseContinuityProofSystem::SuccinctSp1V1,
        &proof,
        &inputs,
    );
    assert!(
        result.is_err(),
        "mutated succinct continuity proof must fail"
    );
}

#[test]
fn mock_continuity_verifier_rejects_reference_hash_proof_system() {
    let driver = SuccinctDriver::new_mock();
    let inputs = sample_public_inputs();

    let result = driver.verify_canonical_collapse_continuity(
        CanonicalCollapseContinuityProofSystem::HashPcdV1,
        &[0u8; 32],
        &inputs,
    );
    assert!(
        result.is_err(),
        "the succinct driver should not claim ownership of HashPcdV1 verification"
    );
}
