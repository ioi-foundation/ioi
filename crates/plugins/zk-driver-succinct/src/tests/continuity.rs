use crate::{simulated_continuity_proof_bytes, SuccinctDriver};
use ioi_api::consensus::CanonicalCollapseContinuityVerifier;
use ioi_types::app::{
    CanonicalCollapseCommitment, CanonicalCollapseContinuityProofSystem,
    CanonicalCollapseContinuityPublicInputs,
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
fn simulated_continuity_verifier_accepts_valid_succinct_proof() {
    let driver = SuccinctDriver::new_mock();
    let inputs = sample_public_inputs();
    let proof = simulated_continuity_proof_bytes(&inputs).expect("simulated proof");

    driver
        .verify_canonical_collapse_continuity(
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1,
            &proof,
            &inputs,
        )
        .expect("simulated succinct continuity proof should verify");
}

#[test]
fn simulated_continuity_verifier_rejects_mutated_succinct_proof() {
    let driver = SuccinctDriver::new_mock();
    let inputs = sample_public_inputs();
    let mut proof = simulated_continuity_proof_bytes(&inputs).expect("simulated proof");
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
fn simulated_continuity_verifier_rejects_reference_hash_proof_system() {
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
