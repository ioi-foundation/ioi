use crate::config::SuccinctDriverConfig;
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

/// AFT-CB R4c cfg-audit: a build WITHOUT the native SP1 backend refuses
/// SuccinctSp1V1 continuity verification outright — even for bytes that
/// satisfy the retired simulated recipe. There is no simulated fallback
/// on this lane.
#[cfg(not(feature = "native"))]
#[test]
fn non_native_build_refuses_succinct_continuity_even_for_old_recipe_bytes() {
    let driver = SuccinctDriver::new(SuccinctDriverConfig::pinned());
    let inputs = sample_public_inputs();
    let old_recipe = simulated_continuity_proof_bytes(&inputs).expect("recipe bytes");

    let err = driver
        .verify_canonical_collapse_continuity(
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1,
            &old_recipe,
            &inputs,
        )
        .expect_err("non-native build must refuse the succinct lane");
    assert!(
        err.to_string().contains("native SP1 backend"),
        "refusal must name the missing backend, got: {err}"
    );
}

/// AFT-CB R4c: a native build with an UNPROVISIONED vkey refuses — the
/// pin is the trust anchor, and its absence is a refusal state, never a
/// fallback.
#[cfg(feature = "native")]
#[test]
fn native_build_refuses_unprovisioned_continuity_vkey() {
    let config = SuccinctDriverConfig {
        canonical_collapse_continuity_vkey_bytes: Vec::new(),
        ..SuccinctDriverConfig::pinned()
    };
    let driver = SuccinctDriver::new(config);
    let inputs = sample_public_inputs();

    let err = driver
        .verify_canonical_collapse_continuity(
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1,
            &[0u8; 32],
            &inputs,
        )
        .expect_err("unprovisioned vkey must refuse");
    assert!(err.to_string().contains("unprovisioned"));
}

#[test]
fn continuity_verifier_rejects_reference_hash_proof_system() {
    let driver = SuccinctDriver::new(SuccinctDriverConfig::pinned());
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
