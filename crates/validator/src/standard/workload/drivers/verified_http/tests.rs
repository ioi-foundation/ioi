use super::*;
use ioi_types::app::{
    build_http_egress_seal_object, CanonicalCollapseKind, CanonicalCollapseObject,
    CanonicalOrderingCollapse, CanonicalSealingCollapse, CollapseState, SealedFinalityProof,
};

fn sample_canonical_collapse_object(height: u64, epoch: u64) -> CanonicalCollapseObject {
    CanonicalCollapseObject {
        height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: CanonicalOrderingCollapse {
            height,
            kind: CanonicalCollapseKind::Close,
            bulletin_commitment_hash: [21u8; 32],
            bulletin_availability_certificate_hash: [22u8; 32],
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_close_hash: [23u8; 32],
            canonical_order_certificate_hash: [24u8; 32],
        },
        sealing: Some(CanonicalSealingCollapse {
            epoch,
            height,
            view: 1,
            kind: CanonicalCollapseKind::Close,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            transcripts_root: [0u8; 32],
            challenges_root: [0u8; 32],
            resolution_hash: [0u8; 32],
        }),
        transactions_root_hash: [31u8; 32],
        resulting_state_root_hash: [32u8; 32],
    }
}

fn sample_receipt() -> EgressReceipt {
    let request_hash = [1u8; 32];
    let handshake = [2u8; 32];
    let request_tx = [3u8; 32];
    let response_tx = [4u8; 32];
    let chain_hash = [5u8; 32];
    let response_hash = [6u8; 32];
    EgressReceipt {
        request_hash,
        server_name: "localhost".into(),
        transcript_version: 1,
        transcript_root: compute_secure_egress_transcript_root(
            request_hash,
            handshake,
            request_tx,
            response_tx,
            chain_hash,
            response_hash,
        )
        .unwrap(),
        handshake_transcript_hash: handshake,
        request_transcript_hash: request_tx,
        response_transcript_hash: response_tx,
        peer_certificate_chain_hash: chain_hash,
        peer_leaf_certificate_hash: [7u8; 32],
        response_hash,
        policy_hash: [8u8; 32],
        finality_tier: FinalityTier::BaseFinal,
        guardian_certificate: None,
        sealed_finality_proof: None,
        seal_object: None,
        canonical_collapse_object: None,
        log_checkpoint: None,
    }
}

#[test]
fn guardian_receipt_rejects_transcript_mismatch() {
    let guard = ReceiptReplayGuard::new(8);
    let mut receipt = sample_receipt();
    let request_body = b"{}".to_vec();
    let response_body = b"ok".to_vec();
    receipt.request_hash = compute_secure_egress_request_hash(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
    )
    .unwrap();
    receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
    receipt.transcript_root = compute_secure_egress_transcript_root(
        receipt.request_hash,
        receipt.handshake_transcript_hash,
        receipt.request_transcript_hash,
        receipt.response_transcript_hash,
        receipt.peer_certificate_chain_hash,
        receipt.response_hash,
    )
    .unwrap();
    receipt.transcript_root[0] ^= 0x11;
    let err = validate_guardian_receipt(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
        &response_body,
        FinalityTier::BaseFinal,
        &receipt,
        &guard,
    )
    .unwrap_err();
    assert!(err.to_string().contains("transcript root mismatch"));
}

#[test]
fn guardian_receipt_rejects_replay() {
    let guard = ReceiptReplayGuard::new(8);
    let mut receipt = sample_receipt();
    let request_body = b"{}".to_vec();
    let response_body = b"ok".to_vec();
    receipt.request_hash = compute_secure_egress_request_hash(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
    )
    .unwrap();
    receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
    receipt.transcript_root = compute_secure_egress_transcript_root(
        receipt.request_hash,
        receipt.handshake_transcript_hash,
        receipt.request_transcript_hash,
        receipt.response_transcript_hash,
        receipt.peer_certificate_chain_hash,
        receipt.response_hash,
    )
    .unwrap();

    validate_guardian_receipt(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
        &response_body,
        FinalityTier::BaseFinal,
        &receipt,
        &guard,
    )
    .unwrap();
    let err = validate_guardian_receipt(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
        &response_body,
        FinalityTier::BaseFinal,
        &receipt,
        &guard,
    )
    .unwrap_err();
    assert!(err.to_string().contains("replay"));
}

#[test]
fn guardian_receipt_accepts_valid_sealed_effect_seal_object() {
    let guard = ReceiptReplayGuard::new(8);
    let request_body = b"{}".to_vec();
    let response_body = b"ok".to_vec();
    let request_hash = compute_secure_egress_request_hash(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
    )
    .unwrap();
    let sealed_finality_proof = SealedFinalityProof {
        epoch: 9,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: [9u8; 32],
        guardian_decision_hash: [10u8; 32],
        guardian_counter: 11,
        guardian_trace_hash: [12u8; 32],
        guardian_measurement_root: [13u8; 32],
        policy_hash: [8u8; 32],
        ..Default::default()
    };
    let canonical_collapse_object = sample_canonical_collapse_object(41, 9);
    let mut receipt = sample_receipt();
    receipt.request_hash = request_hash;
    receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
    receipt.transcript_root = compute_secure_egress_transcript_root(
        receipt.request_hash,
        receipt.handshake_transcript_hash,
        receipt.request_transcript_hash,
        receipt.response_transcript_hash,
        receipt.peer_certificate_chain_hash,
        receipt.response_hash,
    )
    .unwrap();
    receipt.finality_tier = FinalityTier::SealedFinal;
    receipt.policy_hash = [8u8; 32];
    receipt.sealed_finality_proof = Some(sealed_finality_proof.clone());
    receipt.canonical_collapse_object = Some(canonical_collapse_object.clone());
    receipt.seal_object = Some(
        build_http_egress_seal_object(
            request_hash,
            "localhost",
            "POST",
            "/v1/chat/completions",
            receipt.policy_hash,
            &sealed_finality_proof,
            &canonical_collapse_object,
        )
        .unwrap(),
    );

    validate_guardian_receipt(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
        &response_body,
        FinalityTier::SealedFinal,
        &receipt,
        &guard,
    )
    .unwrap();
}

#[test]
fn guardian_receipt_rejects_invalid_sealed_effect_seal_object() {
    let guard = ReceiptReplayGuard::new(8);
    let request_body = b"{}".to_vec();
    let response_body = b"ok".to_vec();
    let request_hash = compute_secure_egress_request_hash(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
    )
    .unwrap();
    let sealed_finality_proof = SealedFinalityProof {
        epoch: 10,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: [1u8; 32],
        guardian_decision_hash: [2u8; 32],
        guardian_counter: 3,
        guardian_trace_hash: [4u8; 32],
        guardian_measurement_root: [5u8; 32],
        policy_hash: [8u8; 32],
        ..Default::default()
    };
    let canonical_collapse_object = sample_canonical_collapse_object(52, 10);
    let mut receipt = sample_receipt();
    receipt.request_hash = request_hash;
    receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
    receipt.transcript_root = compute_secure_egress_transcript_root(
        receipt.request_hash,
        receipt.handshake_transcript_hash,
        receipt.request_transcript_hash,
        receipt.response_transcript_hash,
        receipt.peer_certificate_chain_hash,
        receipt.response_hash,
    )
    .unwrap();
    receipt.finality_tier = FinalityTier::SealedFinal;
    receipt.policy_hash = [8u8; 32];
    receipt.sealed_finality_proof = Some(sealed_finality_proof.clone());
    receipt.canonical_collapse_object = Some(canonical_collapse_object.clone());
    let mut seal_object = build_http_egress_seal_object(
        request_hash,
        "localhost",
        "POST",
        "/v1/chat/completions",
        receipt.policy_hash,
        &sealed_finality_proof,
        &canonical_collapse_object,
    )
    .unwrap();
    seal_object.proof.proof_bytes[0] ^= 0x42;
    receipt.seal_object = Some(seal_object);

    let err = validate_guardian_receipt(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
        &response_body,
        FinalityTier::SealedFinal,
        &receipt,
        &guard,
    )
    .unwrap_err();
    assert!(err.to_string().contains("seal object is invalid"));
}

#[test]
fn guardian_receipt_rejects_mismatched_canonical_collapse_object() {
    let guard = ReceiptReplayGuard::new(8);
    let request_body = b"{}".to_vec();
    let response_body = b"ok".to_vec();
    let request_hash = compute_secure_egress_request_hash(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
    )
    .unwrap();
    let sealed_finality_proof = SealedFinalityProof {
        epoch: 12,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: [1u8; 32],
        guardian_decision_hash: [2u8; 32],
        guardian_counter: 3,
        guardian_trace_hash: [4u8; 32],
        guardian_measurement_root: [5u8; 32],
        policy_hash: [8u8; 32],
        ..Default::default()
    };
    let canonical_collapse_object = sample_canonical_collapse_object(61, 12);
    let mut mismatched_collapse_object = canonical_collapse_object.clone();
    mismatched_collapse_object.resulting_state_root_hash[0] ^= 0x77;
    let mut receipt = sample_receipt();
    receipt.request_hash = request_hash;
    receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
    receipt.transcript_root = compute_secure_egress_transcript_root(
        receipt.request_hash,
        receipt.handshake_transcript_hash,
        receipt.request_transcript_hash,
        receipt.response_transcript_hash,
        receipt.peer_certificate_chain_hash,
        receipt.response_hash,
    )
    .unwrap();
    receipt.finality_tier = FinalityTier::SealedFinal;
    receipt.policy_hash = [8u8; 32];
    receipt.sealed_finality_proof = Some(sealed_finality_proof.clone());
    receipt.canonical_collapse_object = Some(mismatched_collapse_object);
    receipt.seal_object = Some(
        build_http_egress_seal_object(
            request_hash,
            "localhost",
            "POST",
            "/v1/chat/completions",
            receipt.policy_hash,
            &sealed_finality_proof,
            &canonical_collapse_object,
        )
        .unwrap(),
    );

    let err = validate_guardian_receipt(
        "POST",
        "localhost",
        "/v1/chat/completions",
        &request_body,
        &response_body,
        FinalityTier::SealedFinal,
        &receipt,
        &guard,
    )
    .unwrap_err();
    assert!(err.to_string().contains("canonical collapse object"));
}
