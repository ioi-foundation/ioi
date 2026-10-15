// Path: crates/validator/src/standard/workload/ipc/grpc_blockchain/admitted_tip_no_downgrade_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a round 2, RED-3b (the IOI Director's condition on fence rule (1),
//! 2026-10-15): at or below the Agentgres-admitted marker, the post-signing evidence of a stored
//! block may change but never be DOWNGRADED. A header update may ADD a missing signature or
//! sealed finality proof, or REPLACE one, only with a value that VERIFIES (the signature over the
//! identity hash by the block's own producer, whose key is inside the identity preimage; the proof
//! signed by that producer and bound to the block's oracle counter and trace); it may never
//! REMOVE one, nor put in an unverified one.
//!
//! Written against RED-3 (4837d4479) using only its API, the admission-floor fence for
//! UpdateBlockHeader (`header_update_respects_admission_floor`, a permissive stub there): the
//! refusals FAIL at RED-3, the acceptances pass at RED-3 and must keep passing at GREEN-3.

use super::header_update_respects_admission_floor;
use ioi_api::storage::AdmittedTip;
use ioi_types::app::{
    canonical_sealed_finality_proof_signing_bytes, AccountId, Block, BlockHeader,
    ChainTransaction, GuardianQuorumCertificate, QuorumCertificate, SealedFinalityProof,
    SignatureProof, SignatureSuite, StateRoot,
};
use libp2p::identity::Keypair;

const HEIGHT: u64 = 3;
const ORACLE_COUNTER: u64 = 41;
const ORACLE_TRACE: [u8; 32] = [0x7A; 32];

/// The admitted block at HEIGHT, produced by `producer`, with NO signature and NO proof yet.
fn unsigned_block(producer: &Keypair) -> Block<ChainTransaction> {
    Block {
        header: BlockHeader {
            height: HEIGHT,
            view: 0,
            parent_hash: [0x11; 32],
            parent_state_root: StateRoot(vec![0x22; 32]),
            state_root: StateRoot(vec![0xA3; 32]),
            transactions_root: vec![0x44; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([5; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [6; 32],
            producer_pubkey: producer.public().encode_protobuf(),
            oracle_counter: ORACLE_COUNTER,
            oracle_trace_hash: ORACLE_TRACE,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        },
        transactions: Vec::new(),
    }
}

/// The producer's signature over the identity hash, the oracle counter and the oracle trace (the
/// payload consensus verifies: sha256(preimage) || counter_be || trace).
fn header_signature(header: &BlockHeader, signer: &Keypair) -> Vec<u8> {
    let mut payload = header.hash().expect("identity hash");
    payload.extend_from_slice(&header.oracle_counter.to_be_bytes());
    payload.extend_from_slice(&header.oracle_trace_hash);
    signer.sign(&payload).expect("sign the header")
}

fn signed(mut block: Block<ChainTransaction>, signer: &Keypair) -> Block<ChainTransaction> {
    block.header.signature = header_signature(&block.header, signer);
    block
}

/// A sealed finality proof for `header`, bound to its oracle counter and trace (`epoch` varies
/// the proof's content), signed by `signer` presenting `presented_key`.
fn proof(
    header: &BlockHeader,
    epoch: u64,
    signer: &Keypair,
    presented_key: Vec<u8>,
) -> SealedFinalityProof {
    let mut proof = SealedFinalityProof {
        epoch,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        ..Default::default()
    };
    let bytes = canonical_sealed_finality_proof_signing_bytes(&proof).expect("signing bytes");
    proof.proof_signature = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: presented_key,
        signature: signer.sign(&bytes).expect("sign the proof"),
    };
    proof
}

/// A proof the block's own producer signed: it verifies for that block.
fn valid_proof(header: &BlockHeader, epoch: u64, producer: &Keypair) -> SealedFinalityProof {
    proof(header, epoch, producer, producer.public().encode_protobuf())
}

fn with_proof(
    mut block: Block<ChainTransaction>,
    proof: Option<SealedFinalityProof>,
) -> Block<ChainTransaction> {
    block.header.sealed_finality_proof = proof;
    block
}

fn marker_for(block: &Block<ChainTransaction>) -> AdmittedTip {
    AdmittedTip {
        height: block.header.height,
        block_hash: block
            .header
            .hash()
            .expect("identity hash")
            .try_into()
            .expect("32 bytes"),
        state_root: block.header.state_root.0.clone(),
    }
}

/// RED-3b (a). Replacing a VALID stored proof with one that does not verify is refused: a
/// corrupted producer signature, a proof signed by another key, and a validly signed proof bound
/// to another oracle counter.
#[test]
fn replacing_a_valid_finality_proof_with_an_invalid_one_at_or_below_the_admitted_tip_is_refused()
{
    let producer = Keypair::generate_ed25519();
    let intruder = Keypair::generate_ed25519();
    let signed_block = signed(unsigned_block(&producer), &producer);
    let stored = with_proof(
        signed_block.clone(),
        Some(valid_proof(&signed_block.header, 1, &producer)),
    );
    let marker = marker_for(&stored);

    let mut corrupted = valid_proof(&signed_block.header, 2, &producer);
    corrupted.proof_signature.signature[0] ^= 0xFF;
    assert!(
        header_update_respects_admission_floor(
            Some(&marker),
            Some(&stored),
            &with_proof(signed_block.clone(), Some(corrupted)),
        )
        .is_err(),
        "a proof whose producer signature does not verify is refused"
    );

    let foreign = proof(
        &signed_block.header,
        2,
        &intruder,
        intruder.public().encode_protobuf(),
    );
    assert!(
        header_update_respects_admission_floor(
            Some(&marker),
            Some(&stored),
            &with_proof(signed_block.clone(), Some(foreign)),
        )
        .is_err(),
        "a proof signed by a key other than the block's producer is refused"
    );

    let mut other_slot_header = signed_block.header.clone();
    other_slot_header.oracle_counter = ORACLE_COUNTER + 1;
    let unbound = valid_proof(&other_slot_header, 2, &producer);
    assert!(
        header_update_respects_admission_floor(
            Some(&marker),
            Some(&stored),
            &with_proof(signed_block, Some(unbound)),
        )
        .is_err(),
        "a producer-signed proof bound to another oracle counter is refused"
    );
}

/// RED-3b (b). Stripping a stored finality proof is refused.
#[test]
fn stripping_a_stored_finality_proof_at_or_below_the_admitted_tip_is_refused() {
    let producer = Keypair::generate_ed25519();
    let signed_block = signed(unsigned_block(&producer), &producer);
    let stored = with_proof(
        signed_block.clone(),
        Some(valid_proof(&signed_block.header, 1, &producer)),
    );
    assert!(
        header_update_respects_admission_floor(
            Some(&marker_for(&stored)),
            Some(&stored),
            &with_proof(signed_block, None),
        )
        .is_err(),
        "removing the stored sealed finality proof is refused"
    );
}

/// RED-3b (b). Stripping a stored signature is refused.
#[test]
fn stripping_a_stored_signature_at_or_below_the_admitted_tip_is_refused() {
    let producer = Keypair::generate_ed25519();
    let stored = signed(unsigned_block(&producer), &producer);
    let mut stripped = stored.clone();
    stripped.header.signature = Vec::new();
    assert!(
        header_update_respects_admission_floor(Some(&marker_for(&stored)), Some(&stored), &stripped)
            .is_err(),
        "removing the stored producer signature is refused"
    );
}

/// RED-3b. Putting in UNVERIFIED evidence where there was none is refused: a proof that does not
/// verify added to a block that lacked one, and a signature that does not verify added to an
/// unsigned block.
#[test]
fn adding_unverified_evidence_at_or_below_the_admitted_tip_is_refused() {
    let producer = Keypair::generate_ed25519();
    let intruder = Keypair::generate_ed25519();
    let signed_block = signed(unsigned_block(&producer), &producer);
    let mut bad_proof = valid_proof(&signed_block.header, 1, &producer);
    bad_proof.proof_signature.signature[0] ^= 0xFF;
    assert!(
        header_update_respects_admission_floor(
            Some(&marker_for(&signed_block)),
            Some(&signed_block),
            &with_proof(signed_block.clone(), Some(bad_proof)),
        )
        .is_err(),
        "an unverified proof is not added"
    );

    let unsigned = unsigned_block(&producer);
    let forged = signed(unsigned.clone(), &intruder);
    assert!(
        header_update_respects_admission_floor(Some(&marker_for(&unsigned)), Some(&unsigned), &forged)
            .is_err(),
        "a signature by a key other than the producer's is not added"
    );
}

/// RED-3b. The block's other post-signing evidence (its guardian certificate) is never removed
/// or swapped at or below the marker: the workload cannot verify a committee certificate, so it
/// stays as stored.
#[test]
fn removing_or_changing_a_stored_guardian_certificate_at_or_below_the_admitted_tip_is_refused() {
    let producer = Keypair::generate_ed25519();
    let mut stored = signed(unsigned_block(&producer), &producer);
    stored.header.guardian_certificate = Some(GuardianQuorumCertificate {
        counter: ORACLE_COUNTER,
        trace_hash: ORACLE_TRACE,
        decision_hash: [0xDE; 32],
        ..Default::default()
    });
    let marker = marker_for(&stored);
    let mut removed = stored.clone();
    removed.header.guardian_certificate = None;
    assert!(
        header_update_respects_admission_floor(Some(&marker), Some(&stored), &removed).is_err(),
        "removing the stored guardian certificate is refused"
    );
    let mut swapped = stored.clone();
    if let Some(certificate) = swapped.header.guardian_certificate.as_mut() {
        certificate.decision_hash = [0xEE; 32];
    }
    assert!(
        header_update_respects_admission_floor(Some(&marker), Some(&stored), &swapped).is_err(),
        "swapping the stored guardian certificate is refused"
    );
}

/// RED-3b (c), CONTROL (passes at RED-3 on the permissive stub and must pass at GREEN-3): adding
/// a VALID proof to a block that lacked one is accepted, and so is replacing a valid proof with
/// another valid one for the same block.
#[test]
fn adding_or_replacing_a_valid_finality_proof_at_or_below_the_admitted_tip_is_accepted() {
    let producer = Keypair::generate_ed25519();
    let signed_block = signed(unsigned_block(&producer), &producer);
    let marker = marker_for(&signed_block);
    let first = valid_proof(&signed_block.header, 1, &producer);
    assert_eq!(
        header_update_respects_admission_floor(
            Some(&marker),
            Some(&signed_block),
            &with_proof(signed_block.clone(), Some(first.clone())),
        ),
        Ok(()),
        "a valid proof is added to a committed block that lacked one"
    );
    let stored = with_proof(signed_block.clone(), Some(first));
    assert_eq!(
        header_update_respects_admission_floor(
            Some(&marker),
            Some(&stored),
            &with_proof(
                signed_block.clone(),
                Some(valid_proof(&signed_block.header, 2, &producer))
            ),
        ),
        Ok(()),
        "a valid proof replaces a valid proof"
    );
}

/// CONTROL (passes at RED-3 and must pass at GREEN-3): a signature that verifies may be added to
/// an unsigned committed block, and re-delivering the same signed block is accepted.
#[test]
fn adding_a_verifying_signature_at_or_below_the_admitted_tip_is_accepted() {
    let producer = Keypair::generate_ed25519();
    let unsigned = unsigned_block(&producer);
    let signed_block = signed(unsigned.clone(), &producer);
    assert_eq!(
        header_update_respects_admission_floor(
            Some(&marker_for(&unsigned)),
            Some(&unsigned),
            &signed_block,
        ),
        Ok(()),
        "the producer's verifying signature is added"
    );
    assert_eq!(
        header_update_respects_admission_floor(
            Some(&marker_for(&signed_block)),
            Some(&signed_block),
            &signed_block.clone(),
        ),
        Ok(())
    );
}
