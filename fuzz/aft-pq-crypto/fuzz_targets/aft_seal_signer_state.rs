#![no_main]

use ioi_types::app::{AccountId, SealKeyScopeV1};
use ioi_validator::common::guardian::seal_signer::{
    verify_seal_share_v2, DurableSealSignerV2, SharedFileSealStateAnchor,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

const PASSPHRASE: &str = "aft-state-fuzz-passphrase";
const CUSTODY_ID: [u8; 32] = [0xC7; 32];

fn scope(selector: u8) -> SealKeyScopeV1 {
    SealKeyScopeV1 {
        network_id: [0x11; 32],
        configuration_id: [0x22; 32],
        epoch: 7,
        conflict_domain_id: [selector; 32],
        member_id: AccountId([0x44; 32]),
        member_index: 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, operations)) = data.split_first() else {
        return;
    };
    let temp = tempfile::tempdir().expect("create isolated signer fuzz directory");
    let state_path = temp.path().join("signer.state");
    let anchor_root = temp.path().join("external-anchor");
    let signer_scope = scope(selector);
    let key_count = usize::from(selector % 3) + 1;
    let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope)
        .expect("acquire fresh external anchor");
    let (signer, enrollment) = DurableSealSignerV2::provision(
        &state_path,
        PASSPHRASE.into(),
        CUSTODY_ID,
        signer_scope.clone(),
        [0x55; 32],
        [0x66; 32],
        key_count,
        anchor,
    )
    .expect("provision fresh durable signer");

    let mut signer = Some(signer);
    let mut snapshot: Option<Vec<u8>> = None;
    let mut emitted_slots = BTreeSet::new();
    let mut expected_commitment = enrollment.initial_key_commitment;

    // SLH-DSA operations are intentionally expensive. A bounded prefix still
    // explores long enough state sequences while keeping seeded CI campaigns
    // reproducible on ordinary runners.
    for (step, operation) in operations.iter().copied().take(16).enumerate() {
        match operation % 8 {
            0 => {
                if let Some(active) = signer.as_ref() {
                    let mut root = [operation; 32];
                    root[..8].copy_from_slice(&(step as u64).to_le_bytes());
                    if let Ok(share) = active.sign(root) {
                        assert!(
                            emitted_slots.insert(share.seal_slot),
                            "durable signer emitted one slot more than once"
                        );
                        verify_seal_share_v2(&share, expected_commitment)
                            .expect("emitted share must verify from its predecessor commitment");
                        expected_commitment = share.next_key_commitment;
                    }
                }
            }
            1 => {
                drop(signer.take());
                if let Ok(anchor) =
                    SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope)
                {
                    if let Ok((reopened, _burned)) = DurableSealSignerV2::open(
                        &state_path,
                        PASSPHRASE.into(),
                        CUSTODY_ID,
                        anchor,
                    ) {
                        signer = Some(reopened);
                    }
                }
            }
            2 => {
                drop(signer.take());
                let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope)
                    .expect("released signer must release anchor lock");
                assert!(
                    DurableSealSignerV2::open(
                        &state_path,
                        "wrong passphrase".into(),
                        CUSTODY_ID,
                        anchor,
                    )
                    .is_err(),
                    "wrong passphrase opened durable signer state"
                );
                let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope)
                    .expect("failed open must release anchor lock");
                if let Ok((reopened, _)) = DurableSealSignerV2::open(
                    &state_path,
                    PASSPHRASE.into(),
                    CUSTODY_ID,
                    anchor,
                ) {
                    signer = Some(reopened);
                }
            }
            3 => {
                snapshot = std::fs::read(&state_path).ok();
            }
            4 => {
                if let Some(saved) = snapshot.as_ref() {
                    drop(signer.take());
                    std::fs::write(&state_path, saved).expect("restore signer-state snapshot");
                    let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope)
                        .expect("released signer must release anchor lock");
                    if let Ok((reopened, _)) = DurableSealSignerV2::open(
                        &state_path,
                        PASSPHRASE.into(),
                        CUSTODY_ID,
                        anchor,
                    ) {
                        signer = Some(reopened);
                    }
                }
            }
            5 => {
                drop(signer.take());
                let mut bytes = std::fs::read(&state_path).unwrap_or_default();
                if bytes.is_empty() {
                    bytes.push(operation);
                } else if operation & 1 == 0 {
                    bytes.truncate(usize::from(operation) % bytes.len());
                } else {
                    let index = usize::from(operation) % bytes.len();
                    bytes[index] ^= 0x80;
                }
                std::fs::write(&state_path, bytes).expect("write malformed signer state");
                let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope)
                    .expect("released signer must release anchor lock");
                assert!(
                    DurableSealSignerV2::open(
                        &state_path,
                        PASSPHRASE.into(),
                        CUSTODY_ID,
                        anchor,
                    )
                    .is_err(),
                    "corrupt or truncated encrypted signer state was accepted"
                );
            }
            6 => {
                if signer.is_some() {
                    assert!(
                        SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope).is_err(),
                        "a concurrent signer acquired the single-writer anchor"
                    );
                }
            }
            _ => {
                if let Some(active) = signer.as_ref() {
                    for offset in 0..=key_count {
                        let root = [operation.wrapping_add(offset as u8); 32];
                        if let Ok(share) = active.sign(root) {
                            assert!(
                                emitted_slots.insert(share.seal_slot),
                                "exhaustion path reused a terminal slot"
                            );
                            verify_seal_share_v2(&share, expected_commitment)
                                .expect("exhaustion-path share must verify");
                            expected_commitment = share.next_key_commitment;
                        }
                    }
                    assert!(
                        active.sign([0xEE; 32]).is_err(),
                        "finite terminal-key schedule did not fail closed at exhaustion"
                    );
                }
            }
        }
    }

    drop(signer.take());
    if let Ok(anchor) = SharedFileSealStateAnchor::acquire(&anchor_root, &signer_scope) {
        assert!(
            DurableSealSignerV2::open(
                &state_path,
                PASSPHRASE.into(),
                [0xDE; 32],
                anchor,
            )
            .is_err(),
            "wrong custody identity opened durable signer state"
        );
    }
});
