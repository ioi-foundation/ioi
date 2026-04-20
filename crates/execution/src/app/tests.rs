use super::*;
use ioi_types::app::{CanonicalCollapseKind, SignatureSuite};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.data.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        Ok(keys.iter().map(|key| self.data.get(key).cloned()).collect())
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        self.batch_set(inserts)?;
        for key in deletes {
            self.data.remove(key);
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<ioi_api::state::StateScanIter<'_>, StateError> {
        let items = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| {
                Ok((
                    Arc::<[u8]>::from(key.clone()),
                    Arc::<[u8]>::from(value.clone()),
                ))
            })
            .collect::<Vec<_>>();
        Ok(Box::new(items.into_iter()))
    }
}

fn sample_replay_prefix_entry(
    height: u64,
    resulting_state_root_hash: [u8; 32],
    ordering_kind: CanonicalCollapseKind,
) -> AftRecoveredReplayEntry {
    AftRecoveredReplayEntry {
        height,
        resulting_state_root_hash,
        canonical_block_commitment_hash: Some([height.wrapping_add(100) as u8; 32]),
        parent_block_commitment_hash: Some(if height <= 1 {
            [0u8; 32]
        } else {
            [height.wrapping_add(99) as u8; 32]
        }),
        canonical_collapse_commitment_hash: [height as u8; 32],
        previous_canonical_collapse_commitment_hash: [height.saturating_sub(1) as u8; 32],
        ordering_kind,
        ordering_resolution_hash: [height.wrapping_add(40) as u8; 32],
        publication_frontier_hash: if ordering_kind == CanonicalCollapseKind::Close {
            Some([height.wrapping_add(80) as u8; 32])
        } else {
            None
        },
        extracted_bulletin_surface_present: ordering_kind == CanonicalCollapseKind::Close,
        archived_recovered_history_checkpoint_hash: None,
        archived_recovered_history_profile_activation_hash: None,
        archived_recovered_history_retention_receipt_hash: None,
    }
}

fn sample_recovered_header_entry(
    height: u64,
    canonical_block_commitment_hash: [u8; 32],
    parent_block_commitment_hash: [u8; 32],
) -> AftRecoveredConsensusHeaderEntry {
    AftRecoveredConsensusHeaderEntry {
        height,
        view: height,
        canonical_block_commitment_hash,
        parent_block_commitment_hash,
        transactions_root_hash: [height.wrapping_add(70) as u8; 32],
        resulting_state_root_hash: [height.wrapping_add(71) as u8; 32],
        previous_canonical_collapse_commitment_hash: [height.saturating_sub(1) as u8; 32],
    }
}

#[test]
fn recover_execution_restart_anchor_returns_prefix_tip() {
    let replay_prefix = vec![
        sample_replay_prefix_entry(2, [0x22; 32], CanonicalCollapseKind::Close),
        sample_replay_prefix_entry(3, [0x33; 32], CanonicalCollapseKind::Abort),
        sample_replay_prefix_entry(4, [0x44; 32], CanonicalCollapseKind::Close),
    ];

    let anchor = recover_execution_restart_anchor_from_replay_prefix(&replay_prefix)
        .expect("recover restart anchor");

    assert_eq!(anchor.height, 4);
    assert_eq!(anchor.resulting_state_root_hash, [0x44; 32]);
}

#[test]
fn validate_execution_restart_handoff_rejects_tip_state_root_mismatch() {
    let replay_prefix = vec![
        sample_replay_prefix_entry(3, [0x33; 32], CanonicalCollapseKind::Abort),
        sample_replay_prefix_entry(4, [0x44; 32], CanonicalCollapseKind::Close),
    ];

    let error =
        validate_execution_restart_handoff_from_replay_prefix(&replay_prefix, 4, &[0x99; 32])
            .expect_err("mismatched root should fail");

    assert!(error
        .to_string()
        .contains("replay-prefix tip state-root mismatch"));
}

#[test]
fn validate_aft_restart_replay_prefix_uses_bounded_recent_window() {
    let state = MockState::default();
    let mut observed_window = None;

    let anchor = validate_aft_restart_replay_prefix_with_extractor(
        &state,
        10,
        &[0xaa; 32],
        |_, start_height, end_height| {
            observed_window = Some((start_height, end_height));
            Ok(vec![
                sample_replay_prefix_entry(7, [0x77; 32], CanonicalCollapseKind::Close),
                sample_replay_prefix_entry(8, [0x88; 32], CanonicalCollapseKind::Abort),
                sample_replay_prefix_entry(9, [0x99; 32], CanonicalCollapseKind::Close),
                sample_replay_prefix_entry(10, [0xaa; 32], CanonicalCollapseKind::Close),
            ])
        },
    )
    .expect("bounded replay-prefix restart validation");

    assert_eq!(observed_window, Some((7, 10)));
    assert_eq!(anchor.height, 10);
    assert_eq!(anchor.resulting_state_root_hash, [0xaa; 32]);
}

#[test]
fn resolve_execution_anchor_uses_recovered_prefix_when_recent_blocks_absent() {
    let replay_prefix = vec![
        sample_replay_prefix_entry(7, [0x77; 32], CanonicalCollapseKind::Close),
        sample_replay_prefix_entry(8, [0x88; 32], CanonicalCollapseKind::Abort),
        sample_replay_prefix_entry(9, [0x99; 32], CanonicalCollapseKind::Close),
        sample_replay_prefix_entry(10, [0xaa; 32], CanonicalCollapseKind::Close),
    ];
    let recovered_state = AftRecoveredStateSurface {
        replay_prefix,
        ..AftRecoveredStateSurface::default()
    };

    let resolved = resolve_execution_anchor_from_recent_blocks_or_replay_prefix(
        &[],
        &[0xaa; 32],
        &recovered_state,
        8,
        &[0x88; 32],
    )
    .expect("resolve recovered prefix anchor");

    assert_eq!(resolved.0, vec![0x88; 32]);
    assert_eq!(resolved.1, 0);
}

#[test]
fn resolve_execution_parent_anchor_uses_recovered_prefix_tip() {
    let replay_prefix = vec![
        sample_replay_prefix_entry(9, [0x99; 32], CanonicalCollapseKind::Close),
        sample_replay_prefix_entry(10, [0xaa; 32], CanonicalCollapseKind::Close),
    ];
    let recovered_state = AftRecoveredStateSurface {
        replay_prefix,
        ..AftRecoveredStateSurface::default()
    };

    let (parent_hash, parent_state_root) =
        resolve_execution_parent_anchor(10, &[], &[0xaa; 32], &recovered_state)
            .expect("resolve recovered parent anchor");

    assert_eq!(parent_state_root.0, vec![0xaa; 32]);
    assert_eq!(parent_hash, vec![110u8; 32]);
}

#[test]
fn resolve_execution_parent_anchor_matches_ordinary_lane_when_recovered_header_cache_carries_block_hash(
) {
    let mut header = BlockHeader {
        height: 10,
        view: 4,
        parent_hash: [0x91; 32],
        parent_state_root: StateRoot(vec![0x92; 32]),
        state_root: StateRoot(vec![0xaa; 32]),
        transactions_root: vec![0x93; 32],
        timestamp: 1_750_100_000,
        timestamp_ms: 1_750_100_000_000,
        gas_used: 7,
        validator_set: Vec::new(),
        producer_account_id: AccountId([0x94; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [0x95; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    header.signature = vec![1, 2, 3];
    let block = Block {
        header: header.clone(),
        transactions: Vec::new(),
    };
    let block_hash = header.hash().expect("block hash");

    let ordinary = resolve_execution_parent_anchor(
        10,
        &[block],
        &[0xaa; 32],
        &AftRecoveredStateSurface::default(),
    )
    .expect("ordinary parent anchor");
    let replay_prefix = vec![AftRecoveredReplayEntry {
        height: 10,
        resulting_state_root_hash: [0xaa; 32],
        canonical_block_commitment_hash: None,
        parent_block_commitment_hash: Some(header.parent_hash),
        canonical_collapse_commitment_hash: [10u8; 32],
        previous_canonical_collapse_commitment_hash: [9u8; 32],
        ordering_kind: CanonicalCollapseKind::Close,
        ordering_resolution_hash: [50u8; 32],
        publication_frontier_hash: Some([60u8; 32]),
        extracted_bulletin_surface_present: true,
        archived_recovered_history_checkpoint_hash: None,
        archived_recovered_history_profile_activation_hash: None,
        archived_recovered_history_retention_receipt_hash: None,
    }];
    let recovered_headers = vec![sample_recovered_header_entry(
        10,
        block_hash.as_slice().try_into().unwrap(),
        header.parent_hash,
    )];
    let recovered_state = AftRecoveredStateSurface {
        replay_prefix,
        consensus_headers: recovered_headers,
        ..AftRecoveredStateSurface::default()
    };
    let recovered = resolve_execution_parent_anchor(10, &[], &[0xaa; 32], &recovered_state)
        .expect("recovered parent anchor");

    assert_eq!(recovered, ordinary);
}

#[test]
fn resolve_execution_parent_anchor_rejects_recovered_header_block_hash_mismatch() {
    let replay_prefix = vec![sample_replay_prefix_entry(
        10,
        [0xaa; 32],
        CanonicalCollapseKind::Close,
    )];
    let recovered_state = AftRecoveredStateSurface {
        replay_prefix,
        consensus_headers: vec![sample_recovered_header_entry(10, [0xbb; 32], [109u8; 32])],
        ..AftRecoveredStateSurface::default()
    };

    let error = resolve_execution_parent_anchor(10, &[], &[0xaa; 32], &recovered_state)
        .expect_err("mismatched recovered header block hash should fail");

    assert!(error
        .to_string()
        .contains("recovered header block-hash mismatch"));
}

#[test]
fn resolve_execution_parent_anchor_rejects_recovered_tip_root_mismatch() {
    let replay_prefix = vec![sample_replay_prefix_entry(
        10,
        [0xaa; 32],
        CanonicalCollapseKind::Close,
    )];
    let recovered_state = AftRecoveredStateSurface {
        replay_prefix,
        ..AftRecoveredStateSurface::default()
    };

    let error = resolve_execution_parent_anchor(10, &[], &[0xbb; 32], &recovered_state)
        .expect_err("mismatched recovered parent anchor should fail");

    assert!(error
        .to_string()
        .contains("replay-prefix parent state-root mismatch"));
}
