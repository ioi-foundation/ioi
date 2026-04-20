use super::production::parent_ref_from_last_committed_or_recovered_tip;
use super::{
    advance_recovered_tip_anchor_along_restart_headers,
    advance_recovered_tip_anchor_with_certified_parent_qc,
    bounded_recovered_segment_fold_start_height, bounded_recovered_segment_start_height,
    bounded_recovered_window_ranges, bounded_recovered_window_start_height,
    load_folded_recovered_certified_headers, load_folded_recovered_consensus_headers,
    load_folded_recovered_restart_block_headers, load_recovered_segment_fold_page,
    loaded_recovered_ancestry_start_height, reconcile_recovered_tip_anchor_with_parent_qc,
    recovered_consensus_tip_anchor_from_header, recovered_consensus_tip_anchor_from_parts,
    seed_recovered_certified_headers_into_engine, seed_recovered_consensus_headers_into_engine,
    seed_recovered_restart_block_headers_into_engine, select_unique_recovered_publication_bundle,
    stitch_recovered_canonical_header_segments, stitch_recovered_certified_header_segments,
    stream_recovered_ancestry_to_height, RecoveredAncestryStreamReport,
    RecoveredConsensusTipAnchor, AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::app::ChainStatus;
use ioi_api::chain::{QueryStateResponse, StateRef, WorkloadClientApi};
use ioi_api::consensus::ConsensusEngine;
use ioi_consensus::aft::guardian_majority::GuardianMajorityEngine;
use ioi_types::app::{
    aft_archived_recovered_history_checkpoint_hash_key,
    aft_archived_recovered_history_checkpoint_key,
    aft_archived_recovered_history_profile_activation_hash_key,
    aft_archived_recovered_history_profile_activation_height_key,
    aft_archived_recovered_history_profile_activation_key,
    aft_archived_recovered_history_profile_hash_key,
    aft_archived_recovered_history_retention_receipt_key,
    aft_archived_recovered_history_segment_hash_key, aft_archived_recovered_history_segment_key,
    aft_archived_recovered_restart_page_key, aft_canonical_collapse_object_key,
    aft_recovered_publication_bundle_key, aft_recovery_share_material_key,
    archived_recovered_history_retained_through_height,
    archived_recovered_restart_page_range_for_profile, build_archived_recovered_history_checkpoint,
    build_archived_recovered_history_profile, build_archived_recovered_history_profile_activation,
    build_archived_recovered_history_retention_receipt, build_archived_recovered_history_segment,
    build_archived_recovered_restart_page, build_committed_surface_canonical_order_certificate,
    canonical_archived_recovered_history_checkpoint_hash,
    canonical_archived_recovered_history_profile_activation_hash,
    canonical_archived_recovered_history_profile_hash,
    canonical_archived_recovered_history_retention_receipt_hash,
    canonical_archived_recovered_history_segment_hash, canonical_bulletin_close_hash,
    canonical_order_publication_bundle_hash, canonical_recoverable_slot_payload_v4_hash,
    canonical_recoverable_slot_payload_v5_hash, canonical_transaction_root_from_hashes,
    canonical_validator_sets_hash, canonicalize_transactions_for_header,
    derive_canonical_collapse_object_from_recovered_surface,
    derive_canonical_order_execution_object, encode_coded_recovery_shards,
    normalize_recovered_publication_bundle_supporting_witnesses, read_validator_sets,
    recovered_canonical_header_entry, recovered_certified_header_prefix,
    recovered_restart_block_header_entry, set_canonical_collapse_archived_recovered_history_anchor,
    stitch_recovered_restart_block_header_segments, stitch_recovered_restart_block_header_windows,
    to_root_hash, write_validator_sets, AccountId, ArchivedRecoveredHistoryCheckpoint,
    ArchivedRecoveredHistoryCheckpointUpdateRule, ArchivedRecoveredHistoryProfile,
    ArchivedRecoveredHistoryProfileActivation, ArchivedRecoveredHistorySegment,
    ArchivedRecoveredRestartPage, Block, BlockHeader, CanonicalCollapseKind,
    CanonicalCollapseObject, CanonicalOrderPublicationBundle, CanonicalOrderingCollapse, ChainId,
    ChainTransaction, QuorumCertificate, RecoverableSlotPayloadV3, RecoverableSlotPayloadV5,
    RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry, RecoveredPublicationBundle,
    RecoveredRestartBlockHeaderEntry, RecoveredSegmentFoldCursor, RecoveryCodingDescriptor,
    RecoveryCodingFamily, RecoveryShareMaterial, SignHeader, SignatureProof, SignatureSuite,
    StateAnchor, StateRoot, SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1,
    ValidatorV1, AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
    AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
};
use ioi_types::codec;
use ioi_types::config::AftSafetyMode;
use ioi_types::error::ChainError;
use ioi_types::keys::VALIDATOR_SET_KEY;
use std::any::Any;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

fn sample_recovered_restart_step(
    current_anchor: Option<&RecoveredConsensusTipAnchor>,
    previous_step: Option<&RecoveredRestartBlockHeaderEntry>,
    height: u64,
    view: u64,
    block_seed: u8,
    tx_seed: u8,
    state_seed: u8,
    collapse_seed: u8,
    producer_seed: u8,
) -> RecoveredRestartBlockHeaderEntry {
    let (_parent_height, parent_block_hash, parent_state_root, parent_qc) =
        if let Some(previous_step) = previous_step {
            (
                previous_step.header.height,
                previous_step
                    .certified_header
                    .header
                    .canonical_block_commitment_hash,
                previous_step
                    .certified_header
                    .header
                    .resulting_state_root_hash
                    .to_vec(),
                previous_step.certified_quorum_certificate(),
            )
        } else if let Some(current_anchor) = current_anchor {
            (
                current_anchor.height,
                current_anchor.block_hash,
                current_anchor.state_root.clone(),
                QuorumCertificate {
                    height: current_anchor.height,
                    view: view.saturating_sub(1),
                    block_hash: current_anchor.block_hash,
                    ..Default::default()
                },
            )
        } else {
            panic!("sample_recovered_restart_step requires a parent anchor or step");
        };
    let parent_state_root: [u8; 32] = parent_state_root
        .try_into()
        .expect("32-byte parent state root");

    let certified_header = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height,
            view,
            canonical_block_commitment_hash: [block_seed; 32],
            parent_block_commitment_hash: parent_block_hash,
            transactions_root_hash: [tx_seed; 32],
            resulting_state_root_hash: [state_seed; 32],
            previous_canonical_collapse_commitment_hash: [collapse_seed; 32],
        },
        certified_parent_quorum_certificate: parent_qc.clone(),
        certified_parent_resulting_state_root_hash: parent_state_root,
    };

    RecoveredRestartBlockHeaderEntry {
        certified_header: certified_header.clone(),
        header: BlockHeader {
            height,
            view,
            parent_hash: parent_block_hash,
            parent_state_root: StateRoot(parent_state_root.to_vec()),
            state_root: StateRoot(vec![state_seed; 32]),
            transactions_root: vec![tx_seed; 32],
            timestamp: 1_760_000_000 + height,
            timestamp_ms: (1_760_000_000 + height) * 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([producer_seed; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0u8; 32],
            producer_pubkey: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc,
            previous_canonical_collapse_commitment_hash: [collapse_seed; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        },
    }
}

fn sample_recovered_restart_branch(
    current_anchor: &RecoveredConsensusTipAnchor,
    first_height: u64,
    first_view: u64,
    depth: usize,
    seed_base: u8,
) -> Vec<RecoveredRestartBlockHeaderEntry> {
    let mut branch = Vec::with_capacity(depth);
    for offset in 0..depth {
        let seed = seed_base.wrapping_add(offset as u8);
        let step = sample_recovered_restart_step(
            (offset == 0).then_some(current_anchor),
            branch.last(),
            first_height + offset as u64,
            first_view + offset as u64,
            seed,
            seed.wrapping_add(0x10),
            seed.wrapping_add(0x20),
            seed.wrapping_add(0x30),
            seed.wrapping_add(0x40),
        );
        branch.push(step);
    }
    branch
}

fn stitched_restart_windows<'a>(
    branch: &'a [RecoveredRestartBlockHeaderEntry],
    first_height: u64,
    windows: &[(u64, u64)],
) -> Vec<&'a [RecoveredRestartBlockHeaderEntry]> {
    windows
        .iter()
        .map(|(start_height, end_height)| {
            let start_offset = usize::try_from(start_height.saturating_sub(first_height))
                .expect("window start offset fits in usize");
            let end_offset = usize::try_from(end_height.saturating_sub(first_height))
                .expect("window end offset fits in usize");
            &branch[start_offset..=end_offset]
        })
        .collect()
}

fn bounded_stitched_restart_windows<'a>(
    branch: &'a [RecoveredRestartBlockHeaderEntry],
    first_height: u64,
    window: u64,
    overlap: u64,
) -> Vec<&'a [RecoveredRestartBlockHeaderEntry]> {
    let end_height = first_height + branch.len() as u64 - 1;
    let windows = bounded_recovered_window_ranges(first_height, end_height, window, overlap);
    stitched_restart_windows(branch, first_height, &windows)
}

fn stitched_restart_segment(
    branch: &[RecoveredRestartBlockHeaderEntry],
    first_height: u64,
    windows: &[(u64, u64)],
) -> Vec<RecoveredRestartBlockHeaderEntry> {
    let windows = stitched_restart_windows(branch, first_height, windows);
    stitch_recovered_restart_block_header_windows(&windows)
        .expect("stitched recovered restart segment")
}

fn bounded_recovered_segment_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Vec<Vec<(u64, u64)>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let mut next_start = start_height;
    let mut segments = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(segment_span.saturating_sub(1))
            .min(end_height);
        segments.push(bounded_recovered_window_ranges(
            next_start, next_end, window, overlap,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(segment_step);
    }

    segments
}

fn stitched_restart_segment_fold(
    branch: &[RecoveredRestartBlockHeaderEntry],
    first_height: u64,
    segments: &[Vec<(u64, u64)>],
) -> Vec<RecoveredRestartBlockHeaderEntry> {
    let stitched_segments = segments
        .iter()
        .map(|windows| stitched_restart_segment(branch, first_height, windows))
        .collect::<Vec<_>>();
    let slices = stitched_segments
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    stitch_recovered_restart_block_header_segments(&slices)
        .expect("stitched recovered restart segment fold")
}

fn bounded_recovered_segment_fold_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Vec<Vec<Vec<(u64, u64)>>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || segments_per_fold == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let fold_span = segment_span
        .saturating_add(segment_step.saturating_mul(segments_per_fold.saturating_sub(1)));
    let fold_step = segment_step
        .saturating_mul(segments_per_fold.saturating_sub(1))
        .max(1);
    let mut next_start = start_height;
    let mut folds = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(fold_span.saturating_sub(1))
            .min(end_height);
        folds.push(bounded_recovered_segment_ranges(
            next_start,
            next_end,
            window,
            overlap,
            windows_per_segment,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(fold_step);
    }

    folds
}

fn stitched_restart_segment_fold_of_folds(
    branch: &[RecoveredRestartBlockHeaderEntry],
    first_height: u64,
    segment_folds: &[Vec<Vec<(u64, u64)>>],
) -> Vec<RecoveredRestartBlockHeaderEntry> {
    let stitched_folds = segment_folds
        .iter()
        .map(|segments| stitched_restart_segment_fold(branch, first_height, segments))
        .collect::<Vec<_>>();
    let slices = stitched_folds.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_restart_block_header_segments(&slices)
        .expect("stitched recovered restart segment folds")
}

fn run_async_test<F>(future: F) -> F::Output
where
    F: Future,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio test runtime")
        .block_on(future)
}

fn unused_workload_client_error() -> ChainError {
    ChainError::ExecutionClient("unused in recovered consensus unit tests".to_string())
}

#[derive(Debug, Default)]
struct StaticRecoveredWorkloadClient {
    raw_state: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[async_trait]
impl WorkloadClientApi for StaticRecoveredWorkloadClient {
    async fn process_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        Err(unused_workload_client_error())
    }

    async fn get_blocks_range(
        &self,
        _since: u64,
        _max_blocks: u32,
        _max_bytes: u32,
    ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn get_block_by_height(
        &self,
        _height: u64,
    ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> std::result::Result<QueryStateResponse, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn query_raw_state(
        &self,
        key: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
        Ok(self.raw_state.get(key).cloned())
    }

    async fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Ok(self
            .raw_state
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn get_staked_validators(
        &self,
    ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn update_block_header(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(), ChainError> {
        Err(unused_workload_client_error())
    }

    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        Err(unused_workload_client_error())
    }

    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        Err(unused_workload_client_error())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn validator_sets(validators: &[(u8, u128)]) -> ValidatorSetsV1 {
    let entries = validators
        .iter()
        .map(|(seed, weight)| ValidatorV1 {
            account_id: AccountId([*seed; 32]),
            weight: *weight,
            consensus_key: Default::default(),
        })
        .collect::<Vec<_>>();
    ValidatorSetsV1 {
        current: ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: entries.iter().map(|validator| validator.weight).sum(),
            validators: entries,
        },
        next: None,
    }
}

fn gf256_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
    let coding = RecoveryCodingDescriptor {
        family: RecoveryCodingFamily::SystematicGf256KOfNV1,
        share_count,
        recovery_threshold,
    };
    coding.validate().expect("valid gf256 recovery coding");
    coding
}

fn nonzero_test_byte(value: u8) -> u8 {
    if value == 0 {
        1
    } else {
        value
    }
}

fn sample_recovered_publication_fixture_3_of_7_with_parent(
    height: u64,
    seed: u8,
    parent_block_hash: Option<[u8; 32]>,
    previous_collapse: Option<&CanonicalCollapseObject>,
) -> (
    CanonicalCollapseObject,
    RecoverableSlotPayloadV5,
    Vec<RecoveryShareMaterial>,
    RecoveredPublicationBundle,
) {
    let coding = gf256_recovery_coding(7, 3);
    let support_share_indices = [0u16, 3, 6];
    let mut header = BlockHeader {
        height,
        view: 4,
        parent_hash: parent_block_hash.unwrap_or([seed.wrapping_add(1); 32]),
        parent_state_root: StateRoot(vec![seed.wrapping_add(2); 32]),
        state_root: StateRoot(vec![seed.wrapping_add(3); 32]),
        transactions_root: vec![],
        timestamp: 1_750_010_000 + height,
        timestamp_ms: (1_750_010_000 + height) * 1_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([seed.wrapping_add(4); 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [seed.wrapping_add(5); 32],
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
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([seed.wrapping_add(10); 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![seed],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([seed.wrapping_add(11); 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![seed.wrapping_add(1)],
        },
        signature_proof: SignatureProof::default(),
    }));
    let ordered_transactions = canonicalize_transactions_for_header(&header, &[tx_one, tx_two])
        .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|transaction| transaction.hash().expect("tx hash"))
        .collect();
    header.transactions_root =
        canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
    let certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .expect("committed-surface certificate");
    header.canonical_order_certificate = Some(certificate.clone());
    let execution_object = derive_canonical_order_execution_object(&header, &ordered_transactions)
        .expect("canonical order execution object");
    let publication_bundle = CanonicalOrderPublicationBundle {
        bulletin_commitment: execution_object.bulletin_commitment.clone(),
        bulletin_entries: execution_object.bulletin_entries.clone(),
        bulletin_availability_certificate: execution_object
            .bulletin_availability_certificate
            .clone(),
        bulletin_retrievability_profile: execution_object.bulletin_retrievability_profile.clone(),
        bulletin_shard_manifest: execution_object.bulletin_shard_manifest.clone(),
        bulletin_custody_receipt: execution_object.bulletin_custody_receipt.clone(),
        canonical_order_certificate: execution_object.canonical_order_certificate.clone(),
    };
    let block_commitment_hash =
        to_root_hash(&header.hash().expect("header hash")).expect("block commitment hash");
    let payload_v3 = RecoverableSlotPayloadV3 {
        height,
        view: header.view,
        producer_account_id: header.producer_account_id.clone(),
        block_commitment_hash,
        parent_block_hash: header.parent_hash,
        canonical_order_certificate: certificate,
        ordered_transaction_bytes: ordered_transactions
            .iter()
            .map(|transaction| codec::to_bytes_canonical(transaction).expect("encode tx"))
            .collect(),
        canonical_order_publication_bundle_bytes: codec::to_bytes_canonical(&publication_bundle)
            .expect("encode publication bundle"),
    };
    let payload_bytes = codec::to_bytes_canonical(&payload_v3).expect("encode payload");
    let shard_bytes =
        encode_coded_recovery_shards(coding, &payload_bytes).expect("encode coded shards");
    let (payload_v4, _, bulletin_close) =
        ioi_types::app::lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
            .expect("lift recoverable payload v4");
    let (payload_v5, _, _, _) = ioi_types::app::lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
        .expect("lift recoverable payload v5");
    let witnesses = support_share_indices
        .iter()
        .enumerate()
        .map(|(offset, _)| {
            let mut witness_manifest_hash = [0u8; 32];
            witness_manifest_hash[..8].copy_from_slice(&height.to_be_bytes());
            witness_manifest_hash[8] = nonzero_test_byte((offset as u8).wrapping_add(1));
            witness_manifest_hash[9] = nonzero_test_byte(seed.wrapping_add(20 + offset as u8));
            witness_manifest_hash
        })
        .collect::<Vec<_>>();
    let supporting_witness_manifest_hashes =
        normalize_recovered_publication_bundle_supporting_witnesses(&witnesses)
            .expect("normalized supporting witnesses");
    let materials = witnesses
        .iter()
        .zip(support_share_indices.iter())
        .enumerate()
        .map(
            |(offset, (witness_manifest_hash, share_index))| RecoveryShareMaterial {
                height,
                witness_manifest_hash: *witness_manifest_hash,
                block_commitment_hash,
                coding,
                share_index: *share_index,
                share_commitment_hash: {
                    let mut share_commitment_hash = [0u8; 32];
                    share_commitment_hash[..8].copy_from_slice(&height.to_be_bytes());
                    share_commitment_hash[8] = nonzero_test_byte((offset as u8).wrapping_add(1));
                    share_commitment_hash[9] =
                        nonzero_test_byte(seed.wrapping_add(30 + offset as u8));
                    share_commitment_hash
                },
                material_bytes: shard_bytes[usize::from(*share_index)].clone(),
            },
        )
        .collect::<Vec<_>>();
    let recovered = RecoveredPublicationBundle {
        height,
        block_commitment_hash,
        parent_block_commitment_hash: header.parent_hash,
        coding,
        supporting_witness_manifest_hashes: supporting_witness_manifest_hashes.clone(),
        recoverable_slot_payload_hash: canonical_recoverable_slot_payload_v4_hash(&payload_v4)
            .expect("payload hash"),
        recoverable_full_surface_hash: canonical_recoverable_slot_payload_v5_hash(&payload_v5)
            .expect("full surface hash"),
        canonical_order_publication_bundle_hash: canonical_order_publication_bundle_hash(
            &publication_bundle,
        )
        .expect("publication bundle hash"),
        canonical_bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
            .expect("bulletin close hash"),
    };
    let collapse = derive_canonical_collapse_object_from_recovered_surface(
        &payload_v5,
        &bulletin_close,
        previous_collapse,
    )
    .expect("canonical collapse from recovered surface");
    (collapse, payload_v5, materials, recovered)
}

fn seed_recovered_workload_client(
    expected_end_height: u64,
    seed_base: u8,
) -> (
    StaticRecoveredWorkloadClient,
    Vec<RecoveredCanonicalHeaderEntry>,
    Vec<RecoveredCertifiedHeaderEntry>,
    Vec<RecoveredRestartBlockHeaderEntry>,
) {
    let mut raw_state = BTreeMap::new();
    let mut full_surfaces = Vec::with_capacity(expected_end_height as usize);
    let mut headers = Vec::with_capacity(expected_end_height as usize);
    let mut parent_block_hash = None;
    let mut previous_collapse = None;

    for (offset, height) in (1u64..=expected_end_height).enumerate() {
        let seed = seed_base.wrapping_add(offset as u8);
        let (collapse, full_surface, materials, recovered) =
            sample_recovered_publication_fixture_3_of_7_with_parent(
                height,
                seed,
                parent_block_hash,
                previous_collapse.as_ref(),
            );
        let header = recovered_canonical_header_entry(&collapse, &full_surface)
            .expect("recovered canonical header");
        raw_state.insert(
            aft_canonical_collapse_object_key(height),
            codec::to_bytes_canonical(&collapse).expect("encode collapse"),
        );
        for material in &materials {
            raw_state.insert(
                aft_recovery_share_material_key(
                    material.height,
                    &material.witness_manifest_hash,
                    &material.block_commitment_hash,
                ),
                codec::to_bytes_canonical(material).expect("encode material"),
            );
        }
        raw_state.insert(
            aft_recovered_publication_bundle_key(
                recovered.height,
                &recovered.block_commitment_hash,
                &recovered.supporting_witness_manifest_hashes,
            )
            .expect("recovered publication bundle key"),
            codec::to_bytes_canonical(&recovered).expect("encode recovered bundle"),
        );

        parent_block_hash = Some(recovered.block_commitment_hash);
        previous_collapse = Some(collapse);
        full_surfaces.push(full_surface);
        headers.push(header);
    }

    let certified =
        recovered_certified_header_prefix(None, &headers).expect("recovered certified prefix");
    let restart = certified
        .iter()
        .zip(full_surfaces.iter())
        .map(|(certified_header, full_surface)| {
            recovered_restart_block_header_entry(full_surface, certified_header)
                .expect("recovered restart block header")
        })
        .collect::<Vec<_>>();

    (
        StaticRecoveredWorkloadClient { raw_state },
        headers,
        certified,
        restart,
    )
}

fn seed_recovered_workload_client_with_archived_restart_pages(
    expected_end_height: u64,
    retained_start_height: u64,
    seed_base: u8,
) -> (
    StaticRecoveredWorkloadClient,
    Vec<RecoveredCanonicalHeaderEntry>,
    Vec<RecoveredCertifiedHeaderEntry>,
    Vec<RecoveredRestartBlockHeaderEntry>,
) {
    let mut raw_state = BTreeMap::new();
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let validator_set_bytes = write_validator_sets(&validator_sets).expect("encode validator sets");
    let persisted_validator_sets = ioi_types::app::read_validator_sets(&validator_set_bytes)
        .expect("decode persisted validator sets");
    let validator_set_commitment_hash = canonical_validator_sets_hash(&persisted_validator_sets)
        .expect("validator set commitment hash");
    raw_state.insert(VALIDATOR_SET_KEY.to_vec(), validator_set_bytes);
    let archived_profile = build_archived_recovered_history_profile(
        1024,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
    )
    .expect("default archived recovered-history profile");
    let archived_profile_hash =
        canonical_archived_recovered_history_profile_hash(&archived_profile)
            .expect("archived recovered-history profile hash");
    let archived_profile_activation =
        build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None)
            .expect("bootstrap archived recovered-history profile activation");
    let archived_profile_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&archived_profile_activation)
            .expect("bootstrap archived recovered-history profile activation hash");
    raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&archived_profile)
            .expect("encode active archived recovered-history profile"),
    );
    raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&archived_profile_hash),
        codec::to_bytes_canonical(&archived_profile)
            .expect("encode archived recovered-history profile by hash"),
    );
    raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&archived_profile_hash),
        codec::to_bytes_canonical(&archived_profile_activation)
            .expect("encode archived recovered-history profile activation"),
    );
    raw_state.insert(
        aft_archived_recovered_history_profile_activation_hash_key(
            &archived_profile_activation_hash,
        ),
        codec::to_bytes_canonical(&archived_profile_activation)
            .expect("encode archived recovered-history profile activation by hash"),
    );
    raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(1),
        codec::to_bytes_canonical(&archived_profile_activation)
            .expect("encode archived recovered-history profile activation by height"),
    );
    raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
        codec::to_bytes_canonical(&archived_profile_activation)
            .expect("encode latest archived recovered-history profile activation"),
    );
    let mut headers = Vec::with_capacity(expected_end_height as usize);
    let mut retained_full_surfaces = Vec::new();
    let mut retained_headers = Vec::new();
    let mut recovered_bundles = Vec::with_capacity(expected_end_height as usize);
    let mut parent_block_hash = None;
    let mut previous_collapse = None;
    let mut previous_checkpoint = None::<ArchivedRecoveredHistoryCheckpoint>;
    let mut previous_segment = None::<ArchivedRecoveredHistorySegment>;
    let mut previous_page = None::<ArchivedRecoveredRestartPage>;
    let mut previous_header = None::<RecoveredCanonicalHeaderEntry>;

    for (offset, height) in (1u64..=expected_end_height).enumerate() {
        let seed = seed_base.wrapping_add(offset as u8);
        let (collapse, full_surface, materials, recovered) =
            sample_recovered_publication_fixture_3_of_7_with_parent(
                height,
                seed,
                parent_block_hash,
                previous_collapse.as_ref(),
            );
        let header = recovered_canonical_header_entry(&collapse, &full_surface)
            .expect("recovered canonical header");
        let certified = recovered_certified_header_prefix(
            previous_header.as_ref(),
            std::slice::from_ref(&header),
        )
        .expect("single recovered certified header")
        .into_iter()
        .next()
        .expect("single certified header");
        let restart = recovered_restart_block_header_entry(&full_surface, &certified)
            .expect("recovered restart block header");
        recovered_bundles.push(recovered.clone());

        let (segment_start_height, segment_end_height) =
            archived_recovered_restart_page_range_for_profile(height, &archived_profile)
                .expect("archived recovered restart page range");
        let overlap_range = previous_segment.as_ref().and_then(|previous| {
            let overlap_start_height = segment_start_height.max(previous.start_height);
            let overlap_end_height = segment_end_height
                .saturating_sub(1)
                .min(previous.end_height);
            (overlap_start_height <= overlap_end_height)
                .then_some((overlap_start_height, overlap_end_height))
        });
        let segment = build_archived_recovered_history_segment(
            &recovered_bundles[(segment_start_height - 1) as usize..segment_end_height as usize],
            previous_segment.as_ref(),
            overlap_range,
            &archived_profile,
            &archived_profile_activation,
        )
        .expect("archived recovered-history segment");
        let segment_hash = canonical_archived_recovered_history_segment_hash(&segment)
            .expect("archived recovered-history segment hash");

        let mut archived_restart_headers = previous_page
            .as_ref()
            .map(|page| {
                page.restart_headers
                    .iter()
                    .filter(|entry| entry.header.height >= segment.start_height)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        archived_restart_headers.push(restart.clone());
        let archived_page =
            build_archived_recovered_restart_page(&segment, &archived_restart_headers)
                .expect("archived recovered restart page");

        raw_state.insert(
            aft_archived_recovered_history_segment_key(segment.start_height, segment.end_height),
            codec::to_bytes_canonical(&segment).expect("encode archived segment"),
        );
        raw_state.insert(
            aft_archived_recovered_history_segment_hash_key(&segment_hash),
            codec::to_bytes_canonical(&segment).expect("encode archived segment by hash"),
        );
        raw_state.insert(
            aft_archived_recovered_restart_page_key(&segment_hash),
            codec::to_bytes_canonical(&archived_page).expect("encode archived restart page"),
        );
        let archived_checkpoint = build_archived_recovered_history_checkpoint(
            &segment,
            &archived_page,
            previous_checkpoint.as_ref(),
        )
        .expect("archived recovered history checkpoint");
        let archived_checkpoint_hash =
            canonical_archived_recovered_history_checkpoint_hash(&archived_checkpoint)
                .expect("archived recovered history checkpoint hash");
        raw_state.insert(
            aft_archived_recovered_history_checkpoint_key(
                archived_checkpoint.covered_start_height,
                archived_checkpoint.covered_end_height,
            ),
            codec::to_bytes_canonical(&archived_checkpoint)
                .expect("encode archived recovered history checkpoint"),
        );
        raw_state.insert(
            aft_archived_recovered_history_checkpoint_hash_key(&archived_checkpoint_hash),
            codec::to_bytes_canonical(&archived_checkpoint)
                .expect("encode archived recovered history checkpoint by hash"),
        );
        raw_state.insert(
            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
            codec::to_bytes_canonical(&archived_checkpoint)
                .expect("encode latest archived recovered history checkpoint"),
        );
        let archived_retention_receipt = build_archived_recovered_history_retention_receipt(
            &archived_checkpoint,
            validator_set_commitment_hash,
            archived_recovered_history_retained_through_height(
                &archived_checkpoint,
                &archived_profile,
            )
            .expect("archived retained-through height"),
        )
        .expect("archived recovered history retention receipt");
        raw_state.insert(
            aft_archived_recovered_history_retention_receipt_key(&archived_checkpoint_hash),
            codec::to_bytes_canonical(&archived_retention_receipt)
                .expect("encode archived recovered history retention receipt"),
        );

        if height >= retained_start_height {
            let mut anchored_collapse = collapse.clone();
            set_canonical_collapse_archived_recovered_history_anchor(
                &mut anchored_collapse,
                archived_checkpoint_hash,
                archived_profile_activation_hash,
                canonical_archived_recovered_history_retention_receipt_hash(
                    &archived_retention_receipt,
                )
                .expect("hash archived recovered history retention receipt"),
            )
            .expect("set archived recovered-history anchor on retained collapse");
            raw_state.insert(
                aft_canonical_collapse_object_key(height),
                codec::to_bytes_canonical(&anchored_collapse).expect("encode anchored collapse"),
            );
            for material in &materials {
                raw_state.insert(
                    aft_recovery_share_material_key(
                        material.height,
                        &material.witness_manifest_hash,
                        &material.block_commitment_hash,
                    ),
                    codec::to_bytes_canonical(material).expect("encode material"),
                );
            }
            raw_state.insert(
                aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .expect("recovered publication bundle key"),
                codec::to_bytes_canonical(&recovered).expect("encode recovered bundle"),
            );
            retained_full_surfaces.push(full_surface.clone());
            retained_headers.push(header.clone());
        }

        parent_block_hash = Some(recovered.block_commitment_hash);
        previous_collapse = Some(collapse);
        previous_checkpoint = Some(archived_checkpoint);
        previous_segment = Some(segment);
        previous_page = Some(archived_page);
        previous_header = Some(header.clone());
        headers.push(header);
    }

    let retained_previous = if retained_start_height <= 1 {
        None
    } else {
        headers.get((retained_start_height - 2) as usize)
    };
    let retained_certified =
        recovered_certified_header_prefix(retained_previous, &retained_headers)
            .expect("retained recovered certified prefix");
    let retained_restart = retained_certified
        .iter()
        .zip(retained_full_surfaces.iter())
        .map(|(certified_header, full_surface)| {
            recovered_restart_block_header_entry(full_surface, certified_header)
                .expect("retained recovered restart block header")
        })
        .collect::<Vec<_>>();

    (
        StaticRecoveredWorkloadClient { raw_state },
        retained_headers,
        retained_certified,
        retained_restart,
    )
}

fn rotate_active_archived_profile_and_remove_latest_side_indexes(
    client: &mut StaticRecoveredWorkloadClient,
) {
    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");

    let rotated_profile = build_archived_recovered_history_profile(
        active_profile.retention_horizon + 1,
        active_profile.restart_page_window,
        active_profile.restart_page_overlap,
        active_profile.windows_per_segment,
        active_profile.segments_per_fold,
        active_profile.checkpoint_update_rule,
    )
    .expect("rotated archived recovered-history profile");
    let rotated_profile_hash = canonical_archived_recovered_history_profile_hash(&rotated_profile)
        .expect("rotated archived recovered-history profile hash");
    let rotated_activation = build_archived_recovered_history_profile_activation(
        &rotated_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height + 1,
        None,
    )
    .expect("rotated archived recovered-history profile activation");
    let rotated_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&rotated_activation)
            .expect("rotated archived recovered-history profile activation hash");

    client.raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&rotated_profile)
            .expect("encode rotated active archived profile"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&rotated_profile_hash),
        codec::to_bytes_canonical(&rotated_profile)
            .expect("encode rotated archived profile by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&rotated_profile_hash),
        codec::to_bytes_canonical(&rotated_activation)
            .expect("encode rotated archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_hash_key(&rotated_activation_hash),
        codec::to_bytes_canonical(&rotated_activation)
            .expect("encode rotated archived profile activation by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(
            rotated_activation.activation_end_height,
        ),
        codec::to_bytes_canonical(&rotated_activation)
            .expect("encode rotated archived profile activation by height"),
    );

    client
        .raw_state
        .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY);
    client
        .raw_state
        .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY);
    client.raw_state.remove(
        &aft_archived_recovered_history_profile_activation_height_key(
            latest_activation.activation_end_height,
        ),
    );
    client.raw_state.remove(
        &aft_archived_recovered_history_profile_activation_height_key(
            rotated_activation.activation_end_height,
        ),
    );
}

#[derive(Debug)]
struct PersistentRecoveredHistoricalContinuationSimulator {
    client: StaticRecoveredWorkloadClient,
    archived_profile: ArchivedRecoveredHistoryProfile,
    archived_profile_activation: ArchivedRecoveredHistoryProfileActivation,
    archived_profile_activation_hash: [u8; 32],
    validator_set_commitment_hash: [u8; 32],
    parent_block_hash: Option<[u8; 32]>,
    previous_collapse: Option<CanonicalCollapseObject>,
    previous_checkpoint: Option<ArchivedRecoveredHistoryCheckpoint>,
    previous_segment: Option<ArchivedRecoveredHistorySegment>,
    previous_page: Option<ArchivedRecoveredRestartPage>,
    previous_header: Option<RecoveredCanonicalHeaderEntry>,
    recovered_bundles: Vec<RecoveredPublicationBundle>,
    headers: Vec<RecoveredCanonicalHeaderEntry>,
    full_surfaces: Vec<RecoverableSlotPayloadV5>,
    end_height: u64,
}

impl PersistentRecoveredHistoricalContinuationSimulator {
    fn new() -> Self {
        let mut raw_state = BTreeMap::new();
        let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
        let validator_set_bytes =
            write_validator_sets(&validator_sets).expect("encode validator sets");
        let persisted_validator_sets = ioi_types::app::read_validator_sets(&validator_set_bytes)
            .expect("decode persisted validator sets");
        let validator_set_commitment_hash =
            canonical_validator_sets_hash(&persisted_validator_sets)
                .expect("validator set commitment hash");
        raw_state.insert(VALIDATOR_SET_KEY.to_vec(), validator_set_bytes);

        let archived_profile = build_archived_recovered_history_profile(
            1024,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect("default archived recovered-history profile");
        let archived_profile_hash =
            canonical_archived_recovered_history_profile_hash(&archived_profile)
                .expect("archived recovered-history profile hash");
        let archived_profile_activation =
            build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None)
                .expect("bootstrap archived recovered-history profile activation");
        let archived_profile_activation_hash =
            canonical_archived_recovered_history_profile_activation_hash(
                &archived_profile_activation,
            )
            .expect("bootstrap archived recovered-history profile activation hash");

        raw_state.insert(
            AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
            codec::to_bytes_canonical(&archived_profile)
                .expect("encode active archived recovered-history profile"),
        );
        raw_state.insert(
            aft_archived_recovered_history_profile_hash_key(&archived_profile_hash),
            codec::to_bytes_canonical(&archived_profile)
                .expect("encode archived recovered-history profile by hash"),
        );
        raw_state.insert(
            aft_archived_recovered_history_profile_activation_key(&archived_profile_hash),
            codec::to_bytes_canonical(&archived_profile_activation)
                .expect("encode archived recovered-history profile activation"),
        );
        raw_state.insert(
            aft_archived_recovered_history_profile_activation_hash_key(
                &archived_profile_activation_hash,
            ),
            codec::to_bytes_canonical(&archived_profile_activation)
                .expect("encode archived recovered-history profile activation by hash"),
        );
        raw_state.insert(
            aft_archived_recovered_history_profile_activation_height_key(1),
            codec::to_bytes_canonical(&archived_profile_activation)
                .expect("encode archived recovered-history profile activation by height"),
        );
        raw_state.insert(
            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
            codec::to_bytes_canonical(&archived_profile_activation)
                .expect("encode latest archived recovered-history profile activation"),
        );

        Self {
            client: StaticRecoveredWorkloadClient { raw_state },
            archived_profile,
            archived_profile_activation,
            archived_profile_activation_hash,
            validator_set_commitment_hash,
            parent_block_hash: None,
            previous_collapse: None,
            previous_checkpoint: None,
            previous_segment: None,
            previous_page: None,
            previous_header: None,
            recovered_bundles: Vec::new(),
            headers: Vec::new(),
            full_surfaces: Vec::new(),
            end_height: 0,
        }
    }

    fn append_through(
        &mut self,
        expected_end_height: u64,
        retained_start_height: u64,
        seed_base: u8,
    ) {
        assert!(
            expected_end_height > self.end_height,
            "persistent simulator end height must advance"
        );

        for (offset, height) in ((self.end_height + 1)..=expected_end_height).enumerate() {
            let seed = seed_base.wrapping_add(offset as u8);
            let (collapse, full_surface, materials, recovered) =
                sample_recovered_publication_fixture_3_of_7_with_parent(
                    height,
                    seed,
                    self.parent_block_hash,
                    self.previous_collapse.as_ref(),
                );
            let header = recovered_canonical_header_entry(&collapse, &full_surface)
                .expect("recovered canonical header");
            let certified = recovered_certified_header_prefix(
                self.previous_header.as_ref(),
                std::slice::from_ref(&header),
            )
            .expect("single recovered certified header")
            .into_iter()
            .next()
            .expect("single certified header");
            let restart = recovered_restart_block_header_entry(&full_surface, &certified)
                .expect("recovered restart block header");
            self.recovered_bundles.push(recovered.clone());

            let (segment_start_height, segment_end_height) =
                archived_recovered_restart_page_range_for_profile(height, &self.archived_profile)
                    .expect("archived recovered restart page range");
            let overlap_range = self.previous_segment.as_ref().and_then(|previous| {
                let overlap_start_height = segment_start_height.max(previous.start_height);
                let overlap_end_height = segment_end_height
                    .saturating_sub(1)
                    .min(previous.end_height);
                (overlap_start_height <= overlap_end_height)
                    .then_some((overlap_start_height, overlap_end_height))
            });
            let segment = build_archived_recovered_history_segment(
                &self.recovered_bundles
                    [(segment_start_height - 1) as usize..segment_end_height as usize],
                self.previous_segment.as_ref(),
                overlap_range,
                &self.archived_profile,
                &self.archived_profile_activation,
            )
            .expect("archived recovered-history segment");
            let segment_hash = canonical_archived_recovered_history_segment_hash(&segment)
                .expect("archived recovered-history segment hash");

            let mut archived_restart_headers = self
                .previous_page
                .as_ref()
                .map(|page| {
                    page.restart_headers
                        .iter()
                        .filter(|entry| entry.header.height >= segment.start_height)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            archived_restart_headers.push(restart.clone());
            let archived_page =
                build_archived_recovered_restart_page(&segment, &archived_restart_headers)
                    .expect("archived recovered restart page");

            self.client.raw_state.insert(
                aft_archived_recovered_history_segment_key(
                    segment.start_height,
                    segment.end_height,
                ),
                codec::to_bytes_canonical(&segment).expect("encode archived segment"),
            );
            self.client.raw_state.insert(
                aft_archived_recovered_history_segment_hash_key(&segment_hash),
                codec::to_bytes_canonical(&segment).expect("encode archived segment by hash"),
            );
            self.client.raw_state.insert(
                aft_archived_recovered_restart_page_key(&segment_hash),
                codec::to_bytes_canonical(&archived_page).expect("encode archived restart page"),
            );

            let archived_checkpoint = build_archived_recovered_history_checkpoint(
                &segment,
                &archived_page,
                self.previous_checkpoint.as_ref(),
            )
            .expect("archived recovered history checkpoint");
            let archived_checkpoint_hash =
                canonical_archived_recovered_history_checkpoint_hash(&archived_checkpoint)
                    .expect("archived recovered history checkpoint hash");
            self.client.raw_state.insert(
                aft_archived_recovered_history_checkpoint_key(
                    archived_checkpoint.covered_start_height,
                    archived_checkpoint.covered_end_height,
                ),
                codec::to_bytes_canonical(&archived_checkpoint)
                    .expect("encode archived recovered history checkpoint"),
            );
            self.client.raw_state.insert(
                aft_archived_recovered_history_checkpoint_hash_key(&archived_checkpoint_hash),
                codec::to_bytes_canonical(&archived_checkpoint)
                    .expect("encode archived recovered history checkpoint by hash"),
            );
            self.client.raw_state.insert(
                AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
                codec::to_bytes_canonical(&archived_checkpoint)
                    .expect("encode latest archived recovered history checkpoint"),
            );

            let archived_retention_receipt = build_archived_recovered_history_retention_receipt(
                &archived_checkpoint,
                self.validator_set_commitment_hash,
                archived_recovered_history_retained_through_height(
                    &archived_checkpoint,
                    &self.archived_profile,
                )
                .expect("archived retained-through height"),
            )
            .expect("archived recovered history retention receipt");
            self.client.raw_state.insert(
                aft_archived_recovered_history_retention_receipt_key(&archived_checkpoint_hash),
                codec::to_bytes_canonical(&archived_retention_receipt)
                    .expect("encode archived recovered history retention receipt"),
            );

            if height >= retained_start_height {
                let mut anchored_collapse = collapse.clone();
                set_canonical_collapse_archived_recovered_history_anchor(
                    &mut anchored_collapse,
                    archived_checkpoint_hash,
                    self.archived_profile_activation_hash,
                    canonical_archived_recovered_history_retention_receipt_hash(
                        &archived_retention_receipt,
                    )
                    .expect("hash archived recovered history retention receipt"),
                )
                .expect("set archived recovered-history anchor on retained collapse");
                self.client.raw_state.insert(
                    aft_canonical_collapse_object_key(height),
                    codec::to_bytes_canonical(&anchored_collapse)
                        .expect("encode anchored collapse"),
                );
                for material in &materials {
                    self.client.raw_state.insert(
                        aft_recovery_share_material_key(
                            material.height,
                            &material.witness_manifest_hash,
                            &material.block_commitment_hash,
                        ),
                        codec::to_bytes_canonical(material).expect("encode material"),
                    );
                }
                self.client.raw_state.insert(
                    aft_recovered_publication_bundle_key(
                        recovered.height,
                        &recovered.block_commitment_hash,
                        &recovered.supporting_witness_manifest_hashes,
                    )
                    .expect("recovered publication bundle key"),
                    codec::to_bytes_canonical(&recovered).expect("encode recovered bundle"),
                );
            }

            self.parent_block_hash = Some(recovered.block_commitment_hash);
            self.previous_collapse = Some(collapse);
            self.previous_checkpoint = Some(archived_checkpoint);
            self.previous_segment = Some(segment);
            self.previous_page = Some(archived_page);
            self.previous_header = Some(header.clone());
            self.headers.push(header);
            self.full_surfaces.push(full_surface);
        }

        self.end_height = expected_end_height;
    }

    fn rotate_active_profile_and_remove_latest_side_indexes(&mut self) {
        let latest_checkpoint = self
            .previous_checkpoint
            .clone()
            .expect("latest archived checkpoint");
        let rotated_profile = build_archived_recovered_history_profile(
            self.archived_profile.retention_horizon + 1,
            self.archived_profile.restart_page_window,
            self.archived_profile.restart_page_overlap,
            self.archived_profile.windows_per_segment,
            self.archived_profile.segments_per_fold,
            self.archived_profile.checkpoint_update_rule,
        )
        .expect("rotated archived recovered-history profile");
        let rotated_profile_hash =
            canonical_archived_recovered_history_profile_hash(&rotated_profile)
                .expect("rotated archived recovered-history profile hash");
        let rotated_activation = build_archived_recovered_history_profile_activation(
            &rotated_profile,
            Some(&self.archived_profile_activation),
            latest_checkpoint.covered_end_height + 1,
            None,
        )
        .expect("rotated archived recovered-history profile activation");
        let rotated_activation_hash =
            canonical_archived_recovered_history_profile_activation_hash(&rotated_activation)
                .expect("rotated archived recovered-history profile activation hash");

        self.client.raw_state.insert(
            AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
            codec::to_bytes_canonical(&rotated_profile)
                .expect("encode rotated active archived profile"),
        );
        self.client.raw_state.insert(
            aft_archived_recovered_history_profile_hash_key(&rotated_profile_hash),
            codec::to_bytes_canonical(&rotated_profile)
                .expect("encode rotated archived profile by hash"),
        );
        self.client.raw_state.insert(
            aft_archived_recovered_history_profile_activation_key(&rotated_profile_hash),
            codec::to_bytes_canonical(&rotated_activation)
                .expect("encode rotated archived profile activation"),
        );
        self.client.raw_state.insert(
            aft_archived_recovered_history_profile_activation_hash_key(&rotated_activation_hash),
            codec::to_bytes_canonical(&rotated_activation)
                .expect("encode rotated archived profile activation by hash"),
        );
        self.client.raw_state.insert(
            aft_archived_recovered_history_profile_activation_height_key(
                rotated_activation.activation_end_height,
            ),
            codec::to_bytes_canonical(&rotated_activation)
                .expect("encode rotated archived profile activation by height"),
        );

        self.client
            .raw_state
            .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY);
        self.client
            .raw_state
            .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY);
        self.client.raw_state.remove(
            &aft_archived_recovered_history_profile_activation_height_key(
                self.archived_profile_activation.activation_end_height,
            ),
        );
        self.client.raw_state.remove(
            &aft_archived_recovered_history_profile_activation_height_key(
                rotated_activation.activation_end_height,
            ),
        );

        self.archived_profile = rotated_profile;
        self.archived_profile_activation = rotated_activation;
        self.archived_profile_activation_hash = rotated_activation_hash;
    }

    fn retained_suffix(
        &self,
        retained_start_height: u64,
    ) -> (
        Vec<RecoveredCanonicalHeaderEntry>,
        Vec<RecoveredCertifiedHeaderEntry>,
        Vec<RecoveredRestartBlockHeaderEntry>,
    ) {
        let retained_headers =
            self.headers[(retained_start_height - 1) as usize..self.end_height as usize].to_vec();
        let retained_full_surfaces = self.full_surfaces
            [(retained_start_height - 1) as usize..self.end_height as usize]
            .to_vec();
        let retained_previous = if retained_start_height <= 1 {
            None
        } else {
            self.headers.get((retained_start_height - 2) as usize)
        };
        let retained_certified =
            recovered_certified_header_prefix(retained_previous, &retained_headers)
                .expect("retained recovered certified prefix");
        let retained_restart = retained_certified
            .iter()
            .zip(retained_full_surfaces.iter())
            .map(|(certified_header, full_surface)| {
                recovered_restart_block_header_entry(full_surface, certified_header)
                    .expect("retained recovered restart block header")
            })
            .collect::<Vec<_>>();

        (retained_headers, retained_certified, retained_restart)
    }

    fn stream_to_target(
        &self,
        retained_start_height: u64,
        target_height: u64,
    ) -> RecoveredAncestryStreamReport {
        let (recovered_headers, recovered_certified, recovered_restart) =
            self.retained_suffix(retained_start_height);
        let engine =
            seed_recovered_engine(&recovered_headers, &recovered_certified, &recovered_restart);

        run_async_test(stream_recovered_ancestry_to_height(
            &self.client,
            &engine,
            target_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
            &recovered_headers,
            &recovered_certified,
            &recovered_restart,
        ))
        .expect("persistent historical retrievability simulator should stream ancestry")
    }
}

fn seed_recovered_engine(
    recovered_headers: &[RecoveredCanonicalHeaderEntry],
    recovered_certified: &[RecoveredCertifiedHeaderEntry],
    recovered_restart: &[RecoveredRestartBlockHeaderEntry],
) -> Arc<Mutex<GuardianMajorityEngine>> {
    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine_guard = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine_guard, recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine_guard, recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine_guard, recovered_restart);
    });

    engine
}

fn stream_recovered_historical_continuation_cycle_case(
    expected_end_height: u64,
    retained_start_height: u64,
    seed_base: u8,
) -> RecoveredAncestryStreamReport {
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            seed_base,
        );
    rotate_active_archived_profile_and_remove_latest_side_indexes(&mut client);
    let engine =
        seed_recovered_engine(&recovered_headers, &recovered_certified, &recovered_restart);

    run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect("repeated historical retrievability cycle should stream ancestry")
}

fn load_paged_recovered_prefixes_to_height(
    client: &StaticRecoveredWorkloadClient,
    end_height: u64,
    target_height: u64,
) -> Result<(
    Vec<RecoveredCanonicalHeaderEntry>,
    Vec<RecoveredCertifiedHeaderEntry>,
    Vec<RecoveredRestartBlockHeaderEntry>,
)> {
    let mut recovered_headers = run_async_test(load_folded_recovered_consensus_headers(
        client,
        end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))?;
    let mut recovered_certified = run_async_test(load_folded_recovered_certified_headers(
        client,
        end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))?;
    let mut recovered_restart = run_async_test(load_folded_recovered_restart_block_headers(
        client,
        end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))?;
    let mut cursor = RecoveredSegmentFoldCursor::new(
        end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .map_err(|error| anyhow!("recovered segment-fold cursor: {error}"))?;

    while target_height
        < loaded_recovered_ancestry_start_height(
            &recovered_headers,
            &recovered_certified,
            &recovered_restart,
        )
        .unwrap_or(u64::MAX)
    {
        let page = cursor
            .next_page()
            .map_err(|error| anyhow!("advance recovered segment-fold cursor: {error}"))?
            .ok_or_else(|| {
                anyhow!(
                    "recovered segment-fold cursor exhausted before target height {}",
                    target_height
                )
            })?;
        let loaded_page = run_async_test(load_recovered_segment_fold_page(client, &page))?;

        recovered_headers = stitch_recovered_canonical_header_segments(&[
            loaded_page.consensus_headers.as_slice(),
            recovered_headers.as_slice(),
        ])
        .map_err(|error| anyhow!("stitch paged recovered canonical-header ancestry: {error}"))?;
        recovered_certified = stitch_recovered_certified_header_segments(&[
            loaded_page.certified_headers.as_slice(),
            recovered_certified.as_slice(),
        ])
        .map_err(|error| anyhow!("stitch paged recovered certified-header ancestry: {error}"))?;
        recovered_restart = stitch_recovered_restart_block_header_segments(&[
            loaded_page.restart_headers.as_slice(),
            recovered_restart.as_slice(),
        ])
        .map_err(|error| anyhow!("stitch paged recovered restart ancestry: {error}"))?;
    }

    Ok((recovered_headers, recovered_certified, recovered_restart))
}

fn sample_block(height: u64, seed: u8) -> Block<ChainTransaction> {
    Block {
        header: BlockHeader {
            height,
            view: 0,
            parent_hash: [seed.wrapping_sub(1); 32],
            parent_state_root: StateRoot(vec![seed.wrapping_sub(1); 32]),
            state_root: StateRoot(vec![seed; 32]),
            transactions_root: vec![seed.wrapping_add(1); 32],
            timestamp: 1_700_000_000 + u64::from(seed),
            timestamp_ms: 1_700_000_000_000 + u64::from(seed),
            gas_used: u64::from(seed),
            validator_set: vec![vec![seed; 32]],
            producer_account_id: AccountId([seed; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [seed.wrapping_add(2); 32],
            producer_pubkey: vec![seed.wrapping_add(3); 32],
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        },
        transactions: Vec::<ChainTransaction>::new(),
    }
}

#[test]
fn parent_ref_from_last_committed_or_recovered_tip_prefers_committed_block() {
    let block = sample_block(11, 0x41);
    let recovered_tip = RecoveredConsensusTipAnchor {
        height: 11,
        state_root: vec![0x99; 32],
        block_hash: [0x55; 32],
    };

    let parent_ref =
        parent_ref_from_last_committed_or_recovered_tip(&Some(block.clone()), Some(&recovered_tip))
            .expect("parent ref")
            .expect("committed block parent ref");

    assert_eq!(parent_ref.height, block.header.height);
    assert_eq!(parent_ref.state_root, block.header.state_root.0);
    assert_eq!(
        parent_ref.block_hash,
        to_root_hash(&block.header.hash().expect("block hash"))
            .expect("state hash from committed block")
    );
}

#[test]
fn parent_ref_from_last_committed_or_recovered_tip_uses_recovered_tip_when_block_absent() {
    let recovered_tip = RecoveredConsensusTipAnchor {
        height: 13,
        state_root: vec![0x77; 32],
        block_hash: [0x88; 32],
    };

    let parent_ref = parent_ref_from_last_committed_or_recovered_tip(&None, Some(&recovered_tip))
        .expect("parent ref")
        .expect("recovered tip parent ref");

    assert_eq!(parent_ref.height, recovered_tip.height);
    assert_eq!(parent_ref.state_root, recovered_tip.state_root);
    assert_eq!(parent_ref.block_hash, recovered_tip.block_hash);
}

#[test]
fn recovered_consensus_tip_anchor_from_parts_requires_matching_header_height() {
    let collapse = CanonicalCollapseObject {
        height: 17,
        ordering: CanonicalOrderingCollapse {
            height: 17,
            kind: CanonicalCollapseKind::Close,
            ..Default::default()
        },
        resulting_state_root_hash: [0x33; 32],
        ..Default::default()
    };

    assert!(
        recovered_consensus_tip_anchor_from_parts(&collapse, &[]).is_none(),
        "missing recovered header should not produce a restart tip anchor"
    );

    let header = RecoveredCanonicalHeaderEntry {
        height: 17,
        canonical_block_commitment_hash: [0x44; 32],
        resulting_state_root_hash: collapse.resulting_state_root_hash,
        ..Default::default()
    };
    let anchor = recovered_consensus_tip_anchor_from_parts(&collapse, &[header.clone()])
        .expect("restart tip anchor");
    assert_eq!(anchor.height, collapse.height);
    assert_eq!(anchor.state_root, collapse.resulting_state_root_hash);
    assert_eq!(anchor.block_hash, header.canonical_block_commitment_hash);
}

#[test]
fn recovered_consensus_tip_anchor_from_header_uses_recovered_state_root() {
    let header = RecoveredCanonicalHeaderEntry {
        height: 21,
        canonical_block_commitment_hash: [0x71; 32],
        resulting_state_root_hash: [0x72; 32],
        ..Default::default()
    };

    let anchor = recovered_consensus_tip_anchor_from_header(&header);

    assert_eq!(anchor.height, header.height);
    assert_eq!(anchor.block_hash, header.canonical_block_commitment_hash);
    assert_eq!(anchor.state_root, header.resulting_state_root_hash);
}

#[test]
fn reconcile_recovered_tip_anchor_with_parent_qc_accepts_matching_recovered_branch() {
    let parent_ref = StateRef {
        height: 23,
        state_root: vec![0x83; 32],
        block_hash: [0x90; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 23,
        view: 9,
        block_hash: [0x91; 32],
        ..Default::default()
    };
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 23,
        view: 9,
        canonical_block_commitment_hash: [0x91; 32],
        resulting_state_root_hash: [0x83; 32],
        ..Default::default()
    };

    let anchor =
        reconcile_recovered_tip_anchor_with_parent_qc(&parent_ref, &parent_qc, &recovered_header)
            .expect("matching recovered branch should reconcile");

    assert_eq!(anchor.height, parent_ref.height);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, parent_ref.state_root);
}

#[test]
fn reconcile_recovered_tip_anchor_with_parent_qc_rejects_state_root_mismatch() {
    let parent_ref = StateRef {
        height: 24,
        state_root: vec![0x84; 32],
        block_hash: [0x90; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 24,
        view: 3,
        block_hash: [0x92; 32],
        ..Default::default()
    };
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 24,
        view: 3,
        canonical_block_commitment_hash: [0x92; 32],
        resulting_state_root_hash: [0x99; 32],
        ..Default::default()
    };

    assert!(
        reconcile_recovered_tip_anchor_with_parent_qc(&parent_ref, &parent_qc, &recovered_header)
            .is_none(),
        "state-root mismatch should not reconcile a recovered restart branch"
    );
}

#[test]
fn advance_recovered_tip_anchor_with_certified_parent_qc_accepts_matching_recovered_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 24,
        state_root: vec![0x94; 32],
        block_hash: [0xa4; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 25,
        view: 6,
        block_hash: [0xa5; 32],
        ..Default::default()
    };
    let recovered_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 25,
            view: 6,
            canonical_block_commitment_hash: [0xa5; 32],
            parent_block_commitment_hash: [0xa4; 32],
            resulting_state_root_hash: [0x95; 32],
            ..Default::default()
        },
        certified_parent_quorum_certificate: QuorumCertificate {
            height: 24,
            view: 5,
            block_hash: [0xa4; 32],
            ..Default::default()
        },
        certified_parent_resulting_state_root_hash: [0x94; 32],
    };

    let anchor = advance_recovered_tip_anchor_with_certified_parent_qc(
        &current_anchor,
        &parent_qc,
        &recovered_entry,
    )
    .expect("matching recovered certified branch should advance");

    assert_eq!(anchor.height, 25);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0x95; 32]);
}

#[test]
fn advance_recovered_tip_anchor_with_certified_parent_qc_rejects_parent_root_mismatch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 24,
        state_root: vec![0x94; 32],
        block_hash: [0xa4; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 25,
        view: 6,
        block_hash: [0xa5; 32],
        ..Default::default()
    };
    let recovered_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 25,
            view: 6,
            canonical_block_commitment_hash: [0xa5; 32],
            parent_block_commitment_hash: [0xa4; 32],
            resulting_state_root_hash: [0x95; 32],
            ..Default::default()
        },
        certified_parent_quorum_certificate: QuorumCertificate {
            height: 24,
            view: 5,
            block_hash: [0xa4; 32],
            ..Default::default()
        },
        certified_parent_resulting_state_root_hash: [0xff; 32],
    };

    assert!(
        advance_recovered_tip_anchor_with_certified_parent_qc(
            &current_anchor,
            &parent_qc,
            &recovered_entry
        )
        .is_none(),
        "parent state-root mismatch should not advance a recovered certified branch"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_two_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 30,
        state_root: vec![0x31; 32],
        block_hash: [0x41; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        31,
        7,
        0x51,
        0x61,
        0x71,
        0x81,
        0x91,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 32, 8, 0x52, 0x62, 0x72, 0x82, 0x92);
    let parent_qc = step_two.certified_quorum_certificate();

    let anchor = advance_recovered_tip_anchor_along_restart_headers(
        &current_anchor,
        &parent_qc,
        &[step_one.clone(), step_two.clone()],
    )
    .expect("two-step recovered branch should advance");

    assert_eq!(anchor.height, 32);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0x72; 32]);
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 40,
        state_root: vec![0x41; 32],
        block_hash: [0x51; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        41,
        9,
        0x61,
        0x71,
        0x81,
        0x91,
        0xA1,
    );
    let mut step_two =
        sample_recovered_restart_step(None, Some(&step_one), 42, 10, 0x62, 0x72, 0x82, 0x92, 0xA2);
    step_two.header.parent_state_root = StateRoot(vec![0xFF; 32]);
    let parent_qc = step_two.certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(
            &current_anchor,
            &parent_qc,
            &[step_one, step_two],
        )
        .is_none(),
        "conflicting recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_three_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 50,
        state_root: vec![0x51; 32],
        block_hash: [0x61; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        51,
        11,
        0x71,
        0x81,
        0x91,
        0xA1,
        0xB1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 52, 12, 0x72, 0x82, 0x92, 0xA2, 0xB2);
    let step_three =
        sample_recovered_restart_step(None, Some(&step_two), 53, 13, 0x73, 0x83, 0x93, 0xA3, 0xB3);
    let parent_qc = step_three.certified_quorum_certificate();

    let anchor = advance_recovered_tip_anchor_along_restart_headers(
        &current_anchor,
        &parent_qc,
        &[step_one, step_two, step_three],
    )
    .expect("three-step recovered branch should advance");

    assert_eq!(anchor.height, 53);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0x93; 32]);
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_third_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 60,
        state_root: vec![0x61; 32],
        block_hash: [0x71; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        61,
        14,
        0x81,
        0x91,
        0xA1,
        0xB1,
        0xC1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 62, 15, 0x82, 0x92, 0xA2, 0xB2, 0xC2);
    let mut step_three =
        sample_recovered_restart_step(None, Some(&step_two), 63, 16, 0x83, 0x93, 0xA3, 0xB3, 0xC3);
    step_three.header.parent_qc.block_hash[0] ^= 0xFF;
    let parent_qc = step_three.certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(
            &current_anchor,
            &parent_qc,
            &[step_one, step_two, step_three],
        )
        .is_none(),
        "conflicting third-step recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_four_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 70,
        state_root: vec![0x71; 32],
        block_hash: [0x81; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        71,
        17,
        0x91,
        0xA1,
        0xB1,
        0xC1,
        0xD1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 72, 18, 0x92, 0xA2, 0xB2, 0xC2, 0xD2);
    let step_three =
        sample_recovered_restart_step(None, Some(&step_two), 73, 19, 0x93, 0xA3, 0xB3, 0xC3, 0xD3);
    let step_four = sample_recovered_restart_step(
        None,
        Some(&step_three),
        74,
        20,
        0x94,
        0xA4,
        0xB4,
        0xC4,
        0xD4,
    );
    let parent_qc = step_four.certified_quorum_certificate();

    let anchor = advance_recovered_tip_anchor_along_restart_headers(
        &current_anchor,
        &parent_qc,
        &[step_one, step_two, step_three, step_four],
    )
    .expect("four-step recovered branch should advance");

    assert_eq!(anchor.height, 74);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0xB4; 32]);
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_fourth_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 80,
        state_root: vec![0x81; 32],
        block_hash: [0x91; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        81,
        21,
        0xA1,
        0xB1,
        0xC1,
        0xD1,
        0xE1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 82, 22, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2);
    let step_three =
        sample_recovered_restart_step(None, Some(&step_two), 83, 23, 0xA3, 0xB3, 0xC3, 0xD3, 0xE3);
    let mut step_four = sample_recovered_restart_step(
        None,
        Some(&step_three),
        84,
        24,
        0xA4,
        0xB4,
        0xC4,
        0xD4,
        0xE4,
    );
    step_four.header.parent_qc.block_hash[0] ^= 0xFF;
    let parent_qc = step_four.certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(
            &current_anchor,
            &parent_qc,
            &[step_one, step_two, step_three, step_four],
        )
        .is_none(),
        "conflicting fourth-step recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_configured_window_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 90,
        state_root: vec![0x91; 32],
        block_hash: [0xA1; 32],
    };
    let branch = sample_recovered_restart_branch(
        &current_anchor,
        91,
        25,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW as usize,
        0xB1,
    );
    let parent_qc = branch
        .last()
        .expect("configured branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &branch)
            .expect("configured-window recovered branch should advance");

    assert_eq!(
        anchor.height,
        current_anchor.height + AFT_RECOVERED_CONSENSUS_HEADER_WINDOW
    );
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        branch
            .last()
            .expect("configured branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_configured_window_tail() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 100,
        state_root: vec![0xA1; 32],
        block_hash: [0xB1; 32],
    };
    let mut branch = sample_recovered_restart_branch(
        &current_anchor,
        101,
        30,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW as usize,
        0xC1,
    );
    branch
        .last_mut()
        .expect("configured branch tail")
        .header
        .parent_qc
        .block_hash[0] ^= 0xFF;
    let parent_qc = branch
        .last()
        .expect("configured branch tail")
        .certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &branch)
            .is_none(),
        "conflicting configured-window recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_stitched_restart_windows_accepts_overlapping_windows() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 120,
        state_root: vec![0xC1; 32],
        block_hash: [0xD1; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 121, 40, 8, 0xE1);
    let windows = bounded_recovered_window_ranges(
        current_anchor.height + 1,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(windows, vec![(121, 125), (124, 128)]);

    let windows = stitched_restart_windows(&branch, 121, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("stitched overlapping recovered windows should advance");

    assert_eq!(anchor.height, 128);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 130,
        state_root: vec![0xD1; 32],
        block_hash: [0xE1; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 131, 50, 8, 0xF1);
    let windows = bounded_recovered_window_ranges(
        131,
        138,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let stitched_windows = stitched_restart_windows(&branch, 131, &windows);
    let first_window = stitched_windows[0];
    let mut second_window = stitched_windows[1].to_vec();
    second_window[0].header.parent_qc.block_hash[0] ^= 0xFF;

    let error =
        stitch_recovered_restart_block_header_windows(&[first_window, second_window.as_slice()])
            .expect_err("conflicting overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_three_stitched_restart_windows_accepts_recursive_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 220,
        state_root: vec![0x21; 32],
        block_hash: [0x31; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 221, 60, 11, 0x41);
    let windows = bounded_recovered_window_ranges(
        current_anchor.height + 1,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(windows, vec![(221, 225), (224, 228), (227, 231)]);

    let windows = stitched_restart_windows(&branch, 221, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("three stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("three stitched recovered windows should advance");

    assert_eq!(anchor.height, 231);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_middle_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 230,
        state_root: vec![0x22; 32],
        block_hash: [0x32; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 231, 70, 11, 0x42);
    let windows = bounded_recovered_window_ranges(
        231,
        241,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let stitched_windows = stitched_restart_windows(&branch, 231, &windows);
    let first_window = stitched_windows[0];
    let mut second_window = stitched_windows[1].to_vec();
    let third_window = stitched_windows[2];
    second_window[3].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_windows(&[
        first_window,
        second_window.as_slice(),
        third_window,
    ])
    .expect_err("conflicting middle overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_four_stitched_restart_windows_accepts_bounded_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 240,
        state_root: vec![0x23; 32],
        block_hash: [0x33; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 241, 80, 14, 0x43);
    let start_height = bounded_recovered_window_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        4,
    );
    assert_eq!(start_height, 241);
    let windows = bounded_recovered_window_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(
        windows,
        vec![(241, 245), (244, 248), (247, 251), (250, 254)]
    );

    let windows = stitched_restart_windows(&branch, 241, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("four stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("four stitched recovered windows should advance");

    assert_eq!(anchor.height, 254);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_fourth_window_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 250,
        state_root: vec![0x24; 32],
        block_hash: [0x34; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 251, 90, 14, 0x44);
    let windows = bounded_recovered_window_ranges(
        251,
        264,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let stitched_windows = stitched_restart_windows(&branch, 251, &windows);
    let first_window = stitched_windows[0];
    let second_window = stitched_windows[1];
    let third_window = stitched_windows[2];
    let mut fourth_window = stitched_windows[3].to_vec();
    fourth_window[0].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_windows(&[
        first_window,
        second_window,
        third_window,
        fourth_window.as_slice(),
    ])
    .expect_err("conflicting fourth-window overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_five_stitched_restart_windows_accepts_configured_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 270,
        state_root: vec![0x25; 32],
        block_hash: [0x35; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 271, 100, 17, 0x45);
    let start_height = bounded_recovered_window_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    assert_eq!(start_height, 271);
    let windows = bounded_recovered_window_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(
        windows,
        vec![(271, 275), (274, 278), (277, 281), (280, 284), (283, 287)]
    );

    let windows = stitched_restart_windows(&branch, 271, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("five stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("five stitched recovered windows should advance");

    assert_eq!(anchor.height, 287);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_interior_overlap_in_five_window_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 280,
        state_root: vec![0x26; 32],
        block_hash: [0x36; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 281, 110, 17, 0x46);
    let mut windows = bounded_stitched_restart_windows(
        &branch,
        281,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let first_window = windows.remove(0);
    let second_window = windows.remove(0);
    let mut third_window = windows.remove(0).to_vec();
    let fourth_window = windows.remove(0);
    let fifth_window = windows.remove(0);
    third_window[3].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_windows(&[
        first_window,
        second_window,
        third_window.as_slice(),
        fourth_window,
        fifth_window,
    ])
    .expect_err("conflicting interior overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_two_stitched_restart_segments_accepts_recursive_segment_composition(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 300,
        state_root: vec![0x27; 32],
        block_hash: [0x37; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 301, 120, 29, 0x47);
    let first_segment_windows = bounded_recovered_window_ranges(
        301,
        317,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let second_segment_windows = bounded_recovered_window_ranges(
        313,
        329,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(
        first_segment_windows,
        vec![(301, 305), (304, 308), (307, 311), (310, 314), (313, 317)]
    );
    assert_eq!(
        second_segment_windows,
        vec![(313, 317), (316, 320), (319, 323), (322, 326), (325, 329)]
    );

    let first_segment = stitched_restart_segment(&branch, 301, &first_segment_windows);
    let second_segment = stitched_restart_segment(&branch, 301, &second_segment_windows);
    let stitched = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        second_segment.as_slice(),
    ])
    .expect("two stitched restart segments should compose");
    let parent_qc = stitched
        .last()
        .expect("segment-stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("segment-stitched recovered restart branch should advance");

    assert_eq!(anchor.height, 329);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segments_rejects_conflicting_segment_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 330,
        state_root: vec![0x28; 32],
        block_hash: [0x38; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 331, 130, 29, 0x48);
    let first_segment_windows = bounded_recovered_window_ranges(
        331,
        347,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let second_segment_windows = bounded_recovered_window_ranges(
        343,
        359,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );

    let first_segment = stitched_restart_segment(&branch, 331, &first_segment_windows);
    let mut second_segment = stitched_restart_segment(&branch, 331, &second_segment_windows);
    second_segment[1].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        second_segment.as_slice(),
    ])
    .expect_err("conflicting segment overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_three_stitched_restart_segments_accepts_recursive_segment_fold(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 360,
        state_root: vec![0x29; 32],
        block_hash: [0x39; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 361, 140, 41, 0x49);
    let segments = bounded_recovered_segment_ranges(
        361,
        401,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    assert_eq!(
        segments,
        vec![
            vec![(361, 365), (364, 368), (367, 371), (370, 374), (373, 377)],
            vec![(373, 377), (376, 380), (379, 383), (382, 386), (385, 389)],
            vec![(385, 389), (388, 392), (391, 395), (394, 398), (397, 401)],
        ]
    );

    let stitched = stitched_restart_segment_fold(&branch, 361, &segments);
    let parent_qc = stitched
        .last()
        .expect("segment-fold branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("three stitched restart segments should advance");

    assert_eq!(anchor.height, 401);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-fold branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segments_rejects_conflicting_middle_segment_overlap_in_three_segment_fold(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 390,
        state_root: vec![0x2A; 32],
        block_hash: [0x3A; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 391, 150, 41, 0x4A);
    let segments = bounded_recovered_segment_ranges(
        391,
        431,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    let first_segment = stitched_restart_segment(&branch, 391, &segments[0]);
    let mut middle_segment = stitched_restart_segment(&branch, 391, &segments[1]);
    let third_segment = stitched_restart_segment(&branch, 391, &segments[2]);
    middle_segment[12].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        middle_segment.as_slice(),
        third_segment.as_slice(),
    ])
    .expect_err("conflicting middle-segment overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_four_stitched_restart_segments_accepts_live_segment_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 420,
        state_root: vec![0x2B; 32],
        block_hash: [0x3B; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 421, 160, 53, 0x4B);
    let start_height = bounded_recovered_segment_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    assert_eq!(start_height, 421);
    let segments = bounded_recovered_segment_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    assert_eq!(
        segments,
        vec![
            vec![(421, 425), (424, 428), (427, 431), (430, 434), (433, 437)],
            vec![(433, 437), (436, 440), (439, 443), (442, 446), (445, 449)],
            vec![(445, 449), (448, 452), (451, 455), (454, 458), (457, 461)],
            vec![(457, 461), (460, 464), (463, 467), (466, 470), (469, 473)],
        ]
    );

    let stitched = stitched_restart_segment_fold(&branch, 421, &segments);
    let parent_qc = stitched
        .last()
        .expect("segment-fold branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("four stitched restart segments should advance");

    assert_eq!(anchor.height, 473);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-fold branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segments_rejects_conflicting_interior_segment_overlap_in_four_segment_fold(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 450,
        state_root: vec![0x2C; 32],
        block_hash: [0x3C; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 451, 170, 53, 0x4C);
    let segments = bounded_recovered_segment_ranges(
        451,
        503,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    let first_segment = stitched_restart_segment(&branch, 451, &segments[0]);
    let second_segment = stitched_restart_segment(&branch, 451, &segments[1]);
    let mut third_segment = stitched_restart_segment(&branch, 451, &segments[2]);
    let fourth_segment = stitched_restart_segment(&branch, 451, &segments[3]);
    third_segment[12].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        second_segment.as_slice(),
        third_segment.as_slice(),
        fourth_segment.as_slice(),
    ])
    .expect_err("conflicting interior segment overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_two_stitched_restart_segment_folds_accepts_recursive_fold_of_folds(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 480,
        state_root: vec![0x2D; 32],
        block_hash: [0x3D; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 481, 180, 89, 0x4D);
    let start_height = bounded_recovered_segment_fold_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    );
    assert_eq!(start_height, 481);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    assert_eq!(
        segment_folds,
        vec![
            vec![
                vec![(481, 485), (484, 488), (487, 491), (490, 494), (493, 497)],
                vec![(493, 497), (496, 500), (499, 503), (502, 506), (505, 509)],
                vec![(505, 509), (508, 512), (511, 515), (514, 518), (517, 521)],
                vec![(517, 521), (520, 524), (523, 527), (526, 530), (529, 533)],
            ],
            vec![
                vec![(517, 521), (520, 524), (523, 527), (526, 530), (529, 533)],
                vec![(529, 533), (532, 536), (535, 539), (538, 542), (541, 545)],
                vec![(541, 545), (544, 548), (547, 551), (550, 554), (553, 557)],
                vec![(553, 557), (556, 560), (559, 563), (562, 566), (565, 569)],
            ],
        ]
    );

    let stitched = stitched_restart_segment_fold_of_folds(&branch, 481, &segment_folds);
    let parent_qc = stitched
        .last()
        .expect("segment-fold-of-folds branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("two stitched restart segment folds should advance");

    assert_eq!(anchor.height, 569);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-fold-of-folds branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segment_folds_rejects_conflicting_inter_fold_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 520,
        state_root: vec![0x2E; 32],
        block_hash: [0x3E; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 521, 190, 89, 0x4E);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        521,
        609,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    let first_fold = stitched_restart_segment_fold(&branch, 521, &segment_folds[0]);
    let mut second_fold = stitched_restart_segment_fold(&branch, 521, &segment_folds[1]);
    second_fold[8].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_fold.as_slice(),
        second_fold.as_slice(),
    ])
    .expect_err("conflicting inter-fold overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_three_stitched_restart_segment_folds_accepts_recursive_fold_of_folds(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 560,
        state_root: vec![0x2F; 32],
        block_hash: [0x3F; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 561, 200, 125, 0x4F);
    let start_height = bounded_recovered_segment_fold_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        3,
    );
    assert_eq!(start_height, 561);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    assert_eq!(segment_folds.len(), 3);
    assert_eq!(
        segment_folds[0],
        vec![
            vec![(561, 565), (564, 568), (567, 571), (570, 574), (573, 577)],
            vec![(573, 577), (576, 580), (579, 583), (582, 586), (585, 589)],
            vec![(585, 589), (588, 592), (591, 595), (594, 598), (597, 601)],
            vec![(597, 601), (600, 604), (603, 607), (606, 610), (609, 613)],
        ]
    );
    assert_eq!(
        segment_folds[1],
        vec![
            vec![(597, 601), (600, 604), (603, 607), (606, 610), (609, 613)],
            vec![(609, 613), (612, 616), (615, 619), (618, 622), (621, 625)],
            vec![(621, 625), (624, 628), (627, 631), (630, 634), (633, 637)],
            vec![(633, 637), (636, 640), (639, 643), (642, 646), (645, 649)],
        ]
    );
    assert_eq!(
        segment_folds[2],
        vec![
            vec![(633, 637), (636, 640), (639, 643), (642, 646), (645, 649)],
            vec![(645, 649), (648, 652), (651, 655), (654, 658), (657, 661)],
            vec![(657, 661), (660, 664), (663, 667), (666, 670), (669, 673)],
            vec![(669, 673), (672, 676), (675, 679), (678, 682), (681, 685)],
        ]
    );

    let stitched = stitched_restart_segment_fold_of_folds(&branch, 561, &segment_folds);
    let parent_qc = stitched
        .last()
        .expect("three-fold segment composition branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("three stitched restart segment folds should advance");

    assert_eq!(anchor.height, 685);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("three-fold segment composition branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segment_folds_rejects_conflicting_middle_fold_overlap_in_three_fold_composition(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 610,
        state_root: vec![0x30; 32],
        block_hash: [0x40; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 611, 210, 125, 0x50);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        611,
        735,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    let first_fold = stitched_restart_segment_fold(&branch, 611, &segment_folds[0]);
    let mut second_fold = stitched_restart_segment_fold(&branch, 611, &segment_folds[1]);
    let third_fold = stitched_restart_segment_fold(&branch, 611, &segment_folds[2]);
    second_fold[40].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_fold.as_slice(),
        second_fold.as_slice(),
        third_fold.as_slice(),
    ])
    .expect_err("conflicting middle-fold overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn folded_recovered_loaders_match_expected_prefixes_across_fold_budgets() {
    let cases = [(1u64, 53u64, 0x21u8), (2, 89, 0x41), (3, 125, 0x51)];

    for (fold_budget, expected_end_height, seed_base) in cases {
        let (workload_client, expected_headers, expected_certified, expected_restart) =
            seed_recovered_workload_client(expected_end_height, seed_base);

        let loaded_headers = run_async_test(load_folded_recovered_consensus_headers(
            &workload_client,
            expected_end_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            fold_budget,
        ))
        .expect("folded recovered canonical-header prefix");
        assert_eq!(
            loaded_headers, expected_headers,
            "fold budget {fold_budget} recovered canonical-header prefix mismatch"
        );

        let loaded_certified = run_async_test(load_folded_recovered_certified_headers(
            &workload_client,
            expected_end_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            fold_budget,
        ))
        .expect("folded recovered certified-header prefix");
        assert_eq!(
            loaded_certified, expected_certified,
            "fold budget {fold_budget} recovered certified-header prefix mismatch"
        );

        let loaded_restart = run_async_test(load_folded_recovered_restart_block_headers(
            &workload_client,
            expected_end_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            fold_budget,
        ))
        .expect("folded recovered restart block-header prefix");
        assert_eq!(
            loaded_restart, expected_restart,
            "fold budget {fold_budget} recovered restart block-header prefix mismatch"
        );
        assert_eq!(
            loaded_restart.len(),
            expected_end_height as usize,
            "fold budget {fold_budget} restart prefix length mismatch"
        );
        let tail_index = loaded_restart.len() - 1;
        assert_eq!(
            loaded_restart[tail_index].header.parent_qc,
            loaded_restart[tail_index - 1].certified_quorum_certificate(),
            "fold budget {fold_budget} restart tail parent QC mismatch"
        );
    }
}

#[test]
fn stitched_recovered_restart_carriers_reject_conflicting_overlap_across_fold_budgets() {
    let cases = [(1u64, 53usize, 0x22u8), (2, 89, 0x42), (3, 125, 0x52)];

    for (fold_budget, depth, seed_base) in cases {
        let current_anchor = RecoveredConsensusTipAnchor {
            height: 0,
            state_root: vec![seed_base; 32],
            block_hash: [seed_base.wrapping_add(1); 32],
        };
        let branch = sample_recovered_restart_branch(
            &current_anchor,
            1,
            300 + fold_budget,
            depth,
            seed_base.wrapping_add(0x10),
        );

        let error = match fold_budget {
            1 => {
                let segments = bounded_recovered_segment_ranges(
                    1,
                    depth as u64,
                    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                    AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
                );
                let first_segment = stitched_restart_segment(&branch, 1, &segments[0]);
                let second_segment = stitched_restart_segment(&branch, 1, &segments[1]);
                let mut third_segment = stitched_restart_segment(&branch, 1, &segments[2]);
                let fourth_segment = stitched_restart_segment(&branch, 1, &segments[3]);
                third_segment[12].header.parent_qc.block_hash[0] ^= 0xFF;

                stitch_recovered_restart_block_header_segments(&[
                    first_segment.as_slice(),
                    second_segment.as_slice(),
                    third_segment.as_slice(),
                    fourth_segment.as_slice(),
                ])
                .expect_err("conflicting interior segment overlap should be rejected")
            }
            2 => {
                let segment_folds = bounded_recovered_segment_fold_ranges(
                    1,
                    depth as u64,
                    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                    AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
                );
                let first_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[0]);
                let mut second_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[1]);
                second_fold[8].header.parent_qc.block_hash[0] ^= 0xFF;

                stitch_recovered_restart_block_header_segments(&[
                    first_fold.as_slice(),
                    second_fold.as_slice(),
                ])
                .expect_err("conflicting inter-fold overlap should be rejected")
            }
            3 => {
                let segment_folds = bounded_recovered_segment_fold_ranges(
                    1,
                    depth as u64,
                    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                    AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
                );
                let first_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[0]);
                let mut second_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[1]);
                let third_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[2]);
                second_fold[40].header.parent_qc.block_hash[0] ^= 0xFF;

                stitch_recovered_restart_block_header_segments(&[
                    first_fold.as_slice(),
                    second_fold.as_slice(),
                    third_fold.as_slice(),
                ])
                .expect_err("conflicting middle-fold overlap should be rejected")
            }
            _ => unreachable!("unsupported fold-budget conformance case"),
        };

        assert!(
            error.contains("overlap mismatch"),
            "fold budget {fold_budget} should reject conflicting overlap: {error}"
        );
    }
}

#[test]
fn paged_recovered_segment_fold_cursor_matches_direct_extract_for_two_hundred_thirty_three_step_branch(
) {
    let expected_end_height = 233u64;
    let (client, expected_headers, expected_certified, expected_restart) =
        seed_recovered_workload_client(expected_end_height, 0x61);

    let (loaded_headers, loaded_certified, loaded_restart) =
        load_paged_recovered_prefixes_to_height(&client, expected_end_height, 1)
            .expect("paged recovered ancestry");

    assert_eq!(loaded_headers.len(), expected_end_height as usize);
    assert_eq!(loaded_certified.len(), expected_end_height as usize);
    assert_eq!(loaded_restart.len(), expected_end_height as usize);
    assert_eq!(loaded_headers, expected_headers);
    assert_eq!(loaded_certified, expected_certified);
    assert_eq!(loaded_restart, expected_restart);
}

#[test]
fn paged_recovered_segment_fold_cursor_matches_direct_extract_across_page_depths() {
    for (index, expected_end_height) in [89u64, 125, 161, 197, 233].into_iter().enumerate() {
        let seed = 0x70u8.wrapping_add(index as u8);
        let (client, expected_headers, expected_certified, expected_restart) =
            seed_recovered_workload_client(expected_end_height, seed);

        let (loaded_headers, loaded_certified, loaded_restart) =
            load_paged_recovered_prefixes_to_height(&client, expected_end_height, 1)
                .expect("paged recovered ancestry");

        assert_eq!(
                loaded_headers, expected_headers,
                "paged recovered canonical-header ancestry mismatch at end height {expected_end_height}"
            );
        assert_eq!(
                loaded_certified, expected_certified,
                "paged recovered certified-header ancestry mismatch at end height {expected_end_height}"
            );
        assert_eq!(
            loaded_restart, expected_restart,
            "paged recovered restart ancestry mismatch at end height {expected_end_height}"
        );
    }
}

#[test]
fn paged_recovered_segment_fold_cursor_rejects_duplicate_page_ambiguity() {
    let mut cursor = RecoveredSegmentFoldCursor::new(
        233,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .expect("recovered segment-fold cursor");

    let first_page = cursor
        .next_page()
        .expect("advance recovered segment-fold cursor")
        .expect("older recovered page");
    let error = cursor
        .accept_page(&first_page)
        .expect_err("duplicate recovered page must be rejected");
    assert!(
        error.contains("expected page"),
        "unexpected duplicate-page error: {error}"
    );
}

#[test]
fn paged_recovered_segment_fold_cursor_rejects_missing_gap_page() {
    let expected_end_height = 233u64;
    let (mut client, _, _, _) = seed_recovered_workload_client(expected_end_height, 0x63);
    let mut cursor = RecoveredSegmentFoldCursor::new(
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .expect("recovered segment-fold cursor");

    let page = cursor
        .next_page()
        .expect("advance recovered segment-fold cursor")
        .expect("older recovered page");
    let gap_height = page.start_height + 7;
    let recovered_prefix = [
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &gap_height.to_be_bytes(),
    ]
    .concat();
    client
        .raw_state
        .retain(|key, _| !key.starts_with(&recovered_prefix));

    let error = run_async_test(load_recovered_segment_fold_page(&client, &page))
        .expect_err("missing recovered page gap must fail");
    let message = error.to_string();
    assert!(
        (message.contains("expected") && message.contains("loaded"))
            || message.contains("must be consecutive"),
        "unexpected missing-page error: {message}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_pages_older_ranges_and_bounds_engine_cache() {
    let expected_end_height = 233u64;
    let target_height = 1u64;
    let (client, _all_headers, _all_certified, all_restart) =
        seed_recovered_workload_client(expected_end_height, 0x74);
    let recovered_headers = run_async_test(load_folded_recovered_consensus_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("bounded recovered consensus headers");
    let recovered_certified = run_async_test(load_folded_recovered_certified_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("bounded recovered certified headers");
    let recovered_restart = run_async_test(load_folded_recovered_restart_block_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("bounded recovered restart block headers");
    let base_start_height = loaded_recovered_ancestry_start_height(
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    )
    .expect("bounded recovered start height");
    let base_tail_entry = recovered_restart
        .last()
        .expect("bounded recovered restart tail")
        .clone();
    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect("stream recovered ancestry to target");

    assert!(report.covered_target, "target height must be covered");
    assert!(
        !report.exhausted,
        "stream should not exhaust before reaching genesis"
    );
    assert!(
        report.loaded_pages.len() > 1,
        "expected multiple paged recovered ranges: {:?}",
        report.loaded_pages
    );
    let final_page = report
        .loaded_pages
        .last()
        .copied()
        .expect("final streamed recovered page");
    assert_eq!(final_page.0, 1, "final streamed page must reach genesis");
    assert!(
        final_page.1 < base_start_height,
        "final streamed range should stay disjoint from the bounded base suffix"
    );

    let pruned_heights = report
        .loaded_pages
        .iter()
        .take(report.loaded_pages.len().saturating_sub(1))
        .map(|(start_height, _)| *start_height)
        .filter(|height| final_page.1 < *height && *height < base_start_height)
        .collect::<Vec<_>>();
    let target_entry = all_restart
        .iter()
        .find(|entry| entry.header.height == target_height)
        .expect("restart entry at target height")
        .clone();

    run_async_test(async {
        let engine = engine.lock().await;
        assert!(
                <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                    &*engine,
                    &target_entry.certified_quorum_certificate(),
                )
                .is_some(),
                "streamed target height should remain available after paging"
            );
        assert!(
                <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                    &*engine,
                    &base_tail_entry.certified_quorum_certificate(),
                )
                .is_some(),
                "bounded base suffix should remain retained after paging"
            );
        for pruned_height in pruned_heights {
            let pruned_entry = all_restart
                .iter()
                .find(|entry| entry.header.height == pruned_height)
                .expect("restart entry for pruned height");
            assert!(
                    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                        &*engine,
                        &pruned_entry.certified_quorum_certificate(),
                    )
                    .is_none(),
                    "intermediate streamed page at height {pruned_height} should be evicted once paging advances"
                );
        }
    });
}

#[test]
fn stream_recovered_ancestry_to_height_falls_back_to_archived_restart_pages() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7A,
        );
    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect("stream recovered ancestry across archived fallback");

    assert!(
        report.covered_target,
        "archived fallback should cover the target"
    );
    assert!(
        !report.exhausted,
        "archived fallback should not exhaust before height 1"
    );
    assert!(
        report.loaded_pages.iter().any(|page| page.0 == 1),
        "archived fallback should reach an archived page whose start height reaches genesis"
    );

    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let (expected_archived_start_height, expected_archived_end_height) =
        archived_recovered_restart_page_range_for_profile(
            retained_start_height - 1,
            &active_profile,
        )
        .expect("expected archived recovered restart page range");
    let target_segment: ArchivedRecoveredHistorySegment = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&aft_archived_recovered_history_segment_key(
                expected_archived_start_height,
                expected_archived_end_height,
            ))
            .expect("archived segment covering the retained predecessor range")
            .clone(),
    )
    .expect("decode archived segment for the retained predecessor range");
    let target_segment_hash = canonical_archived_recovered_history_segment_hash(&target_segment)
        .expect("archived segment hash for the retained predecessor range");
    let target_page: ArchivedRecoveredRestartPage = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&aft_archived_recovered_restart_page_key(
                &target_segment_hash,
            ))
            .expect("archived restart page for the retained predecessor range")
            .clone(),
    )
    .expect("decode archived restart page for the retained predecessor range");
    let target_entry = target_page
        .restart_headers
        .first()
        .expect("first archived restart entry in the retained predecessor range")
        .clone();

    run_async_test(async {
        let engine = engine.lock().await;
        assert!(
                <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                    &*engine,
                    &target_entry.certified_quorum_certificate(),
                )
                .is_some(),
                "archived fallback target should be present in the engine cache"
            );
    });
}

#[test]
fn stream_recovered_ancestry_to_height_discovers_archived_fallback_from_canonical_collapse_anchor_without_latest_checkpoint_side_key(
) {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7B,
        );
    client
        .raw_state
        .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY);

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect("stream recovered ancestry without latest archived checkpoint tip");

    assert!(
            report.covered_target,
            "canonical collapse anchor should bootstrap archived fallback without the latest checkpoint side key"
        );
    assert!(
            !report.exhausted,
            "canonical collapse anchor should keep archived fallback live without the latest checkpoint side key"
        );
    assert!(
            report.loaded_pages.iter().any(|page| page.0 == 1),
            "canonical collapse anchor should still load archived pages to genesis-facing coverage: {:?}",
            report.loaded_pages
        );
}

#[test]
fn stream_recovered_ancestry_to_height_requires_canonical_collapse_archived_anchor_for_fallback() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x81,
        );
    let collapse_key = aft_canonical_collapse_object_key(expected_end_height);
    let mut retained_tip: CanonicalCollapseObject = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&collapse_key)
            .expect("retained canonical collapse tip")
            .clone(),
    )
    .expect("decode retained canonical collapse tip");
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut retained_tip,
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
    )
    .expect("clear retained canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip)
            .expect("encode retained canonical collapse tip without archived-history anchor"),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect("stream recovered ancestry without canonical collapse archived-history anchor");

    assert!(
            !report.covered_target,
            "missing canonical collapse archived-history anchor must not infer archived fallback coverage"
        );
    assert!(
            report.exhausted,
            "missing canonical collapse archived-history anchor must fail closed as exhausted recovered ancestry"
        );
    assert!(
        report.loaded_pages.is_empty(),
        "missing canonical collapse archived-history anchor must not load archived pages: {:?}",
        report.loaded_pages
    );
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_conflicting_canonical_collapse_archived_anchor() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x82,
        );
    let collapse_key = aft_canonical_collapse_object_key(expected_end_height);
    let mut retained_tip: CanonicalCollapseObject = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&collapse_key)
            .expect("retained canonical collapse tip")
            .clone(),
    )
    .expect("decode retained canonical collapse tip");
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut retained_tip,
        [0xC1; 32],
        [0xC2; 32],
        [0xC3; 32],
    )
    .expect("set conflicting retained canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip)
            .expect("encode retained canonical collapse tip with conflicting anchor"),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("conflicting canonical collapse archived-history anchor must fail closed");
    assert!(
        error
            .to_string()
            .contains("checkpoint anchor is missing from state"),
        "unexpected conflicting canonical anchor error: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_requires_archived_retention_receipt_for_fallback() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7C,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let latest_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
            .expect("latest archived checkpoint hash");
    client
        .raw_state
        .remove(&aft_archived_recovered_history_retention_receipt_key(
            &latest_checkpoint_hash,
        ));

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("missing archived retention receipt must fail closed");
    assert!(
        error
            .to_string()
            .contains("retention receipt anchor is missing from state"),
        "unexpected error for missing archived retention receipt: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_conflicting_anchored_retention_receipt_hash() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7E,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let latest_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
            .expect("latest archived checkpoint hash");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let latest_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&latest_activation)
            .expect("latest archived profile activation hash");
    let collapse_key = aft_canonical_collapse_object_key(expected_end_height);
    let mut retained_tip: CanonicalCollapseObject = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&collapse_key)
            .expect("retained canonical collapse tip")
            .clone(),
    )
    .expect("decode retained canonical collapse tip");
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut retained_tip,
        latest_checkpoint_hash,
        latest_activation_hash,
        [0xD7; 32],
    )
    .expect("set conflicting canonical collapse retention receipt anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip)
            .expect("encode retained canonical collapse tip with conflicting receipt hash"),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("conflicting canonical collapse receipt anchor must fail closed");
    assert!(
        error
            .to_string()
            .contains("retention receipt anchor does not match the published receipt"),
        "unexpected error for conflicting anchored receipt hash: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_uses_historical_archived_profile_after_active_rotation_without_latest_activation_indexes(
) {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7D,
        );
    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let conflicting_profile = build_archived_recovered_history_profile(
        active_profile.retention_horizon + 1,
        active_profile.restart_page_window,
        active_profile.restart_page_overlap,
        active_profile.windows_per_segment,
        active_profile.segments_per_fold,
        active_profile.checkpoint_update_rule,
    )
    .expect("rotated archived recovered-history profile");
    let conflicting_profile_hash =
        canonical_archived_recovered_history_profile_hash(&conflicting_profile)
            .expect("rotated archived recovered-history profile hash");
    let conflicting_activation = build_archived_recovered_history_profile_activation(
        &conflicting_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height + 1,
        None,
    )
    .expect("rotated archived recovered-history profile activation");
    client.raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting archived profile"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode rotated archived profile by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode rotated archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode rotated archived profile activation by height"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode latest rotated archived profile activation"),
    );
    client
        .raw_state
        .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY);
    client.raw_state.remove(
        &aft_archived_recovered_history_profile_activation_height_key(
            latest_activation.activation_end_height,
        ),
    );
    client.raw_state.remove(
        &aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect("historical archived profile should remain valid after active-profile rotation");
    assert!(report.covered_target);
    assert!(!report.exhausted);
    assert!(
        report.loaded_pages.iter().any(|page| page.0 == 1),
        "historical archived profile should still reach genesis-facing archived coverage"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_matches_three_recurring_historical_continuation_cycles_on_runtime_side(
) {
    let cycles = [
        (1u64, 40u64, 31u64, 0x84u8),
        (2, 80, 71, 0x94),
        (3, 120, 111, 0xA4),
    ];

    for (cycle, expected_end_height, retained_start_height, seed_base) in cycles {
        let report = stream_recovered_historical_continuation_cycle_case(
            expected_end_height,
            retained_start_height,
            seed_base,
        );

        assert!(
            report.covered_target,
            "runtime recurring cycle {cycle} should cover genesis-facing target height"
        );
        assert!(
            !report.exhausted,
            "runtime recurring cycle {cycle} should not exhaust archived continuation"
        );
        assert!(
            !report.loaded_pages.is_empty(),
            "runtime recurring cycle {cycle} should page older historical retrievability ranges"
        );
        assert!(
            report.loaded_pages.iter().any(|page| page.0 == 1),
            "runtime recurring cycle {cycle} should reach a genesis-facing archived page: {:?}",
            report.loaded_pages
        );
    }
}

#[test]
fn stream_recovered_ancestry_to_height_matches_persistent_historical_continuation_churn_simulator()
{
    let target_height = 1u64;
    let cycles = [
        (1u64, 40u64, 31u64, 0x84u8),
        (2, 80, 71, 0x94),
        (3, 120, 111, 0xA4),
    ];
    let mut simulator = PersistentRecoveredHistoricalContinuationSimulator::new();

    for (cycle, expected_end_height, retained_start_height, seed_base) in cycles {
        simulator.append_through(expected_end_height, retained_start_height, seed_base);
        simulator.rotate_active_profile_and_remove_latest_side_indexes();
        let report = simulator.stream_to_target(retained_start_height, target_height);

        assert!(
            report.covered_target,
            "persistent runtime churn cycle {cycle} should cover genesis-facing target height"
        );
        assert!(
            !report.exhausted,
            "persistent runtime churn cycle {cycle} should not exhaust archived continuation"
        );
        assert!(
                !report.loaded_pages.is_empty(),
                "persistent runtime churn cycle {cycle} should page older historical retrievability ranges"
            );
        assert!(
                report.loaded_pages.iter().any(|page| page.0 == 1),
                "persistent runtime churn cycle {cycle} should still reach a genesis-facing archived page: {:?}",
                report.loaded_pages
            );
    }
}

#[test]
fn stream_recovered_ancestry_to_height_requires_referenced_archived_profile_for_fallback() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7E,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    client
        .raw_state
        .remove(&aft_archived_recovered_history_profile_hash_key(
            &latest_checkpoint.archived_profile_hash,
        ));

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("missing referenced archived profile must fail closed");
    assert!(error
        .to_string()
        .contains("references a missing archived profile hash"));
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_mixed_profile_archived_chain() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7F,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let conflicting_profile = build_archived_recovered_history_profile(
        active_profile.retention_horizon + 1,
        active_profile.restart_page_window,
        active_profile.restart_page_overlap,
        active_profile.windows_per_segment,
        active_profile.segments_per_fold,
        active_profile.checkpoint_update_rule,
    )
    .expect("conflicting archived recovered-history profile");
    let conflicting_profile_hash =
        canonical_archived_recovered_history_profile_hash(&conflicting_profile)
            .expect("conflicting archived recovered-history profile hash");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting archived profile by hash"),
    );
    let conflicting_activation = build_archived_recovered_history_profile_activation(
        &conflicting_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height + 1,
        None,
    )
    .expect("conflicting archived recovered-history profile activation");
    let conflicting_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&conflicting_activation)
            .expect("conflicting archived recovered-history profile activation hash");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_hash_key(&conflicting_activation_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by height"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode latest conflicting archived profile activation"),
    );
    client.raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting active archived profile"),
    );

    let mut conflicting_checkpoint = latest_checkpoint.clone();
    conflicting_checkpoint.archived_profile_hash = conflicting_profile_hash;
    let conflicting_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&conflicting_checkpoint)
            .expect("conflicting archived checkpoint hash");
    client.raw_state.insert(
        aft_archived_recovered_history_checkpoint_key(
            conflicting_checkpoint.covered_start_height,
            conflicting_checkpoint.covered_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting archived checkpoint"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_checkpoint_hash_key(&conflicting_checkpoint_hash),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting archived checkpoint by hash"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting latest archived checkpoint"),
    );
    let validator_sets = read_validator_sets(
        client
            .raw_state
            .get(VALIDATOR_SET_KEY)
            .expect("active validator set")
            .as_slice(),
    )
    .expect("decode validator set");
    let validator_set_commitment_hash =
        canonical_validator_sets_hash(&validator_sets).expect("validator set commitment hash");
    let conflicting_receipt = build_archived_recovered_history_retention_receipt(
        &conflicting_checkpoint,
        validator_set_commitment_hash,
        archived_recovered_history_retained_through_height(
            &conflicting_checkpoint,
            &conflicting_profile,
        )
        .expect("conflicting retained-through height"),
    )
    .expect("conflicting archived retention receipt");
    let collapse_key = aft_canonical_collapse_object_key(expected_end_height);
    let mut retained_tip: CanonicalCollapseObject = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&collapse_key)
            .expect("retained canonical collapse tip")
            .clone(),
    )
    .expect("decode retained canonical collapse tip");
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut retained_tip,
        conflicting_checkpoint_hash,
        conflicting_activation_hash,
        canonical_archived_recovered_history_retention_receipt_hash(&conflicting_receipt)
            .expect("conflicting archived receipt hash"),
    )
    .expect("set conflicting canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip).expect(
            "encode retained canonical collapse tip with conflicting archived-history anchor",
        ),
    );
    client
        .raw_state
        .remove(&aft_archived_recovered_history_retention_receipt_key(
            &canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
                .expect("latest archived checkpoint hash"),
        ));
    client.raw_state.insert(
        aft_archived_recovered_history_retention_receipt_key(&conflicting_checkpoint_hash),
        codec::to_bytes_canonical(&conflicting_receipt)
            .expect("encode conflicting archived retention receipt"),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("mixed-profile archived chain must fail closed");
    assert!(
        error
            .to_string()
            .contains("predates the governing profile activation tip")
            || error
                .to_string()
                .contains("crosses the successor profile activation tip"),
        "unexpected mixed-profile archived chain error: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_conflicting_archived_profile_activation_predecessor_history(
) {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x80,
        );
    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let conflicting_profile = build_archived_recovered_history_profile(
        active_profile.retention_horizon + 1,
        active_profile.restart_page_window,
        active_profile.restart_page_overlap,
        active_profile.windows_per_segment,
        active_profile.segments_per_fold,
        active_profile.checkpoint_update_rule,
    )
    .expect("conflicting archived recovered-history profile");
    let conflicting_profile_hash =
        canonical_archived_recovered_history_profile_hash(&conflicting_profile)
            .expect("conflicting archived recovered-history profile hash");
    let conflicting_activation = build_archived_recovered_history_profile_activation(
        &conflicting_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height,
        None,
    )
    .expect("conflicting archived recovered-history profile activation");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting archived profile by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by height"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode latest conflicting archived profile activation"),
    );
    client.raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting active archived profile"),
    );

    let mut conflicting_checkpoint = latest_checkpoint.clone();
    conflicting_checkpoint.archived_profile_hash = conflicting_profile_hash;
    let conflicting_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&conflicting_checkpoint)
            .expect("conflicting archived checkpoint hash");
    client.raw_state.insert(
        aft_archived_recovered_history_checkpoint_key(
            conflicting_checkpoint.covered_start_height,
            conflicting_checkpoint.covered_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting archived checkpoint"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_checkpoint_hash_key(&conflicting_checkpoint_hash),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting archived checkpoint by hash"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode latest conflicting archived checkpoint"),
    );

    let validator_sets = read_validator_sets(
        client
            .raw_state
            .get(VALIDATOR_SET_KEY)
            .expect("active validator set")
            .as_slice(),
    )
    .expect("decode validator set");
    let validator_set_commitment_hash =
        canonical_validator_sets_hash(&validator_sets).expect("validator set commitment hash");
    let conflicting_receipt = build_archived_recovered_history_retention_receipt(
        &conflicting_checkpoint,
        validator_set_commitment_hash,
        archived_recovered_history_retained_through_height(
            &conflicting_checkpoint,
            &conflicting_profile,
        )
        .expect("conflicting retained-through height"),
    )
    .expect("conflicting archived retention receipt");

    let collapse_key = aft_canonical_collapse_object_key(expected_end_height);
    let mut retained_tip: CanonicalCollapseObject = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&collapse_key)
            .expect("retained canonical collapse tip")
            .clone(),
    )
    .expect("decode retained canonical collapse tip");
    let conflicting_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&conflicting_activation)
            .expect("conflicting archived profile activation hash");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_hash_key(&conflicting_activation_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by hash"),
    );
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut retained_tip,
        conflicting_checkpoint_hash,
        conflicting_activation_hash,
        canonical_archived_recovered_history_retention_receipt_hash(&conflicting_receipt)
            .expect("conflicting archived receipt hash"),
    )
    .expect("set conflicting canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip).expect(
            "encode retained canonical collapse tip with conflicting archived-history anchor",
        ),
    );
    client
        .raw_state
        .remove(&aft_archived_recovered_history_retention_receipt_key(
            &canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
                .expect("latest archived checkpoint hash"),
        ));
    client.raw_state.insert(
        aft_archived_recovered_history_retention_receipt_key(&conflicting_checkpoint_hash),
        codec::to_bytes_canonical(&conflicting_receipt)
            .expect("encode conflicting archived retention receipt"),
    );

    let mut conflicting_predecessor = latest_activation.clone();
    conflicting_predecessor.activation_end_height = conflicting_activation.activation_end_height;
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(
            &conflicting_predecessor.archived_profile_hash,
        ),
        codec::to_bytes_canonical(&conflicting_predecessor)
            .expect("encode conflicting predecessor activation"),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("conflicting archived activation predecessor history must fail closed");
    assert!(
        error
            .to_string()
            .contains("must advance to a strictly later archived tip height"),
        "unexpected archived activation predecessor conflict error: {error}"
    );
}

#[test]
fn paged_recovered_segment_fold_cursor_rejects_conflicting_late_page_overlap() {
    let expected_end_height = 233u64;
    let (mut client, _, _, _) = seed_recovered_workload_client(expected_end_height, 0x62);
    let mut recovered_headers = run_async_test(load_folded_recovered_consensus_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("initial folded recovered headers");
    let mut recovered_certified = run_async_test(load_folded_recovered_certified_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("initial folded recovered certified headers");
    let mut recovered_restart = run_async_test(load_folded_recovered_restart_block_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("initial folded recovered restart headers");
    let mut cursor = RecoveredSegmentFoldCursor::new(
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .expect("recovered segment-fold cursor");

    for _ in 0..2 {
        let page = cursor
            .next_page()
            .expect("advance recovered segment-fold cursor")
            .expect("older recovered page");
        let loaded_page = run_async_test(load_recovered_segment_fold_page(&client, &page))
            .expect("load older recovered segment-fold page");
        recovered_headers = stitch_recovered_canonical_header_segments(&[
            loaded_page.consensus_headers.as_slice(),
            recovered_headers.as_slice(),
        ])
        .expect("stitch older recovered canonical-header page");
        recovered_certified = stitch_recovered_certified_header_segments(&[
            loaded_page.certified_headers.as_slice(),
            recovered_certified.as_slice(),
        ])
        .expect("stitch older recovered certified-header page");
        recovered_restart = stitch_recovered_restart_block_header_segments(&[
            loaded_page.restart_headers.as_slice(),
            recovered_restart.as_slice(),
        ])
        .expect("stitch older recovered restart page");
    }
    assert_eq!(
        loaded_recovered_ancestry_start_height(
            &recovered_headers,
            &recovered_certified,
            &recovered_restart,
        ),
        Some(73),
        "two older pages should extend the cached prefix down to height 73",
    );

    let key = aft_canonical_collapse_object_key(79);
    let mut collapse: CanonicalCollapseObject = codec::from_bytes_canonical(
        client
            .raw_state
            .get(&key)
            .expect("collapse bytes for late overlap height"),
    )
    .expect("decode canonical collapse object");
    collapse.previous_canonical_collapse_commitment_hash[0] ^= 0x5a;
    client.raw_state.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode conflicting collapse"),
    );

    let page = cursor
        .next_page()
        .expect("advance recovered segment-fold cursor")
        .expect("late conflicting page");
    let loaded_page = run_async_test(load_recovered_segment_fold_page(&client, &page))
        .expect("load conflicting recovered segment-fold page");

    let error = stitch_recovered_canonical_header_segments(&[
        loaded_page.consensus_headers.as_slice(),
        recovered_headers.as_slice(),
    ])
    .expect_err("late conflicting overlap must fail");
    let message = error.to_string();
    assert!(
        message.contains("overlap mismatch at height 79"),
        "unexpected paged overlap error: {message}"
    );
}

#[test]
fn select_unique_recovered_publication_bundle_rejects_conflicting_surfaces() {
    let bundle_a = RecoveredPublicationBundle {
        height: 19,
        block_commitment_hash: [0x10; 32],
        parent_block_commitment_hash: [0x11; 32],
        coding: RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicGf256KOfNV1,
            share_count: 7,
            recovery_threshold: 3,
        },
        supporting_witness_manifest_hashes: vec![[0x12; 32], [0x13; 32], [0x14; 32]],
        recoverable_slot_payload_hash: [0x15; 32],
        recoverable_full_surface_hash: [0x16; 32],
        canonical_order_publication_bundle_hash: [0x17; 32],
        canonical_bulletin_close_hash: [0x18; 32],
    };
    let mut bundle_b = bundle_a.clone();
    bundle_b.canonical_bulletin_close_hash = [0x19; 32];

    assert!(
            select_unique_recovered_publication_bundle(vec![bundle_a.clone(), bundle_b]).is_none(),
            "conflicting recovered surfaces should not collapse into a unique validator restart surface"
        );
    assert_eq!(
        select_unique_recovered_publication_bundle(vec![bundle_a.clone(), bundle_a.clone()]),
        Some(bundle_a)
    );
}
