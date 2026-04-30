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

