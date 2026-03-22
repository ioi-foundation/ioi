// Path: crates/validator/src/standard/orchestration/consensus.rs
use super::aft_collapse::require_persisted_aft_canonical_collapse_if_needed;
use crate::metrics::consensus_metrics as metrics;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::ingestion::ChainTipInfo;
use crate::standard::orchestration::mempool::Mempool;
use anyhow::{anyhow, Result};
use ioi_api::chain::StateRef;
use ioi_api::crypto::BatchVerifier;
use ioi_api::{
    chain::AnchoredStateView,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::SerializableKey,
    crypto::SigningKeyPair,
    state::{ProofProvider, StateManager, Verifier},
};

use ioi_crypto::sign::dilithium::MldsaKeyPair;

use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{
        account_id_from_key_material, aft_archived_recovered_history_checkpoint_hash_key,
        aft_archived_recovered_history_profile_activation_hash_key,
        aft_archived_recovered_history_profile_activation_key,
        aft_archived_recovered_history_profile_hash_key,
        aft_archived_recovered_history_retention_receipt_key,
        aft_archived_recovered_history_segment_hash_key, aft_archived_recovered_restart_page_key,
        aft_canonical_collapse_object_key, canonical_archived_recovered_history_checkpoint_hash,
        canonical_archived_recovered_history_profile_activation_hash,
        canonical_archived_recovered_history_retention_receipt_hash,
        canonical_archived_recovered_history_segment_hash,
        canonical_archived_recovered_restart_page_hash, canonical_bulletin_close_hash,
        canonical_collapse_historical_continuation_anchor, canonical_order_publication_bundle_hash,
        canonical_recoverable_slot_payload_v5_hash, canonical_validator_sets_hash,
        canonicalize_transactions_for_header, read_validator_sets,
        recover_full_canonical_order_surface_from_share_materials,
        recovered_canonical_header_entry, recovered_certified_header_prefix,
        recovered_restart_block_header_entry, stitch_recovered_canonical_header_segments,
        stitch_recovered_canonical_header_windows, stitch_recovered_certified_header_segments,
        stitch_recovered_certified_header_windows, stitch_recovered_restart_block_header_segments,
        stitch_recovered_restart_block_header_windows, timestamp_millis_to_legacy_seconds,
        to_root_hash, validate_archived_recovered_history_checkpoint_against_profile,
        validate_archived_recovered_history_profile,
        validate_archived_recovered_history_profile_activation_against_checkpoint,
        validate_archived_recovered_history_profile_activation_checkpoint,
        validate_archived_recovered_history_profile_activation_successor,
        validate_archived_recovered_history_retention_receipt_against_profile,
        validate_archived_recovered_history_segment_against_profile,
        validate_archived_recovered_restart_page_against_profile, validate_recovered_page_coverage,
        AccountId, AftHistoricalContinuationSurface, AftRecoveredStateObservationStats,
        AftRecoveredStateSurface, ArchivedRecoveredHistoryCheckpoint,
        ArchivedRecoveredHistoryProfile, ArchivedRecoveredHistoryProfileActivation,
        ArchivedRecoveredHistoryRetentionReceipt, ArchivedRecoveredHistorySegment,
        ArchivedRecoveredRestartPage, Block, BlockHeader, CanonicalCollapseObject,
        ChainTransaction, ConsensusVote, QuorumCertificate, RecoverableSlotPayloadV5,
        RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry, RecoveredPublicationBundle,
        RecoveredRestartBlockHeaderEntry, RecoveredSegmentFoldCursor, RecoveredSegmentFoldPage,
        RecoveryShareMaterial, SignatureSuite, StateAnchor, StateRoot,
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
    },
    codec,
    config::AftSafetyMode,
    keys::VALIDATOR_SET_KEY,
};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

fn benchmark_trace_enabled() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

pub(crate) const AFT_RECOVERED_CONSENSUS_HEADER_WINDOW: u64 = 5;
pub(crate) const AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP: u64 = 2;
pub(crate) const DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET: u64 = 5;
const MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET: u64 = 8;
pub(crate) const DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET: u64 = 4;
const MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET: u64 = 8;
pub(crate) const DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET: u64 = 2;
const MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveredConsensusTipAnchor {
    height: u64,
    state_root: Vec<u8>,
    block_hash: [u8; 32],
}

mod production;
mod recovery;
#[cfg(test)]
mod tests;

pub use self::production::drive_consensus_tick;
pub(crate) use self::production::{
    recovered_consensus_header_stitch_segment_budget,
    recovered_consensus_header_stitch_window_budget,
};
use self::recovery::*;
