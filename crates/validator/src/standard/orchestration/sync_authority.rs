// Path: crates/validator/src/standard/orchestration/sync_authority.rs
//! What sync may do on a peer's word (P7, build Ruling 12; the approved sync scope).
//!
//! At the trunk an HONEST peer advertises its Agentgres-admitted height and serves only admitted
//! blocks, so sync already follows certified history for honest peers. The residual is
//! AUTHENTICATION: the advertised height and the served blocks were trusted as given. These
//! decisions close it, each as a pure function the sync loop calls:
//!
//! - **G1, the parent certificate** (the loop asks the engine): every synced block's own
//!   `parent_qc` must verify against the membership in its parent state before the block is
//!   applied or used to reconcile anything.
//! - **G1, the replacement certificate** ([`replacement_certificate`]): a block that REPLACES a
//!   local tentative block at height H must itself be certified, by the batch's block H+1
//!   naming it (`parent_hash` and `parent_qc` both bind H's hash, at height H); the engine then
//!   verifies that certificate. Without it the trunk replaced local state on an uncertified
//!   block's word.
//! - **Source selection** ([`SyncAuthority`]): a peer whose batch fails either check is dropped
//!   (never targeted again in this sync) and counted, with no change to the status protocol.
//! - **T5, the retry bound** ([`SyncAuthority::record_failure`], [`retry_backoff`]): consecutive
//!   failed batches without progress end in an explicit halt after [`SYNC_RETRY_BOUND`], never an
//!   unbounded loop. The retries back off (250 ms doubling every 4 failures, capped at 8 s), so the
//!   bound spans about two minutes without progress, not a burst.
//! - **T2b, admitted-tier evidence** ([`classify_drained_block`], [`SyncConflictEvidenceV1`]): a
//!   served block at or below the admitted height whose hash differs from this node's admitted
//!   block is a durable-tier conflict. It halts the node with the evidence written durably,
//!   instead of being drained silently by height.

use ioi_types::app::{Block, BlockHeader, QuorumCertificate};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Consecutive failed sync batches (refused, unusable, or empty while behind) tolerated without
/// progress before the node halts sync explicitly (T5). Any applied block resets the count.
pub(crate) const SYNC_RETRY_BOUND: u32 = 32;

/// Why no replacement certificate is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReplacementRefusal {
    /// The batch ends at the replacement block. An honest peer serves only admitted blocks, so
    /// its admitted tip arrives without its certifying child until the peer admits the next
    /// height: wait and retry (counted), never drop the peer for it.
    Missing,
    /// The batch carries H+1 but it does not certify H: the batch is inconsistent. Drop the peer.
    Invalid(String),
}

impl std::fmt::Display for ReplacementRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplacementRefusal::Missing => write!(
                f,
                "the batch ends at the replacement block, so nothing certifies it yet; a replacement needs H+1 in the same batch"
            ),
            ReplacementRefusal::Invalid(reason) => f.write_str(reason),
        }
    }
}

/// The certificate that authorizes replacing local state at `block`'s height with `block`: the
/// `parent_qc` of the batch's next block, which must sit at height H+1 and bind H's exact hash
/// in both `parent_hash` and its certificate. Structural only; the engine verifies the signatures.
pub(crate) fn replacement_certificate<'a, T>(
    block: &Block<T>,
    next_in_batch: Option<&'a Block<T>>,
) -> Result<&'a QuorumCertificate, ReplacementRefusal>
where
    T: Clone,
{
    let height = block.header.height;
    let hash = block.header.hash().map_err(|error| {
        ReplacementRefusal::Invalid(format!(
            "the replacement block's hash cannot be derived: {error}"
        ))
    })?;
    let next = next_in_batch.ok_or(ReplacementRefusal::Missing)?;
    if next.header.height != height.saturating_add(1) {
        return Err(ReplacementRefusal::Invalid(format!(
            "the block after H={height} in the batch is at H={}, not H+1",
            next.header.height
        )));
    }
    if next.header.parent_hash.as_slice() != hash.as_slice() {
        return Err(ReplacementRefusal::Invalid(format!(
            "the H+1 block's parent_hash does not name the replacement block at H={height}"
        )));
    }
    let certificate = &next.header.parent_qc;
    if certificate.height != height || certificate.block_hash.as_slice() != hash.as_slice() {
        return Err(ReplacementRefusal::Invalid(format!(
            "the H+1 block's parent certificate (H={}) does not certify the replacement block at H={height}",
            certificate.height
        )));
    }
    Ok(certificate)
}

/// The wait before the next retry after `consecutive_failures` failed batches: 250 ms, doubling
/// every 4 failures, capped at 8 s (T5: the bound spans minutes, not a burst).
pub(crate) fn retry_backoff(consecutive_failures: u32) -> std::time::Duration {
    let doublings = (consecutive_failures / 4).min(5);
    std::time::Duration::from_millis(250u64 << doublings)
}

/// What one sync session has learned about its peers (source selection and T5).
#[derive(Debug, Clone, Default)]
pub(crate) struct SyncAuthority {
    /// Peers whose batches failed certificate verification in this sync: never targeted again.
    pub(crate) refused_peers: BTreeSet<PeerId>,
    /// Consecutive failed batches without an applied block.
    pub(crate) consecutive_failures: u32,
}

/// The outcome of recording one failed batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncRetry {
    /// Retry from another peer.
    Retry,
    /// The bound is exhausted: halt sync explicitly.
    Exhausted,
}

impl SyncAuthority {
    /// Drops `peer` from this sync: its batch failed certificate verification.
    pub(crate) fn refuse_peer(&mut self, peer: PeerId) {
        self.refused_peers.insert(peer);
    }

    /// Whether `peer` may be a sync target.
    pub(crate) fn may_target(&self, peer: &PeerId) -> bool {
        !self.refused_peers.contains(peer)
    }

    /// Counts one failed batch; at [`SYNC_RETRY_BOUND`] consecutive failures, sync must halt.
    pub(crate) fn record_failure(&mut self) -> SyncRetry {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= SYNC_RETRY_BOUND {
            SyncRetry::Exhausted
        } else {
            SyncRetry::Retry
        }
    }

    /// An applied block is progress: the failure count restarts.
    pub(crate) fn record_progress(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// What a served block at or below the cursor means, before it is drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainedBlock {
    /// Already held here (the same hash), or above the admitted tier: drain it as before.
    Drain,
    /// At or below the admitted height with a different hash than this node's admitted block:
    /// a durable-tier conflict (T2b). Halt with evidence; never drain it silently.
    AdmittedTierConflict,
}

/// Classifies a served block at `height` that the cursor already covers. `local_hash` is this
/// node's block at that height, if it holds one.
pub(crate) fn classify_drained_block(
    height: u64,
    admitted_height: u64,
    local_hash: Option<&[u8]>,
    peer_hash: &[u8],
) -> DrainedBlock {
    match local_hash {
        Some(local) if height <= admitted_height && local != peer_hash => {
            DrainedBlock::AdmittedTierConflict
        }
        _ => DrainedBlock::Drain,
    }
}

/// The evidence a durable-tier sync conflict leaves behind (T2b): both blocks' headers, the
/// certificate the peer's batch carried for its block (if any, and whether it verified), and
/// where it came from. The local block's own admission certificate stays recoverable from
/// Agentgres by `height` and `local_block_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SyncConflictEvidenceV1 {
    /// `ioi.aft.sync-conflict-evidence.v1`.
    pub(crate) schema: String,
    /// The conflicting height.
    pub(crate) height: u64,
    /// This node's Agentgres-admitted height when the conflict was seen.
    pub(crate) admitted_height: u64,
    /// This node's block at that height.
    pub(crate) local_header: BlockHeader,
    /// Its hash, hex.
    pub(crate) local_block_hash: String,
    /// The peer's block at that height.
    pub(crate) peer_header: BlockHeader,
    /// Its hash, hex.
    pub(crate) peer_block_hash: String,
    /// The certificate the peer's batch carried for its block (the next block's parent QC).
    pub(crate) peer_certificate: Option<QuorumCertificate>,
    /// Whether that certificate verified against the membership in this node's state.
    pub(crate) peer_certificate_verified: bool,
    /// The serving peer.
    pub(crate) peer: String,
    /// Wall-clock milliseconds when it was recorded.
    pub(crate) observed_at_ms: u64,
}

/// The schema name of [`SyncConflictEvidenceV1`].
pub(crate) const SYNC_CONFLICT_EVIDENCE_SCHEMA: &str = "ioi.aft.sync-conflict-evidence.v1";

/// Writes `evidence` under `root/sync-conflict-evidence/` durably (a temporary file, fsync,
/// rename, directory fsync) and returns its path. An existing record is never overwritten.
pub(crate) fn write_sync_conflict_evidence(
    root: &Path,
    evidence: &SyncConflictEvidenceV1,
) -> std::io::Result<PathBuf> {
    let dir = root.join("sync-conflict-evidence");
    std::fs::create_dir_all(&dir)?;
    let name = format!(
        "{}-{}-{}.json",
        evidence.height,
        &evidence.peer_block_hash[..evidence.peer_block_hash.len().min(16)],
        evidence.observed_at_ms
    );
    let path = dir.join(name);
    if path.exists() {
        return Ok(path);
    }
    let bytes = serde_json::to_vec_pretty(evidence)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let staged = dir.join(format!(".{}.tmp", std::process::id()));
    {
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&staged, &path)?;
    std::fs::File::open(&dir)?.sync_all()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{AccountId, ChainTransaction, SignatureSuite, StateRoot};

    fn header(height: u64, parent_hash: [u8; 32], parent_qc: QuorumCertificate) -> BlockHeader {
        BlockHeader {
            height,
            view: 0,
            parent_hash,
            parent_state_root: StateRoot(vec![height as u8; 32]),
            state_root: StateRoot(vec![height as u8 + 1; 32]),
            transactions_root: vec![height as u8 + 2; 32],
            timestamp: height,
            timestamp_ms: height * 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([3u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [4u8; 32],
            producer_pubkey: vec![5u8; 32],
            oracle_counter: height,
            oracle_trace_hash: [6u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            parent_qc,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            signature: vec![7u8; 64],
        }
    }

    fn block(header: BlockHeader) -> Block<ChainTransaction> {
        Block {
            header,
            transactions: Vec::new(),
        }
    }

    fn hash32(header: &BlockHeader) -> [u8; 32] {
        header.hash().unwrap().try_into().unwrap()
    }

    fn qc(height: u64, block_hash: [u8; 32]) -> QuorumCertificate {
        QuorumCertificate {
            height,
            view: 0,
            block_hash,
            signatures: Vec::new(),
            aggregated_signature: Vec::new(),
            signers_bitfield: Vec::new(),
        }
    }

    /// The trunk replaced local state with a peer block on no certificate at all; now the
    /// replacement needs the batch's H+1 binding H's exact hash.
    #[test]
    fn a_replacement_needs_the_next_block_certifying_it() {
        let replacement = block(header(11, [1u8; 32], qc(10, [1u8; 32])));
        let replacement_hash = hash32(&replacement.header);
        let child = block(header(12, replacement_hash, qc(11, replacement_hash)));
        assert_eq!(
            replacement_certificate(&replacement, Some(&child)).unwrap(),
            &qc(11, replacement_hash)
        );
        // The batch ends at the replacement: nothing certifies it yet (not the peer's fault).
        assert_eq!(
            replacement_certificate(&replacement, None).unwrap_err(),
            ReplacementRefusal::Missing
        );
        // A gap in the batch.
        let gapped = block(header(13, replacement_hash, qc(11, replacement_hash)));
        assert!(matches!(
            replacement_certificate(&replacement, Some(&gapped)),
            Err(ReplacementRefusal::Invalid(_))
        ));
        // A child of ANOTHER block at H.
        let elsewhere = block(header(12, [9u8; 32], qc(11, [9u8; 32])));
        assert!(matches!(
            replacement_certificate(&replacement, Some(&elsewhere)),
            Err(ReplacementRefusal::Invalid(_))
        ));
        // A child naming the block by parent_hash whose certificate certifies another block.
        let wrong_qc = block(header(12, replacement_hash, qc(11, [9u8; 32])));
        assert!(matches!(
            replacement_certificate(&replacement, Some(&wrong_qc)).unwrap_err(),
            ReplacementRefusal::Invalid(reason) if reason.contains("does not certify")
        ));
        // A child whose certificate names the block but whose parent_hash names another: not a
        // child of the replacement (the engine refuses such a proposal), so it certifies nothing.
        let foster = block(header(12, [9u8; 32], qc(11, replacement_hash)));
        assert!(matches!(
            replacement_certificate(&replacement, Some(&foster)).unwrap_err(),
            ReplacementRefusal::Invalid(reason) if reason.contains("parent_hash")
        ));
        // A certificate at the wrong height.
        let wrong_height = block(header(12, replacement_hash, qc(10, replacement_hash)));
        assert!(matches!(
            replacement_certificate(&replacement, Some(&wrong_height)),
            Err(ReplacementRefusal::Invalid(_))
        ));
    }

    #[test]
    fn a_refused_peer_is_dropped_and_failures_are_bounded() {
        let mut authority = SyncAuthority::default();
        let liar = PeerId::random();
        let honest = PeerId::random();
        authority.refuse_peer(liar);
        assert!(!authority.may_target(&liar));
        assert!(authority.may_target(&honest));
        for _ in 1..SYNC_RETRY_BOUND {
            assert_eq!(authority.record_failure(), SyncRetry::Retry);
        }
        // The trunk retried without limit; the bound-th consecutive failure halts.
        assert_eq!(authority.record_failure(), SyncRetry::Exhausted);
        authority.record_progress();
        assert_eq!(authority.record_failure(), SyncRetry::Retry);
        // The backoff grows to a cap, so the bound spans about two minutes.
        assert_eq!(retry_backoff(0), std::time::Duration::from_millis(250));
        assert_eq!(retry_backoff(4), std::time::Duration::from_millis(500));
        assert_eq!(retry_backoff(31), std::time::Duration::from_secs(8));
        let span: u128 = (0..SYNC_RETRY_BOUND)
            .map(|k| retry_backoff(k).as_millis())
            .sum();
        assert!((100_000..200_000).contains(&span), "{span} ms");
    }

    /// The trunk drained every served block at or below the cursor by height alone; an admitted
    /// block with another hash is now a durable-tier conflict.
    #[test]
    fn an_admitted_height_with_another_hash_is_a_conflict_not_a_drain() {
        let ours = [1u8; 32];
        let theirs = [2u8; 32];
        assert_eq!(
            classify_drained_block(10, 10, Some(&ours), &theirs),
            DrainedBlock::AdmittedTierConflict
        );
        assert_eq!(
            classify_drained_block(9, 10, Some(&ours), &theirs),
            DrainedBlock::AdmittedTierConflict
        );
        // The same block, a height above the admitted tier, or no local block to compare.
        assert_eq!(
            classify_drained_block(10, 10, Some(&ours), &ours),
            DrainedBlock::Drain
        );
        assert_eq!(
            classify_drained_block(11, 10, Some(&ours), &theirs),
            DrainedBlock::Drain
        );
        assert_eq!(
            classify_drained_block(10, 10, None, &theirs),
            DrainedBlock::Drain
        );
    }

    #[test]
    fn conflict_evidence_is_written_durably_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let local = header(10, [1u8; 32], qc(9, [1u8; 32]));
        let peer = header(10, [1u8; 32], qc(9, [2u8; 32]));
        let evidence = SyncConflictEvidenceV1 {
            schema: SYNC_CONFLICT_EVIDENCE_SCHEMA.into(),
            height: 10,
            admitted_height: 10,
            local_block_hash: hex::encode(hash32(&local)),
            local_header: local,
            peer_block_hash: hex::encode(hash32(&peer)),
            peer_header: peer,
            peer_certificate: Some(qc(10, [2u8; 32])),
            peer_certificate_verified: true,
            peer: PeerId::random().to_string(),
            observed_at_ms: 1_700_000_000_000,
        };
        let path = write_sync_conflict_evidence(dir.path(), &evidence).unwrap();
        let read: SyncConflictEvidenceV1 =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(read, evidence);
        // A second write of the same record keeps the first.
        std::fs::write(&path, b"first").unwrap();
        assert_eq!(
            write_sync_conflict_evidence(dir.path(), &evidence).unwrap(),
            path
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }
}
