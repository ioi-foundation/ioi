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
//! - **What a certificate check means** ([`certificate_verdict`]): verified; REFUTED against
//!   inputs this node fully holds (the peer is at fault); or CANNOT BE EVALUATED here (an input
//!   other than the certificate, such as the parent state, a member key, or an asynchronous
//!   parent proof, is missing locally). Only a refutation drops a peer.
//! - **Crossing a hash-fallback height** ([`async_reference_binding`], [`async_child_verdict`]):
//!   the child of a virtual block carries the signature-free asynchronous reference as its
//!   parent certificate. A node without the asynchronous parent proof checks that the reference
//!   is the canonical one to the parent it holds, and lets the child's OWN certificate (the
//!   batch's next block's parent certificate, verified) decide.
//! - **Source selection** ([`SyncAuthority`]): a peer whose batch is refuted is dropped (never
//!   targeted again in this sync, by any target assignment: [`SyncAuthority::choose_target`])
//!   and counted, with no change to the status protocol.
//! - **T5, the retry bound** ([`SyncAuthority::record_failure`], [`retry_backoff`]): consecutive
//!   failed batches (refused, unusable, empty while behind, timed out, or no usable target)
//!   without cursor progress from ANY path end the sync SESSION explicitly after
//!   [`SYNC_RETRY_BOUND`], never an unbounded loop and never a node freeze. The retries back off
//!   (250 ms doubling every 4 failures, capped at 8 s), so the bound spans about two minutes
//!   without progress, not a burst.
//! - **T2b, admitted-tier evidence** ([`classify_drained_block`], [`admitted_tier_action`],
//!   [`SyncConflictEvidenceV1`]): a served block at or below the admitted height whose hash
//!   differs from this node's admitted block is a durable-tier conflict only when a verified
//!   certificate (the batch's H+1 parent QC) certifies it: then it halts the node with the
//!   evidence written durably. Refuted or inconsistent, it is rejected and its peer dropped;
//!   uncertified or unevaluable, it is rejected and the sync waits (counted).

use ioi_types::app::{Block, BlockHeader, QuorumCertificate};
use ioi_types::error::ConsensusError;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Consecutive failed sync batches (refused, unusable, empty while behind, timed out, or no
/// usable target) tolerated without progress before the sync session ends explicitly (T5). Any
/// cursor progress, from sync or from live gossip, resets the count.
pub(crate) const SYNC_RETRY_BOUND: u32 = 32;

/// What a certificate check concluded, from this node's side (P7 round 2, M2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CertificateVerdict {
    /// The certificate verified.
    Verified,
    /// This node cannot evaluate it: an input other than the certificate is missing or unreadable
    /// here. Not evidence against the peer: wait and retry (counted), never drop the peer.
    CannotEvaluate(String),
    /// Refuted against inputs this node fully holds: the peer served a bad certificate.
    Refuted(String),
}

/// Classifies an engine's certificate check. `DependencyNotFound` (the engine's "cannot evaluate
/// here", see the AFT engine's `verify_certificate_against_view`) and `StateAccess` (a local
/// state read failed) are local conditions; every other error is a refutation.
pub(crate) fn certificate_verdict(result: Result<(), ConsensusError>) -> CertificateVerdict {
    match result {
        Ok(()) => CertificateVerdict::Verified,
        Err(error @ (ConsensusError::DependencyNotFound(_) | ConsensusError::StateAccess(_))) => {
            CertificateVerdict::CannotEvaluate(error.to_string())
        }
        Err(error) => CertificateVerdict::Refuted(error.to_string()),
    }
}

/// What the replacement-certificate check decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReplacementCheck {
    /// The batch's H+1 certifies the block, and the engine verified that certificate.
    Verified,
    /// Nothing certifies the block yet (the batch ends at it), or the certificate cannot be
    /// evaluated here (its parent state, a key or a proof is missing locally): wait and retry,
    /// counted, without dropping the peer.
    Await(String),
    /// The batch is inconsistent or its certificate is refuted: drop the peer.
    Refuse(String),
}

/// Combines the structural replacement check ([`replacement_certificate`]) with the engine's
/// verdict on the certificate it found (`Ok(verdict)`; the engine is asked only then).
pub(crate) fn replacement_check(
    outcome: Result<CertificateVerdict, ReplacementRefusal>,
) -> ReplacementCheck {
    match outcome {
        Err(ReplacementRefusal::Missing) => {
            ReplacementCheck::Await(ReplacementRefusal::Missing.to_string())
        }
        Err(ReplacementRefusal::Invalid(reason)) => ReplacementCheck::Refuse(reason),
        Ok(verdict) => match verdict {
            CertificateVerdict::Verified => ReplacementCheck::Verified,
            CertificateVerdict::CannotEvaluate(reason) => ReplacementCheck::Await(reason),
            CertificateVerdict::Refuted(reason) => ReplacementCheck::Refuse(reason),
        },
    }
}

/// Whether `certificate` carries no signature material at all: the shape of the canonical
/// asynchronous-parent reference to a hash-fallback virtual block
/// (`aft_async_canonical_parent_reference`), which the AFT engine accepts only with the typed
/// asynchronous parent proof it holds in memory (installed by the live hash-async carrier path).
pub(crate) fn is_signature_free(certificate: &QuorumCertificate) -> bool {
    certificate.signatures.is_empty()
        && certificate.aggregated_signature.is_empty()
        && certificate.signers_bitfield.is_empty()
}

/// Whether a block's signature-free parent reference names this node's own parent block
/// canonically (P7 round 2b, M2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AsyncReferenceBinding {
    /// The reference is exactly the canonical asynchronous reference to the parent block this
    /// node holds at the parent height.
    Bound,
    /// This node does not hold the block the reference names (no block at the parent height, or
    /// another one there): it cannot evaluate the reference.
    NotHeld(String),
    /// The reference names this node's parent block but is not its canonical asynchronous
    /// reference: refuted against inputs this node fully holds.
    Mismatch(String),
}

/// Compares `block`'s signature-free parent reference with the canonical asynchronous reference
/// to `local_parent`, the block this node holds at the parent height. Structural only; the
/// reference carries no authority of its own (see [`async_child_verdict`]).
pub(crate) fn async_reference_binding<T: Clone>(
    block: &Block<T>,
    local_parent: Option<&Block<T>>,
) -> AsyncReferenceBinding {
    let height = block.header.height;
    let Some(parent) = local_parent else {
        return AsyncReferenceBinding::NotHeld(format!(
            "no block at H={} is held here",
            height.saturating_sub(1)
        ));
    };
    let parent_hash = match parent.header.hash() {
        Ok(hash) => hash,
        Err(error) => {
            return AsyncReferenceBinding::NotHeld(format!(
                "the local parent's hash cannot be derived: {error}"
            ))
        }
    };
    if parent.header.height.saturating_add(1) != height
        || parent_hash.as_slice() != block.header.parent_hash.as_slice()
    {
        return AsyncReferenceBinding::NotHeld(format!(
            "the block at H={height} names a parent this node does not hold"
        ));
    }
    match ioi_types::app::aft_async_canonical_parent_reference(&parent.header) {
        Ok(expected) if expected == block.header.parent_qc => AsyncReferenceBinding::Bound,
        Ok(_) => AsyncReferenceBinding::Mismatch(format!(
            "the parent reference of the block at H={height} is not the canonical asynchronous reference to its parent"
        )),
        Err(error) => AsyncReferenceBinding::NotHeld(format!(
            "the canonical reference to the local parent cannot be derived: {error}"
        )),
    }
}

/// G1 for the child of an asynchronous parent whose reference is bound
/// ([`AsyncReferenceBinding::Bound`]) but that this node cannot evaluate (it does not hold the
/// asynchronous parent proof). The child's OWN certificate decides: the batch's next block's
/// parent certificate, structurally bound to the child ([`replacement_certificate`]) and
/// verified by the engine (`Ok(verdict)`). A verified quorum certified the child, whose header
/// binds the reference, and an honest voter accepts a child of an asynchronous parent only with
/// the proof (the AFT engine's `verify_certificate_against_view` and `has_async_parent_proof`).
/// A batch ending at the child waits (counted, peer kept); an inconsistent batch is refuted.
pub(crate) fn async_child_verdict(
    outcome: Result<CertificateVerdict, ReplacementRefusal>,
) -> CertificateVerdict {
    match outcome {
        Err(ReplacementRefusal::Missing) => CertificateVerdict::CannotEvaluate(
            "the batch ends at the child of an asynchronous parent: nothing in it certifies the child yet"
                .into(),
        ),
        Err(ReplacementRefusal::Invalid(reason)) => CertificateVerdict::Refuted(format!(
            "the batch does not certify the child of an asynchronous parent: {reason}"
        )),
        Ok(verdict) => verdict,
    }
}

/// What to do about a served block that differs from this node's block at an admitted height
/// (T2b; P7 round 2, M1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmittedTierAction {
    /// A verified certificate certifies the peer's block: a durable-tier conflict. Halt with the
    /// evidence (Ruling 12: T2b halts on a conflict WITH a certified peer block).
    Halt,
    /// The peer's batch is inconsistent or its certificate refuted: reject the block, drop the
    /// peer (Ruling 12 as amended, (c): an uncertified peer block is REJECTED).
    RefusePeer(String),
    /// Nothing certifies the peer's block yet, or its certificate cannot be evaluated here:
    /// reject the block (never drain it, never halt on it) and retry, counted.
    Await(String),
}

/// T2b's decision from the replacement-certificate check of the conflicting peer block.
pub(crate) fn admitted_tier_action(check: ReplacementCheck) -> AdmittedTierAction {
    match check {
        ReplacementCheck::Verified => AdmittedTierAction::Halt,
        ReplacementCheck::Refuse(reason) => AdmittedTierAction::RefusePeer(reason),
        ReplacementCheck::Await(reason) => AdmittedTierAction::Await(reason),
    }
}

/// The number of leading blocks in a batch that the cursor already covers: every block at a
/// height `<= next`, where `next` is the last height this node applied or holds (context.rs,
/// `SyncProgress::next`). Those are drained (after T2b's hash comparison); the block at
/// `next + 1` is the first one applied. Build Ruling 12 item 4.
pub(crate) fn drained_prefix_len(heights: impl IntoIterator<Item = u64>, next: u64) -> usize {
    heights
        .into_iter()
        .take_while(|height| *height <= next)
        .count()
}

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
    /// Peers whose batches were refuted in this sync: never targeted again.
    pub(crate) refused_peers: BTreeSet<PeerId>,
    /// Consecutive failed batches without cursor progress.
    pub(crate) consecutive_failures: u32,
    /// The highest cursor (`SyncProgress::next`) seen at a failure. A failure at a higher cursor
    /// means the node progressed since (by sync or by live gossip), so the count restarts.
    pub(crate) progress_mark: Option<u64>,
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

    /// Counts one failed batch at cursor `next`; at [`SYNC_RETRY_BOUND`] consecutive failures
    /// without progress, the session must end. A cursor above every earlier failure's is progress
    /// (from any path: an applied sync block, or a live gossip block), and restarts the count.
    pub(crate) fn record_failure(&mut self, next: u64) -> SyncRetry {
        if self.progress_mark.map_or(true, |mark| next > mark) {
            self.progress_mark = Some(next);
            self.consecutive_failures = 0;
        }
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

    /// The peer to target next: the `current` target if it is still usable, else the first
    /// usable candidate. A refused peer, or the peer that just `failed`, is never chosen. Every
    /// target assignment in the sync loop goes through here (P7 round 2, M4).
    pub(crate) fn choose_target(
        &self,
        current: Option<PeerId>,
        failed: Option<PeerId>,
        candidates: impl IntoIterator<Item = PeerId>,
    ) -> Option<PeerId> {
        let usable = |peer: &PeerId| Some(*peer) != failed && self.may_target(peer);
        current
            .filter(usable)
            .or_else(|| candidates.into_iter().find(usable))
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
            assert_eq!(authority.record_failure(7), SyncRetry::Retry);
        }
        // The trunk retried without limit; the bound-th consecutive failure ends the session.
        assert_eq!(authority.record_failure(7), SyncRetry::Exhausted);
        authority.record_progress();
        assert_eq!(authority.record_failure(7), SyncRetry::Retry);
        // The backoff grows to a cap, so the bound spans about two minutes.
        assert_eq!(retry_backoff(0), std::time::Duration::from_millis(250));
        assert_eq!(retry_backoff(4), std::time::Duration::from_millis(500));
        assert_eq!(retry_backoff(31), std::time::Duration::from_secs(8));
        let span: u128 = (0..SYNC_RETRY_BOUND)
            .map(|k| retry_backoff(k).as_millis())
            .sum();
        assert!((100_000..200_000).contains(&span), "{span} ms");
    }

    /// M3 (round 2): progress from ANY path restarts the count. A cursor that advances between
    /// failures (live gossip applying blocks while sync batches come back empty) never exhausts;
    /// a rewound cursor is not progress until it passes the highest mark.
    #[test]
    fn cursor_progress_from_any_path_restarts_the_failure_count() {
        let mut authority = SyncAuthority::default();
        for cursor in 10..(10 + 4 * u64::from(SYNC_RETRY_BOUND)) {
            assert_eq!(authority.record_failure(cursor), SyncRetry::Retry);
            assert_eq!(authority.consecutive_failures, 1);
        }
        let mut authority = SyncAuthority::default();
        assert_eq!(authority.record_failure(20), SyncRetry::Retry);
        // A rewind to 18, then back to 20: neither passes the mark, so both count.
        assert_eq!(authority.record_failure(18), SyncRetry::Retry);
        assert_eq!(authority.record_failure(20), SyncRetry::Retry);
        assert_eq!(authority.consecutive_failures, 3);
        assert_eq!(authority.record_failure(21), SyncRetry::Retry);
        assert_eq!(authority.consecutive_failures, 1);
    }

    /// M4 (round 2): a refused peer is never chosen, whether it is the current target or a
    /// candidate; neither is the peer that just failed.
    #[test]
    fn target_choice_never_picks_a_refused_or_failed_peer() {
        let mut authority = SyncAuthority::default();
        let (liar, failed, honest) = (PeerId::random(), PeerId::random(), PeerId::random());
        authority.refuse_peer(liar);
        assert_eq!(
            authority.choose_target(Some(liar), None, [liar, honest]),
            Some(honest)
        );
        assert_eq!(
            authority.choose_target(Some(failed), Some(failed), [failed, liar, honest]),
            Some(honest)
        );
        assert_eq!(
            authority.choose_target(Some(honest), None, [liar]),
            Some(honest)
        );
        assert_eq!(authority.choose_target(None, None, [liar]), None);
        assert_eq!(authority.choose_target(Some(liar), None, []), None);
    }

    /// M2 (round 2): only a refutation is the peer's fault.
    #[test]
    fn only_a_refutation_counts_against_the_peer() {
        assert_eq!(certificate_verdict(Ok(())), CertificateVerdict::Verified);
        assert!(matches!(
            certificate_verdict(Err(ConsensusError::DependencyNotFound("proof".into()))),
            CertificateVerdict::CannotEvaluate(_)
        ));
        assert!(matches!(
            certificate_verdict(Err(ConsensusError::StateAccess(
                ioi_types::error::StateError::KeyNotFound
            ))),
            CertificateVerdict::CannotEvaluate(_)
        ));
        assert!(matches!(
            certificate_verdict(Err(ConsensusError::BlockVerificationFailed("bad".into()))),
            CertificateVerdict::Refuted(_)
        ));
        // The replacement check: a structural failure, else the verdict.
        assert!(matches!(
            replacement_check(Err(ReplacementRefusal::Missing)),
            ReplacementCheck::Await(_)
        ));
        assert!(matches!(
            replacement_check(Err(ReplacementRefusal::Invalid("gap".into()))),
            ReplacementCheck::Refuse(_)
        ));
        assert_eq!(
            replacement_check(Ok(CertificateVerdict::Verified)),
            ReplacementCheck::Verified
        );
        assert!(matches!(
            replacement_check(Ok(CertificateVerdict::CannotEvaluate("x".into()))),
            ReplacementCheck::Await(_)
        ));
        assert!(matches!(
            replacement_check(Ok(CertificateVerdict::Refuted("x".into()))),
            ReplacementCheck::Refuse(_)
        ));
    }

    /// M2 (round 2b): the asynchronous reference binds only canonically to the parent this node
    /// holds, and the child's own certificate decides.
    #[test]
    fn an_asynchronous_reference_binds_only_canonically_and_its_child_needs_its_own_certificate() {
        let mut signed = qc(10, [1u8; 32]);
        signed.signatures = vec![(AccountId([9u8; 32]), vec![1u8; 64])];
        let parent = block(header(11, [1u8; 32], signed.clone()));
        assert!(!is_signature_free(&parent.header.parent_qc));
        let parent_hash = hash32(&parent.header);
        let reference =
            ioi_types::app::aft_async_canonical_parent_reference(&parent.header).unwrap();
        assert!(is_signature_free(&reference));
        let child = block(header(12, parent_hash, reference));
        assert_eq!(
            async_reference_binding(&child, Some(&parent)),
            AsyncReferenceBinding::Bound
        );
        assert!(matches!(
            async_reference_binding(&child, None),
            AsyncReferenceBinding::NotHeld(_)
        ));
        let other_parent = block(header(11, [2u8; 32], signed));
        assert!(matches!(
            async_reference_binding(&child, Some(&other_parent)),
            AsyncReferenceBinding::NotHeld(_)
        ));
        let mut forged = child.clone();
        forged.header.parent_qc.view += 1;
        assert!(matches!(
            async_reference_binding(&forged, Some(&parent)),
            AsyncReferenceBinding::Mismatch(_)
        ));
        assert!(matches!(
            async_child_verdict(Err(ReplacementRefusal::Missing)),
            CertificateVerdict::CannotEvaluate(_)
        ));
        assert!(matches!(
            async_child_verdict(Err(ReplacementRefusal::Invalid("gap".into()))),
            CertificateVerdict::Refuted(_)
        ));
        for verdict in [
            CertificateVerdict::Verified,
            CertificateVerdict::CannotEvaluate("x".into()),
            CertificateVerdict::Refuted("x".into()),
        ] {
            assert_eq!(async_child_verdict(Ok(verdict.clone())), verdict);
        }
    }

    /// M1 (round 2): T2b halts only on a verified certificate for the peer's block.
    #[test]
    fn an_admitted_tier_conflict_halts_only_when_certified() {
        assert_eq!(
            admitted_tier_action(ReplacementCheck::Verified),
            AdmittedTierAction::Halt
        );
        assert!(matches!(
            admitted_tier_action(ReplacementCheck::Refuse("x".into())),
            AdmittedTierAction::RefusePeer(_)
        ));
        assert!(matches!(
            admitted_tier_action(ReplacementCheck::Await("x".into())),
            AdmittedTierAction::Await(_)
        ));
    }

    /// m4 (round 2), Ruling 12 item 4: `next` is the last height applied or held, so the block
    /// AT `next` is drained and the block at `next + 1` is the first applied.
    #[test]
    fn the_drained_prefix_ends_at_next_inclusive() {
        assert_eq!(drained_prefix_len([8, 9, 10, 11, 12], 10), 3);
        assert_eq!(drained_prefix_len([10, 11], 10), 1);
        assert_eq!(drained_prefix_len([11, 12], 10), 0);
        assert_eq!(drained_prefix_len([9, 10], 10), 2);
        assert_eq!(drained_prefix_len([], 10), 0);
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
