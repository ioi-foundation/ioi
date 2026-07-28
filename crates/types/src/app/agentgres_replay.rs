//! M2 agentgres replay/recovery seam: operation-log suffix admission bound to
//! the writer-fence plane's durable truth, lost-suffix candidate derivation
//! from replica head/watermark truth, and recovery-side production of the
//! registered lost-suffix custody record.
//!
//! Layering: the `agentgres` crate is deliberately dependency-minimal (its
//! mux/replica engine knows offsets, epochs, and bytes — never contracts), so
//! the admission seam lives here as the thin adapter the daemon wires between
//! `MuxEngine` replay truth and the M2 plane families. Every admission input
//! is resolved from durable server truth, never asserted by a caller
//! (INV-37): the applied watermark, the active writer-epoch transition, the
//! open lost-suffix custody rows, and the restore bindings all arrive as
//! server-resolved records of already-registered families.
//!
//! The falsifiable claim this seam refuses on, dimension by dimension:
//! a lost suffix never silently replays (`lost_suffix`), an applied suffix
//! never duplicates (`duplicate_suffix`), a stale or unadmitted writer never
//! replays (`stale_writer`/`unadmitted_epoch`/`fence_refused`), a
//! wrong-System projection target never accepts a foreign System's suffix
//! (`wrong_system`), a restore whose manifest commitment departs the restored
//! source state root never applies (`restore_mismatch`), and a gap between
//! the watermark and the suffix never silently drops entries (`suffix_gap`).
//! Incomplete or invalid durable sources fail closed (`source_incomplete`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::hypervisor_environment_lifecycle::{
    backup_manifest_root, CHANGE_PLAN_CONTRACT, ENVIRONMENT_BACKUP_CONTRACT,
};
use super::system_activation::namespace;
use super::system_writer_fence::{
    lost_suffix_record_root, FenceVerdict, PriorWriterLogObservation,
    SuffixAcknowledgementCertainty, WriterFenceHead, LOST_SUFFIX_CONTRACT,
};

/// Named refusal dimensions of the replay-admission claim. Every refusal
/// names exactly one dimension; an admitted suffix replays exactly once.
pub const REPLAY_REFUSAL_DIMENSIONS: [&str; 9] = [
    "wrong_system",
    "stale_writer",
    "unadmitted_epoch",
    "fence_refused",
    "duplicate_suffix",
    "suffix_gap",
    "lost_suffix",
    "restore_mismatch",
    "source_incomplete",
];

/// Custody-row bound mirrored from the writer-fence plane's lost-suffix
/// builder: an excluded suffix beyond this never compiles a custody record.
pub const LOST_SUFFIX_CUSTODY_ROW_BOUND: u64 = 256;

/// One operation of a presented replay suffix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySuffixEntry {
    /// Exact operation-log offset.
    pub operation_offset: u64,
    /// Per-operation content commitment ref.
    pub operation_commitment_ref: String,
}

/// One contiguous operation-log suffix presented for replay. The System
/// binding and writer epoch are resolved by the server from the log's durable
/// identity, never asserted by a transport caller (INV-37).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySuffix {
    /// The System whose operation log this suffix belongs to.
    pub system_id: String,
    /// The writer epoch the suffix was admitted under.
    pub writer_epoch: u64,
    /// First operation offset of the suffix (inclusive).
    pub first_offset: u64,
    /// Last operation offset of the suffix (inclusive).
    pub last_offset: u64,
    /// Exactly one row per offset in `first_offset..=last_offset`.
    pub entries: Vec<ReplaySuffixEntry>,
}

/// Durable truth of the projection target a suffix would replay into. Every
/// field is server-resolved from committed plane records.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayTargetTruth<'a> {
    /// The projection target's System binding.
    pub target_system_id: &'a str,
    /// Writer-fence head replayed from committed transitions only.
    pub fence_head: &'a WriterFenceHead,
    /// Highest operation offset already applied to the target (the
    /// idempotence watermark; zero before the first application).
    pub applied_watermark: u64,
    /// Durable lost-suffix custody record revisions for this System.
    pub lost_suffix_records: &'a [Value],
}

/// Restore-flow binding: the staged change plan, its durable source backup,
/// and the source state root actually observed on the restored bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreBinding<'a> {
    /// The declared immutable restore/activation plan.
    pub change_plan: &'a Value,
    /// The durable manifest-complete source backup the plan cites.
    pub source_backup: &'a Value,
    /// The source state root resolved from the restored state, never from
    /// the request.
    pub restored_source_state_root_ref: &'a str,
}

/// The total replay-admission verdict: admit replays the exact suffix once;
/// every refusal names exactly one dimension and replays nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayVerdict {
    /// Whether the exact suffix may replay.
    pub admitted: bool,
    /// Named refusal dimension, absent only on admit.
    pub refusal_dimension: Option<&'static str>,
    /// Human-readable refusal reason, absent only on admit.
    pub refusal_reason: Option<String>,
    /// The exact admitted offset range, absent on refusal.
    pub admitted_range: Option<(u64, u64)>,
    /// The watermark after applying the admitted range, absent on refusal.
    pub resulting_watermark: Option<u64>,
}

impl ReplayVerdict {
    fn refuse(dimension: &'static str, reason: impl Into<String>) -> Self {
        debug_assert!(REPLAY_REFUSAL_DIMENSIONS.contains(&dimension));
        Self {
            admitted: false,
            refusal_dimension: Some(dimension),
            refusal_reason: Some(reason.into()),
            admitted_range: None,
            resulting_watermark: None,
        }
    }

    fn admit(first: u64, last: u64) -> Self {
        Self {
            admitted: true,
            refusal_dimension: None,
            refusal_reason: None,
            admitted_range: Some((first, last)),
            resulting_watermark: Some(last),
        }
    }
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn opt_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Admit or refuse one operation-log suffix for replay into one projection
/// target. This is a TOTAL function: every input produces a verdict, never a
/// panic and never an error. An admitted suffix replays exactly once — the
/// caller advances the durable watermark to `resulting_watermark`, after
/// which the same suffix refuses as `duplicate_suffix` (idempotence).
pub fn admit_replay_suffix(
    truth: &ReplayTargetTruth<'_>,
    suffix: &ReplaySuffix,
    fence_verdict: &FenceVerdict,
    restore: Option<&RestoreBinding<'_>>,
) -> ReplayVerdict {
    // Structural coverage: the declared rows must cover exactly the declared
    // contiguous range; a mis-declared suffix could silently drop an entry.
    if suffix.first_offset == 0 || suffix.first_offset > suffix.last_offset {
        return ReplayVerdict::refuse(
            "suffix_gap",
            "the declared suffix range is not a non-empty forward range of admitted offsets",
        );
    }
    let mut offsets: Vec<u64> = suffix
        .entries
        .iter()
        .map(|entry| entry.operation_offset)
        .collect();
    offsets.sort_unstable();
    let expected: Vec<u64> = (suffix.first_offset..=suffix.last_offset).collect();
    if offsets != expected {
        return ReplayVerdict::refuse(
            "suffix_gap",
            "the suffix rows do not cover exactly the declared offset range; a partial \
             declaration could silently drop an entry",
        );
    }

    // Dimension — wrong_system: a projection target never accepts a foreign
    // System's operations.
    if suffix.system_id != truth.target_system_id {
        return ReplayVerdict::refuse(
            "wrong_system",
            format!(
                "the suffix belongs to '{}' but the projection target is bound to '{}'",
                suffix.system_id, truth.target_system_id
            ),
        );
    }

    // Dimensions — stale_writer / unadmitted_epoch: the suffix's writer epoch
    // must BE the active writer-epoch record's epoch.
    if truth.fence_head.active_transition.is_none() || truth.fence_head.active_epoch == 0 {
        return ReplayVerdict::refuse(
            "unadmitted_epoch",
            "no admitted writer epoch is active; nothing replays before genesis",
        );
    }
    if suffix.writer_epoch < truth.fence_head.active_epoch {
        return ReplayVerdict::refuse(
            "stale_writer",
            format!(
                "stale writer epoch {}: the fence truth has admitted the higher epoch {} and \
                 the consequential-effect fence refuses stale epochs",
                suffix.writer_epoch, truth.fence_head.active_epoch
            ),
        );
    }
    if suffix.writer_epoch > truth.fence_head.active_epoch {
        return ReplayVerdict::refuse(
            "unadmitted_epoch",
            format!(
                "writer epoch {} has not been admitted by durable fence truth",
                suffix.writer_epoch
            ),
        );
    }

    // Dimension — fence_refused: the plane's total fence verdict must admit
    // with exactly one selected final invoker.
    if !fence_verdict.admitted || fence_verdict.selected_final_invokers != 1 {
        return ReplayVerdict::refuse(
            "fence_refused",
            format!(
                "the consequential-effect fence refuses this replay ({}: {})",
                fence_verdict.refusal_dimension.unwrap_or("unnamed"),
                fence_verdict
                    .refusal_reason
                    .as_deref()
                    .unwrap_or("no reason recorded"),
            ),
        );
    }

    // Dimensions — duplicate_suffix / suffix_gap: the suffix must begin at
    // exactly the applied watermark plus one. At or below the watermark it is
    // already applied (replay is idempotent, never duplicating); beyond
    // watermark plus one it would silently skip entries.
    if suffix.first_offset <= truth.applied_watermark {
        return ReplayVerdict::refuse(
            "duplicate_suffix",
            format!(
                "offsets at or below the applied watermark {} are already applied; replay is \
                 idempotent and never duplicates",
                truth.applied_watermark
            ),
        );
    }
    if suffix.first_offset != truth.applied_watermark + 1 {
        return ReplayVerdict::refuse(
            "suffix_gap",
            format!(
                "the suffix begins at {} but the applied watermark is {}; the gap would \
                 silently drop entries",
                suffix.first_offset, truth.applied_watermark
            ),
        );
    }

    // Dimension — lost_suffix: an offset retained by a lost-suffix custody
    // record replays only through an explicit `resolved` disposition; a
    // `retained_ambiguous` row excludes it until custody resolves and a
    // `refused` row excludes it permanently.
    for record in truth.lost_suffix_records {
        if validate_architecture_contract(LOST_SUFFIX_CONTRACT, record).is_err() {
            return ReplayVerdict::refuse(
                "source_incomplete",
                "a durable lost-suffix record fails its registered contract; incomplete \
                 custody truth fails closed",
            );
        }
        if opt_str(record, "/system_id") != Some(truth.target_system_id) {
            continue;
        }
        let empty = Vec::new();
        let rows = record
            .pointer("/excluded_suffix/entries")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for row in rows {
            let Some(offset) = row.get("operation_offset").and_then(Value::as_u64) else {
                continue;
            };
            if offset < suffix.first_offset || offset > suffix.last_offset {
                continue;
            }
            match row.get("custody_status").and_then(Value::as_str) {
                Some("resolved") => {}
                Some("refused") => {
                    return ReplayVerdict::refuse(
                        "lost_suffix",
                        format!(
                            "offset {offset} carries an explicit refused custody disposition \
                             and never replays"
                        ),
                    );
                }
                _ => {
                    return ReplayVerdict::refuse(
                        "lost_suffix",
                        format!(
                            "offset {offset} is retained ambiguous by an open lost-suffix \
                             record; it is excluded until its custody row resolves"
                        ),
                    );
                }
            }
        }
    }

    // Dimension — restore_mismatch: for restore flows, the change plan's
    // manifest commitment must bind the durable backup and the backup's
    // source state root must match the root observed on the restored state.
    if let Some(binding) = restore {
        if validate_architecture_contract(CHANGE_PLAN_CONTRACT, binding.change_plan).is_err() {
            return ReplayVerdict::refuse(
                "source_incomplete",
                "the bound change plan fails its registered contract; incomplete restore \
                 truth fails closed",
            );
        }
        if validate_architecture_contract(ENVIRONMENT_BACKUP_CONTRACT, binding.source_backup)
            .is_err()
        {
            return ReplayVerdict::refuse(
                "source_incomplete",
                "the bound source backup fails its registered contract; incomplete restore \
                 truth fails closed",
            );
        }
        if opt_str(binding.change_plan, "/plan_type") != Some("environment_restore") {
            return ReplayVerdict::refuse(
                "restore_mismatch",
                "the bound change plan is not a restore plan",
            );
        }
        let backup_ref = opt_str(binding.source_backup, "/backup_ref").unwrap_or("");
        if opt_str(binding.change_plan, "/restore/source_backup_ref") != Some(backup_ref) {
            return ReplayVerdict::refuse(
                "restore_mismatch",
                "the change plan cites a different source backup than the durable backup \
                 presented",
            );
        }
        let recomputed = match backup_manifest_root(binding.source_backup) {
            Ok(root) => root,
            Err(_) => {
                return ReplayVerdict::refuse(
                    "source_incomplete",
                    "the backup manifest commitment is not recomputable from durable truth",
                )
            }
        };
        if opt_str(binding.source_backup, "/manifest_root") != Some(recomputed.as_str()) {
            return ReplayVerdict::refuse(
                "restore_mismatch",
                "the durable backup's manifest commitment does not recompute; substituted \
                 manifest rows never restore",
            );
        }
        if opt_str(binding.change_plan, "/restore/restore_manifest_root")
            != Some(recomputed.as_str())
        {
            return ReplayVerdict::refuse(
                "restore_mismatch",
                "the change plan's manifest commitment departs the durable backup manifest",
            );
        }
        let backup_source_root = opt_str(binding.source_backup, "/source_state_root_ref");
        if opt_str(
            binding.change_plan,
            "/restore/source_root_and_head_expectations/source_state_root_ref",
        ) != backup_source_root
        {
            return ReplayVerdict::refuse(
                "restore_mismatch",
                "the change plan's expected source state root departs the durable backup",
            );
        }
        if backup_source_root != Some(binding.restored_source_state_root_ref) {
            return ReplayVerdict::refuse(
                "restore_mismatch",
                "the restored source state root does not match the manifest-committed \
                 backup source; a restore mismatch never applies",
            );
        }
    }

    ReplayVerdict::admit(suffix.first_offset, suffix.last_offset)
}

/// Replica-side continuity truth resolved from the successor's durable log
/// (the authoritative history head), the last operation offset common to
/// both histories (the replica watermark at divergence), and the deposed
/// epoch's acknowledged range. These are engine facts (`MuxEngine`/replica
/// watermarks), resolved by the daemon, never asserted by a caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaContinuityTruth {
    /// Last operation offset common to both histories (watermark truth).
    pub last_common_offset: u64,
    /// State root at the last common offset.
    pub last_common_state_root: String,
    /// Authoritative head offset of the successor history.
    pub authoritative_head_offset: u64,
    /// State root at the authoritative head.
    pub authoritative_head_state_root: String,
    /// Highest offset the deposed epoch acknowledged.
    pub deposed_acknowledged_offset: u64,
}

/// Derive the lost-suffix candidate observation on a writer change: the
/// candidate range is exactly `last common + 1 ..= deposed acknowledged`.
/// `None` means the deposed writer acknowledged nothing beyond the common
/// history — there is no lost suffix. The custody rows must cover exactly
/// the candidate range; partial coverage refuses rather than silently
/// dropping an excluded operation.
pub fn derive_prior_writer_log_observation(
    truth: &ReplicaContinuityTruth,
    entry_commitment_refs: &[(u64, String)],
    custody_artifact_refs: &[String],
    acknowledgement_certainty: SuffixAcknowledgementCertainty,
    reconciliation_policy_ref: &str,
) -> Result<Option<PriorWriterLogObservation>, String> {
    if !canonical_hash(&truth.last_common_state_root)
        || !canonical_hash(&truth.authoritative_head_state_root)
    {
        return Err("a continuity state root is not canonical".to_owned());
    }
    if truth.authoritative_head_offset < truth.last_common_offset {
        return Err("the authoritative head never regresses below the common history".to_owned());
    }
    if !reconciliation_policy_ref.starts_with("policy://")
        || reconciliation_policy_ref.chars().any(char::is_whitespace)
    {
        return Err("the reconciliation policy ref is not canonical".to_owned());
    }
    if truth.deposed_acknowledged_offset <= truth.last_common_offset {
        return Ok(None);
    }
    let first = truth.last_common_offset + 1;
    let last = truth.deposed_acknowledged_offset;
    if last - first + 1 > LOST_SUFFIX_CUSTODY_ROW_BOUND {
        return Err("the excluded suffix exceeds the custody row bound".to_owned());
    }
    let mut offsets: Vec<u64> = entry_commitment_refs
        .iter()
        .map(|(offset, _)| *offset)
        .collect();
    offsets.sort_unstable();
    let expected: Vec<u64> = (first..=last).collect();
    if offsets != expected {
        return Err(
            "the custody rows do not cover exactly the candidate range; partial custody \
             would silently drop an excluded operation"
                .to_owned(),
        );
    }
    if custody_artifact_refs.is_empty() {
        return Err("an excluded suffix requires at least one custody artifact".to_owned());
    }
    let mut sorted_refs = entry_commitment_refs.to_vec();
    sorted_refs.sort_by_key(|(offset, _)| *offset);
    Ok(Some(PriorWriterLogObservation {
        last_common_offset: truth.last_common_offset,
        last_common_state_root: truth.last_common_state_root.clone(),
        acknowledged_offset: truth.deposed_acknowledged_offset,
        authoritative_head_offset: truth.authoritative_head_offset,
        authoritative_head_state_root: truth.authoritative_head_state_root.clone(),
        entry_commitment_refs: sorted_refs,
        custody_artifact_refs: custody_artifact_refs.to_vec(),
        acknowledgement_certainty,
        reconciliation_policy_ref: reconciliation_policy_ref.to_owned(),
    }))
}

/// Produce and contract-validate the recovery-side lost-suffix record from
/// one derived observation, byte-identical to the writer-fence plane's
/// builder for the same observation (the unit proofs pin this parity against
/// the registered fixture). Returns the stamped record and its timeless
/// revision root, or `None` when nothing was excluded.
pub fn build_recovery_lost_suffix_record(
    system_id: &str,
    writer_epoch_transition_ref: &str,
    prior_writer_epoch: u64,
    successor_writer_epoch: u64,
    observation: &PriorWriterLogObservation,
    recorded_at: &str,
) -> Result<Option<(Value, String)>, String> {
    let ns = namespace(system_id)?;
    if successor_writer_epoch != prior_writer_epoch + 1 {
        return Err("the successor writer epoch advances by exactly one".to_owned());
    }
    if observation.acknowledged_offset <= observation.last_common_offset {
        return Ok(None);
    }
    let first = observation.last_common_offset + 1;
    let last = observation.acknowledged_offset;
    let count = last - first + 1;
    if count > LOST_SUFFIX_CUSTODY_ROW_BOUND {
        return Err("the excluded suffix exceeds the custody row bound".to_owned());
    }
    let mut sorted_refs = observation.entry_commitment_refs.clone();
    sorted_refs.sort_by_key(|(offset, _)| *offset);
    let offsets: Vec<u64> = sorted_refs.iter().map(|(offset, _)| *offset).collect();
    let expected: Vec<u64> = (first..=last).collect();
    if offsets != expected {
        return Err(
            "the excluded suffix custody rows do not cover exactly the acknowledged range"
                .to_owned(),
        );
    }
    let entries: Vec<Value> = sorted_refs
        .iter()
        .map(|(offset, commitment_ref)| {
            json!({
                "operation_offset": offset,
                "operation_commitment_ref": commitment_ref,
                "custody_status": "retained_ambiguous",
                "resolution_receipt_ref": Value::Null,
                "resolution_evidence_refs": [],
            })
        })
        .collect();
    let commitment_refs: Vec<Value> = sorted_refs
        .iter()
        .map(|(_, commitment_ref)| json!(commitment_ref))
        .collect();
    let (classification, disposition) = match observation.acknowledgement_certainty {
        SuffixAcknowledgementCertainty::Unacknowledged => {
            ("lost_unacknowledged", "retained_for_forensics")
        }
        SuffixAcknowledgementCertainty::AckedBelowRequiredDurability => (
            "orphaned_acknowledged_below_required_durability",
            "compensating_transition_required",
        ),
        SuffixAcknowledgementCertainty::Ambiguous => ("ambiguous", "adjudication_required"),
    };
    let record = json!({
        "schema_version": "ioi.lost-suffix-record.v1",
        "lost_suffix_record_id": format!("lost-suffix://{ns}/epoch-{successor_writer_epoch}"),
        "system_id": system_id,
        "writer_epoch_transition_ref": writer_epoch_transition_ref,
        "prior_writer_epoch": prior_writer_epoch,
        "successor_writer_epoch": successor_writer_epoch,
        "last_common": {
            "operation_offset": observation.last_common_offset,
            "state_root": observation.last_common_state_root,
        },
        "authoritative_head": {
            "operation_offset": observation.authoritative_head_offset,
            "state_root": observation.authoritative_head_state_root,
        },
        "excluded_suffix": {
            "first_offset": first,
            "last_offset": last,
            "operation_count": count,
            "commitment_refs": commitment_refs,
            "custody_artifact_refs": observation.custody_artifact_refs,
            "entries": entries,
        },
        "classification": classification,
        "reconciliation_policy_ref": observation.reconciliation_policy_ref,
        "disposition": disposition,
        "disposition_receipt_refs": [],
        "predecessor_record_root": Value::Null,
        "status": "open",
        "recorded_at": recorded_at,
    });
    validate_architecture_contract(LOST_SUFFIX_CONTRACT, &record)
        .map_err(|error| format!("recovery lost-suffix record is invalid: {error}"))?;
    let root = lost_suffix_record_root(&record)?;
    Ok(Some((record, root)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::system_writer_fence::{
        build_fence_context, evaluate_consequential_effect_fence, replay_writer_epoch_transitions,
        resolve_lost_suffix_record, FenceContextOrigin, FenceServerTruth,
        LostSuffixEntryResolution,
    };

    const SYSTEM: &str = "system://acme/system-alpha";
    const NODE_A: &str = "node://acme/system-alpha/alpha-node-1";
    const NODE_B: &str = "node://acme/system-alpha/beta-node-2";

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }

    fn genesis() -> Value {
        fixture("autonomous-system-writer-epoch-transition-v1/positive-genesis.json")
    }

    fn promotion() -> Value {
        fixture("autonomous-system-writer-epoch-transition-v1/positive-promotion.json")
    }

    fn head_after(transitions: &[Value]) -> WriterFenceHead {
        replay_writer_epoch_transitions(SYSTEM, transitions).expect("fence head replays")
    }

    fn fence_truth<'a>(
        active: &'a Value,
        executing_node_id: &'a str,
        now: &'a str,
    ) -> FenceServerTruth<'a> {
        FenceServerTruth {
            system_id: SYSTEM,
            executing_node_id,
            active_transition: Some(active),
            node_membership_root:
                "sha256:3232323232323232323232323232323232323232323232323232323232323232",
            deployment_profile_root:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            authority_revocation_epoch: 12,
            read_state_root:
                "sha256:0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            read_watermark: "operation-offset:7",
            expected_payload_hash:
                "sha256:6161616161616161616161616161616161616161616161616161616161616161",
            now,
        }
    }

    /// A genuinely admitting fence verdict under the active epoch-2 writer.
    fn admitting_verdict(active: &Value) -> FenceVerdict {
        let truth = fence_truth(active, NODE_B, "2026-07-28T13:00:06Z");
        let context = build_fence_context(
            &truth,
            "wallet.network/effects",
            "external_effect",
            "replay-suffix-8-9",
            "2026-07-28T13:03:00Z",
            "2026-07-28T13:00:36Z",
            "temporal-evaluation://acme/system-alpha/effect/replay-1",
            &h(0x4E),
        )
        .expect("PEP context builds");
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert!(verdict.admitted, "{:?}", verdict.refusal_reason);
        verdict
    }

    /// A genuinely stale fence verdict: the epoch-1 PEP context held by the
    /// deposed writer, evaluated against the advanced epoch-2 fence truth.
    fn stale_verdict(active: &Value) -> FenceVerdict {
        let held = fixture("consequential-effect-fence-context-v1/positive-active-writer.json");
        let truth = fence_truth(active, NODE_A, "2026-07-28T13:00:06Z");
        let verdict =
            evaluate_consequential_effect_fence(&truth, &held, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("stale"));
        verdict
    }

    fn suffix_8_9() -> ReplaySuffix {
        ReplaySuffix {
            system_id: SYSTEM.into(),
            writer_epoch: 2,
            first_offset: 8,
            last_offset: 9,
            entries: vec![
                ReplaySuffixEntry {
                    operation_offset: 8,
                    operation_commitment_ref: "commitment://acme/system-alpha/op/8".into(),
                },
                ReplaySuffixEntry {
                    operation_offset: 9,
                    operation_commitment_ref: "commitment://acme/system-alpha/op/9".into(),
                },
            ],
        }
    }

    fn replica_truth() -> ReplicaContinuityTruth {
        ReplicaContinuityTruth {
            last_common_offset: 7,
            last_common_state_root: h(0x0E),
            authoritative_head_offset: 7,
            authoritative_head_state_root: h(0x0F),
            deposed_acknowledged_offset: 9,
        }
    }

    fn commitments() -> Vec<(u64, String)> {
        vec![
            (8, "commitment://acme/system-alpha/op/8".into()),
            (9, "commitment://acme/system-alpha/op/9".into()),
        ]
    }

    fn custody_artifacts() -> Vec<String> {
        vec!["artifact://acme/system-alpha/lost-suffix/epoch-2/bytes".into()]
    }

    fn open_record() -> Value {
        fixture("lost-suffix-record-v1/positive-open-retained.json")
    }

    fn resolution(offset: u64) -> LostSuffixEntryResolution {
        LostSuffixEntryResolution {
            operation_offset: offset,
            custody_status: "resolved".into(),
            resolution_receipt_ref: format!(
                "receipt://acme/system-alpha/lost-suffix/epoch-2/op/{offset}"
            ),
            resolution_evidence_refs: vec![],
        }
    }

    fn truth_with<'a>(
        head: &'a WriterFenceHead,
        watermark: u64,
        records: &'a [Value],
    ) -> ReplayTargetTruth<'a> {
        ReplayTargetTruth {
            target_system_id: SYSTEM,
            fence_head: head,
            applied_watermark: watermark,
            lost_suffix_records: records,
        }
    }

    // The M2 ladder: write under epoch 1 → depose → the lost suffix is
    // captured from replica truth → ambiguous custody excludes replay →
    // explicit resolution admits the suffix exactly once → the second replay
    // refuses as a duplicate (idempotence, no loss, no duplication).
    #[test]
    fn ladder_depose_capture_resolve_then_replay_exactly_once() {
        let head = head_after(&[genesis(), promotion()]);
        assert_eq!(head.active_epoch, 2);
        let active = head.active_transition.clone().expect("active transition");
        let verdict = admitting_verdict(&active);

        // Recovery: the candidate range derives from replica head/watermark
        // truth versus the deposed epoch's acknowledged range.
        let observation = derive_prior_writer_log_observation(
            &replica_truth(),
            &commitments(),
            &custody_artifacts(),
            SuffixAcknowledgementCertainty::Ambiguous,
            "policy://acme/lost-suffix/reconciliation-v1",
        )
        .expect("observation derives")
        .expect("a lost suffix exists");
        assert_eq!(observation.last_common_offset, 7);
        assert_eq!(observation.acknowledged_offset, 9);

        // The recovery-side record is byte-identical to the registered
        // canon fixture of the writer-fence plane's family.
        let (record, root) = build_recovery_lost_suffix_record(
            SYSTEM,
            "writer-transition://acme/system-alpha/epoch/2",
            1,
            2,
            &observation,
            "2026-07-28T13:00:05Z",
        )
        .expect("record builds")
        .expect("a record exists");
        assert_eq!(record, open_record());
        assert_eq!(root, lost_suffix_record_root(&open_record()).expect("root"));

        // While ambiguous, the retained entries exclude the suffix.
        let records = [record.clone()];
        let refused = admit_replay_suffix(
            &truth_with(&head, 7, &records),
            &suffix_8_9(),
            &verdict,
            None,
        );
        assert_eq!(refused.refusal_dimension, Some("lost_suffix"));
        assert!(!refused.admitted);

        // Explicit per-entry resolution through the registered family.
        let resolved = resolve_lost_suffix_record(
            &record,
            &[resolution(8), resolution(9)],
            "reconciled",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect("custody resolves");

        // The resolved suffix replays exactly once.
        let records = [resolved];
        let admitted = admit_replay_suffix(
            &truth_with(&head, 7, &records),
            &suffix_8_9(),
            &verdict,
            None,
        );
        assert!(admitted.admitted, "{:?}", admitted.refusal_reason);
        assert_eq!(admitted.admitted_range, Some((8, 9)));
        assert_eq!(admitted.resulting_watermark, Some(9));

        // Idempotence: after the watermark advances, the same suffix is a
        // refused duplicate — no loss, no duplication.
        let duplicate = admit_replay_suffix(
            &truth_with(&head, 9, &records),
            &suffix_8_9(),
            &verdict,
            None,
        );
        assert_eq!(duplicate.refusal_dimension, Some("duplicate_suffix"));
        assert!(!duplicate.admitted);
    }

    // Negative — lost suffix: ambiguous custody excludes replay.
    #[test]
    fn lost_suffix_entry_replay_is_refused_while_ambiguous() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let verdict = admitting_verdict(&active);
        let records = [open_record()];
        let verdict = admit_replay_suffix(
            &truth_with(&head, 7, &records),
            &suffix_8_9(),
            &verdict,
            None,
        );
        assert_eq!(verdict.refusal_dimension, Some("lost_suffix"));
        assert!(verdict
            .refusal_reason
            .as_deref()
            .expect("reason")
            .contains("retained ambiguous"));
    }

    // Negative — lost suffix: an explicitly refused custody row never
    // replays, even after the record leaves `open`.
    #[test]
    fn refused_custody_entry_never_replays() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        let mut refusal = resolution(8);
        refusal.custody_status = "refused".into();
        let resolved = resolve_lost_suffix_record(
            &open_record(),
            &[refusal, resolution(9)],
            "adjudicated",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/adjudication",
        )
        .expect("custody resolves");
        let records = [resolved];
        let verdict =
            admit_replay_suffix(&truth_with(&head, 7, &records), &suffix_8_9(), &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("lost_suffix"));
        assert!(verdict
            .refusal_reason
            .as_deref()
            .expect("reason")
            .contains("refused custody"));
    }

    // Negative — duplicated suffix: the watermark/dedup check refuses whole
    // and partial re-application.
    #[test]
    fn duplicated_suffix_replay_is_refused_by_the_watermark() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        for watermark in [8, 9, 20] {
            let verdict = admit_replay_suffix(
                &truth_with(&head, watermark, &[]),
                &suffix_8_9(),
                &fence,
                None,
            );
            assert_eq!(
                verdict.refusal_dimension,
                Some("duplicate_suffix"),
                "watermark {watermark}"
            );
        }
    }

    // Negative — a gap between the watermark and the suffix never silently
    // drops entries, and a mis-declared suffix range refuses structurally.
    #[test]
    fn suffix_gap_and_partial_declaration_are_refused() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        let verdict = admit_replay_suffix(&truth_with(&head, 5, &[]), &suffix_8_9(), &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("suffix_gap"));

        let mut partial = suffix_8_9();
        partial.entries.pop();
        let verdict = admit_replay_suffix(&truth_with(&head, 7, &[]), &partial, &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("suffix_gap"));
    }

    // Negative — stale writer: a suffix admitted under the deposed epoch is
    // refused, and the concurring fence verdict is genuinely stale.
    #[test]
    fn stale_writer_replay_is_refused_by_the_fence() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = stale_verdict(&active);
        let mut suffix = suffix_8_9();
        suffix.writer_epoch = 1;
        let verdict = admit_replay_suffix(&truth_with(&head, 7, &[]), &suffix, &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("stale_writer"));
        assert!(!verdict.admitted);

        // Even a suffix declaring the admitted epoch cannot replay past a
        // refusing fence verdict.
        let verdict = admit_replay_suffix(&truth_with(&head, 7, &[]), &suffix_8_9(), &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("fence_refused"));
        assert!(verdict
            .refusal_reason
            .as_deref()
            .expect("reason")
            .contains("stale"));
    }

    // Negative — an epoch durable truth never admitted refuses, as does any
    // replay before genesis.
    #[test]
    fn unadmitted_epoch_replay_is_refused() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        let mut suffix = suffix_8_9();
        suffix.writer_epoch = 3;
        let verdict = admit_replay_suffix(&truth_with(&head, 7, &[]), &suffix, &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("unadmitted_epoch"));

        let pre_genesis = WriterFenceHead {
            active_epoch: 0,
            active_transition: None,
        };
        let verdict = admit_replay_suffix(
            &truth_with(&pre_genesis, 0, &[]),
            &suffix_8_9(),
            &fence,
            None,
        );
        assert_eq!(verdict.refusal_dimension, Some("unadmitted_epoch"));
    }

    // Negative — wrong-System projection: a target bound to another System
    // refuses the suffix.
    #[test]
    fn wrong_system_projection_is_refused() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        let truth = ReplayTargetTruth {
            target_system_id: "system://acme/system-beta",
            fence_head: &head,
            applied_watermark: 7,
            lost_suffix_records: &[],
        };
        let verdict = admit_replay_suffix(&truth, &suffix_8_9(), &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("wrong_system"));
        assert!(!verdict.admitted);
    }

    // Restore flow: the exact fixture pair admits; every departure between
    // the plan's manifest commitment, the durable backup, and the restored
    // source state root refuses as a restore mismatch.
    #[test]
    fn restore_mismatch_is_refused_and_the_exact_binding_admits() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        let plan = fixture("hypervisor-change-plan-v1/positive-restore-declared.json");
        let backup = fixture("hypervisor-environment-backup-v1/positive-complete.json");
        let restored_root =
            "state-root://sha256:0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

        let binding = RestoreBinding {
            change_plan: &plan,
            source_backup: &backup,
            restored_source_state_root_ref: restored_root,
        };
        let verdict = admit_replay_suffix(
            &truth_with(&head, 7, &[]),
            &suffix_8_9(),
            &fence,
            Some(&binding),
        );
        assert!(verdict.admitted, "{:?}", verdict.refusal_reason);

        // The restored source state root departs the manifest-committed
        // backup source.
        let mismatched = RestoreBinding {
            restored_source_state_root_ref:
                "state-root://sha256:1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d",
            ..binding.clone()
        };
        let verdict = admit_replay_suffix(
            &truth_with(&head, 7, &[]),
            &suffix_8_9(),
            &fence,
            Some(&mismatched),
        );
        assert_eq!(verdict.refusal_dimension, Some("restore_mismatch"));

        // A tampered manifest commitment is caught by the backup family's
        // registered invariant before this seam: incomplete durable restore
        // truth fails closed rather than restoring.
        let mut tampered = backup.clone();
        tampered["manifest_root"] = json!(h(0x66));
        let broken = RestoreBinding {
            change_plan: &plan,
            source_backup: &tampered,
            restored_source_state_root_ref: restored_root,
        };
        let verdict = admit_replay_suffix(
            &truth_with(&head, 7, &[]),
            &suffix_8_9(),
            &fence,
            Some(&broken),
        );
        assert_eq!(verdict.refusal_dimension, Some("source_incomplete"));

        // A plan re-pointed at a different source backup breaks its own
        // immutable plan commitment: the registered invariant fails it
        // closed before any binding comparison.
        let mut foreign_plan = plan.clone();
        foreign_plan["restore"]["source_backup_ref"] =
            json!("environment-backup://local/env-alpha/2026-07-28/0002");
        let detached = RestoreBinding {
            change_plan: &foreign_plan,
            source_backup: &backup,
            restored_source_state_root_ref: restored_root,
        };
        let verdict = admit_replay_suffix(
            &truth_with(&head, 7, &[]),
            &suffix_8_9(),
            &fence,
            Some(&detached),
        );
        assert_eq!(verdict.refusal_dimension, Some("source_incomplete"));
    }

    // Fail-closed source incompleteness: invalid durable custody truth never
    // silently admits.
    #[test]
    fn invalid_lost_suffix_source_fails_closed() {
        let head = head_after(&[genesis(), promotion()]);
        let active = head.active_transition.clone().expect("active");
        let fence = admitting_verdict(&active);
        let mut corrupt = open_record();
        corrupt.as_object_mut().expect("object").remove("status");
        let records = [corrupt];
        let verdict =
            admit_replay_suffix(&truth_with(&head, 7, &records), &suffix_8_9(), &fence, None);
        assert_eq!(verdict.refusal_dimension, Some("source_incomplete"));
    }

    // Recovery derivation negatives: nothing lost yields no record; partial
    // custody coverage refuses.
    #[test]
    fn recovery_derivation_is_honest_about_absence_and_coverage() {
        let nothing_lost = ReplicaContinuityTruth {
            last_common_offset: 9,
            last_common_state_root: h(0x0E),
            authoritative_head_offset: 9,
            authoritative_head_state_root: h(0x0E),
            deposed_acknowledged_offset: 9,
        };
        assert!(derive_prior_writer_log_observation(
            &nothing_lost,
            &[],
            &custody_artifacts(),
            SuffixAcknowledgementCertainty::Ambiguous,
            "policy://acme/lost-suffix/reconciliation-v1",
        )
        .expect("derives")
        .is_none());

        let partial = derive_prior_writer_log_observation(
            &replica_truth(),
            &commitments()[..1],
            &custody_artifacts(),
            SuffixAcknowledgementCertainty::Ambiguous,
            "policy://acme/lost-suffix/reconciliation-v1",
        );
        assert!(partial
            .expect_err("partial coverage refuses")
            .contains("cover exactly"));
    }

    // Every named refusal dimension is a declared member and the declared
    // set never shrinks silently.
    #[test]
    fn refusal_dimensions_are_the_declared_closed_set() {
        let mut dimensions = REPLAY_REFUSAL_DIMENSIONS.to_vec();
        dimensions.sort_unstable();
        dimensions.dedup();
        assert_eq!(dimensions.len(), REPLAY_REFUSAL_DIMENSIONS.len());
        for required in [
            "wrong_system",
            "stale_writer",
            "duplicate_suffix",
            "lost_suffix",
            "restore_mismatch",
        ] {
            assert!(REPLAY_REFUSAL_DIMENSIONS.contains(&required), "{required}");
        }
    }
}
