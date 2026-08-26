//! Durable shared WorkLifecycle owner: persistence store and read/owner-scoped
//! diagnostic routes around the accepted kernel.
//!
//! I/O and durability only. Every mechanic — content commitment, exact-head
//! compare-and-swap, object-scoped idempotency, chain reconstruction, active-
//! child projection, the rebuildable projection, cancellation planning, and
//! immutable archive/snapshot/resume continuity — belongs to
//! [`WorkLifecycleLogCore`] in
//! `ioi_services::agentic::runtime::kernel::runtime_work_lifecycle_log`. This
//! module loads an object's records, hands them to the core, and persists what
//! the core admits. It makes no admission decision of its own and never
//! acquires a domain object's write authority (ADR 0034 sub-ruling 1, INV-35).
//!
//! PERSISTENCE. The precedent store (`265ee73b8`) wrote plain daemon JSON
//! projections through `persist_record`/`read_record_dir`. That never crosses
//! Agentgres, so a crash between "route said yes" and "truth is durable" would
//! be invisible. This owner instead persists every family through the existing
//! generic owner-namespaced event-stream admission
//! (`substrate_store::admit_event_stream_operation`): each crossing is an atomic
//! Agentgres transition with an exact expected head, confirmed durable before it
//! is a fact, and it FAILS CLOSED when the required substrate is unavailable
//! rather than reverting to a local file. Cross-process serialization and the
//! exact-head/idempotency CAS are therefore enforced twice — once by the
//! kernel over its own content-commitment head, once by Agentgres over the
//! stream head — and neither layer trusts storage order.
//!
//! Five durable families, one owner namespace each: the append-only record log,
//! the rebuildable projection checkpoint, cancellation-fanout plans, immutable
//! archive segments, and archive-bound snapshots. The record log is the source
//! of truth; every read rebuilds from it and refuses malformed, forked, gapped,
//! missing, tampered, or owner-drifted evidence. Hot record logs are never
//! pruned here.
//!
//! The GoalRun create route composes this owner for its application-owned plan,
//! ContextCell reference, and GoalRun lifecycle projection. That bounded binding
//! does not transfer Session, launch, thread, HarnessInvocation, or other kernel
//! truth to GoalRun, and no other object owner is implied to be wired here.

use std::collections::BTreeMap;
use std::sync::Arc;

use agentgres::event_stream::AdmissionRefusal;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use ioi_services::agentic::runtime::kernel::runtime_work_lifecycle_log::{
    AppendOutcome, CancellationIntent, LegalEdgeGate, ResumedProjection, WorkLifecycleLogCore,
    WorkLifecycleLogError,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::substrate_store;
use super::DaemonState;

/// Owner namespaces for the five durable families. Each is a canonical
/// event-stream owner namespace (`[a-z0-9._-]`, <= 96 bytes).
pub(crate) const RECORDS_NS: &str = "work-lifecycle-records";
pub(crate) const PROJECTIONS_NS: &str = "work-lifecycle-projections";
pub(crate) const CANCELLATION_PLANS_NS: &str = "work-lifecycle-cancellation-plans";
pub(crate) const ARCHIVE_SEGMENTS_NS: &str = "work-lifecycle-archive-segments";
pub(crate) const SNAPSHOTS_NS: &str = "work-lifecycle-snapshots";

/// Operation kinds. The generic event-stream admission requires the `Event`
/// class, whose op kinds start with `event_stream.`.
const RECORD_OP_KIND: &str = "event_stream.work_lifecycle_record";
const PROJECTION_OP_KIND: &str = "event_stream.work_lifecycle_projection";
const CANCELLATION_PLAN_OP_KIND: &str = "event_stream.work_lifecycle_cancellation_plan";
const ARCHIVE_SEGMENT_OP_KIND: &str = "event_stream.work_lifecycle_archive_segment";
const SNAPSHOT_OP_KIND: &str = "event_stream.work_lifecycle_snapshot";

/// A projection/snapshot append may lose a benign race with a concurrent
/// checkpoint writer on its own stream; re-read the head and retry a bounded
/// number of times before surfacing the conflict.
const CHECKPOINT_PERSIST_RETRIES: u32 = 4;

/// Map an object ref to a canonical, collision-resistant stream tail.
///
/// A `work_run://run-1/..` object ref is not a canonical event-stream tail
/// (`://`, and a `..` would be refused by the substrate). The SHA-256 of the
/// exact object ref is a stable 64-hex tail that satisfies the coordinate rules
/// and cannot be spoofed onto another object.
fn object_stream_tail(object_ref: &str) -> String {
    format!("obj.{:x}", Sha256::digest(object_ref.as_bytes()))
}

/// Map an archive ref to its own single-genesis immutable stream tail.
fn archive_stream_tail(archive_ref: &str) -> String {
    format!("arc.{:x}", Sha256::digest(archive_ref.as_bytes()))
}

// ---------------------------------------------------------------------------
// Owner-internal Rust API. GoalRun creation composes this seam with its own
// LegalEdgeGate; subsequent owners must supply and prove their own gate.
// ---------------------------------------------------------------------------

/// The outcome of one durable append.
#[derive(Debug, Clone)]
pub(crate) struct AppendReport {
    /// True when an object-scoped idempotency key replayed with identical bytes;
    /// nothing new was written.
    pub(crate) replayed: bool,
    /// The admitted record, `record_hash`/`resulting_head` stamped by the kernel.
    pub(crate) record: Value,
    /// The kernel content-commitment head after this record.
    pub(crate) resulting_head: String,
    /// The rebuilt active projection persisted alongside the record.
    pub(crate) projection: Value,
    /// The Agentgres stream sequence for a genuine append; `None` on replay.
    pub(crate) agentgres_seq: Option<u64>,
}

/// The outcome of one compaction: an immutable archive segment and the snapshot
/// bound to its root/head.
#[derive(Debug, Clone)]
pub(crate) struct CompactionReport {
    pub(crate) archive_ref: String,
    pub(crate) snapshot_ref: String,
    pub(crate) through_head: String,
    pub(crate) archive_root: String,
    pub(crate) segment: Value,
    pub(crate) snapshot: Value,
}

/// A durability or admission failure surfaced by the store.
#[derive(Debug)]
pub(crate) enum WorkLifecycleStoreError {
    /// The kernel refused: an integrity, census, authority, or planning refusal.
    /// Carries the kernel's stable code so it names itself identically on the
    /// wire wherever admission is attempted.
    Kernel(WorkLifecycleLogError),
    /// The substrate refused or was unavailable.
    Substrate(AdmissionRefusal),
    /// A concurrent writer advanced the record stream head; the caller re-reads
    /// and retries against the exact current head.
    HeadConflict,
    /// An immutable archive segment already exists under this ref with different
    /// bytes; a segment is written once and never rewritten.
    ArchiveImmutable,
    /// No object at these coordinates.
    NotFound,
    /// The candidate/request did not carry a usable `object_ref`.
    ObjectRefInvalid,
    /// A durable record is missing the owner it was born with.
    OwnerRefMissing,
    /// A snapshot binds a head the current record log no longer contains: a
    /// torn compaction. Resume fails closed rather than resume onto a fork.
    ResumeHeadUnbound,
    /// A record stored under a stream tail does not derive that tail from its
    /// own `object_ref`: a foreign or mis-filed record. It is rejected rather
    /// than normalized into the requested object.
    ForeignTailRecord,
}

impl WorkLifecycleStoreError {
    pub(crate) fn code(&self) -> String {
        match self {
            Self::Kernel(error) => error.code().to_string(),
            Self::Substrate(refusal) => refusal.code().to_string(),
            Self::HeadConflict => "work_lifecycle_record_head_conflict".to_string(),
            Self::ArchiveImmutable => "work_lifecycle_archive_immutable".to_string(),
            Self::NotFound => "work_lifecycle_object_not_found".to_string(),
            Self::ObjectRefInvalid => "work_lifecycle_object_ref_invalid".to_string(),
            Self::OwnerRefMissing => "work_lifecycle_owner_ref_missing".to_string(),
            Self::ResumeHeadUnbound => "work_lifecycle_resume_head_unbound".to_string(),
            Self::ForeignTailRecord => "work_lifecycle_foreign_tail_record".to_string(),
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Kernel(error) => error.message().to_string(),
            Self::Substrate(refusal) => refusal.to_string(),
            Self::HeadConflict => {
                "the record stream advanced under a concurrent writer; re-read the head and retry"
                    .to_string()
            }
            Self::ArchiveImmutable => {
                "an archive segment already exists under this ref with different bytes".to_string()
            }
            Self::NotFound => "no admitted work-lifecycle object at these coordinates".to_string(),
            Self::ObjectRefInvalid => "record requires a non-empty object_ref".to_string(),
            Self::OwnerRefMissing => "the object's durable owner_ref is missing".to_string(),
            Self::ResumeHeadUnbound => {
                "the snapshot binds a head the current record log no longer contains".to_string()
            }
            Self::ForeignTailRecord => {
                "a stored record does not derive its stream tail from its own object_ref"
                    .to_string()
            }
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            Self::Kernel(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Substrate(refusal) => match refusal {
                AdmissionRefusal::HeadConflict => StatusCode::CONFLICT,
                AdmissionRefusal::CoordinatesNotCanonical(_)
                | AdmissionRefusal::SameKeyDifferentBytes { .. } => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                AdmissionRefusal::CapabilityAbsent => StatusCode::SERVICE_UNAVAILABLE,
                AdmissionRefusal::DurabilityUnconfirmed(_)
                | AdmissionRefusal::ProjectionDisagreesWithAck
                | AdmissionRefusal::SubstrateUnavailable(_) => StatusCode::BAD_GATEWAY,
            },
            Self::HeadConflict | Self::ArchiveImmutable => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::ObjectRefInvalid => StatusCode::BAD_REQUEST,
            Self::OwnerRefMissing => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ResumeHeadUnbound => StatusCode::CONFLICT,
            Self::ForeignTailRecord => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

impl From<WorkLifecycleLogError> for WorkLifecycleStoreError {
    fn from(error: WorkLifecycleLogError) -> Self {
        Self::Kernel(error)
    }
}

type StoreResult<T> = Result<T, WorkLifecycleStoreError>;

/// The durable WorkLifecycle owner over one daemon data dir.
#[derive(Clone)]
pub(crate) struct WorkLifecycleStore {
    data_dir: String,
    core: WorkLifecycleLogCore,
}

impl WorkLifecycleStore {
    pub(crate) fn new(data_dir: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            core: WorkLifecycleLogCore,
        }
    }

    // --- substrate reads --------------------------------------------------

    /// The raw kernel-record payloads on one stream tail, as stored (order not
    /// trusted). Callers MUST validate tail scope before using these.
    fn raw_record_payloads(&self, tail: &str) -> StoreResult<Vec<Value>> {
        Ok(
            substrate_store::read_event_stream_history(&self.data_dir, RECORDS_NS, tail)
                .map_err(WorkLifecycleStoreError::Substrate)?
                .into_iter()
                .map(|projection| projection.operation.payload)
                .collect(),
        )
    }

    /// The records for one object, proving every stored record derives the
    /// object's stream tail from its own `object_ref`.
    ///
    /// The stream is keyed by `object_stream_tail(object_ref)`, so a payload
    /// whose `object_ref` differs is a foreign or mis-filed record. It is
    /// rejected — never normalized into the requested object — so a read can
    /// never fold another object's record into this one's chain or projection.
    fn record_payloads_for(&self, object_ref: &str) -> StoreResult<Vec<Value>> {
        let tail = object_stream_tail(object_ref);
        let payloads = self.raw_record_payloads(&tail)?;
        for payload in &payloads {
            let stored = payload
                .get("object_ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if stored != object_ref || object_stream_tail(stored) != tail {
                return Err(WorkLifecycleStoreError::ForeignTailRecord);
            }
        }
        Ok(payloads)
    }

    /// The records on one stream tail whose owning `object_ref` is not known to
    /// the caller (the diagnostic census enumerates tails, not object refs).
    ///
    /// The owning object ref is taken from the stored records themselves and
    /// must derive exactly this tail; every record must share it. This proves
    /// the tail is derived from the records' `object_ref` without trusting a
    /// caller-supplied ref.
    fn record_payloads_by_tail(&self, tail: &str) -> StoreResult<Vec<Value>> {
        let payloads = self.raw_record_payloads(tail)?;
        let Some(first) = payloads.first() else {
            return Ok(payloads);
        };
        let object_ref = first
            .get("object_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if object_ref.is_empty() || object_stream_tail(&object_ref) != *tail {
            return Err(WorkLifecycleStoreError::ForeignTailRecord);
        }
        for payload in &payloads {
            if payload.get("object_ref").and_then(Value::as_str) != Some(object_ref.as_str()) {
                return Err(WorkLifecycleStoreError::ForeignTailRecord);
            }
        }
        Ok(payloads)
    }

    /// The current Agentgres head for one namespaced stream tail.
    fn stream_head(&self, namespace: &str, tail: &str) -> StoreResult<Option<String>> {
        Ok(
            substrate_store::read_event_stream_operation(&self.data_dir, namespace, tail)
                .map_err(WorkLifecycleStoreError::Substrate)?
                .map(|projection| projection.head),
        )
    }

    /// The latest payload admitted on one namespaced stream tail.
    fn stream_payload(&self, namespace: &str, tail: &str) -> StoreResult<Option<Value>> {
        Ok(
            substrate_store::read_event_stream_operation(&self.data_dir, namespace, tail)
                .map_err(WorkLifecycleStoreError::Substrate)?
                .map(|projection| projection.operation.payload),
        )
    }

    /// Load one object's records in append order, reconstructed from storage.
    ///
    /// Storage order is not trusted; the kernel walks the head chain and fails
    /// closed on fork, gap, orphan, duplicate genesis, owner drift, or a
    /// tampered hash. Ports the precedent's `load_chain` onto the durable
    /// substrate.
    pub(crate) fn load_chain(&self, object_ref: &str) -> StoreResult<Vec<Value>> {
        let payloads = self.record_payloads_for(object_ref)?;
        Ok(self.core.reconstruct_chain(&payloads)?)
    }

    // --- append ----------------------------------------------------------

    /// Append one record under the kernel's admission, then persist it and the
    /// rebuilt projection. A refusal never writes.
    pub(crate) fn append(&self, candidate: &Value) -> StoreResult<AppendReport> {
        self.append_inner(candidate, None)
    }

    /// As [`append`](Self::append), additionally authorizing the transition
    /// through the caller's kind-specific [`LegalEdgeGate`]. The caller owns the
    /// legal-edge/authority table; the shared kernel never acquires it.
    pub(crate) fn append_gated(
        &self,
        candidate: &Value,
        gate: &dyn LegalEdgeGate,
    ) -> StoreResult<AppendReport> {
        self.append_inner(candidate, Some(gate))
    }

    fn append_inner(
        &self,
        candidate: &Value,
        gate: Option<&dyn LegalEdgeGate>,
    ) -> StoreResult<AppendReport> {
        let object_ref = candidate
            .get("object_ref")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(WorkLifecycleStoreError::ObjectRefInvalid)?
            .to_string();
        let tail = object_stream_tail(&object_ref);

        // Read the exact stream state the append will compare against. The
        // Agentgres head is the CAS precondition; the payloads are the kernel's
        // log. Both come from one durable read.
        let history = substrate_store::read_event_stream_history(&self.data_dir, RECORDS_NS, &tail)
            .map_err(WorkLifecycleStoreError::Substrate)?;
        let agentgres_head = history.last().map(|projection| projection.head.clone());
        let log: Vec<Value> = history
            .into_iter()
            .map(|projection| projection.operation.payload)
            .collect();

        // The tail is keyed by this object's ref; a stored record with a foreign
        // object_ref is a mis-filed record and is never folded into this chain.
        for payload in &log {
            if payload.get("object_ref").and_then(Value::as_str) != Some(object_ref.as_str()) {
                return Err(WorkLifecycleStoreError::ForeignTailRecord);
            }
        }

        // Kernel admission first. This is the ONLY refusal that writes nothing;
        // it runs before any substrate crossing.
        let planned = match gate {
            Some(gate) => self.core.plan_append_gated(&log, candidate, gate),
            None => self.core.plan_append(&log, candidate),
        }?;

        if planned.outcome == AppendOutcome::IdempotentReplay {
            // The replayed record is already durable, but a crash may have left
            // the CURRENT projection checkpoint unwritten. Rebuild the FULL
            // current projection and persist it keyed by the CURRENT chain head
            // record — never the (possibly older) replayed record.
            //
            // Keying by the replayed record would be wrong two ways when an old
            // idempotency key is replayed after later appends landed: it could
            // append an older prefix projection on top of the latest one and
            // regress the durable latest projection, and its bytes could differ
            // from an existing checkpoint under that key. Keying by the current
            // head both repairs the current checkpoint (crash-after-current
            // case) and converges (an already-durable current projection
            // replays unchanged, leaving the latest at the current head).
            let chain = self.core.reconstruct_chain(&log)?;
            let projection = self.core.project(&chain)?;
            if let Some(current) = chain.last() {
                let current_hash = current
                    .get("record_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                self.persist_checkpoint(
                    PROJECTIONS_NS,
                    &tail,
                    PROJECTION_OP_KIND,
                    &projection,
                    &current_hash,
                    clamp_ms(current),
                )?;
            }
            return Ok(AppendReport {
                replayed: true,
                record: planned.record,
                resulting_head: planned.resulting_head,
                projection,
                agentgres_seq: None,
            });
        }

        let record_hash = planned
            .record
            .get("record_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let recorded_at_ms = clamp_ms(&planned.record);

        // Persist the record: an atomic Agentgres transition with an exact
        // expected head. A concurrent winner turns this into a head conflict,
        // which the caller resolves by re-reading — never a silent retry.
        let admitted = substrate_store::admit_event_stream_operation(
            &self.data_dir,
            RECORDS_NS,
            &tail,
            RECORD_OP_KIND,
            agentgres_head.as_deref(),
            &planned.record,
            recorded_at_ms,
            &record_hash,
        )
        .map_err(|refusal| match refusal {
            AdmissionRefusal::HeadConflict => WorkLifecycleStoreError::HeadConflict,
            other => WorkLifecycleStoreError::Substrate(other),
        })?;

        // Record persisted THEN rebuild and persist the projection. The
        // projection is a rebuildable checkpoint; every read still rebuilds
        // from the record log, so a projection that lags the record is a stale
        // cache, never lost truth.
        let mut full = log;
        full.push(planned.record.clone());
        let projection = self.core.project(&full)?;
        self.persist_checkpoint(
            PROJECTIONS_NS,
            &tail,
            PROJECTION_OP_KIND,
            &projection,
            &record_hash,
            recorded_at_ms,
        )?;

        Ok(AppendReport {
            replayed: admitted.replayed,
            record: planned.record,
            resulting_head: planned.resulting_head,
            projection,
            agentgres_seq: Some(admitted.projection.seq),
        })
    }

    // --- read models -----------------------------------------------------

    /// The rebuildable active projection for one object, reconstructed from its
    /// record log with a complete strict census. Refuses a malformed, forked,
    /// gapped, or tampered log.
    pub(crate) fn read_projection(&self, object_ref: &str) -> StoreResult<Value> {
        let payloads = self.record_payloads_for(object_ref)?;
        if payloads.is_empty() {
            return Err(WorkLifecycleStoreError::NotFound);
        }
        Ok(self.core.project(&payloads)?)
    }

    /// The reconstructed record chain for one object.
    pub(crate) fn read_records(&self, object_ref: &str) -> StoreResult<Vec<Value>> {
        let chain = self.load_chain(object_ref)?;
        if chain.is_empty() {
            return Err(WorkLifecycleStoreError::NotFound);
        }
        Ok(chain)
    }

    // --- cancellation planning ------------------------------------------

    /// Derive and persist a `CancellationFanoutPlan` over active typed children.
    ///
    /// Planning only: this appends no lifecycle record, transitions nothing, and
    /// the plan can never claim child completion (the kernel guarantees
    /// `requires_completion_receipt: true`). Each child owner still executes and
    /// receipts its own drain/fence/revocation/compensation/reconciliation.
    pub(crate) fn plan_cancellation(
        &self,
        object_ref: &str,
        intent: &CancellationIntent,
        now_ms: i64,
    ) -> StoreResult<Value> {
        let chain = self.read_records(object_ref)?;
        let source_head = chain
            .last()
            .and_then(|record| record.get("resulting_head"))
            .and_then(Value::as_str)
            .ok_or(WorkLifecycleStoreError::NotFound)?
            .to_string();

        let plan = self
            .core
            .plan_cancellation_fanout(object_ref, &source_head, &chain, intent)?;

        // A plan is durable evidence that a cancellation was planned at this
        // head; persist it on its own append-only family, keyed by its exact
        // bytes so an identical re-plan replays rather than forking.
        let plan_key = format!("plan.{:x}", Sha256::digest(plan.to_string().as_bytes()));
        self.persist_checkpoint(
            CANCELLATION_PLANS_NS,
            &object_stream_tail(object_ref),
            CANCELLATION_PLAN_OP_KIND,
            &plan,
            &plan_key,
            clamp_i64(now_ms),
        )?;
        Ok(plan)
    }

    // --- compaction ------------------------------------------------------

    /// Write an immutable archive segment through the current head, then a
    /// snapshot bound to that archive's root and head.
    ///
    /// The archive is persisted BEFORE the snapshot. Hot record logs are never
    /// pruned here; the snapshot is a checkpoint, never a license to discard the
    /// archive or the record log.
    pub(crate) fn compact(&self, object_ref: &str, now_ms: i64) -> StoreResult<CompactionReport> {
        let payloads = self.record_payloads_for(object_ref)?;
        if payloads.is_empty() {
            return Err(WorkLifecycleStoreError::NotFound);
        }
        let chain = self.core.reconstruct_chain(&payloads)?;
        let through_head = chain
            .last()
            .and_then(|record| record.get("resulting_head"))
            .and_then(Value::as_str)
            .ok_or(WorkLifecycleStoreError::NotFound)?
            .to_string();
        let head_hex = through_head
            .strip_prefix("sha256:")
            .unwrap_or(&through_head)
            .to_string();
        let object_tail = object_stream_tail(object_ref);
        let archive_ref = format!("work-lifecycle-archive://{object_tail}/seg-{head_hex}");
        let snapshot_ref = format!("work-lifecycle-snapshot://{object_tail}/snap-{head_hex}");
        let archive_tail = archive_stream_tail(&archive_ref);

        // Archive first, and immutably. A segment already durable at this ref is
        // the canonical one; a re-compaction at the same head returns it rather
        // than re-minting bytes (the segment's `created_at_ms` would otherwise
        // drift and collide with its own idempotency key). Only an absent
        // segment is planned and written, expected-absent.
        let segment = match self.stream_payload(ARCHIVE_SEGMENTS_NS, &archive_tail)? {
            Some(existing) => existing,
            None => {
                let planned = self.core.plan_archive_segment(
                    &archive_ref,
                    &payloads,
                    &through_head,
                    now_ms,
                )?;
                self.persist_archive(&archive_ref, &planned, clamp_i64(now_ms))?;
                // Re-read the durable segment so the snapshot binds exactly what
                // was admitted, even if a concurrent writer won the write.
                self.stream_payload(ARCHIVE_SEGMENTS_NS, &archive_tail)?
                    .unwrap_or(planned)
            }
        };
        let archive_root = segment
            .get("archive_root")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        // Snapshot bound to the durable archive root/head. If the latest
        // snapshot already binds this exact head and root, it is the canonical
        // checkpoint and is returned unchanged; otherwise a new one is planned
        // and appended.
        let snapshot = match self.stream_payload(SNAPSHOTS_NS, &object_tail)? {
            Some(existing)
                if existing.get("through_head").and_then(Value::as_str)
                    == Some(through_head.as_str())
                    && existing.get("archive_root").and_then(Value::as_str)
                        == Some(archive_root.as_str()) =>
            {
                existing
            }
            _ => {
                let planned = self.core.plan_snapshot(&snapshot_ref, &segment, now_ms)?;
                self.persist_checkpoint(
                    SNAPSHOTS_NS,
                    &object_tail,
                    SNAPSHOT_OP_KIND,
                    &planned,
                    &through_head,
                    clamp_i64(now_ms),
                )?;
                self.stream_payload(SNAPSHOTS_NS, &object_tail)?
                    .unwrap_or(planned)
            }
        };

        Ok(CompactionReport {
            archive_ref,
            snapshot_ref,
            through_head,
            archive_root,
            segment,
            snapshot,
        })
    }

    /// The latest snapshot admitted for one object, if any.
    pub(crate) fn latest_snapshot(&self, object_ref: &str) -> StoreResult<Option<Value>> {
        self.stream_payload(SNAPSHOTS_NS, &object_stream_tail(object_ref))
    }

    /// Resume from the latest snapshot and apply the append-only tail, so
    /// resume-plus-tail reconstructs the same projection and idempotency
    /// decisions as a full replay. `None` when the object has no snapshot yet.
    pub(crate) fn resume(&self, object_ref: &str) -> StoreResult<Option<ResumedProjection>> {
        let Some(snapshot) = self.latest_snapshot(object_ref)? else {
            return Ok(None);
        };
        let through_head = snapshot
            .get("through_head")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let chain = self.read_records(object_ref)?;
        let boundary = chain.iter().position(|record| {
            record.get("resulting_head").and_then(Value::as_str) == Some(through_head.as_str())
        });
        let tail: Vec<Value> = match boundary {
            Some(index) => chain[index + 1..].to_vec(),
            // The snapshot binds a head the record log no longer contains: a
            // torn compaction. Fail closed rather than resume onto a fork.
            None => return Err(WorkLifecycleStoreError::ResumeHeadUnbound),
        };
        Ok(Some(self.core.resume_and_project(&snapshot, &tail)?))
    }

    // --- diagnostics -----------------------------------------------------

    /// A process-wide, read-only status diagnostic: the kernel is present,
    /// durable per-family object counts, per-kind lifecycle counts folded from
    /// the record log, and the (empty) live owner-route bindings.
    pub(crate) fn status_summary(&self) -> StoreResult<Value> {
        let record_tails = self.family_tails(RECORDS_NS)?;
        let mut per_kind: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut unreadable_objects: u64 = 0;
        for tail in &record_tails {
            match self.project_by_tail(tail) {
                Ok(projection) => {
                    let kind = projection
                        .get("object_kind")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                    let records = projection
                        .get("record_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let entry = per_kind.entry(kind).or_insert((0, 0));
                    entry.0 += 1;
                    entry.1 += records;
                }
                // A read model that hides a census failure is worse than one
                // that counts it: an unreadable object is reported, not dropped.
                Err(_) => unreadable_objects += 1,
            }
        }

        let per_kind_counts: Vec<Value> = per_kind
            .into_iter()
            .map(|(object_kind, (object_count, record_count))| {
                json!({
                    "object_kind": object_kind,
                    "object_count": object_count,
                    "record_count": record_count,
                })
            })
            .collect();

        Ok(json!({
            "schema_version": "ioi.work-lifecycle-status.v1",
            "kernel_present": true,
            "durable_family_object_counts": {
                RECORDS_NS: record_tails.len() as u64,
                PROJECTIONS_NS: self.family_tails(PROJECTIONS_NS)?.len() as u64,
                CANCELLATION_PLANS_NS: self.family_tails(CANCELLATION_PLANS_NS)?.len() as u64,
                ARCHIVE_SEGMENTS_NS: self.family_tails(ARCHIVE_SEGMENTS_NS)?.len() as u64,
                SNAPSHOTS_NS: self.family_tails(SNAPSHOTS_NS)?.len() as u64,
            },
            "per_kind_lifecycle_counts": per_kind_counts,
            "unreadable_objects": unreadable_objects,
            "live_owner_route_bindings": [{
                "object_kind": "goal_run",
                "route": "POST /v1/goal-orchestration/goal-runs",
                "admission_paths": ["direct_non_system", "system_activation"],
                "owned_scope": ["application_plan", "context_cell_ref", "goal_run_lifecycle"],
            }, {
                "object_kind": "outcome_room",
                "route": "POST /v1/goal-orchestration/outcome-rooms",
                "admission_paths": ["hosted_system_genesis"],
                "owned_scope": ["outcome_room_application_lifecycle"],
            }],
            "nonclaim": "GoalRun creation is bound only for GoalRun-owned application plan/state and invocation references. Hosted OutcomeRoom creation is bound only for its proposed-to-open application lifecycle after the room System Agentgres genesis; room shared state and child lifecycles remain on the room System owner. Session, launch, thread, HarnessInvocation, and child-owner runtime truth remain with their kernel owners; GoalGroundingLoop, WorkRun, AutomationRun, ContextCell lifecycle, and external-handle owners are not generalized by these bindings. Cancellation plans claim no child completion. Hot record logs are never pruned; snapshots are checkpoints, never a license to discard the archive.",
        }))
    }

    fn family_tails(&self, namespace: &str) -> StoreResult<Vec<String>> {
        substrate_store::list_event_stream_tails(&self.data_dir, namespace).map_err(|error| {
            WorkLifecycleStoreError::Substrate(AdmissionRefusal::SubstrateUnavailable(
                error.to_string(),
            ))
        })
    }

    fn project_by_tail(&self, tail: &str) -> StoreResult<Value> {
        let payloads = self.record_payloads_by_tail(tail)?;
        Ok(self.core.project(&payloads)?)
    }

    // --- durable checkpoint helpers -------------------------------------

    /// Persist one rebuildable checkpoint (projection, plan, or snapshot) on its
    /// own stream, under exact-head CAS with an idempotency key. Retries a
    /// bounded number of times on a benign concurrent-checkpoint head conflict,
    /// because an identical checkpoint under the same key replays rather than
    /// forks.
    fn persist_checkpoint(
        &self,
        namespace: &str,
        tail: &str,
        op_kind: &str,
        payload: &Value,
        idem_key: &str,
        recorded_at_ms: u64,
    ) -> StoreResult<()> {
        let mut attempts = 0;
        loop {
            let head = self.stream_head(namespace, tail)?;
            match substrate_store::admit_event_stream_operation(
                &self.data_dir,
                namespace,
                tail,
                op_kind,
                head.as_deref(),
                payload,
                recorded_at_ms,
                idem_key,
            ) {
                Ok(_) => return Ok(()),
                Err(AdmissionRefusal::HeadConflict) if attempts < CHECKPOINT_PERSIST_RETRIES => {
                    attempts += 1;
                    continue;
                }
                Err(other) => return Err(WorkLifecycleStoreError::Substrate(other)),
            }
        }
    }

    /// Persist one immutable archive segment: a single genesis on its own
    /// stream, expected absent. An identical segment replays; a different one
    /// under the same ref is an immutability violation.
    fn persist_archive(
        &self,
        archive_ref: &str,
        segment: &Value,
        recorded_at_ms: u64,
    ) -> StoreResult<()> {
        let idem_key = segment
            .get("archive_root")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match substrate_store::admit_event_stream_operation(
            &self.data_dir,
            ARCHIVE_SEGMENTS_NS,
            &archive_stream_tail(archive_ref),
            ARCHIVE_SEGMENT_OP_KIND,
            None,
            segment,
            recorded_at_ms,
            &idem_key,
        ) {
            Ok(_) => Ok(()),
            // A concurrent compaction may have already written this ref. That is
            // benign only if the durable segment binds the same archive root;
            // any other occupant is an immutability violation.
            Err(AdmissionRefusal::HeadConflict) => {
                match self.stream_payload(ARCHIVE_SEGMENTS_NS, &archive_stream_tail(archive_ref))? {
                    Some(existing)
                        if existing.get("archive_root").and_then(Value::as_str)
                            == Some(idem_key.as_str()) =>
                    {
                        Ok(())
                    }
                    _ => Err(WorkLifecycleStoreError::ArchiveImmutable),
                }
            }
            Err(other) => Err(WorkLifecycleStoreError::Substrate(other)),
        }
    }
}

fn clamp_ms(record: &Value) -> u64 {
    clamp_i64(
        record
            .get("occurred_at_ms")
            .and_then(Value::as_i64)
            .unwrap_or(0),
    )
}

fn clamp_i64(value: i64) -> u64 {
    value.max(0) as u64
}

// ---------------------------------------------------------------------------
// Authenticated daemon routes. Read-only status/projection diagnostics and
// owner-scoped cancellation planning/compaction. There is NO generic append
// mutation on the wire: append is an owner-internal Rust API only.
// ---------------------------------------------------------------------------

/// A refusal that reaches the wire WITH its machine code (the shared `AppError`
/// renders only a message).
#[derive(Debug)]
pub(crate) struct Refused(StatusCode, Value);

impl IntoResponse for Refused {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(self.1)).into_response()
    }
}

fn bad(status: StatusCode, code: &str, message: &str) -> Refused {
    Refused(
        status,
        json!({ "error": { "code": code, "message": message } }),
    )
}

fn store_refused(error: WorkLifecycleStoreError) -> Refused {
    bad(error.http_status(), &error.code(), &error.message())
}

fn scope_refused(refusal: substrate_store::RequestScopeRefusal) -> Refused {
    let status = match refusal {
        substrate_store::RequestScopeRefusal::AuthenticationRequired
        | substrate_store::RequestScopeRefusal::PrincipalIdentityInvalid => {
            StatusCode::UNAUTHORIZED
        }
        substrate_store::RequestScopeRefusal::TenantAuthorityRequired
        | substrate_store::RequestScopeRefusal::ResourceScopeRequired
        | substrate_store::RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
        substrate_store::RequestScopeRefusal::SubstrateUnavailable(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    let message = refusal.message();
    bad(status, refusal.code(), &message)
}

fn request_identity(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<substrate_store::RequestIdentity, Refused> {
    substrate_store::resolve_request_identity(&st.data_dir, headers).map_err(scope_refused)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Owner-scope one object read/action.
///
/// The caller states the `owner_ref` it claims; the authenticated principal
/// must either be that principal owner or be bound to that owner tenant BEFORE
/// any read, so an unauthorized caller gets no cross-owner existence oracle.
/// The durable projection's own
/// `owner_ref` must then match the claim, or the object is reported absent —
/// the caller can only probe objects under an owner it belongs to, and the
/// durable owner truth is never overridden by the request.
fn owner_scoped_projection(
    store: &WorkLifecycleStore,
    identity: &substrate_store::RequestIdentity,
    object_ref: &str,
    claimed_owner_ref: &str,
) -> Result<Value, Refused> {
    if claimed_owner_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_lifecycle_owner_ref_required",
            "an owner-scoped work-lifecycle request names the owner_ref it claims",
        ));
    }
    if claimed_owner_ref != identity.principal_ref && !identity.authorizes_tenant(claimed_owner_ref)
    {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "work_lifecycle_owner_forbidden",
            "the authenticated principal is neither the claimed principal owner nor bound to the claimed owner tenant",
        ));
    }
    let projection = store.read_projection(object_ref).map_err(store_refused)?;
    let durable_owner = projection
        .get("owner_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "work_lifecycle_owner_ref_missing",
                "the object's durable owner_ref is missing",
            )
        })?;
    if durable_owner != claimed_owner_ref {
        // Do not distinguish "exists under another owner" from "does not exist".
        return Err(bad(
            StatusCode::NOT_FOUND,
            "work_lifecycle_object_not_found",
            "no admitted work-lifecycle object at these coordinates for this owner",
        ));
    }
    Ok(projection)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_millis() as i64)
        .unwrap_or_default()
}

/// Derive the cancellation requester from the authenticated principal.
///
/// `requested_by_ref` is authority, not a caller-carried field: a body that
/// asserts a different requester is attempting to plan a cancellation as
/// someone else. Any supplied value that is not the authenticated principal is
/// refused, and the intent always carries `identity.principal_ref` — never the
/// request body. (The owner-internal Rust API may still supply an owner-derived
/// requester, because there the caller IS the daemon-owned kind owner.)
fn cancellation_requester(
    identity: &substrate_store::RequestIdentity,
    body: &Value,
) -> Result<String, Refused> {
    if let Some(supplied) = body.get("requested_by_ref").and_then(Value::as_str) {
        if !supplied.is_empty() && supplied != identity.principal_ref {
            return Err(bad(
                StatusCode::FORBIDDEN,
                "work_lifecycle_requester_substitution",
                "requested_by_ref is derived from the authenticated principal; a different \
                 supplied value is caller-substituted authority",
            ));
        }
    }
    Ok(identity.principal_ref.clone())
}

#[derive(serde::Deserialize)]
pub(crate) struct ObjectQuery {
    object_ref: Option<String>,
    owner_ref: Option<String>,
}

/// `GET /v1/hypervisor/work-lifecycle/status`
///
/// Read-only diagnostic. Reports the shared kernel presence, durable per-family
/// object counts, per-kind lifecycle counts, and the (empty) live owner-route
/// bindings. It neither creates nor transitions any object.
pub(crate) async fn handle_work_lifecycle_status(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, Refused> {
    // A process-wide operator diagnostic still requires a real principal; there
    // is no anonymous oracle.
    let _identity = request_identity(&st, &headers)?;
    let summary = WorkLifecycleStore::new(&st.data_dir)
        .status_summary()
        .map_err(store_refused)?;
    Ok(Json(summary))
}

/// `GET /v1/hypervisor/work-lifecycle/projection?object_ref=..&owner_ref=..`
///
/// The rebuildable active projection for one owner-scoped object, reconstructed
/// from its record log with a complete strict census.
pub(crate) async fn handle_work_lifecycle_projection(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<ObjectQuery>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let object_ref = query.object_ref.unwrap_or_default();
    let owner_ref = query.owner_ref.unwrap_or_default();
    if object_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_lifecycle_object_ref_required",
            "a projection read names the object_ref it reads",
        ));
    }
    let store = WorkLifecycleStore::new(&st.data_dir);
    let projection = owner_scoped_projection(&store, &identity, &object_ref, &owner_ref)?;
    Ok(Json(json!({
        "object_ref": object_ref,
        "projection": projection,
    })))
}

/// `GET /v1/hypervisor/work-lifecycle/records?object_ref=..&owner_ref=..`
///
/// The reconstructed record chain for one owner-scoped object, in append order.
pub(crate) async fn handle_work_lifecycle_records(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<ObjectQuery>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let object_ref = query.object_ref.unwrap_or_default();
    let owner_ref = query.owner_ref.unwrap_or_default();
    if object_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_lifecycle_object_ref_required",
            "a records read names the object_ref it reads",
        ));
    }
    let store = WorkLifecycleStore::new(&st.data_dir);
    // Owner-scope through the projection first, then serve the chain.
    let _projection = owner_scoped_projection(&store, &identity, &object_ref, &owner_ref)?;
    let records = store.read_records(&object_ref).map_err(store_refused)?;
    Ok(Json(json!({
        "object_ref": object_ref,
        "record_count": records.len() as u64,
        "records": records,
    })))
}

/// `POST /v1/hypervisor/work-lifecycle/cancellation-plan`
///
/// Owner-scoped cancellation PLANNING. Derives and persists the fanout plan; it
/// does not execute it and never claims child completion. Body carries
/// `object_ref`, `owner_ref`, and the cancellation intent fields.
pub(crate) async fn handle_work_lifecycle_cancellation_plan(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let object_ref = text(&body, "object_ref");
    let owner_ref = text(&body, "owner_ref");
    if object_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_lifecycle_object_ref_required",
            "a cancellation plan names the object_ref it plans over",
        ));
    }
    let store = WorkLifecycleStore::new(&st.data_dir);
    let _projection = owner_scoped_projection(&store, &identity, object_ref, owner_ref)?;

    // The requester is the authenticated principal, never the request body.
    let requested_by_ref = cancellation_requester(&identity, &body)?;
    let intent = CancellationIntent {
        requested_by_ref,
        reason: text(&body, "reason").to_string(),
        compensation_policy_ref: body
            .get("compensation_policy_ref")
            .and_then(Value::as_str)
            .map(str::to_string),
        effect_reconciliation_policy_ref: body
            .get("effect_reconciliation_policy_ref")
            .and_then(Value::as_str)
            .map(str::to_string),
        timeout_at_ms: body.get("timeout_at_ms").and_then(Value::as_i64),
    };
    let plan = store
        .plan_cancellation(object_ref, &intent, now_ms())
        .map_err(store_refused)?;
    Ok(Json(json!({
        "object_ref": object_ref,
        "cancellation_plan": plan,
        "nonclaim": "The plan derives the required child actions at the admitted head; only child-owner completion receipts prove any child settled. This plan claims no child completion.",
    })))
}

/// `POST /v1/hypervisor/work-lifecycle/compaction`
///
/// Owner-scoped compaction. Writes the immutable archive segment through the
/// current head, then the archive-root/head-bound snapshot. Hot record logs are
/// not pruned. Body carries `object_ref` and `owner_ref`.
pub(crate) async fn handle_work_lifecycle_compaction(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let object_ref = text(&body, "object_ref");
    let owner_ref = text(&body, "owner_ref");
    if object_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_lifecycle_object_ref_required",
            "a compaction names the object_ref it compacts",
        ));
    }
    let store = WorkLifecycleStore::new(&st.data_dir);
    let _projection = owner_scoped_projection(&store, &identity, object_ref, owner_ref)?;
    let report = store.compact(object_ref, now_ms()).map_err(store_refused)?;
    Ok(Json(json!({
        "object_ref": object_ref,
        "archive_ref": report.archive_ref,
        "snapshot_ref": report.snapshot_ref,
        "through_head": report.through_head,
        "archive_root": report.archive_root,
        "archive_segment": report.segment,
        "snapshot": report.snapshot,
        "nonclaim": "Compaction wrote an immutable archive segment before the snapshot; the hot record log is retained, and the snapshot is a checkpoint, never a license to discard the archive.",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT: &str = "work_run://run-1";
    const OWNER: &str = "project://alpha";

    fn genesis() -> Value {
        json!({
            "schema_version": "ioi.work-lifecycle-record.v1",
            "record_id": "work-lifecycle://run-1/0",
            "record_hash": "",
            "record_type": "phase_transition",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "owner_ref": OWNER,
            "expected_head": Value::Null,
            "resulting_head": "",
            "idempotency_key": "genesis-1",
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "authority_grant_refs": [],
            "decision_receipt_ref": Value::Null,
            "evidence_refs": [],
            "receipt_refs": ["receipt://run-1/create"],
            "phase_transition": { "from_phase": Value::Null, "to_phase": "pending" },
            "child_reference": Value::Null,
            "occurred_at_ms": 1_000,
        })
    }

    fn attach(id: &str, key: &str, class: &str, head: &str, at: i64) -> Value {
        json!({
            "schema_version": "ioi.work-lifecycle-record.v1",
            "record_id": format!("work-lifecycle://run-1/{id}"),
            "record_hash": "",
            "record_type": "child_reference",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "owner_ref": OWNER,
            "expected_head": head,
            "resulting_head": "",
            "idempotency_key": key,
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "authority_grant_refs": [],
            "decision_receipt_ref": Value::Null,
            "evidence_refs": [],
            "receipt_refs": [format!("receipt://run-1/{id}")],
            "phase_transition": Value::Null,
            "child_reference": {
                "operation": "attach",
                "relation_kind": "harness_invocation",
                "child_ref": format!("harness_invocation://{id}"),
                "effect_recovery_class": class,
            },
            "occurred_at_ms": at,
        })
    }

    fn phase(id: &str, key: &str, to_phase: &str, head: &str, at: i64) -> Value {
        json!({
            "schema_version": "ioi.work-lifecycle-record.v1",
            "record_id": format!("work-lifecycle://run-1/{id}"),
            "record_hash": "",
            "record_type": "phase_transition",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "owner_ref": OWNER,
            "expected_head": head,
            "resulting_head": "",
            "idempotency_key": key,
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "authority_grant_refs": [],
            "decision_receipt_ref": Value::Null,
            "evidence_refs": [],
            "receipt_refs": [format!("receipt://run-1/{id}")],
            "phase_transition": { "from_phase": "pending", "to_phase": to_phase },
            "child_reference": Value::Null,
            "occurred_at_ms": at,
        })
    }

    fn fresh_store() -> (tempfile::TempDir, WorkLifecycleStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        substrate_store::reset_handle_for_test();
        let store = WorkLifecycleStore::new(dir.path().to_str().unwrap());
        (dir, store)
    }

    #[test]
    fn owner_scope_accepts_the_exact_principal_or_an_authorized_tenant() {
        let (_dir, store) = fresh_store();
        store.append(&genesis()).expect("genesis");

        let principal_owner = substrate_store::request_identity_for_test(OWNER, []);
        assert!(owner_scoped_projection(&store, &principal_owner, OBJECT, OWNER).is_ok());

        let tenant_member =
            substrate_store::request_identity_for_test("user://member", [OWNER.to_string()]);
        assert!(owner_scoped_projection(&store, &tenant_member, OBJECT, OWNER).is_ok());

        let stranger = substrate_store::request_identity_for_test("user://stranger", []);
        let refusal = owner_scoped_projection(&store, &stranger, OBJECT, OWNER)
            .expect_err("unrelated principal must be refused");
        assert_eq!(refusal.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn append_persists_then_reloads_as_a_chain() {
        let (_dir, store) = fresh_store();

        let report = store.append(&genesis()).expect("genesis");
        assert!(!report.replayed);
        let head = report.resulting_head.clone();
        assert!(head.starts_with("sha256:"));
        assert_eq!(report.agentgres_seq, Some(0));

        let head = store
            .append(&attach("a", "k-a", "reversible", &head, 2_000))
            .expect("attach")
            .resulting_head;
        let running = store
            .append(&phase("p1", "k-run", "running", &head, 3_000))
            .expect("phase");

        // The projection rebuilt from the durable log is exact.
        let projection = store.read_projection(OBJECT).expect("projection");
        assert_eq!(projection["active_phase"], json!("running"));
        assert_eq!(projection["record_count"], json!(3));
        assert_eq!(projection["owner_ref"], json!(OWNER));
        assert_eq!(projection["head"], json!(running.resulting_head));
        assert_eq!(
            projection["active_children"]["harness_invocation"][0]["child_ref"],
            json!("harness_invocation://a")
        );

        // The reconstructed chain is in append order and byte-durable.
        let chain = store.read_records(OBJECT).expect("chain");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2]["resulting_head"], json!(running.resulting_head));
    }

    #[test]
    fn refused_append_writes_nothing() {
        let (_dir, store) = fresh_store();
        store.append(&genesis()).expect("genesis");

        // A second genesis on the same object fails closed.
        let mut second = genesis();
        second["idempotency_key"] = json!("genesis-2");
        second["record_id"] = json!("work-lifecycle://run-1/0b");
        let refused = store.append(&second);
        assert!(refused.is_err(), "second genesis must be refused");
        assert_eq!(
            refused.err().unwrap().code(),
            "work_lifecycle_log_duplicate_genesis"
        );

        // Nothing was written by the refusal.
        assert_eq!(store.read_records(OBJECT).expect("chain").len(), 1);
    }

    #[test]
    fn idempotent_replay_writes_no_new_record() {
        let (_dir, store) = fresh_store();
        let first = store.append(&genesis()).expect("genesis");
        assert!(!first.replayed);
        // Exact resubmission of the same genesis bytes replays.
        let replay = store.append(&genesis()).expect("replay");
        assert!(replay.replayed);
        assert_eq!(replay.agentgres_seq, None);
        assert_eq!(store.read_records(OBJECT).expect("chain").len(), 1);
    }

    #[test]
    fn read_rejects_a_tampered_log_is_covered_by_the_kernel() {
        // The store hands the raw payloads to the kernel, so a fork/gap/tamper
        // is refused on read. Prove the store surfaces that refusal rather than
        // a false projection: a stale expected_head is a fork the kernel names.
        let (_dir, store) = fresh_store();
        let genesis_report = store.append(&genesis()).expect("genesis");
        let head = genesis_report.resulting_head;
        store
            .append(&attach("a", "k-a", "none", &head, 2_000))
            .expect("attach");
        // A successor that still binds the genesis head is a fork off a stale
        // predecessor; the kernel refuses it and the store writes nothing.
        let forked = store.append(&attach("b", "k-b", "none", &head, 3_000));
        assert!(forked.is_err());
        assert_eq!(
            forked.err().unwrap().code(),
            "work_lifecycle_log_head_mismatch"
        );
        assert_eq!(store.read_records(OBJECT).expect("chain").len(), 2);
    }

    #[test]
    fn compaction_then_resume_equals_full_replay() {
        let (_dir, store) = fresh_store();
        let mut head = store.append(&genesis()).expect("genesis").resulting_head;
        head = store
            .append(&attach("a", "k-a", "reversible", &head, 2_000))
            .expect("attach")
            .resulting_head;
        head = store
            .append(&phase("p1", "k-run", "running", &head, 3_000))
            .expect("phase")
            .resulting_head;
        let _ = store
            .append(&attach("b", "k-b", "none", &head, 4_000))
            .expect("attach-b");

        let full_projection = store.read_projection(OBJECT).expect("full projection");

        // Compaction writes an immutable archive then a bound snapshot.
        let report = store.compact(OBJECT, 10).expect("compaction");
        assert!(report.archive_root.starts_with("sha256:"));
        assert_eq!(report.snapshot["archive_root"], json!(report.archive_root));
        assert_eq!(report.snapshot["through_head"], json!(report.through_head));

        // Re-compaction of the same head replays the immutable segment.
        let again = store.compact(OBJECT, 11).expect("recompaction");
        assert_eq!(again.archive_root, report.archive_root);

        // Resume from the latest snapshot; the tail is empty because the
        // snapshot binds the current head, so resume equals the full projection.
        let resumed = store.resume(OBJECT).expect("resume").expect("some");
        assert_eq!(resumed.projection, full_projection);

        // The hot record log is retained, never pruned by compaction.
        assert_eq!(store.read_records(OBJECT).expect("chain").len(), 4);
    }

    #[test]
    fn cancellation_plan_persists_and_never_claims_completion() {
        let (_dir, store) = fresh_store();
        let head = store.append(&genesis()).expect("genesis").resulting_head;
        store
            .append(&attach("a", "k-a", "irreversible", &head, 2_000))
            .expect("attach");

        let intent = CancellationIntent {
            requested_by_ref: "actor://owner".into(),
            reason: "stop".into(),
            effect_reconciliation_policy_ref: Some("policy://reconcile".into()),
            ..Default::default()
        };
        let plan = store
            .plan_cancellation(OBJECT, &intent, 5_000)
            .expect("plan");
        assert_eq!(plan["requires_completion_receipt"], json!(true));
        assert!(!plan.to_string().contains("succeeded"));
        assert!(!plan.to_string().contains("completed"));
        // Planning appended no lifecycle record.
        assert_eq!(store.read_records(OBJECT).expect("chain").len(), 2);
        // The plan is durable on its own family.
        assert_eq!(store.family_tails(CANCELLATION_PLANS_NS).unwrap().len(), 1);

        // A compensatable child without a compensation policy is refused.
        // Use a fresh object whose only policy-needing child is compensatable,
        // so the compensation refusal is not shadowed by the irreversible child
        // above (children are evaluated in sorted order).
        let (_dir2, store2) = fresh_store();
        let head2 = store2.append(&genesis()).expect("genesis").resulting_head;
        store2
            .append(&attach("c", "k-c", "compensatable", &head2, 6_000))
            .expect("attach-c");
        let bad_intent = CancellationIntent {
            requested_by_ref: "actor://owner".into(),
            reason: "stop".into(),
            ..Default::default()
        };
        let refused = store2.plan_cancellation(OBJECT, &bad_intent, 7_000);
        assert_eq!(
            refused.err().unwrap().code(),
            "work_lifecycle_cancellation_compensation_policy_required"
        );
    }

    #[test]
    fn status_summary_counts_durable_families() {
        let (_dir, store) = fresh_store();
        assert_eq!(
            store.status_summary().unwrap()["durable_family_object_counts"][RECORDS_NS],
            json!(0)
        );
        let head = store.append(&genesis()).expect("genesis").resulting_head;
        store
            .append(&phase("p1", "k-run", "running", &head, 2_000))
            .expect("phase");
        let summary = store.status_summary().expect("summary");
        assert_eq!(summary["kernel_present"], json!(true));
        assert_eq!(
            summary["durable_family_object_counts"][RECORDS_NS],
            json!(1)
        );
        assert_eq!(
            summary["durable_family_object_counts"][PROJECTIONS_NS],
            json!(1)
        );
        assert_eq!(
            summary.pointer("/live_owner_route_bindings/0/object_kind"),
            Some(&json!("goal_run"))
        );
        assert_eq!(
            summary.pointer("/live_owner_route_bindings/1/object_kind"),
            Some(&json!("outcome_room"))
        );
        let kinds = summary["per_kind_lifecycle_counts"].as_array().unwrap();
        assert_eq!(kinds.len(), 1);
        assert_eq!(kinds[0]["object_kind"], json!("work_run"));
        assert_eq!(kinds[0]["object_count"], json!(1));
        assert_eq!(kinds[0]["record_count"], json!(2));
    }

    #[test]
    fn idempotent_replay_repairs_a_missing_projection_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        substrate_store::reset_handle_for_test();
        let data_dir = dir.path().to_str().unwrap().to_string();
        let store = WorkLifecycleStore::new(&data_dir);

        // Simulate a crash between record commit and projection persist: admit
        // ONLY the record event, exactly as `append` would, with no projection.
        let core = WorkLifecycleLogCore;
        let planned = core.plan_append(&[], &genesis()).expect("plan genesis");
        assert_eq!(planned.outcome, AppendOutcome::Appended);
        let tail = object_stream_tail(OBJECT);
        let record_hash = planned.record["record_hash"].as_str().unwrap().to_string();
        substrate_store::admit_event_stream_operation(
            &data_dir,
            RECORDS_NS,
            &tail,
            RECORD_OP_KIND,
            None,
            &planned.record,
            clamp_ms(&planned.record),
            &record_hash,
        )
        .expect("record admitted");

        // The projection checkpoint is absent — the crash.
        assert!(
            substrate_store::read_event_stream_operation(&data_dir, PROJECTIONS_NS, &tail)
                .unwrap()
                .is_none(),
            "precondition: projection checkpoint must be missing"
        );

        // An idempotent replay of the exact genesis restores the durable
        // projection before returning, so a crashed caller heals by retry.
        let report = store.append(&genesis()).expect("replay");
        assert!(report.replayed);
        let durable =
            substrate_store::read_event_stream_operation(&data_dir, PROJECTIONS_NS, &tail)
                .unwrap()
                .expect("projection restored")
                .operation
                .payload;
        assert_eq!(durable["active_phase"], json!("pending"));
        assert_eq!(durable["record_count"], json!(1));
        assert_eq!(durable["head"], json!(record_hash));
    }

    #[test]
    fn replaying_an_old_record_keeps_the_latest_projection_at_the_current_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        substrate_store::reset_handle_for_test();
        let data_dir = dir.path().to_str().unwrap().to_string();
        let store = WorkLifecycleStore::new(&data_dir);

        // Land a genesis and then a later phase, so the current head is beyond
        // the genesis record.
        let head = store.append(&genesis()).expect("genesis").resulting_head;
        let running = store
            .append(&phase("p1", "k-run", "running", &head, 2_000))
            .expect("phase");
        let current_head = running.resulting_head.clone();
        let tail = object_stream_tail(OBJECT);
        let records_before = store.read_records(OBJECT).expect("chain").len();

        // Replay the OLD genesis idempotency key after the later phase landed.
        let report = store.append(&genesis()).expect("replay old genesis");
        assert!(report.replayed);
        // The returned projection reflects the CURRENT head, not the old genesis
        // state — a replay of an earlier record never regresses the projection.
        assert_eq!(report.projection["active_phase"], json!("running"));
        assert_eq!(report.projection["record_count"], json!(2));
        assert_eq!(report.projection["head"], json!(current_head));

        // The durable LATEST projection is still at the current head/phase.
        let durable =
            substrate_store::read_event_stream_operation(&data_dir, PROJECTIONS_NS, &tail)
                .unwrap()
                .expect("projection")
                .operation
                .payload;
        assert_eq!(durable["active_phase"], json!("running"));
        assert_eq!(durable["record_count"], json!(2));
        assert_eq!(durable["head"], json!(current_head));

        // The replay wrote no new lifecycle record.
        assert_eq!(
            store.read_records(OBJECT).expect("chain").len(),
            records_before
        );
    }

    #[test]
    fn cancellation_route_rejects_requester_substitution() {
        let identity = substrate_store::request_identity_for_test(
            "user://acme/op",
            ["org://acme".to_string()],
        );

        // A body asserting a different requester is refused as substitution.
        let foreign = json!({ "requested_by_ref": "user://intruder" });
        let refused = cancellation_requester(&identity, &foreign)
            .err()
            .expect("refused");
        assert_eq!(refused.0, StatusCode::FORBIDDEN);
        assert_eq!(
            refused.1["error"]["code"],
            json!("work_lifecycle_requester_substitution")
        );

        // An omitted or matching field yields the authenticated principal.
        assert_eq!(
            cancellation_requester(&identity, &json!({})).unwrap(),
            "user://acme/op"
        );
        assert_eq!(
            cancellation_requester(&identity, &json!({ "requested_by_ref": "user://acme/op" }))
                .unwrap(),
            "user://acme/op"
        );
    }

    #[test]
    fn read_rejects_a_foreign_tail_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        substrate_store::reset_handle_for_test();
        let data_dir = dir.path().to_str().unwrap().to_string();
        let store = WorkLifecycleStore::new(&data_dir);

        // A legitimate genesis for run-1.
        store.append(&genesis()).expect("genesis");
        let tail = object_stream_tail(OBJECT);
        let head = substrate_store::read_event_stream_operation(&data_dir, RECORDS_NS, &tail)
            .unwrap()
            .unwrap()
            .head;

        // Mis-file a foreign object's genesis record INTO run-1's stream tail.
        let core = WorkLifecycleLogCore;
        let mut foreign = genesis();
        foreign["object_ref"] = json!("work_run://run-2");
        foreign["idempotency_key"] = json!("genesis-2");
        let foreign_record = core
            .plan_append(&[], &foreign)
            .expect("foreign plan")
            .record;
        let foreign_hash = foreign_record["record_hash"].as_str().unwrap().to_string();
        substrate_store::admit_event_stream_operation(
            &data_dir,
            RECORDS_NS,
            &tail,
            RECORD_OP_KIND,
            Some(head.as_str()),
            &foreign_record,
            clamp_ms(&foreign_record),
            &foreign_hash,
        )
        .expect("foreign mis-filed");

        // Reads for run-1 refuse the foreign-tail record rather than folding
        // another object's record into this object's chain or projection.
        assert_eq!(
            store.read_records(OBJECT).unwrap_err().code(),
            "work_lifecycle_foreign_tail_record"
        );
        assert_eq!(
            store.read_projection(OBJECT).unwrap_err().code(),
            "work_lifecycle_foreign_tail_record"
        );
    }

    #[test]
    fn compaction_repairs_a_missing_snapshot_after_a_persisted_archive() {
        let (_dir, store) = fresh_store();
        let head = store.append(&genesis()).expect("genesis").resulting_head;
        store
            .append(&attach("a", "k-a", "none", &head, 2_000))
            .expect("attach");

        // Persist ONLY the archive segment: a crash after the immutable archive
        // is durable but before the snapshot.
        let payloads = store.record_payloads_for(OBJECT).expect("payloads");
        let through = payloads
            .iter()
            .filter_map(|record| record.get("resulting_head").and_then(Value::as_str))
            .last()
            .map(str::to_string)
            .expect("head");
        let head_hex = through.strip_prefix("sha256:").unwrap_or(&through);
        let object_tail = object_stream_tail(OBJECT);
        let archive_ref = format!("work-lifecycle-archive://{object_tail}/seg-{head_hex}");
        let segment = WorkLifecycleLogCore
            .plan_archive_segment(&archive_ref, &payloads, &through, 10)
            .expect("segment");
        store
            .persist_archive(&archive_ref, &segment, 10)
            .expect("archive persisted");
        assert!(
            store.latest_snapshot(OBJECT).unwrap().is_none(),
            "precondition: snapshot must be missing"
        );

        // Compaction finds the durable archive and repairs the missing snapshot
        // rather than re-minting the segment.
        let report = store
            .compact(OBJECT, 11)
            .expect("compaction repairs snapshot");
        assert_eq!(
            report.archive_root,
            segment["archive_root"].as_str().unwrap()
        );
        assert_eq!(report.snapshot["through_head"], json!(through));
        assert!(store.latest_snapshot(OBJECT).unwrap().is_some());
    }
}
