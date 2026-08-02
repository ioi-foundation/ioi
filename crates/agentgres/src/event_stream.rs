//! Owner-namespaced event-stream admission — the canonical discipline for
//! crossing an atomic Agentgres transition with an exact expected head.
//!
//! This module was LIFTED here from the daemon binary module
//! (`hypervisor_daemon_routes::substrate_store`) on 2026-08-02 under
//! `m5-agentgres-durable-event-subscription-successor`. The lift was a move,
//! not a copy: the binary-module implementation was deleted in the same
//! commit, so there is exactly one admission discipline in the tree and no
//! second copy to drift.
//!
//! Three properties are structural rather than documentary:
//!
//! 1. NO HANDLE-ACQUISITION PATH. Every entry point takes `&MuxHandle` and
//!    this module cannot obtain one — it never calls `spawn_mux_writer*`,
//!    `MuxEngine::open`, or any other opener. "Exactly one handle steward per
//!    process" is therefore an API-surface fact, not a convention someone has
//!    to remember. The steward lives in the daemon, which owns the writer
//!    lock, the generation check, and the process-local cache as one
//!    mechanism.
//!
//! 2. THE WHOLE DISCIPLINE TRAVELS TOGETHER. Canonicality gates, idempotent
//!    re-projection, the same-key-different-bytes refusal, head-conflict
//!    mapping, durability confirmation (with its fault-injection hook), and
//!    the ack-versus-projection cross-check are one unit. Lifting the CAS
//!    while leaving the cross-check behind would move the mechanism and
//!    strand the proof that the mechanism worked.
//!
//! 3. GENERICITY. The owner namespace is DATA. Nothing here branches on a
//!    namespace value and no consumer vocabulary (GoalRun, thread, room)
//!    appears in any admission-required field. Two unrelated owners traverse
//!    identical code; that is what the >= 2-namespace proof asserts.

use crate::mux::{ExactProjection, MuxAdmitError, MuxHandle};
use crate::{Operation, Refusal};
use serde_json::Value;
use std::path::Path;

/// Typed refusal vocabulary for event-stream admission.
///
/// Every failure mode is NAMED. A caller cannot distinguish "the substrate
/// refused" from "the wiring is absent" by inspecting an opaque error string,
/// and no variant here is satisfiable by falling back to another store: a
/// refusal is the outcome, never a signal to try somewhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// Stream coordinates, operation kind, expected head, or idempotency key
    /// is not canonical. Carries which one, because "not canonical" without a
    /// subject is a refusal the caller cannot act on.
    CoordinatesNotCanonical(&'static str),
    /// An operation is already admitted under this idempotency key with
    /// DIFFERENT bytes. Re-admitting identical bytes is idempotent and
    /// returns the prior fact; re-admitting different bytes under the same
    /// key is a caller defect and is refused by its own name rather than
    /// surfacing as an incidental head conflict.
    SameKeyDifferentBytes { idem_key: String },
    /// The stream advanced past the supplied expected head (or exists when
    /// absence was required). The caller re-reads and retries against the
    /// exact current head; it never retries unconditionally.
    HeadConflict,
    /// The admitted append could not be confirmed durable. An unconfirmed
    /// append is not an admitted fact, so this refuses rather than returning
    /// a projection the substrate might lose.
    DurabilityUnconfirmed(String),
    /// The exact projection disagrees with the ack that produced it. This
    /// cannot be recovered from and must never be papered over: it means the
    /// engine acknowledged something other than what it stored.
    ProjectionDisagreesWithAck,
    /// The substrate itself failed (I/O, writer channel, engine error).
    SubstrateUnavailable(String),
    /// No admission capability was injected at this boundary. This is the
    /// fail-closed refusal: an un-injected build REFUSES, and never reverts
    /// to a legacy append-only file. Reverting would let a wiring gap decay
    /// the substrate back to the spine this cut replaced, silently and with
    /// every bar still green.
    CapabilityAbsent,
}

impl AdmissionRefusal {
    /// Stable machine code for this refusal. Route layers map these to wire
    /// codes; verifiers assert on them.
    pub fn code(&self) -> &'static str {
        match self {
            AdmissionRefusal::CoordinatesNotCanonical(_) => {
                "event_stream_coordinates_not_canonical"
            }
            AdmissionRefusal::SameKeyDifferentBytes { .. } => {
                "event_stream_same_key_different_bytes"
            }
            AdmissionRefusal::HeadConflict => "event_stream_expected_head_conflict",
            AdmissionRefusal::DurabilityUnconfirmed(_) => "event_stream_durability_unconfirmed",
            AdmissionRefusal::ProjectionDisagreesWithAck => {
                "event_stream_projection_disagrees_with_ack"
            }
            AdmissionRefusal::SubstrateUnavailable(_) => "event_stream_admission_failed",
            AdmissionRefusal::CapabilityAbsent => "event_stream_admission_capability_absent",
        }
    }
}

impl std::fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionRefusal::CoordinatesNotCanonical(subject) => {
                write!(f, "event stream {subject} is not canonical")
            }
            AdmissionRefusal::SameKeyDifferentBytes { idem_key } => write!(
                f,
                "idempotency key {idem_key} is already admitted with different bytes"
            ),
            AdmissionRefusal::HeadConflict => {
                write!(f, "event stream Agentgres head conflict")
            }
            AdmissionRefusal::DurabilityUnconfirmed(detail) => {
                write!(f, "event stream admission durability unconfirmed: {detail}")
            }
            AdmissionRefusal::ProjectionDisagreesWithAck => write!(
                f,
                "event stream Agentgres projection disagrees with its admission ack"
            ),
            AdmissionRefusal::SubstrateUnavailable(detail) => {
                write!(f, "event stream Agentgres admission failed: {detail}")
            }
            AdmissionRefusal::CapabilityAbsent => write!(
                f,
                "no event-stream admission capability is injected at this boundary"
            ),
        }
    }
}

impl std::error::Error for AdmissionRefusal {}

/// One admitted append, as the caller states it.
#[derive(Debug, Clone)]
pub struct EventAdmission<'a> {
    pub owner_namespace: &'a str,
    pub stream_tail: &'a str,
    pub op_kind: &'a str,
    /// `None` requires the stream to be absent; `Some(head)` is
    /// compare-and-swap against that exact head.
    pub expected_head: Option<&'a str>,
    pub payload: &'a Value,
    pub recorded_at_ms: u64,
    pub idem_key: &'a str,
}

/// The admission capability, as injected across a process boundary.
///
/// This trait is a CAPABILITY SURFACE, not a convenience: each method is a
/// statement about what the holder is PERMITTED to do with the substrate. It
/// is bounded at these four operations by owner ruling (2026-08-02); a fifth
/// requires a filed record arguing for it, because an unbounded capability
/// trait converges on direct substrate access with extra ceremony.
pub trait EventStreamAdmission: Send + Sync {
    /// Admit one event append against the stream's exact head.
    fn admit_event(&self, request: EventAdmission<'_>)
        -> Result<ExactProjection, AdmissionRefusal>;

    /// Read the exact admitted head of one stream, without admitting.
    fn read_head(
        &self,
        owner_namespace: &str,
        stream_tail: &str,
    ) -> Result<Option<ExactProjection>, AdmissionRefusal>;

    /// Admit one subscription-lease state transition. Leases mint no chain of
    /// their own: the transition is admitted through canonical Agentgres on
    /// the lease's own object key.
    fn admit_lease_transition(
        &self,
        request: EventAdmission<'_>,
    ) -> Result<ExactProjection, AdmissionRefusal>;

    /// Advance one lease's delivery checkpoint. A checkpoint is an admitted
    /// fact, not a scalar the delivery adapter may substitute.
    fn advance_checkpoint(
        &self,
        request: EventAdmission<'_>,
    ) -> Result<ExactProjection, AdmissionRefusal>;
}

/// Confirm the substrate log is durable on disk.
///
/// The fault-injection hook travels WITH the discipline: a durability
/// confirmation whose failure path is unreachable in test is a confirmation
/// nobody has watched fail. `IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE=1`
/// forces the refusal, and the env-var name is preserved verbatim from the
/// pre-lift implementation so the M4 fault-injection proofs keep exercising
/// this exact path.
pub fn confirm_log_durability(engine_dir: &Path) -> Result<(), AdmissionRefusal> {
    if std::env::var("IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(AdmissionRefusal::DurabilityUnconfirmed(
            "test-forced required-admission durability failure".to_owned(),
        ));
    }
    let sync = |result: std::io::Result<()>| {
        result.map_err(|error| AdmissionRefusal::DurabilityUnconfirmed(error.to_string()))
    };
    sync(
        std::fs::File::open(engine_dir.join("muxlog.bin"))
            .and_then(|file| file.sync_all())
            .map(|_| ()),
    )?;
    sync(
        std::fs::File::open(engine_dir)
            .and_then(|file| file.sync_all())
            .map(|_| ()),
    )
}

fn canonical_component(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Validate the coordinates that identify one owner-namespaced stream.
/// Exposed so callers can refuse malformed coordinates before acquiring a
/// handle rather than after.
pub fn validate_stream_coordinates(
    owner_namespace: &str,
    stream_tail: &str,
) -> Result<(), AdmissionRefusal> {
    if !canonical_component(owner_namespace, 96)
        || !owner_namespace.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(AdmissionRefusal::CoordinatesNotCanonical("owner namespace"));
    }
    if !canonical_component(stream_tail, 160) {
        return Err(AdmissionRefusal::CoordinatesNotCanonical("tail"));
    }
    Ok(())
}

fn validate_admission(request: &EventAdmission<'_>) -> Result<(), AdmissionRefusal> {
    validate_stream_coordinates(request.owner_namespace, request.stream_tail)?;
    if request.op_kind.is_empty()
        || request.op_kind.len() > 96
        || !request.op_kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
    {
        return Err(AdmissionRefusal::CoordinatesNotCanonical("operation kind"));
    }
    if request.expected_head.is_some_and(|head| {
        !head.strip_prefix("sha256:").is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    }) {
        return Err(AdmissionRefusal::CoordinatesNotCanonical("expected head"));
    }
    if request.idem_key.is_empty() || request.idem_key.len() > 256 {
        return Err(AdmissionRefusal::CoordinatesNotCanonical("idempotency key"));
    }
    Ok(())
}

/// Admit one operation against the exact Agentgres head of one
/// owner-namespaced stream.
///
/// Takes `&MuxHandle` and cannot obtain one: see the module note on handle
/// stewardship. `engine_dir` is the substrate directory the handle was opened
/// over, used only to confirm durability of the append this call made.
pub fn admit_event_stream_operation(
    handle: &MuxHandle,
    engine_dir: &Path,
    request: EventAdmission<'_>,
) -> Result<ExactProjection, AdmissionRefusal> {
    validate_admission(&request)?;

    let object_ref =
        crate::refs::event_stream_object_ref(request.owner_namespace, request.stream_tail);
    let domain = crate::refs::event_stream_domain(request.owner_namespace, request.stream_tail);
    let operation = Operation {
        domain: domain.clone(),
        object_ref: object_ref.clone(),
        op_kind: request.op_kind.to_owned(),
        expected_head: request.expected_head.map(str::to_owned),
        expected_absent: request.expected_head.is_none(),
        payload: request.payload.clone(),
        recorded_at_ms: request.recorded_at_ms,
        idem_key: request.idem_key.to_owned(),
    };

    let projected = handle
        .project_exact(&domain, &object_ref)
        .map_err(|error| AdmissionRefusal::SubstrateUnavailable(error.to_string()))?;
    if let Some(existing) = projected {
        if existing.operation == operation {
            // Identical bytes under an already-admitted key: idempotent, and
            // the durability of the ORIGINAL append is still confirmed before
            // the prior fact is handed back as current.
            confirm_log_durability(engine_dir)?;
            return Ok(existing);
        }
        if existing.operation.idem_key == operation.idem_key {
            // Same key, different bytes. Named here rather than left to
            // surface as an incidental head conflict, because the two have
            // different causes and different caller remedies.
            return Err(AdmissionRefusal::SameKeyDifferentBytes {
                idem_key: operation.idem_key,
            });
        }
    }

    let ack = match handle.admit(operation.clone()) {
        Ok(ack) => ack,
        Err(MuxAdmitError::Refused(
            Refusal::ExpectedHeadConflict { .. } | Refusal::ExpectedAbsentConflict { .. },
        )) => return Err(AdmissionRefusal::HeadConflict),
        Err(error) => return Err(AdmissionRefusal::SubstrateUnavailable(error.to_string())),
    };
    confirm_log_durability(engine_dir)?;
    let exact = handle
        .project_exact(&domain, &object_ref)
        .map_err(|error| AdmissionRefusal::SubstrateUnavailable(error.to_string()))?
        .ok_or_else(|| {
            AdmissionRefusal::SubstrateUnavailable(
                "event stream Agentgres admission has no exact projection".to_owned(),
            )
        })?;
    if exact.operation != operation
        || exact.seq != ack.seq
        || exact.head != ack.new_head
        || exact.admission_batch_seq != ack.batch_seq
        || exact.admission_root != ack.root
    {
        return Err(AdmissionRefusal::ProjectionDisagreesWithAck);
    }
    Ok(exact)
}

/// Read the exact current admitted head for one owner-namespaced stream.
/// Non-canonical coordinates read as absent rather than as an error: a read
/// asks whether a stream exists, and coordinates that could never name one
/// answer that question with `None`.
pub fn read_event_stream_head(
    handle: &MuxHandle,
    owner_namespace: &str,
    stream_tail: &str,
) -> Result<Option<ExactProjection>, AdmissionRefusal> {
    if validate_stream_coordinates(owner_namespace, stream_tail).is_err() {
        return Ok(None);
    }
    let object_ref = crate::refs::event_stream_object_ref(owner_namespace, stream_tail);
    let domain = crate::refs::event_stream_domain(owner_namespace, stream_tail);
    handle
        .project_exact(&domain, &object_ref)
        .map_err(|error| AdmissionRefusal::SubstrateUnavailable(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Refusal codes appear in route responses, verifier assertions, and
    // retained evidence. Renaming one is a wire change, not a refactor.
    #[test]
    fn refusal_codes_are_pinned() {
        assert_eq!(
            AdmissionRefusal::CoordinatesNotCanonical("tail").code(),
            "event_stream_coordinates_not_canonical"
        );
        assert_eq!(
            AdmissionRefusal::SameKeyDifferentBytes {
                idem_key: "k".into()
            }
            .code(),
            "event_stream_same_key_different_bytes"
        );
        assert_eq!(
            AdmissionRefusal::HeadConflict.code(),
            "event_stream_expected_head_conflict"
        );
        assert_eq!(
            AdmissionRefusal::CapabilityAbsent.code(),
            "event_stream_admission_capability_absent"
        );
    }

    // Coordinate validation is namespace-GENERIC: two unrelated owners are
    // accepted and rejected by identical rules. A gate that special-cased a
    // namespace would show up here as an asymmetry.
    #[test]
    fn coordinate_validation_is_namespace_generic() {
        for namespace in ["thread-orchestration", "automation-scheduler"] {
            assert!(validate_stream_coordinates(namespace, "s1").is_ok());
            assert!(validate_stream_coordinates(namespace, "").is_err());
            assert!(validate_stream_coordinates(namespace, "../escape").is_err());
        }
        assert!(validate_stream_coordinates("Thread-Orchestration", "s1").is_err());
        assert!(validate_stream_coordinates("", "s1").is_err());
    }

    #[test]
    fn expected_head_must_be_a_full_sha256() {
        let payload = Value::Null;
        let request = |head| EventAdmission {
            owner_namespace: "automation-scheduler",
            stream_tail: "s1",
            op_kind: "event_stream.append",
            expected_head: head,
            payload: &payload,
            recorded_at_ms: 0,
            idem_key: "k1",
        };
        let full = format!("sha256:{}", "a".repeat(64));
        let unprefixed = "a".repeat(64);
        assert!(validate_admission(&request(None)).is_ok());
        assert!(validate_admission(&request(Some(&full))).is_ok());
        assert!(validate_admission(&request(Some("sha256:short"))).is_err());
        assert!(validate_admission(&request(Some(&unprefixed))).is_err());
    }

    // The durability fault-injection hook must be reachable from a test, or
    // the confirmation is a bar nobody has watched fire. This asserts the
    // hook itself, under a temp dir that has no log at all.
    #[test]
    fn forced_durability_failure_refuses() {
        std::env::set_var("IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE", "1");
        let refusal = confirm_log_durability(Path::new("/nonexistent")).unwrap_err();
        std::env::remove_var("IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE");
        assert_eq!(refusal.code(), "event_stream_durability_unconfirmed");
    }
}
