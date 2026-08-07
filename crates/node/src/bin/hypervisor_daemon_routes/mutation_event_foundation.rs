//! Shared admission boundary for owner-scoped daemon mutations.
//!
//! This module deliberately does not create a second journal or receipt store.
//! Agentgres' owner-namespaced operation chain is the durable operation, event,
//! compare-and-swap, idempotency, and hash-linked receipt authority.  The
//! boundary here adds the request-scope proof that the generic substrate cannot
//! infer: the authenticated principal must be the principal that reserved the
//! resource, its current membership must still authorize the exact tenant, and
//! the resource kind/ref used by the handler must match that immutable scope.
//!
//! A route using this boundary therefore gets one uniform answer to the load-
//! bearing questions:
//! * same owner + key + logical bytes replays the original admitted fact;
//! * same owner + key + changed bytes refuses;
//! * a successor requires the exact current head;
//! * a different principal cannot borrow another principal's key or receipt;
//! * success is returned only after Agentgres confirms log durability and the
//!   exact projection agrees with the admission acknowledgement; and
//! * replay/reconnect is rebuilt from the durable history after restart.

use agentgres::event_stream::AdmissionRefusal;
use agentgres::mux::ExactProjection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use super::substrate_store::{RequestIdentity, RequestResourceScope, RequestScopeRefusal};

pub(crate) struct ScopedMutation<'a> {
    pub(crate) identity: &'a RequestIdentity,
    pub(crate) scope: &'a RequestResourceScope,
    pub(crate) resource_kind: &'a str,
    pub(crate) resource_ref: &'a str,
    pub(crate) owner_namespace: &'a str,
    pub(crate) stream_tail: &'a str,
    pub(crate) op_kind: &'a str,
    pub(crate) expected_head: Option<&'a str>,
    pub(crate) payload: &'a Value,
    pub(crate) idempotency_key: &'a str,
    pub(crate) recorded_at_ms: u64,
}

#[derive(Debug)]
pub(crate) enum MutationRefusal {
    Scope(RequestScopeRefusal),
    IdempotencyKeyInvalid,
    GenesisExpectedHeadPresent,
    SuccessorExpectedHeadRequired,
    RequestFingerprintFailed(String),
    Admission(AdmissionRefusal),
}

impl MutationRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Scope(error) => error.code(),
            Self::IdempotencyKeyInvalid => "mutation_idempotency_key_invalid",
            Self::GenesisExpectedHeadPresent => "mutation_genesis_expected_head_present",
            Self::SuccessorExpectedHeadRequired => "mutation_successor_expected_head_required",
            Self::RequestFingerprintFailed(_) => "mutation_request_fingerprint_failed",
            Self::Admission(error) => error.code(),
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Scope(error) => error.message(),
            Self::IdempotencyKeyInvalid => {
                "idempotency_key is required, must be at most 256 bytes, and may not contain control characters".into()
            }
            Self::GenesisExpectedHeadPresent => {
                "a genesis mutation requires absence and cannot carry expected_head".into()
            }
            Self::SuccessorExpectedHeadRequired => {
                "a successor mutation must compare-and-swap against an explicit expected_head".into()
            }
            Self::RequestFingerprintFailed(message) => message.clone(),
            Self::Admission(error) => error.to_string(),
        }
    }
}

pub(crate) struct MutationCommit {
    pub(crate) projection: ExactProjection,
    pub(crate) replayed: bool,
    /// Stable logical-command fingerprint.  Wall-clock and expected-head are
    /// intentionally excluded, matching Agentgres replay identity: a retry
    /// after an ambiguous response observes a newer head but is still the same
    /// command.
    pub(crate) request_fingerprint: String,
    pub(crate) operation_ref: String,
    pub(crate) receipt_ref: String,
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn validate_scope_fields(
    authenticated_principal_ref: &str,
    authorized_tenant_refs: &BTreeSet<String>,
    scope: &RequestResourceScope,
    resource_kind: &str,
    resource_ref: &str,
) -> Result<(), RequestScopeRefusal> {
    if scope.resource_kind != resource_kind || scope.resource_ref != resource_ref {
        return Err(RequestScopeRefusal::ResourceScopeRequired);
    }
    if scope.principal_ref != authenticated_principal_ref
        || !authorized_tenant_refs.contains(&scope.tenant_ref)
    {
        return Err(RequestScopeRefusal::ResourceScopeRequired);
    }
    if scope.tenant_ref != scope.owner_ref {
        return Err(RequestScopeRefusal::ResourceOwnerMismatch);
    }
    Ok(())
}

fn validate_scope(request: &ScopedMutation<'_>) -> Result<(), MutationRefusal> {
    validate_scope_fields(
        &request.identity.principal_ref,
        &request.identity.tenant_refs,
        request.scope,
        request.resource_kind,
        request.resource_ref,
    )
    .map_err(MutationRefusal::Scope)
}

fn fingerprint(request: &ScopedMutation<'_>) -> Result<String, MutationRefusal> {
    let material = json!({
        "schema_version": "ioi.owner-scoped-mutation-command.v1",
        "principal_ref": request.identity.principal_ref,
        "tenant_ref": request.scope.tenant_ref,
        "owner_ref": request.scope.owner_ref,
        "resource_kind": request.resource_kind,
        "resource_ref": request.resource_ref,
        "owner_namespace": request.owner_namespace,
        "stream_tail": request.stream_tail,
        "operation_kind": request.op_kind,
        "idempotency_key": request.idempotency_key,
        "payload": request.payload,
    });
    serde_jcs::to_vec(&material)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| MutationRefusal::RequestFingerprintFailed(error.to_string()))
}

/// Admit one owner-scoped mutation through the canonical Agentgres chain.
///
/// `genesis=true` means expected-absent.  Every successor must carry an exact
/// expected head; the helper never reads a head on the caller's behalf because
/// read-then-default silently weakens compare-and-swap under concurrency.
pub(crate) fn admit_owner_scoped_mutation(
    data_dir: &str,
    genesis: bool,
    request: ScopedMutation<'_>,
) -> Result<MutationCommit, MutationRefusal> {
    validate_scope(&request)?;
    if !valid_idempotency_key(request.idempotency_key) {
        return Err(MutationRefusal::IdempotencyKeyInvalid);
    }
    if genesis && request.expected_head.is_some() {
        return Err(MutationRefusal::GenesisExpectedHeadPresent);
    }
    if !genesis && request.expected_head.is_none() {
        return Err(MutationRefusal::SuccessorExpectedHeadRequired);
    }
    let request_fingerprint = fingerprint(&request)?;
    let admitted = super::substrate_store::admit_event_stream_operation(
        data_dir,
        request.owner_namespace,
        request.stream_tail,
        request.op_kind,
        request.expected_head,
        request.payload,
        request.recorded_at_ms,
        request.idempotency_key,
    )
    .map_err(MutationRefusal::Admission)?;
    let projection = admitted.projection;
    let operation_ref = agentgres::refs::event_stream_operation_ref(
        request.owner_namespace,
        request.stream_tail,
        projection.seq,
        &projection.head,
    );
    let receipt_ref = agentgres::refs::event_stream_receipt_ref(
        request.owner_namespace,
        request.stream_tail,
        projection.admission_batch_seq,
        &projection.admission_root,
    );
    Ok(MutationCommit {
        projection,
        replayed: admitted.replayed,
        request_fingerprint,
        operation_ref,
        receipt_ref,
    })
}

/// Authorize and read one exact head.  Owner filtering is enforced before the
/// substrate read, so a different principal cannot use a read as an existence
/// oracle for another principal's object.
pub(crate) fn read_owner_scoped_head(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    resource_kind: &str,
    resource_ref: &str,
    owner_namespace: &str,
    stream_tail: &str,
) -> Result<Option<ExactProjection>, MutationRefusal> {
    validate_scope_fields(
        &identity.principal_ref,
        &identity.tenant_refs,
        scope,
        resource_kind,
        resource_ref,
    )
    .map_err(MutationRefusal::Scope)?;
    super::substrate_store::read_event_stream_operation(data_dir, owner_namespace, stream_tail)
        .map_err(MutationRefusal::Admission)
}

/// Authorize and replay a complete stream history from durable truth.
pub(crate) fn read_owner_scoped_history(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    resource_kind: &str,
    resource_ref: &str,
    owner_namespace: &str,
    stream_tail: &str,
) -> Result<Vec<ExactProjection>, MutationRefusal> {
    validate_scope_fields(
        &identity.principal_ref,
        &identity.tenant_refs,
        scope,
        resource_kind,
        resource_ref,
    )
    .map_err(MutationRefusal::Scope)?;
    super::substrate_store::read_event_stream_history(data_dir, owner_namespace, stream_tail)
        .map_err(MutationRefusal::Admission)
}

/// Verify that a persisted checkpoint still names an exact retained event.
/// A missing sequence or changed head is a typed resync requirement, never an
/// empty successful delivery.
pub(crate) fn checkpoint_is_retained(
    history: &[ExactProjection],
    acknowledged_seq: u64,
    acknowledged_head: &str,
) -> bool {
    history
        .iter()
        .any(|entry| entry.seq == acknowledged_seq && entry.head == acknowledged_head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static DURABILITY_FAULT_ENV: Mutex<()> = Mutex::new(());

    fn scope(principal: &str, tenant: &str) -> RequestResourceScope {
        RequestResourceScope {
            resource_kind: "test-object".into(),
            resource_ref: "test://object/1".into(),
            principal_ref: principal.into(),
            tenant_ref: tenant.into(),
            owner_ref: tenant.into(),
            correlation_ref: "correlation://test/1".into(),
        }
    }

    fn request<'a>(
        identity: &'a RequestIdentity,
        scope: &'a RequestResourceScope,
        namespace: &'a str,
        payload: &'a Value,
        key: &'a str,
        expected_head: Option<&'a str>,
    ) -> ScopedMutation<'a> {
        ScopedMutation {
            identity,
            scope,
            resource_kind: "test-object",
            resource_ref: "test://object/1",
            owner_namespace: namespace,
            stream_tail: "object-1",
            op_kind: if expected_head.is_some() {
                "event_stream.test_updated"
            } else {
                "event_stream.test_created"
            },
            expected_head,
            payload,
            idempotency_key: key,
            recorded_at_ms: 1,
        }
    }

    #[test]
    fn scope_proof_refuses_cross_principal_and_cross_tenant_borrowing() {
        let allowed = BTreeSet::from(["org://one".to_string()]);
        let mine = scope("user://one", "org://one");
        assert!(validate_scope_fields(
            "user://one",
            &allowed,
            &mine,
            "test-object",
            "test://object/1"
        )
        .is_ok());
        assert!(matches!(
            validate_scope_fields(
                "user://two",
                &allowed,
                &mine,
                "test-object",
                "test://object/1"
            ),
            Err(RequestScopeRefusal::ResourceScopeRequired)
        ));
        assert!(matches!(
            validate_scope_fields(
                "user://one",
                &BTreeSet::from(["org://two".to_string()]),
                &mine,
                "test-object",
                "test://object/1"
            ),
            Err(RequestScopeRefusal::ResourceScopeRequired)
        ));
    }

    #[test]
    fn scope_proof_binds_exact_resource_coordinates() {
        let allowed = BTreeSet::from(["org://one".to_string()]);
        let mine = scope("user://one", "org://one");
        assert!(validate_scope_fields(
            "user://one",
            &allowed,
            &mine,
            "different-kind",
            "test://object/1"
        )
        .is_err());
        assert!(validate_scope_fields(
            "user://one",
            &allowed,
            &mine,
            "test-object",
            "test://object/2"
        )
        .is_err());
    }

    #[test]
    fn idempotency_validation_is_closed_and_bounded() {
        assert!(valid_idempotency_key("one"));
        assert!(!valid_idempotency_key(""));
        assert!(!valid_idempotency_key("bad\nkey"));
        assert!(!valid_idempotency_key(&"x".repeat(257)));
    }

    #[test]
    fn admission_replays_after_restart_and_refuses_changed_body_and_stale_head() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://one".to_string()],
        );
        let scope = scope("user://one", "org://one");
        let first_payload = json!({"value": 1});
        let first = admit_owner_scoped_mutation(
            data_dir,
            true,
            request(
                &identity,
                &scope,
                "mutation-foundation-test",
                &first_payload,
                "create-one",
                None,
            ),
        )
        .unwrap();
        assert!(!first.replayed);
        assert!(first.receipt_ref.starts_with("receipt://"));

        // Drop the process-local handle.  The next call must reconstruct the
        // key and original receipt from the durable log, not memory.
        super::super::substrate_store::reset_handle_for_test();
        let replay = admit_owner_scoped_mutation(
            data_dir,
            true,
            request(
                &identity,
                &scope,
                "mutation-foundation-test",
                &first_payload,
                "create-one",
                None,
            ),
        )
        .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.projection.seq, first.projection.seq);
        assert_eq!(replay.receipt_ref, first.receipt_ref);

        let changed = json!({"value": 2});
        assert!(matches!(
            admit_owner_scoped_mutation(
                data_dir,
                true,
                request(
                    &identity,
                    &scope,
                    "mutation-foundation-test",
                    &changed,
                    "create-one",
                    None,
                )
            ),
            Err(MutationRefusal::Admission(
                AdmissionRefusal::SameKeyDifferentBytes { .. }
            ))
        ));

        let successor_payload = json!({"value": 2});
        let successor = admit_owner_scoped_mutation(
            data_dir,
            false,
            request(
                &identity,
                &scope,
                "mutation-foundation-test",
                &successor_payload,
                "update-one",
                Some(&first.projection.head),
            ),
        )
        .unwrap();
        assert!(!successor.replayed);
        let stale_payload = json!({"value": 3});
        assert!(matches!(
            admit_owner_scoped_mutation(
                data_dir,
                false,
                request(
                    &identity,
                    &scope,
                    "mutation-foundation-test",
                    &stale_payload,
                    "update-two",
                    Some(&first.projection.head),
                )
            ),
            Err(MutationRefusal::Admission(AdmissionRefusal::HeadConflict))
        ));
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn cross_principal_cannot_borrow_an_admitted_key_or_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let owner = super::super::substrate_store::request_identity_for_test(
            "user://owner",
            ["org://one".to_string()],
        );
        let intruder = super::super::substrate_store::request_identity_for_test(
            "user://intruder",
            ["org://one".to_string()],
        );
        let scope = scope("user://owner", "org://one");
        let payload = json!({"value": 1});
        let admitted = admit_owner_scoped_mutation(
            data_dir,
            true,
            request(
                &owner,
                &scope,
                "mutation-foundation-principal-test",
                &payload,
                "shared-looking-key",
                None,
            ),
        )
        .unwrap();
        assert!(!admitted.replayed);
        assert!(matches!(
            admit_owner_scoped_mutation(
                data_dir,
                true,
                request(
                    &intruder,
                    &scope,
                    "mutation-foundation-principal-test",
                    &payload,
                    "shared-looking-key",
                    None,
                ),
            ),
            Err(MutationRefusal::Scope(
                RequestScopeRefusal::ResourceScopeRequired
            ))
        ));
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn durability_confirmation_failure_never_returns_success_and_exact_retry_converges() {
        // The hook is process-global, so serialize the small interval in which
        // it is present.  Agentgres appends before confirming the directory;
        // this is the deliberately ambiguous failure a caller must resolve by
        // retrying the exact command, never by inventing a fresh key.
        let _environment_guard = DURABILITY_FAULT_ENV.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://one".to_string()],
        );
        let scope = scope("user://one", "org://one");
        let payload = json!({"value": "durability-fault"});

        let forced = agentgres::event_stream::force_durability_failure_for_this_thread();
        let failed = admit_owner_scoped_mutation(
            data_dir,
            true,
            request(
                &identity,
                &scope,
                "mutation-foundation-durability-test",
                &payload,
                "durability-key",
                None,
            ),
        );
        drop(forced);
        assert!(matches!(
            failed,
            Err(MutationRefusal::Admission(
                AdmissionRefusal::DurabilityUnconfirmed(_)
            ))
        ));

        // Resetting the process handle makes the retry prove that the original
        // operation is reconstructed from the log.  No second append and no
        // borrowed receipt are permitted.
        super::super::substrate_store::reset_handle_for_test();
        let retry = admit_owner_scoped_mutation(
            data_dir,
            true,
            request(
                &identity,
                &scope,
                "mutation-foundation-durability-test",
                &payload,
                "durability-key",
                None,
            ),
        )
        .unwrap();
        assert!(retry.replayed);
        assert_eq!(retry.projection.seq, 0);
        assert!(retry.receipt_ref.starts_with("receipt://"));
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn checkpoint_requires_the_exact_retained_sequence_and_head() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://one".to_string()],
        );
        let scope = scope("user://one", "org://one");
        let payload = json!({"value": 1});
        let admitted = admit_owner_scoped_mutation(
            data_dir,
            true,
            request(
                &identity,
                &scope,
                "mutation-foundation-checkpoint-test",
                &payload,
                "checkpoint-key",
                None,
            ),
        )
        .unwrap();
        let history = read_owner_scoped_history(
            data_dir,
            &identity,
            &scope,
            "test-object",
            "test://object/1",
            "mutation-foundation-checkpoint-test",
            "object-1",
        )
        .unwrap();
        assert!(checkpoint_is_retained(
            &history,
            admitted.projection.seq,
            &admitted.projection.head
        ));
        assert!(!checkpoint_is_retained(
            &history,
            admitted.projection.seq + 1,
            &admitted.projection.head
        ));
        assert!(!checkpoint_is_retained(
            &history,
            admitted.projection.seq,
            &format!("sha256:{}", "0".repeat(64))
        ));
        super::super::substrate_store::reset_handle_for_test();
    }
}
