//! Generic owner-namespaced event streams and their durable subscription
//! leases — the canonical substrate owner for `m5-agentgres-durable-event-
//! subscription-successor`.
//!
//! Two properties are load-bearing and both are structural, not documentary:
//!
//! 1. GENERICITY. The owner namespace is DATA. Nothing in this module branches
//!    on a namespace value, and no consumer vocabulary (GoalRun, thread, room)
//!    appears in any admission-required field. Two unrelated owners traverse
//!    the identical code path; that is what the >= 2-namespace proof asserts.
//!
//! 2. THE EVENT-CLASS LINE (canon: agentgres/doctrine.md). An ADMITTED class
//!    crosses an atomic Agentgres transition with an exact expected head. An
//!    EPHEMERAL class mints no sequence, head, root, or receipt and — the
//!    decisive bar — awaits no Agentgres operation. The ephemeral path here
//!    never calls the admission core, so the structural property is a fact
//!    about the code rather than a claim about it.

use super::substrate_store;
use super::DaemonState;
use agentgres::event_stream::AdmissionRefusal;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

const EVENT_STREAM_SCOPE_KIND: &str = "daemon-event-stream";
const SUBSCRIPTION_SCOPE_KIND: &str = "daemon-subscription-lease";

/// A refusal that reaches the wire WITH its machine code.
///
/// The daemon's shared `AppError` renders only `{error:{message}}`, so a code
/// packed into its string body is swallowed on the way out — the field every
/// verifier and every caller keys off would exist in the source and not in
/// the response. These routes therefore own their refusal rendering.
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

/// Map one typed substrate refusal onto the wire.
///
/// The refusal VOCABULARY is the library's, not this route's: the code and
/// message come from `AdmissionRefusal` so that the same failure names itself
/// identically wherever admission is attempted. A route that reworded the
/// substrate's refusals would make two callers of one mechanism look like two
/// mechanisms.
fn refused(refusal: AdmissionRefusal) -> Refused {
    let status = match refusal {
        AdmissionRefusal::HeadConflict => StatusCode::CONFLICT,
        AdmissionRefusal::CoordinatesNotCanonical(_)
        | AdmissionRefusal::SameKeyDifferentBytes { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        // An absent capability is a wiring fault in THIS deployment, not a
        // client error and not an upstream failure: it is retryable only
        // after the boundary is wired, so it is reported as unavailable.
        AdmissionRefusal::CapabilityAbsent => StatusCode::SERVICE_UNAVAILABLE,
        AdmissionRefusal::DurabilityUnconfirmed(_)
        | AdmissionRefusal::ProjectionDisagreesWithAck
        | AdmissionRefusal::SubstrateUnavailable(_) => StatusCode::BAD_GATEWAY,
    };
    let message = refusal.to_string();
    bad(status, refusal.code(), &message)
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

fn mutation_refused(refusal: super::mutation_event_foundation::MutationRefusal) -> Refused {
    use super::mutation_event_foundation::MutationRefusal;
    match refusal {
        MutationRefusal::Scope(error) => scope_refused(error),
        MutationRefusal::Admission(error) => refused(error),
        MutationRefusal::IdempotencyKeyInvalid
        | MutationRefusal::GenesisExpectedHeadPresent
        | MutationRefusal::SuccessorExpectedHeadRequired => {
            let message = refusal.message();
            bad(StatusCode::BAD_REQUEST, refusal.code(), &message)
        }
        MutationRefusal::RequestFingerprintFailed(_) => {
            let message = refusal.message();
            bad(StatusCode::INTERNAL_SERVER_ERROR, refusal.code(), &message)
        }
    }
}

fn request_identity(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<substrate_store::RequestIdentity, Refused> {
    substrate_store::resolve_request_identity(&st.data_dir, headers).map_err(scope_refused)
}

fn event_stream_ref(owner_namespace: &str, stream_tail: &str) -> String {
    format!("event-stream://{owner_namespace}/{stream_tail}")
}

fn subscription_ref(owner_namespace: &str, lease_tail: &str) -> String {
    format!("subscription-lease://{owner_namespace}/{lease_tail}")
}

fn bind_scope(
    st: &DaemonState,
    identity: &substrate_store::RequestIdentity,
    resource_kind: &str,
    resource_ref: &str,
    owner_ref: &str,
    idempotency_key: &str,
) -> Result<substrate_store::RequestResourceScope, Refused> {
    substrate_store::bind_request_resource_scope(
        &st.data_dir,
        identity,
        resource_kind,
        resource_ref,
        owner_ref,
        owner_ref,
        idempotency_key,
    )
    .map_err(scope_refused)
}

fn authorize_scope(
    st: &DaemonState,
    identity: &substrate_store::RequestIdentity,
    resource_kind: &str,
    resource_ref: &str,
) -> Result<substrate_store::RequestResourceScope, Refused> {
    substrate_store::authorize_request_resource_scope(
        &st.data_dir,
        identity,
        resource_kind,
        resource_ref,
        None,
    )
    .map_err(scope_refused)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Validate one declaration at ADMISSION time.
///
/// Exactly-one-side is enforced here, once, when the declaration becomes
/// durable truth — not on every append against whatever the caller sent. A
/// class appearing on both lists is a contradiction the substrate must refuse
/// rather than resolve, because resolving it would mean choosing which side of
/// the event-class line the owner meant.
fn validate_declaration(declaration: &Value) -> Result<(), Refused> {
    let list = |name: &str| -> Vec<String> {
        declaration
            .get(name)
            .and_then(Value::as_array)
            .map(|classes| {
                classes
                    .iter()
                    .map(|class| text(class, "class_id").to_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let admitted = list("admitted_truth_classes");
    let ephemeral = list("ephemeral_delivery_classes");
    if admitted.is_empty() && ephemeral.is_empty() {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "event_class_declaration_empty",
            "a stream declares at least one event class before it admits anything",
        ));
    }
    for side in [&admitted, &ephemeral] {
        for class_id in side.iter() {
            if class_id.is_empty() {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "event_class_unnamed",
                    "every declared class carries a class_id",
                ));
            }
        }
    }
    if let Some(both) = admitted.iter().find(|id| ephemeral.contains(id)) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "event_class_on_both_sides",
            &format!(
                "class {both} is declared as BOTH admitted truth and ephemeral delivery; \
                 the event-class line admits no class on both sides"
            ),
        ));
    }
    for class_id in admitted.iter().chain(ephemeral.iter()) {
        let payload_ref = ["admitted_truth_classes", "ephemeral_delivery_classes"]
            .iter()
            .filter_map(|list_name| declaration.get(*list_name).and_then(Value::as_array))
            .flatten()
            .find(|class| text(class, "class_id") == class_id)
            .map(|class| text(class, "payload_schema_ref"))
            .unwrap_or_default();
        if payload_ref.is_empty() {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "event_class_untyped",
                "a declared class types its payload by owner-declared schema ref",
            ));
        }
    }
    Ok(())
}

/// Classify one class against the stream's ADMITTED declaration.
///
/// The declaration argument comes from the stream's genesis operation read out
/// of Agentgres — never from the append request. A request-supplied
/// declaration would let any caller assert which side of the event-class line
/// its own event falls on, which makes the line a claim rather than a fact.
fn classify<'a>(body: &'a Value, class_id: &str) -> Option<(&'a str, bool)> {
    for (list, admitted) in [
        ("admitted_truth_classes", true),
        ("ephemeral_delivery_classes", false),
    ] {
        if let Some(classes) = body.get(list).and_then(Value::as_array) {
            for class in classes {
                if text(class, "class_id") == class_id {
                    return Some((text(class, "payload_schema_ref"), admitted));
                }
            }
        }
    }
    None
}

/// The operation kind that carries a stream's durable event-class declaration.
const GENESIS_OP_KIND: &str = "event_stream.genesis";

/// Read the stream's ADMITTED declaration out of its genesis operation.
///
/// This is the whole of F1: the declaration is a fact about the stream, held
/// in the first admitted operation on its chain, and every append is judged
/// against it. Returning `None` means the stream was never declared, which
/// refuses the append rather than defaulting it to either side of the line.
fn admitted_declaration(
    st: &DaemonState,
    owner_namespace: &str,
    stream_tail: &str,
) -> Result<Option<Value>, Refused> {
    substrate_store::lookup_declaration(&st.data_dir, owner_namespace, stream_tail, GENESIS_OP_KIND)
        .map_err(refused)
}

/// GET /v1/event-streams/_substrate-traversals — the steward's traversal
/// counters, so a verifier can assert ZERO substrate traversals on the
/// ephemeral path by POSITIVE DETECTION.
///
/// An unchanged head does not prove a read did not happen; only counting the
/// reads does. These counters are the instrument, and the verifier proves the
/// instrument can read non-zero before it trusts a zero.
pub(crate) async fn handle_substrate_traversals(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, Refused> {
    // Diagnostic counters are process-wide but still not a public anonymous
    // oracle.  Resolve a real principal; no development fallback exists.
    let _identity = request_identity(&st, &headers)?;
    let (walks, hits, fills, admitted, domains) = substrate_store::traversal_counters();
    Ok(Json(json!({
        "history_walks": walks,
        "declaration_cache_hits": hits,
        "declaration_cache_fills": fills,
        "admitted_operations": admitted,
        "hydrated_domains": domains,
    })))
}

/// POST /v1/event-streams/:owner_namespace/:stream_tail
///
/// Declare one stream, once. The declaration is admitted inside an
/// EXPECTED-ABSENT genesis operation, so redeclaration is refused by the
/// substrate's own compare-and-swap rather than by a check that could be
/// forgotten: a second genesis has a head where absence was required.
pub(crate) async fn handle_event_stream_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, stream_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let Some(declaration) = body.get("event_class_declaration") else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "event_class_declaration_required",
            "a stream is declared before it admits anything",
        ));
    };
    validate_declaration(declaration)?;
    let owner_ref = text(&body, "owner_ref");
    if owner_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "event_stream_owner_ref_required",
            "an event stream is bound to one authenticated tenant owner_ref",
        ));
    }
    let idempotency_key = text(&body, "idempotency_key");
    if idempotency_key.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "stream creation carries a caller-owned idempotency key",
        ));
    }
    let resource_ref = event_stream_ref(&owner_namespace, &stream_tail);
    let scope = bind_scope(
        &st,
        &identity,
        EVENT_STREAM_SCOPE_KIND,
        &resource_ref,
        owner_ref,
        idempotency_key,
    )?;
    // Expected-absent remains the concurrency rule, but an exact duplicate
    // under the SAME key/body is allowed to replay the original fact.  A fresh
    // key or changed declaration still conflicts, so a client can resolve an
    // ambiguous create without "declaring again".
    let admitted = super::mutation_event_foundation::admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        super::mutation_event_foundation::ScopedMutation {
            identity: &identity,
            scope: &scope,
            resource_kind: EVENT_STREAM_SCOPE_KIND,
            resource_ref: &resource_ref,
            owner_namespace: &owner_namespace,
            stream_tail: &stream_tail,
            op_kind: GENESIS_OP_KIND,
            expected_head: None,
            payload: declaration,
            recorded_at_ms: body
                .get("recorded_at_ms")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            idempotency_key,
        },
    )
    .map_err(|refusal| match refusal {
        super::mutation_event_foundation::MutationRefusal::Admission(
            AdmissionRefusal::HeadConflict,
        ) => bad(
            StatusCode::CONFLICT,
            "event_stream_already_declared",
            "this stream already carries a different creation identity or declaration",
        ),
        other => mutation_refused(other),
    })?;
    let exact = &admitted.projection;
    substrate_store::remember_declaration(&owner_namespace, &stream_tail, declaration);

    Ok(Json(json!({
        "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        "owner_namespace": owner_namespace,
        "declared": true,
        "replayed": admitted.replayed,
        "request_fingerprint": admitted.request_fingerprint,
        "operation_ref": admitted.operation_ref,
        "receipt_ref": admitted.receipt_ref,
        "event_class_declaration": declaration,
        "admitted_head": {
            "operation_ref": agentgres::refs::event_stream_operation_ref(
                &owner_namespace, &stream_tail, exact.seq, &exact.head),
            "resulting_head_ref": exact.head,
            "admission_receipt_ref": agentgres::refs::event_stream_receipt_ref(
                &owner_namespace, &stream_tail, exact.admission_batch_seq, &exact.admission_root),
            "admission_root_ref": exact.admission_root,
        },
        "agentgres_sequence": exact.seq,
        "nonclaim": "The declaration is durable stream truth admitted once; appends are judged against it, never against request-supplied bytes.",
    })))
}

/// POST /v1/event-streams/:owner_namespace/:stream_tail/events
///
/// Appends one event to an owner-namespaced stream. An admitted class crosses
/// canonical Agentgres with an exact expected head; an ephemeral class is
/// delivered without ever entering the admission path.
pub(crate) async fn handle_event_stream_append(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, stream_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let resource_ref = event_stream_ref(&owner_namespace, &stream_tail);
    // Authorize before reading the declaration/head.  A denied caller does not
    // get an existence oracle for another principal's stream.
    let scope = authorize_scope(&st, &identity, EVENT_STREAM_SCOPE_KIND, &resource_ref)?;
    let class_id = text(&body, "class_id");
    if class_id.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "event_class_id_required",
            "an append names the owner-declared class it belongs to",
        ));
    }
    // The declaration comes from the stream, not the request. A caller cannot
    // assert which side of the event-class line its own event falls on.
    let Some(declaration) = admitted_declaration(&st, &owner_namespace, &stream_tail)? else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "event_stream_undeclared",
            "this stream carries no admitted event-class declaration; declare it before appending",
        ));
    };
    let Some((payload_schema_ref, admitted)) =
        classify(&declaration, class_id).map(|(r, a)| (r.to_owned(), a))
    else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "event_class_undeclared",
            "the class is not declared as admitted truth or ephemeral delivery for this stream",
        ));
    };
    if payload_schema_ref.is_empty() {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "event_class_untyped",
            "a declared class types its payload by owner-declared schema ref",
        ));
    }

    if !admitted {
        // Ephemeral: no sequence, no head, no root, no receipt, and NO
        // Agentgres operation is awaited. Returning here is the structural
        // property the canon rule names as decisive.
        return Ok(Json(json!({
            "delivery": "ephemeral",
            "class_id": class_id,
            "payload_schema_ref": payload_schema_ref,
            "owner_namespace": owner_namespace,
            "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
            "nonclaim": "Ephemeral delivery mints no sequence, head, root, or receipt and awaits no Agentgres operation.",
        })));
    }

    // A declared stream always has a head.  Never read-and-default a missing
    // precondition: that converts an explicit CAS into last-writer-wins.
    let expected_head = body.get("expected_head").and_then(Value::as_str);
    if expected_head.is_none() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "event_stream_expected_head_required",
            "an admitted append must compare-and-swap against the exact observed stream head",
        ));
    }
    let idem_key = text(&body, "idempotency_key");
    if idem_key.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "an admitted append carries an idempotency key",
        ));
    }
    let recorded_at_ms = body
        .get("recorded_at_ms")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    // The admitted bytes carry the CLASS, not just the payload. A class known
    // only to the request that made it cannot be filtered on later, so a
    // lease's permitted-class scope would be unenforceable against admitted
    // truth -- it would have to trust the delivery adapter instead.
    let envelope = json!({
        "class_id": class_id,
        "payload_schema_ref": payload_schema_ref,
        "payload": body.get("payload").cloned().unwrap_or(Value::Null),
    });
    let admitted = super::mutation_event_foundation::admit_owner_scoped_mutation(
        &st.data_dir,
        false,
        super::mutation_event_foundation::ScopedMutation {
            identity: &identity,
            scope: &scope,
            resource_kind: EVENT_STREAM_SCOPE_KIND,
            resource_ref: &resource_ref,
            owner_namespace: &owner_namespace,
            stream_tail: &stream_tail,
            op_kind: "event_stream.append",
            expected_head,
            payload: &envelope,
            recorded_at_ms,
            idempotency_key: idem_key,
        },
    )
    .map_err(mutation_refused)?;
    let exact = &admitted.projection;

    Ok(Json(json!({
        "delivery": "admitted",
        "replayed": admitted.replayed,
        "class_id": class_id,
        "payload_schema_ref": payload_schema_ref,
        "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        "owner_namespace": owner_namespace,
        "request_fingerprint": admitted.request_fingerprint,
        "operation_ref": admitted.operation_ref,
        "receipt_ref": admitted.receipt_ref,
        "admitted_head": {
            "operation_ref": agentgres::refs::event_stream_operation_ref(
                &owner_namespace, &stream_tail, exact.seq, &exact.head),
            "resulting_head_ref": exact.head,
            "admission_receipt_ref": agentgres::refs::event_stream_receipt_ref(
                &owner_namespace, &stream_tail, exact.admission_batch_seq, &exact.admission_root),
            "admission_root_ref": exact.admission_root,
        },
        "agentgres_sequence": exact.seq,
    })))
}

/// GET /v1/event-streams/:owner_namespace/:stream_tail — the exact admitted
/// head, by reference only.
pub(crate) async fn handle_event_stream_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, stream_tail)): AxumPath<(String, String)>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let resource_ref = event_stream_ref(&owner_namespace, &stream_tail);
    let scope = authorize_scope(&st, &identity, EVENT_STREAM_SCOPE_KIND, &resource_ref)?;
    let exact = super::mutation_event_foundation::read_owner_scoped_head(
        &st.data_dir,
        &identity,
        &scope,
        EVENT_STREAM_SCOPE_KIND,
        &resource_ref,
        &owner_namespace,
        &stream_tail,
    )
    .map_err(mutation_refused)?;
    let Some(exact) = exact else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "event_stream_not_found",
            "no admitted event stream exists at these coordinates",
        ));
    };
    Ok(Json(json!({
        "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        "owner_namespace": owner_namespace,
        "admitted_head": {
            "operation_ref": agentgres::refs::event_stream_operation_ref(
                &owner_namespace, &stream_tail, exact.seq, &exact.head),
            "resulting_head_ref": exact.head,
            "admission_receipt_ref": agentgres::refs::event_stream_receipt_ref(
                &owner_namespace, &stream_tail, exact.admission_batch_seq, &exact.admission_root),
            "admission_root_ref": exact.admission_root,
        },
        "agentgres_sequence": exact.seq,
    })))
}

// ---------------------------------------------------------------------------
// The subscription-lease plane.
//
// A lease owns NO transition chain of its own. Every state change -- admit,
// checkpoint advance, revoke -- is admitted through canonical Agentgres on the
// lease's own object key, so the lease's current state IS the payload of its
// admitted head. There is no lease table, no adapter-local truth, and no way
// for a delivery adapter to hold state the substrate cannot replay.
//
// The capability surface stays at FOUR operations. Checkpoint advance and
// revoke are both lease TRANSITIONS distinguished by op_kind; read is
// read_head. Nothing here needs a fifth.

/// The Agentgres stream tail one lease's transitions are admitted under.
fn lease_stream_tail(lease_tail: &str) -> String {
    format!("lease.{lease_tail}")
}

/// Read a lease's current admitted state: the payload of its head transition.
pub(crate) fn admitted_lease(
    st: &DaemonState,
    owner_namespace: &str,
    lease_tail: &str,
) -> Result<Option<(Value, u64, String)>, Refused> {
    let projection = substrate_store::read_event_stream_operation(
        &st.data_dir,
        owner_namespace,
        &lease_stream_tail(lease_tail),
    )
    .map_err(refused)?;
    Ok(projection.map(|p| (p.operation.payload, p.seq, p.head)))
}

/// Render one lease at the record's declared schema. Every REQUIRED field of
/// projection-subscription-lease.v1 is present; a create response that carried
/// only a subset would describe a lease the contract does not admit.
fn lease_view(state: &Value, seq: u64, head: &str, lease_tail: &str) -> Value {
    json!({
        "schema_version": state.get("schema_version").cloned().unwrap_or(json!("projection-subscription-lease.v1")),
        "lease_id": format!("subscription-lease://{lease_tail}"),
        "stream_id": state.get("stream_id").cloned().unwrap_or(Value::Null),
        "subscriber_ref": state.get("subscriber_ref").cloned().unwrap_or(Value::Null),
        "lease_state": state.get("lease_state").cloned().unwrap_or(json!("active")),
        "expires_at_ref": state.get("expires_at_ref").cloned().unwrap_or(Value::Null),
        "projection_binding": state.get("projection_binding").cloned().unwrap_or(Value::Null),
        "backpressure": state.get("backpressure").cloned().unwrap_or(Value::Null),
        "acknowledged_checkpoint": state.get("acknowledged_checkpoint").cloned().unwrap_or(Value::Null),
        "delivery_adapter_kind": state.get("delivery_adapter_kind").cloned().unwrap_or(json!("pull")),
        "admitted_lease_transition": {
            "operation_ref": agentgres::refs::subscription_lease_operation_ref(lease_tail, seq, head),
            "resulting_head_ref": head,
        },
        "nonclaim": "The lease references canonical Agentgres truth and owns no transition chain; delivery adapters own nothing.",
    })
}

/// Is this lease usable for delivery right now, or must it fail closed?
///
/// Every negative outcome here is TYPED. An expired or revoked lease does not
/// deliver a shorter list -- it refuses by name, because "delivered nothing"
/// and "may not deliver" are different facts and a consumer must be able to
/// tell them apart.
fn lease_is_deliverable(state: &Value, now_ms: u64) -> Result<(), Refused> {
    match state
        .get("lease_state")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "active" => {}
        "revoked" => {
            return Err(bad(
                StatusCode::CONFLICT,
                "subscription_lease_revoked",
                "this lease is revoked; delivery under a revoked lease is unleased delivery",
            ))
        }
        other => {
            return Err(bad(
                StatusCode::CONFLICT,
                "subscription_lease_not_active",
                &format!("lease state {other} does not admit delivery"),
            ))
        }
    }
    if let Some(expires) = state.get("expires_at_ms").and_then(Value::as_u64) {
        if now_ms >= expires {
            return Err(bad(
                StatusCode::CONFLICT,
                "subscription_lease_expired",
                "this lease expired; delivery past expiry is unleased delivery",
            ));
        }
    }
    Ok(())
}

/// Admit one lease transition on the lease's own object key.
fn admit_lease_transition(
    st: &DaemonState,
    identity: &substrate_store::RequestIdentity,
    scope: &substrate_store::RequestResourceScope,
    owner_namespace: &str,
    lease_tail: &str,
    op_kind: &str,
    expected_head: Option<&str>,
    next_state: &Value,
    recorded_at_ms: u64,
    idem_key: &str,
) -> Result<super::mutation_event_foundation::MutationCommit, Refused> {
    let resource_ref = subscription_ref(owner_namespace, lease_tail);
    super::mutation_event_foundation::admit_owner_scoped_mutation(
        &st.data_dir,
        expected_head.is_none(),
        super::mutation_event_foundation::ScopedMutation {
            identity,
            scope,
            resource_kind: SUBSCRIPTION_SCOPE_KIND,
            resource_ref: &resource_ref,
            owner_namespace,
            stream_tail: &lease_stream_tail(lease_tail),
            op_kind,
            expected_head,
            payload: next_state,
            idempotency_key: idem_key,
            recorded_at_ms,
        },
    )
    .map_err(mutation_refused)
}

/// GET /v1/subscriptions/:owner_namespace/:lease_tail — the lease, exactly.
pub(crate) async fn handle_subscription_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let resource_ref = subscription_ref(&owner_namespace, &lease_tail);
    let _scope = authorize_scope(&st, &identity, SUBSCRIPTION_SCOPE_KIND, &resource_ref)?;
    let Some((state, seq, head)) = admitted_lease(&st, &owner_namespace, &lease_tail)? else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "subscription_lease_not_found",
            "no admitted lease exists at these coordinates",
        ));
    };
    Ok(Json(lease_view(&state, seq, &head, &lease_tail)))
}

/// POST /v1/subscriptions/:owner_namespace/:lease_tail/checkpoint
///
/// Advance the acknowledged checkpoint. A checkpoint is an ADMITTED FACT, not
/// a scalar a delivery adapter may substitute: it moves only forward, and only
/// to a sequence the source stream actually admitted.
pub(crate) async fn handle_subscription_checkpoint(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let lease_resource_ref = subscription_ref(&owner_namespace, &lease_tail);
    let lease_scope =
        authorize_scope(&st, &identity, SUBSCRIPTION_SCOPE_KIND, &lease_resource_ref)?;
    let Some((state, _seq, _head)) = admitted_lease(&st, &owner_namespace, &lease_tail)? else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "subscription_lease_not_found",
            "no admitted lease exists at these coordinates",
        ));
    };
    let now_ms = body
        .get("now_ms")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default()
        });
    lease_is_deliverable(&state, now_ms)?;

    let Some(to_seq) = body.get("acknowledged_seq").and_then(Value::as_u64) else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "subscription_checkpoint_seq_required",
            "a checkpoint advance names the sequence it acknowledges",
        ));
    };
    let expected_head = text(&body, "expected_head");
    if expected_head.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "subscription_expected_head_required",
            "a checkpoint transition must name the exact observed lease head",
        ));
    }
    let idempotency_key = text(&body, "idempotency_key");
    if idempotency_key.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "subscription_idempotency_key_required",
            "a checkpoint transition carries a caller-owned idempotency key",
        ));
    }
    let current = state
        .get("acknowledged_checkpoint")
        .and_then(|c| c.get("acknowledged_seq"))
        .and_then(Value::as_u64);
    if current.is_some_and(|at| to_seq < at) {
        return Err(bad(
            StatusCode::CONFLICT,
            "subscription_checkpoint_would_rewind",
            "a checkpoint advances; rewinding one would re-deliver events the subscriber already acknowledged",
        ));
    }

    // The acknowledged sequence must exist on the SOURCE stream. Accepting an
    // arbitrary integer would let a subscriber acknowledge events that were
    // never admitted -- checkpoint substitution, which this record names as a
    // fault to fail closed on.
    let stream_tail = state
        .get("stream_tail")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let stream_resource_ref = event_stream_ref(&owner_namespace, &stream_tail);
    let stream_scope = authorize_scope(
        &st,
        &identity,
        EVENT_STREAM_SCOPE_KIND,
        &stream_resource_ref,
    )?;
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &stream_scope,
        EVENT_STREAM_SCOPE_KIND,
        &stream_resource_ref,
        &owner_namespace,
        &stream_tail,
    )
    .map_err(mutation_refused)?;
    if !history.iter().any(|p| p.seq == to_seq) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "subscription_checkpoint_not_admitted",
            "the acknowledged sequence is not an admitted operation on this lease's stream",
        ));
    }

    let mut next = state.clone();
    next["acknowledged_checkpoint"] = json!({
        "acknowledged_seq": to_seq,
        "acknowledged_head_ref": history.iter().find(|p| p.seq == to_seq).map(|p| p.head.clone()),
    });
    // A fresh key for an already-achieved state is not allowed to borrow the
    // old transition's receipt.  An exact retry under the original key is
    // handed to Agentgres, which replays that original fact.
    let lease_history = super::mutation_event_foundation::read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &lease_scope,
        SUBSCRIPTION_SCOPE_KIND,
        &lease_resource_ref,
        &owner_namespace,
        &lease_stream_tail(&lease_tail),
    )
    .map_err(mutation_refused)?;
    let key_previously_admitted = lease_history
        .iter()
        .any(|entry| entry.operation.idem_key == idempotency_key);
    if current == Some(to_seq) && !key_previously_admitted {
        return Err(bad(
            StatusCode::CONFLICT,
            "subscription_checkpoint_already_acknowledged",
            "the checkpoint is already at this sequence; a fresh idempotency key is not consumed for a no-op",
        ));
    }
    let committed = admit_lease_transition(
        &st,
        &identity,
        &lease_scope,
        &owner_namespace,
        &lease_tail,
        "subscription_lease.checkpoint_advance",
        Some(expected_head),
        &next,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        idempotency_key,
    )?;
    let mut view = lease_view(
        &committed.projection.operation.payload,
        committed.projection.seq,
        &committed.projection.head,
        &lease_tail,
    );
    view["replayed"] = json!(committed.replayed);
    view["request_fingerprint"] = json!(committed.request_fingerprint);
    view["operation_ref"] = json!(committed.operation_ref);
    view["receipt_ref"] = json!(committed.receipt_ref);
    Ok(Json(view))
}

/// POST /v1/subscriptions/:owner_namespace/:lease_tail/revoke
pub(crate) async fn handle_subscription_revoke(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let resource_ref = subscription_ref(&owner_namespace, &lease_tail);
    let scope = authorize_scope(&st, &identity, SUBSCRIPTION_SCOPE_KIND, &resource_ref)?;
    let Some((state, _seq, _head)) = admitted_lease(&st, &owner_namespace, &lease_tail)? else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "subscription_lease_not_found",
            "no admitted lease exists at these coordinates",
        ));
    };
    let expected_head = text(&body, "expected_head");
    if expected_head.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "subscription_expected_head_required",
            "a revoke transition must name the exact observed lease head",
        ));
    }
    let idempotency_key = text(&body, "idempotency_key");
    if idempotency_key.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "subscription_idempotency_key_required",
            "a revoke transition carries a caller-owned idempotency key",
        ));
    }
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &scope,
        SUBSCRIPTION_SCOPE_KIND,
        &resource_ref,
        &owner_namespace,
        &lease_stream_tail(&lease_tail),
    )
    .map_err(mutation_refused)?;
    let key_previously_admitted = history
        .iter()
        .any(|entry| entry.operation.idem_key == idempotency_key);
    if state.get("lease_state").and_then(Value::as_str) == Some("revoked")
        && !key_previously_admitted
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "subscription_lease_already_revoked",
            "this lease is already revoked; a fresh idempotency key is not consumed for a no-op",
        ));
    }
    let mut next = state.clone();
    next["lease_state"] = json!("revoked");
    let committed = admit_lease_transition(
        &st,
        &identity,
        &scope,
        &owner_namespace,
        &lease_tail,
        "subscription_lease.revoke",
        Some(expected_head),
        &next,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        idempotency_key,
    )?;
    let mut view = lease_view(
        &committed.projection.operation.payload,
        committed.projection.seq,
        &committed.projection.head,
        &lease_tail,
    );
    view["replayed"] = json!(committed.replayed);
    view["request_fingerprint"] = json!(committed.request_fingerprint);
    view["operation_ref"] = json!(committed.operation_ref);
    view["receipt_ref"] = json!(committed.receipt_ref);
    Ok(Json(view))
}

/// GET /v1/subscriptions/:owner_namespace/:lease_tail/delivery
///
/// Deliver from the durable acknowledged checkpoint forward. This is the
/// resume path: a subscriber that restarts asks again and receives exactly the
/// events after its last acknowledged checkpoint -- no cursor held in memory,
/// no one-shot body that cannot be re-requested.
pub(crate) async fn handle_subscription_delivery(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    let lease_resource_ref = subscription_ref(&owner_namespace, &lease_tail);
    let _lease_scope =
        authorize_scope(&st, &identity, SUBSCRIPTION_SCOPE_KIND, &lease_resource_ref)?;
    let Some((state, _seq, _head)) = admitted_lease(&st, &owner_namespace, &lease_tail)? else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "subscription_lease_not_found",
            "no admitted lease exists at these coordinates",
        ));
    };
    // Expiry is measured against the real clock. Passing a hardcoded zero
    // here made every expiry check vacuously false -- caught by the verifier,
    // not by inspection.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();
    lease_is_deliverable(&state, now_ms)?;

    let stream_tail = state
        .get("stream_tail")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let permitted: Vec<String> = state
        .get("permitted_event_class_ids")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let window = state
        .get("backpressure")
        .and_then(|b| b.get("max_undelivered_events"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let from = state
        .get("acknowledged_checkpoint")
        .and_then(|c| c.get("acknowledged_seq"))
        .and_then(Value::as_u64);

    let stream_resource_ref = event_stream_ref(&owner_namespace, &stream_tail);
    let stream_scope = authorize_scope(
        &st,
        &identity,
        EVENT_STREAM_SCOPE_KIND,
        &stream_resource_ref,
    )?;
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &stream_scope,
        EVENT_STREAM_SCOPE_KIND,
        &stream_resource_ref,
        &owner_namespace,
        &stream_tail,
    )
    .map_err(mutation_refused)?;
    if let Some(checkpoint) = state.get("acknowledged_checkpoint") {
        if !checkpoint.is_null() {
            let seq = checkpoint.get("acknowledged_seq").and_then(Value::as_u64);
            let checkpoint_head = checkpoint
                .get("acknowledged_head_ref")
                .and_then(Value::as_str);
            if !matches!((seq, checkpoint_head), (Some(seq), Some(checkpoint_head))
                if super::mutation_event_foundation::checkpoint_is_retained(&history, seq, checkpoint_head))
            {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "subscription_checkpoint_gap_requires_resync",
                    "the admitted checkpoint no longer names an exact retained source event; fetch a fresh snapshot and create a successor lease",
                ));
            }
        }
    }
    let mut pending: Vec<Value> = history
        .into_iter()
        .filter(|p| from.is_none_or(|at| p.seq > at))
        .filter(|p| p.operation.op_kind != GENESIS_OP_KIND)
        .filter(|p| {
            permitted.is_empty()
                || p.operation
                    .payload
                    .get("class_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| permitted.iter().any(|allowed| allowed == id))
        })
        .map(|p| json!({ "seq": p.seq, "head_ref": p.head, "payload": p.operation.payload }))
        .collect();

    // Backpressure resolves to a TYPED OUTCOME, never a silent drop. When more
    // is pending than the declared window, the response says so and says where
    // to resume; it does not quietly truncate and it does not discard the tail.
    let total = pending.len() as u64;
    let lagged = window > 0 && total > window;
    if lagged {
        pending.truncate(window as usize);
    }
    let resume_after = pending
        .last()
        .and_then(|e| e.get("seq").and_then(Value::as_u64))
        .or(from);

    Ok(Json(json!({
        "lease_id": format!("subscription-lease://{lease_tail}"),
        "delivered_from_checkpoint": from,
        "events": pending,
        "pending_total": total,
        "backpressure_window": window,
        "delivery_outcome": if lagged { "bounded_by_backpressure_window" } else { "drained" },
        "resume_after_seq": resume_after,
        "nonclaim": "Delivery is bounded by the declared window and resumable from the admitted checkpoint; no event is dropped, and lag is a typed outcome rather than a log line.",
    })))
}

/// POST /v1/subscriptions — create a durable subscription lease over one
/// owner-namespaced stream. The lease transition is itself admitted through
/// canonical Agentgres: the family mints no lease chain of its own.
pub(crate) async fn handle_subscription_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let identity = request_identity(&st, &headers)?;
    for required in [
        "owner_namespace",
        "stream_tail",
        "subscriber_ref",
        "lease_tail",
        "idempotency_key",
    ] {
        if text(&body, required).is_empty() {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "subscription_field_required",
                "owner_namespace, stream_tail, subscriber_ref, lease_tail, and idempotency_key are required",
            ));
        }
    }
    let owner_namespace = text(&body, "owner_namespace").to_owned();
    let stream_tail = text(&body, "stream_tail").to_owned();
    let lease_tail = text(&body, "lease_tail").to_owned();

    // A lease may only be issued over a stream that actually exists: an
    // unleased delivery is refused, and so is a lease over nothing.
    let stream_resource_ref = event_stream_ref(&owner_namespace, &stream_tail);
    let stream_scope = authorize_scope(
        &st,
        &identity,
        EVENT_STREAM_SCOPE_KIND,
        &stream_resource_ref,
    )?;
    let stream = super::mutation_event_foundation::read_owner_scoped_head(
        &st.data_dir,
        &identity,
        &stream_scope,
        EVENT_STREAM_SCOPE_KIND,
        &stream_resource_ref,
        &owner_namespace,
        &stream_tail,
    )
    .map_err(mutation_refused)?;
    if stream.is_none() {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "subscription_stream_unresolved",
            "a lease requires an admitted stream at the named coordinates",
        ));
    }

    let permitted = body
        .get("permitted_event_class_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).count())
        .unwrap_or_default();
    if permitted == 0 {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "subscription_scope_required",
            "a lease names at least one permitted event class",
        ));
    }
    let max_undelivered = body
        .get("max_undelivered_events")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if max_undelivered == 0 {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "subscription_backpressure_unbounded",
            "a lease declares a bounded backpressure window; lag resolves to a typed outcome, never a silent drop",
        ));
    }

    let state = json!({
        "schema_version": "projection-subscription-lease.v1",
        "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        "stream_tail": stream_tail,
        "owner_namespace": owner_namespace,
        "subscriber_ref": text(&body, "subscriber_ref"),
        "lease_state": "active",
        "expires_at_ref": body.get("expires_at_ref").cloned().unwrap_or(Value::Null),
        "expires_at_ms": body.get("expires_at_ms").cloned().unwrap_or(Value::Null),
        "projection_binding": body.get("projection_binding").cloned().unwrap_or(json!({
            "binding_kind": "exact_stream_head",
            "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        })),
        "backpressure": json!({
            "max_undelivered_events": max_undelivered,
            "lag_outcome": "bounded_by_backpressure_window",
        }),
        "acknowledged_checkpoint": Value::Null,
        "delivery_adapter_kind": body.get("delivery_adapter_kind").cloned().unwrap_or(json!("pull")),
        "permitted_event_class_ids": body.get("permitted_event_class_ids").cloned().unwrap_or(json!([])),
        "principal_ref": identity.principal_ref.clone(),
        "owner_ref": stream_scope.owner_ref.clone(),
        "tenant_ref": stream_scope.tenant_ref.clone(),
    });
    let lease_resource_ref = subscription_ref(&owner_namespace, &lease_tail);
    let lease_scope = bind_scope(
        &st,
        &identity,
        SUBSCRIPTION_SCOPE_KIND,
        &lease_resource_ref,
        &stream_scope.owner_ref,
        text(&body, "idempotency_key"),
    )?;
    let committed = admit_lease_transition(
        &st,
        &identity,
        &lease_scope,
        &owner_namespace,
        &lease_tail,
        "subscription_lease.admit",
        None,
        &state,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        text(&body, "idempotency_key"),
    )?;
    let mut view = lease_view(
        &committed.projection.operation.payload,
        committed.projection.seq,
        &committed.projection.head,
        &lease_tail,
    );
    view["replayed"] = json!(committed.replayed);
    view["request_fingerprint"] = json!(committed.request_fingerprint);
    view["operation_ref"] = json!(committed.operation_ref);
    view["receipt_ref"] = json!(committed.receipt_ref);
    Ok(Json(view))
}
