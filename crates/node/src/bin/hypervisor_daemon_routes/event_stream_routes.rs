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
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

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
    let history =
        substrate_store::read_event_stream_history(&st.data_dir, owner_namespace, stream_tail)
            .map_err(refused)?;
    Ok(history
        .into_iter()
        .find(|projection| projection.operation.op_kind == GENESIS_OP_KIND)
        .map(|projection| projection.operation.payload))
}

/// POST /v1/event-streams/:owner_namespace/:stream_tail
///
/// Declare one stream, once. The declaration is admitted inside an
/// EXPECTED-ABSENT genesis operation, so redeclaration is refused by the
/// substrate's own compare-and-swap rather than by a check that could be
/// forgotten: a second genesis has a head where absence was required.
pub(crate) async fn handle_event_stream_create(
    State(st): State<Arc<DaemonState>>,
    AxumPath((owner_namespace, stream_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let Some(declaration) = body.get("event_class_declaration") else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "event_class_declaration_required",
            "a stream is declared before it admits anything",
        ));
    };
    validate_declaration(declaration)?;

    // Refuse redeclaration explicitly. Leaving this to the expected-absent CAS
    // is not enough: an identical redeclaration carries identical bytes under
    // the same key and would REPLAY as success, which reads as "declared
    // again" rather than "refused". The rule is one declaration per stream,
    // so it is checked as one declaration per stream.
    if admitted_declaration(&st, &owner_namespace, &stream_tail)?.is_some() {
        return Err(bad(
            StatusCode::CONFLICT,
            "event_stream_already_declared",
            "this stream already carries an admitted event-class declaration; \
             redeclaration would rewrite truth callers have already been judged against",
        ));
    }

    let admitted = substrate_store::admit_event_stream_operation(
        &st.data_dir,
        &owner_namespace,
        &stream_tail,
        GENESIS_OP_KIND,
        None, // expected-absent: this stream must not already exist
        declaration,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        &format!("genesis-{owner_namespace}-{stream_tail}"),
    )
    .map_err(|refusal| match refusal {
        AdmissionRefusal::HeadConflict => bad(
            StatusCode::CONFLICT,
            "event_stream_already_declared",
            "this stream already carries an admitted event-class declaration; \
             redeclaration would rewrite truth callers have already been judged against",
        ),
        other => refused(other),
    })?;
    let exact = &admitted.projection;

    Ok(Json(json!({
        "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        "owner_namespace": owner_namespace,
        "declared": true,
        "replayed": admitted.replayed,
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
    AxumPath((owner_namespace, stream_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
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

    // A declared stream always has a head, so expected-absent is never the
    // right precondition for an append. An explicit expected_head is honoured
    // verbatim; otherwise the append CASes against the head read here.
    let current_head =
        substrate_store::read_event_stream_operation(&st.data_dir, &owner_namespace, &stream_tail)
            .map_err(refused)?
            .map(|projection| projection.head);
    let expected_head = body
        .get("expected_head")
        .and_then(Value::as_str)
        .or(current_head.as_deref());
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
    let admitted = substrate_store::admit_event_stream_operation(
        &st.data_dir,
        &owner_namespace,
        &stream_tail,
        "event_stream.append",
        expected_head,
        &envelope,
        recorded_at_ms,
        idem_key,
    )
    .map_err(refused)?;
    let exact = &admitted.projection;

    Ok(Json(json!({
        "delivery": "admitted",
        "replayed": admitted.replayed,
        "class_id": class_id,
        "payload_schema_ref": payload_schema_ref,
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

/// GET /v1/event-streams/:owner_namespace/:stream_tail — the exact admitted
/// head, by reference only.
pub(crate) async fn handle_event_stream_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath((owner_namespace, stream_tail)): AxumPath<(String, String)>,
) -> Result<Json<Value>, Refused> {
    let exact =
        substrate_store::read_event_stream_operation(&st.data_dir, &owner_namespace, &stream_tail)
            .map_err(refused)?;
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
fn admitted_lease(
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
    owner_namespace: &str,
    lease_tail: &str,
    op_kind: &str,
    expected_head: Option<&str>,
    next_state: &Value,
    recorded_at_ms: u64,
    idem_key: &str,
) -> Result<(u64, String), Refused> {
    let admitted = substrate_store::admit_event_stream_operation(
        &st.data_dir,
        owner_namespace,
        &lease_stream_tail(lease_tail),
        op_kind,
        expected_head,
        next_state,
        recorded_at_ms,
        idem_key,
    )
    .map_err(refused)?;
    Ok((admitted.projection.seq, admitted.projection.head))
}

/// GET /v1/subscriptions/:owner_namespace/:lease_tail — the lease, exactly.
pub(crate) async fn handle_subscription_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
) -> Result<Json<Value>, Refused> {
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
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let Some((state, _seq, head)) = admitted_lease(&st, &owner_namespace, &lease_tail)? else {
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
    let history =
        substrate_store::read_event_stream_history(&st.data_dir, &owner_namespace, &stream_tail)
            .map_err(refused)?;
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
    let (seq, new_head) = admit_lease_transition(
        &st,
        &owner_namespace,
        &lease_tail,
        "subscription_lease.checkpoint_advance",
        Some(&head),
        &next,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        &format!("checkpoint-{lease_tail}-{to_seq}"),
    )?;
    Ok(Json(lease_view(&next, seq, &new_head, &lease_tail)))
}

/// POST /v1/subscriptions/:owner_namespace/:lease_tail/revoke
pub(crate) async fn handle_subscription_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    let Some((state, _seq, head)) = admitted_lease(&st, &owner_namespace, &lease_tail)? else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "subscription_lease_not_found",
            "no admitted lease exists at these coordinates",
        ));
    };
    let mut next = state.clone();
    next["lease_state"] = json!("revoked");
    let (seq, new_head) = admit_lease_transition(
        &st,
        &owner_namespace,
        &lease_tail,
        "subscription_lease.revoke",
        Some(&head),
        &next,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        &format!("revoke-{lease_tail}"),
    )?;
    Ok(Json(lease_view(&next, seq, &new_head, &lease_tail)))
}

/// GET /v1/subscriptions/:owner_namespace/:lease_tail/delivery
///
/// Deliver from the durable acknowledged checkpoint forward. This is the
/// resume path: a subscriber that restarts asks again and receives exactly the
/// events after its last acknowledged checkpoint -- no cursor held in memory,
/// no one-shot body that cannot be re-requested.
pub(crate) async fn handle_subscription_delivery(
    State(st): State<Arc<DaemonState>>,
    AxumPath((owner_namespace, lease_tail)): AxumPath<(String, String)>,
) -> Result<Json<Value>, Refused> {
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

    let history =
        substrate_store::read_event_stream_history(&st.data_dir, &owner_namespace, &stream_tail)
            .map_err(refused)?;
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
    Json(body): Json<Value>,
) -> Result<Json<Value>, Refused> {
    for required in [
        "owner_namespace",
        "stream_tail",
        "subscriber_ref",
        "lease_tail",
    ] {
        if text(&body, required).is_empty() {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "subscription_field_required",
                "owner_namespace, stream_tail, subscriber_ref, and lease_tail are required",
            ));
        }
    }
    let owner_namespace = text(&body, "owner_namespace").to_owned();
    let stream_tail = text(&body, "stream_tail").to_owned();
    let lease_tail = text(&body, "lease_tail").to_owned();

    // A lease may only be issued over a stream that actually exists: an
    // unleased delivery is refused, and so is a lease over nothing.
    let stream =
        substrate_store::read_event_stream_operation(&st.data_dir, &owner_namespace, &stream_tail)
            .map_err(refused)?;
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
    });
    let (seq, head) = admit_lease_transition(
        &st,
        &owner_namespace,
        &lease_tail,
        "subscription_lease.admit",
        None,
        &state,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        &format!("lease-{lease_tail}"),
    )?;
    Ok(Json(lease_view(&state, seq, &head, &lease_tail)))
}
