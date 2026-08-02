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
use super::{AppError, DaemonState};
use agentgres::event_stream::AdmissionRefusal;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

fn bad(status: StatusCode, code: &str, message: &str) -> AppError {
    AppError(
        status,
        json!({ "error": { "code": code, "message": message } }).to_string(),
    )
}

/// Map one typed substrate refusal onto the wire.
///
/// The refusal VOCABULARY is the library's, not this route's: the code and
/// message come from `AdmissionRefusal` so that the same failure names itself
/// identically wherever admission is attempted. A route that reworded the
/// substrate's refusals would make two callers of one mechanism look like two
/// mechanisms.
fn refused(refusal: AdmissionRefusal) -> AppError {
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

/// The owner's declared class table for one stream, read from the request.
/// The substrate validates SHAPE — that a class is declared and on exactly one
/// side of the line — never the owner's vocabulary.
fn classify<'a>(body: &'a Value, class_id: &str) -> Option<(&'a str, bool)> {
    for (list, admitted) in [
        ("admitted_truth_classes", true),
        ("ephemeral_delivery_classes", false),
    ] {
        if let Some(classes) = body
            .get("event_class_declaration")
            .and_then(|d| d.get(list))
            .and_then(Value::as_array)
        {
            for class in classes {
                if text(class, "class_id") == class_id {
                    return Some((text(class, "payload_schema_ref"), admitted));
                }
            }
        }
    }
    None
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
) -> Result<Json<Value>, AppError> {
    let class_id = text(&body, "class_id");
    if class_id.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "event_class_id_required",
            "an append names the owner-declared class it belongs to",
        ));
    }
    let Some((payload_schema_ref, admitted)) = classify(&body, class_id) else {
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

    let expected_head = body.get("expected_head").and_then(Value::as_str);
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

    let exact = substrate_store::admit_event_stream_operation(
        &st.data_dir,
        &owner_namespace,
        &stream_tail,
        "event_stream.append",
        expected_head,
        body.get("payload").unwrap_or(&Value::Null),
        recorded_at_ms,
        idem_key,
    )
    .map_err(refused)?;

    Ok(Json(json!({
        "delivery": "admitted",
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
) -> Result<Json<Value>, AppError> {
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

/// POST /v1/subscriptions — create a durable subscription lease over one
/// owner-namespaced stream. The lease transition is itself admitted through
/// canonical Agentgres: the family mints no lease chain of its own.
pub(crate) async fn handle_subscription_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
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

    let exact = substrate_store::admit_event_stream_operation(
        &st.data_dir,
        &owner_namespace,
        &format!("lease.{lease_tail}"),
        "subscription_lease.admit",
        body.get("expected_head").and_then(Value::as_str),
        &body,
        body.get("recorded_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        &format!("lease-{lease_tail}"),
    )
    .map_err(refused)?;

    Ok(Json(json!({
        "lease_id": format!("subscription-lease://{lease_tail}"),
        "stream_id": format!("event-stream://{owner_namespace}/{stream_tail}"),
        "lease_state": "active",
        "admitted_lease_transition": {
            "operation_ref": agentgres::refs::subscription_lease_operation_ref(&lease_tail, exact.seq, &exact.head),
            "resulting_head_ref": exact.head,
            "admission_receipt_ref": agentgres::refs::subscription_lease_receipt_ref(
                &lease_tail, exact.admission_batch_seq, &exact.admission_root),
            "admission_root_ref": exact.admission_root,
        },
        "nonclaim": "The lease references canonical Agentgres truth and owns no transition chain; delivery adapters own nothing.",
    })))
}
