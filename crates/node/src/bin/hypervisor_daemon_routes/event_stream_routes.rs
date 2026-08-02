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

    let admitted = substrate_store::admit_event_stream_operation(
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

    let admitted = substrate_store::admit_event_stream_operation(
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
    let exact = &admitted.projection;

    Ok(Json(json!({
        "replayed": admitted.replayed,
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
