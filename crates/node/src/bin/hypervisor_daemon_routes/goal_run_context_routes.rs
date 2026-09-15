//! GoalRun-owned ContextLease and ContextHandoff revisions (M04.11).
//!
//! The subject of this module is the ioi.ai orchestration application's own context objects, not
//! Hypervisor core: canon puts their shapes in `domains/ioi-ai/goal-run-execution.md`, and the
//! GoalRun plane already writes the third one (`goal-run-context-cells`) through
//! `build_implementer_context_cell`. Leases and handoffs existed only as INLINE JSON on the
//! activation record until this module — which is how one of them came to name a subject canon
//! forbids: `"issued_to": profile_ref` issues a lease to a reusable HarnessProfile, where canon says
//! "`issued_to_ref` names only a concrete ContextCell or HarnessInvocation". Nothing could refuse it
//! because nothing validated it. Every record here is validated against its REGISTERED contract
//! before it is written, so that shape is now unrepresentable.
//!
//! WHAT THIS MODULE DELIBERATELY DOES NOT OWN. Purpose, data classes, privacy class, redaction,
//! retention and destination/egress are NOT lease fields. They belong to the bound
//! `PolicyBoundDataView` revision and to the `InformationFlowLabel` the lease references, and the
//! resolution below folds them by SUBTRACTION through that plane's OWN published reader
//! (`resolve_admitted_policy_bound_data_view`) rather than reading its records a second time. A
//! lease that declared its own data class could claim one WIDER than the view it leases, which is
//! the hole the object exists to close. The view reader also refuses a family head, the predecessor's
//! `policy-bound-data-view://` spelling and a cross-tenant read BEFORE returning bytes, so this
//! module inherits those refusals instead of restating them.
//!
//! The write path is the estate's shared owner-scoped mutation spine, so genesis-vs-successor,
//! CAS on the head, idempotent replay and scope refusals are the spine's, not this module's:
//! `expected_head: None` admits, `Some(head)` narrows, revokes, accepts or rejects.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::goalrun_routes::sealed;
use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, require_write_caller,
    scope_refusal_reply, stream_tail, ScopedMutation,
};
use super::policy_bound_data_view_revision_routes::resolve_admitted_policy_bound_data_view;
use super::substrate_store::{
    authorize_request_resource_scope, bind_request_resource_scope, resolve_request_identity,
    RequestIdentity,
};
use super::DaemonState;

type Reply = (StatusCode, Json<Value>);

const OWNER_NAMESPACE: &str = "goal-run-context";
const LEASE_RESOURCE_KIND: &str = "context-lease";
const HANDOFF_RESOURCE_KIND: &str = "context-handoff";

const LEASE_SCHEMA_VERSION: &str = "ioi.context-lease.v1";
const HANDOFF_SCHEMA_VERSION: &str = "ioi.context-handoff.v1";

const LEASE_CONTRACT_ID: &str = "schema://ioi/applications/ioi-ai/context-lease/v1";
const HANDOFF_CONTRACT_ID: &str = "schema://ioi/applications/ioi-ai/context-handoff/v1";

const LEASE_ADMITTED_OP: &str = "context_lease_admitted";
const LEASE_NARROWED_OP: &str = "context_lease_narrowed";
const LEASE_REVOKED_OP: &str = "context_lease_revoked";
const HANDOFF_ADMITTED_OP: &str = "context_handoff_admitted";
const HANDOFF_ACCEPTED_OP: &str = "context_handoff_accepted";
const HANDOFF_REJECTED_OP: &str = "context_handoff_rejected";

const LEASE_REQUEST_FIELDS: &[&str] = &[
    "context_lease_id",
    "context_cell_ref",
    "issued_to_ref",
    "lease_kind",
    "allowed_ref_patterns",
    "denied_ref_patterns",
    "authority_scope_refs",
    "budget_ref",
    "ttl_seconds",
    "receipt_required",
    "leased_refs",
    "information_flow_label_refs",
    "permitted_recipient_roles",
    "idempotency_key",
];

const NARROW_REQUEST_FIELDS: &[&str] = &[
    "allowed_ref_patterns",
    "denied_ref_patterns",
    "authority_scope_refs",
    "ttl_seconds",
    "leased_refs",
    "information_flow_label_refs",
    "permitted_recipient_roles",
    "idempotency_key",
];

const HANDOFF_REQUEST_FIELDS: &[&str] = &[
    "handoff_id",
    "from_context_cell_ref",
    "to_context_cell_ref",
    "handoff_kind",
    "payload_ref",
    "context_lease_refs",
    "acceptance_refs",
    "receipt_refs",
    "idempotency_key",
];

const DECISION_REQUEST_FIELDS: &[&str] = &["idempotency_key"];

/// The non-grants a handoff carries on every record. They are CONSTANT by construction: the block
/// exists to be inspectable, so a caller cannot supply it and cannot weaken it.
fn handoff_non_grants() -> Value {
    json!({
        "authority_widening": "none",
        "context_declassification": "none",
        "executable_state_transfer": "none",
        "budget_creation": "none",
        "receiver_policy_bypass": "none",
    })
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": code, "message": message.into() })),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn string_list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn refuse_unknown_request_fields(body: &Value, allowed: &[&str], route: &str) -> Result<(), Reply> {
    let Some(object) = body.as_object() else {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "context_request_body_not_object",
            format!("the {route} request body must be a JSON object"),
        ));
    };
    let permitted: BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !permitted.contains(key.as_str()))
        .cloned()
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(refuse(
        StatusCode::BAD_REQUEST,
        "context_request_unknown_field",
        format!(
            "the {route} request carries field(s) this route does not admit: {}. A dimension this object INHERITS (purpose, data class, redaction, retention, destination) is the bound view's and the label's, never the lease's to declare",
            unknown.join(", ")
        ),
    ))
}

/// Validate a record against its REGISTERED contract before it is written. The registry is the
/// authority on the shape; this module never re-states the field list as a second spine.
fn validate_against_contract(contract_id: &str, record: &Value, code: &str) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract_id,
        record,
    )
    .map_err(|error| {
        refuse(
            StatusCode::BAD_REQUEST,
            code,
            format!("the record violates its registered contract and is NOT admitted: {error}"),
        )
    })
}

fn goal_subject_ref(goal_run_id: &str) -> String {
    format!("goal://{goal_run_id}")
}

/// Build the lease record from the caller's request, filling every server-resolved member. The
/// caller never supplies `schema_version`, `work_subject_ref`, `successor_of`,
/// `predecessor_remains_valid`, `receipt_root` or `status`: those are the daemon's (INV-37), which
/// is why they are absent from `LEASE_REQUEST_FIELDS`.
fn build_lease(body: &Value, goal_run_id: &str) -> Result<Value, Reply> {
    let lease_id = text(body, "context_lease_id");
    if !lease_id.starts_with("context-lease://") || lease_id.len() <= "context-lease://".len() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "context_lease_id_not_canonical",
            "a lease names itself context-lease://<id>; the legacy context_lease:// spelling is refused because the ref-scheme registry forbids emitting it",
        ));
    }
    let record = json!({
        "schema_version": LEASE_SCHEMA_VERSION,
        "context_lease_id": lease_id,
        "work_subject_ref": goal_subject_ref(goal_run_id),
        "context_cell_ref": body.get("context_cell_ref").cloned().unwrap_or(Value::Null),
        "issued_to_ref": text(body, "issued_to_ref"),
        "lease_kind": text(body, "lease_kind"),
        "allowed_ref_patterns": Value::Array(
            string_list(body, "allowed_ref_patterns").into_iter().map(Value::from).collect(),
        ),
        "denied_ref_patterns": Value::Array(
            string_list(body, "denied_ref_patterns").into_iter().map(Value::from).collect(),
        ),
        "authority_scope_refs": Value::Array(
            string_list(body, "authority_scope_refs").into_iter().map(Value::from).collect(),
        ),
        "budget_ref": body.get("budget_ref").cloned().unwrap_or(Value::Null),
        "ttl_seconds": body.get("ttl_seconds").cloned().unwrap_or(Value::Null),
        "receipt_required": body.get("receipt_required").and_then(Value::as_bool).unwrap_or(true),
        "leased_refs": Value::Array(
            string_list(body, "leased_refs").into_iter().map(Value::from).collect(),
        ),
        "information_flow_label_refs": Value::Array(
            string_list(body, "information_flow_label_refs").into_iter().map(Value::from).collect(),
        ),
        "permitted_recipient_roles": Value::Array(
            string_list(body, "permitted_recipient_roles").into_iter().map(Value::from).collect(),
        ),
        "successor_of": Value::Null,
        "predecessor_remains_valid": false,
        "status": "active",
    });
    let record = sealed(record);
    validate_against_contract(LEASE_CONTRACT_ID, &record, "context_lease_contract_invalid")?;
    Ok(record)
}

/// A narrowing is SUBTRACTION. Permission narrows; widening is a NEW binding on record, never an
/// edit of this one, so every member that could grant reach is checked as a subset of the
/// predecessor's and a longer TTL is refused by name.
fn refuse_widening(prior: &Value, next: &Value) -> Result<(), Reply> {
    for member in [
        "leased_refs",
        "allowed_ref_patterns",
        "authority_scope_refs",
        "information_flow_label_refs",
        "permitted_recipient_roles",
    ] {
        let before: BTreeSet<String> = string_list(prior, member).into_iter().collect();
        let after: BTreeSet<String> = string_list(next, member).into_iter().collect();
        let added: Vec<String> = after.difference(&before).cloned().collect();
        if !added.is_empty() {
            return Err(refuse(
                StatusCode::CONFLICT,
                "context_lease_widened",
                format!(
                    "narrowing subtracts: `{member}` gained {} which the predecessor did not carry. Widening a lease is a NEW binding on record, admitted under its own key, never a successor of this one",
                    added.join(", ")
                ),
            ));
        }
    }
    // The denial list may only GROW: a successor that forgets a denial has widened reach by removal.
    let denied_before: BTreeSet<String> = string_list(prior, "denied_ref_patterns")
        .into_iter()
        .collect();
    let denied_after: BTreeSet<String> = string_list(next, "denied_ref_patterns")
        .into_iter()
        .collect();
    let dropped: Vec<String> = denied_before.difference(&denied_after).cloned().collect();
    if !dropped.is_empty() {
        return Err(refuse(
            StatusCode::CONFLICT,
            "context_lease_denial_dropped",
            format!(
                "a successor may add denials and never drop them; {} disappeared, which widens reach by removal",
                dropped.join(", ")
            ),
        ));
    }
    let before_ttl = prior.get("ttl_seconds").and_then(Value::as_u64);
    let after_ttl = next.get("ttl_seconds").and_then(Value::as_u64);
    match (before_ttl, after_ttl) {
        (Some(before), Some(after)) if after > before => Err(refuse(
            StatusCode::CONFLICT,
            "context_lease_ttl_extended",
            format!("narrowing cannot extend a lease: ttl_seconds {before} -> {after}"),
        )),
        (Some(_), None) => Err(refuse(
            StatusCode::CONFLICT,
            "context_lease_ttl_removed",
            "a bounded lease cannot become unbounded through a narrowing",
        )),
        _ => Ok(()),
    }
}

fn lease_from_history(history: &[agentgres::mux::ExactProjection]) -> Option<(Value, String)> {
    history.iter().find_map(|entry| {
        matches!(
            entry.operation.op_kind.as_str(),
            LEASE_ADMITTED_OP | LEASE_NARROWED_OP | LEASE_REVOKED_OP
        )
        .then(|| {
            entry
                .operation
                .payload
                .get("context_lease")
                .cloned()
                .map(|lease| (lease, entry.head.clone()))
        })
        .flatten()
    })
}

fn handoff_from_history(history: &[agentgres::mux::ExactProjection]) -> Option<(Value, String)> {
    history.iter().find_map(|entry| {
        matches!(
            entry.operation.op_kind.as_str(),
            HANDOFF_ADMITTED_OP | HANDOFF_ACCEPTED_OP | HANDOFF_REJECTED_OP
        )
        .then(|| {
            entry
                .operation
                .payload
                .get("context_handoff")
                .cloned()
                .map(|handoff| (handoff, entry.head.clone()))
        })
        .flatten()
    })
}

// ------------------------------------------------------------------------------------- leases

pub(crate) async fn handle_context_lease_admit(
    State(st): State<Arc<DaemonState>>,
    Path(goal_run_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST: validating content before authenticating answers 422 where 401 is owed.
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        refuse_unknown_request_fields(&body, LEASE_REQUEST_FIELDS, "context lease")
    {
        return response;
    }
    let record = match build_lease(&body, &goal_run_id) {
        Ok(record) => record,
        Err(response) => return response,
    };
    let lease_ref = text(&record, "context_lease_id");
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(LEASE_RESOURCE_KIND, &lease_ref);
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        OWNER_NAMESPACE,
        &tail,
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let stored = prior
                .operation
                .payload
                .get("context_lease")
                .cloned()
                .unwrap_or(Value::Null);
            if text(&stored, "receipt_root") != text(&record, "receipt_root") {
                return refuse(
                    StatusCode::CONFLICT,
                    "context_lease_replay_diverged",
                    "the same idempotency key already admitted a DIFFERENT lease: its receipt_root does not match. Author the changed lease under a new key",
                );
            }
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "context_lease_ref": lease_ref,
                    "context_lease": stored,
                    "admitted_head": prior.head,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }
    let recorded_at_ms = now_ms();
    let payload = json!({
        "context_lease": record,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: LEASE_RESOURCE_KIND,
            resource_ref: &lease_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: LEASE_ADMITTED_OP,
            expected_head: None,
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "context_lease_ref": lease_ref,
            "context_lease": record,
            "admitted_head": commit.projection.head,
        })),
    )
}

/// Narrow or revoke: both are SUCCESSORS on the lease's own stream, so both inherit the spine's CAS
/// on the head. `revoking` decides which, because the only difference is the status the successor
/// carries and whether the caller may restate members at all.
async fn admit_lease_successor(
    st: Arc<DaemonState>,
    goal_run_id: String,
    lease_id: String,
    headers: HeaderMap,
    body: Value,
    revoking: bool,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let allowed = if revoking {
        DECISION_REQUEST_FIELDS
    } else {
        NARROW_REQUEST_FIELDS
    };
    let route = if revoking { "revoke" } else { "narrow" };
    if let Err(response) = refuse_unknown_request_fields(&body, allowed, route) {
        return response;
    }
    let lease_ref = format!("context-lease://{lease_id}");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        Some(&caller.owner_ref),
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(LEASE_RESOURCE_KIND, &lease_ref);
    let history = match read_owner_scoped_history(
        &st.data_dir,
        &caller.identity,
        &scope,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        OWNER_NAMESPACE,
        &tail,
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some((prior, head)) = lease_from_history(&history) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "context_lease_unknown",
            "no admitted lease answers to that ref",
        );
    };
    if text(&prior, "work_subject_ref") != goal_subject_ref(&goal_run_id) {
        return refuse(
            StatusCode::NOT_FOUND,
            "context_lease_subject_mismatch",
            "that lease belongs to a different work subject; a lease is reached through its own GoalRun",
        );
    }
    let prior_status = text(&prior, "status");
    if prior_status == "revoked" || prior_status == "expired" {
        return refuse(
            StatusCode::CONFLICT,
            "context_lease_terminal",
            format!("the lease is already {prior_status}; a terminal lease admits no successor"),
        );
    }

    let mut next = prior.clone();
    if let Some(object) = next.as_object_mut() {
        object.remove("receipt_root");
        if revoking {
            object.insert("status".into(), json!("revoked"));
        } else {
            for member in NARROW_REQUEST_FIELDS {
                if *member == "idempotency_key" {
                    continue;
                }
                if let Some(value) = body.get(*member) {
                    object.insert((*member).to_string(), value.clone());
                }
            }
        }
        object.insert(
            "successor_of".into(),
            json!(text(&prior, "context_lease_id")),
        );
        object.insert("predecessor_remains_valid".into(), json!(false));
    }
    let next = sealed(next);
    if !revoking {
        if let Err(response) = refuse_widening(&prior, &next) {
            return response;
        }
    }
    if let Err(response) =
        validate_against_contract(LEASE_CONTRACT_ID, &next, "context_lease_contract_invalid")
    {
        return response;
    }

    let recorded_at_ms = now_ms();
    let payload = json!({
        "context_lease": next,
        "predecessor": prior,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: LEASE_RESOURCE_KIND,
            resource_ref: &lease_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: if revoking {
                LEASE_REVOKED_OP
            } else {
                LEASE_NARROWED_OP
            },
            expected_head: Some(&head),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "context_lease_ref": lease_ref,
            "context_lease": next,
            "admitted_head": commit.projection.head,
        })),
    )
}

pub(crate) async fn handle_context_lease_narrow(
    State(st): State<Arc<DaemonState>>,
    Path((goal_run_id, lease_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    admit_lease_successor(st, goal_run_id, lease_id, headers, body, false).await
}

pub(crate) async fn handle_context_lease_revoke(
    State(st): State<Arc<DaemonState>>,
    Path((goal_run_id, lease_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    admit_lease_successor(st, goal_run_id, lease_id, headers, body, true).await
}

/// The least-context RESOLUTION: rebuilt on every read, never persisted, and never wider than what
/// the bound views allow. Each `view://…/revision/…` entry is resolved through the view plane's own
/// published reader under the CALLER's identity, so a cross-tenant read, a family head and the
/// legacy spelling are refused by that owner before any bytes come back, and the uses this lease can
/// serve are the INTERSECTION of the views' own `allowed_uses`.
pub(crate) async fn handle_context_lease_resolution(
    State(st): State<Arc<DaemonState>>,
    Path((goal_run_id, lease_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let lease_ref = format!("context-lease://{lease_id}");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let history = match read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &scope,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        OWNER_NAMESPACE,
        &stream_tail(LEASE_RESOURCE_KIND, &lease_ref),
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some((lease, head)) = lease_from_history(&history) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "context_lease_unknown",
            "no admitted lease answers to that ref",
        );
    };
    if text(&lease, "work_subject_ref") != goal_subject_ref(&goal_run_id) {
        return refuse(
            StatusCode::NOT_FOUND,
            "context_lease_subject_mismatch",
            "that lease belongs to a different work subject",
        );
    }
    let status = text(&lease, "status");
    if status != "active" {
        return refuse(
            StatusCode::CONFLICT,
            "context_lease_not_active",
            format!("a {status} lease resolves nothing"),
        );
    }

    // Views contribute their OWN denials. A lease that binds no view resolves to its refs unchanged
    // and says so, rather than implying a policy nobody asserted.
    let mut view_bindings = Vec::new();
    let mut intersected: Option<BTreeSet<String>> = None;
    for reference in string_list(&lease, "leased_refs") {
        if !reference.starts_with("view://") {
            continue;
        }
        let resolved = match resolve_admitted_policy_bound_data_view(
            &st.data_dir,
            &identity,
            None,
            &reference,
        ) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if !resolved.is_active() {
            return refuse(
                StatusCode::CONFLICT,
                "context_lease_view_not_active",
                format!("{reference} is not an active view revision, so this lease resolves nothing through it"),
            );
        }
        let uses: BTreeSet<String> = resolved.allowed_uses().into_iter().collect();
        intersected = Some(match intersected {
            None => uses.clone(),
            Some(existing) => existing.intersection(&uses).cloned().collect(),
        });
        view_bindings.push(json!({
            "view_revision_ref": reference,
            "allowed_uses": uses.iter().cloned().collect::<Vec<String>>(),
        }));
    }

    let (permitted_uses, uses_source) = match intersected {
        Some(uses) => (
            uses.into_iter().collect::<Vec<String>>(),
            "intersection_of_bound_view_allowed_uses",
        ),
        None => (Vec::new(), "no_view_bound_to_this_lease"),
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "context_lease_ref": lease_ref,
            "context_lease": lease,
            "admitted_head": head,
            "resolution": {
                "read_model_only": true,
                "leased_refs": string_list(&lease, "leased_refs"),
                "view_bindings": view_bindings,
                "permitted_uses": permitted_uses,
                "permitted_uses_source": uses_source,
                // Said, not implied: the dimensions this lease INHERITS are the bound view's and the
                // label's, and this resolution neither restates nor widens them.
                "inherited_dimensions": {
                    "owner": "policy_bound_data_view_revision_and_information_flow_label",
                    "members": [
                        "purpose",
                        "data_classes",
                        "privacy_class",
                        "redaction",
                        "retention_and_hold",
                        "destination_and_egress"
                    ],
                    "restated_here": false
                },
                "information_flow_label_refs": string_list(&lease, "information_flow_label_refs"),
            },
        })),
    )
}

// ----------------------------------------------------------------------------------- handoffs

pub(crate) async fn handle_context_handoff_admit(
    State(st): State<Arc<DaemonState>>,
    Path(goal_run_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        refuse_unknown_request_fields(&body, HANDOFF_REQUEST_FIELDS, "context handoff")
    {
        return response;
    }
    let handoff_id = text(&body, "handoff_id");
    if !handoff_id.starts_with("handoff://") || handoff_id.len() <= "handoff://".len() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "context_handoff_id_not_canonical",
            "a handoff names itself handoff://<id>",
        );
    }
    let record = sealed(json!({
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "handoff_id": handoff_id,
        "work_subject_ref": goal_subject_ref(&goal_run_id),
        "from_context_cell_ref": text(&body, "from_context_cell_ref"),
        "to_context_cell_ref": text(&body, "to_context_cell_ref"),
        "handoff_kind": text(&body, "handoff_kind"),
        "payload_ref": body.get("payload_ref").cloned().unwrap_or(Value::Null),
        "context_lease_refs": Value::Array(
            string_list(&body, "context_lease_refs").into_iter().map(Value::from).collect(),
        ),
        "acceptance_refs": Value::Array(
            string_list(&body, "acceptance_refs").into_iter().map(Value::from).collect(),
        ),
        "receipt_refs": Value::Array(
            string_list(&body, "receipt_refs").into_iter().map(Value::from).collect(),
        ),
        // Constant by construction: the caller cannot supply or weaken a non-grant.
        "non_grants": handoff_non_grants(),
        "successor_of": Value::Null,
        "status": "sent",
    }));
    if text(&record, "from_context_cell_ref") == text(&record, "to_context_cell_ref") {
        return refuse(
            StatusCode::BAD_REQUEST,
            "context_handoff_self_directed",
            "a handoff moves context BETWEEN cells; a cell handing off to itself is a summarisation, not a handoff",
        );
    }
    if let Err(response) = validate_against_contract(
        HANDOFF_CONTRACT_ID,
        &record,
        "context_handoff_contract_invalid",
    ) {
        return response;
    }
    let handoff_ref = text(&record, "handoff_id");
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        HANDOFF_RESOURCE_KIND,
        &handoff_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(HANDOFF_RESOURCE_KIND, &handoff_ref);
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        HANDOFF_RESOURCE_KIND,
        &handoff_ref,
        OWNER_NAMESPACE,
        &tail,
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let stored = prior
                .operation
                .payload
                .get("context_handoff")
                .cloned()
                .unwrap_or(Value::Null);
            if text(&stored, "receipt_root") != text(&record, "receipt_root") {
                return refuse(
                    StatusCode::CONFLICT,
                    "context_handoff_replay_diverged",
                    "the same idempotency key already admitted a DIFFERENT handoff",
                );
            }
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "context_handoff_ref": handoff_ref,
                    "context_handoff": stored,
                    "admitted_head": prior.head,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }
    let recorded_at_ms = now_ms();
    let payload = json!({
        "context_handoff": record,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: HANDOFF_RESOURCE_KIND,
            resource_ref: &handoff_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: HANDOFF_ADMITTED_OP,
            expected_head: None,
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "context_handoff_ref": handoff_ref,
            "context_handoff": record,
            "admitted_head": commit.projection.head,
        })),
    )
}

/// Acceptance and rejection are SUCCESSORS. Acceptance creates a CANDIDATE under the receiver's own
/// policy: it transfers no authority and copies no lease, so the accepted record names the leases it
/// arrived with and grants the receiver nothing it does not independently hold.
async fn decide_handoff(
    st: Arc<DaemonState>,
    goal_run_id: String,
    handoff_id: String,
    headers: HeaderMap,
    body: Value,
    accepting: bool,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let route = if accepting { "accept" } else { "reject" };
    if let Err(response) = refuse_unknown_request_fields(&body, DECISION_REQUEST_FIELDS, route) {
        return response;
    }
    let handoff_ref = format!("handoff://{handoff_id}");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        HANDOFF_RESOURCE_KIND,
        &handoff_ref,
        Some(&caller.owner_ref),
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(HANDOFF_RESOURCE_KIND, &handoff_ref);
    let history = match read_owner_scoped_history(
        &st.data_dir,
        &caller.identity,
        &scope,
        HANDOFF_RESOURCE_KIND,
        &handoff_ref,
        OWNER_NAMESPACE,
        &tail,
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some((prior, head)) = handoff_from_history(&history) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "context_handoff_unknown",
            "no admitted handoff answers to that ref",
        );
    };
    if text(&prior, "work_subject_ref") != goal_subject_ref(&goal_run_id) {
        return refuse(
            StatusCode::NOT_FOUND,
            "context_handoff_subject_mismatch",
            "that handoff belongs to a different work subject",
        );
    }
    let prior_status = text(&prior, "status");
    if prior_status != "sent" {
        return refuse(
            StatusCode::CONFLICT,
            "context_handoff_not_pending",
            format!(
                "the handoff is {prior_status}; only a sent handoff can be accepted or rejected"
            ),
        );
    }

    let mut next = prior.clone();
    if let Some(object) = next.as_object_mut() {
        object.remove("receipt_root");
        object.insert(
            "status".into(),
            json!(if accepting { "accepted" } else { "rejected" }),
        );
        object.insert("successor_of".into(), json!(text(&prior, "handoff_id")));
        // The non-grants are re-asserted on the successor rather than inherited silently: the
        // decision is the moment the claim matters most.
        object.insert("non_grants".into(), handoff_non_grants());
    }
    let next = sealed(next);
    if let Err(response) = validate_against_contract(
        HANDOFF_CONTRACT_ID,
        &next,
        "context_handoff_contract_invalid",
    ) {
        return response;
    }
    let recorded_at_ms = now_ms();
    let payload = json!({
        "context_handoff": next,
        "predecessor": prior,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: HANDOFF_RESOURCE_KIND,
            resource_ref: &handoff_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: if accepting {
                HANDOFF_ACCEPTED_OP
            } else {
                HANDOFF_REJECTED_OP
            },
            expected_head: Some(&head),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "context_handoff_ref": handoff_ref,
            "context_handoff": next,
            "admitted_head": commit.projection.head,
            "candidate_under_receiver_policy": accepting,
        })),
    )
}

pub(crate) async fn handle_context_handoff_accept(
    State(st): State<Arc<DaemonState>>,
    Path((goal_run_id, handoff_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    decide_handoff(st, goal_run_id, handoff_id, headers, body, true).await
}

pub(crate) async fn handle_context_handoff_reject(
    State(st): State<Arc<DaemonState>>,
    Path((goal_run_id, handoff_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    decide_handoff(st, goal_run_id, handoff_id, headers, body, false).await
}

/// Admit the activation lane's OWN ContextLease for one implementer role.
///
/// The activation lane used to write this lease as an inline literal on the goal-run record, and
/// that is how it came to name a reusable HarnessProfile as the lease subject: `issued_to_ref` here
/// is the implementer's own CELL, which is what canon permits. The lease is now an ADMITTED revision
/// on the shared spine like any other, so the array the goal run carries is a projection of what was
/// admitted rather than a second source of truth.
///
/// The idempotency key is DERIVED from the run and the role rather than taken from the caller: a
/// replayed creation must replay the same lease instead of minting a second one for the same cell.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_activation_context_lease(
    data_dir: &str,
    identity: &RequestIdentity,
    owner_ref: &str,
    goal_run_id: &str,
    role_key: &str,
    cell_ref: &str,
    workspace_ref: &str,
    denied_session_workspace_ref: &str,
) -> Result<Value, Reply> {
    let lease_ref = format!("context-lease://cl_{goal_run_id}_{role_key}");
    let record = sealed(json!({
        "schema_version": LEASE_SCHEMA_VERSION,
        "context_lease_id": lease_ref,
        "work_subject_ref": goal_subject_ref(goal_run_id),
        "context_cell_ref": cell_ref,
        // The CELL, never the reusable HarnessProfile the inline literal used to name.
        "issued_to_ref": cell_ref,
        "lease_kind": "worktree",
        "allowed_ref_patterns": [workspace_ref],
        "denied_ref_patterns": [
            "secret://",
            "unsafe_plaintext://",
            denied_session_workspace_ref,
        ],
        "authority_scope_refs": [],
        "budget_ref": format!("budget://goal-run/{goal_run_id}/invocation"),
        "ttl_seconds": 3600,
        "receipt_required": true,
        // The implementer's writable surface is ITS candidate workspace only.
        "leased_refs": [workspace_ref],
        "information_flow_label_refs": [],
        "permitted_recipient_roles": ["implementer"],
        "successor_of": Value::Null,
        "predecessor_remains_valid": false,
        "status": "active",
    }));
    validate_against_contract(LEASE_CONTRACT_ID, &record, "context_lease_contract_invalid")?;

    let idempotency_key = format!("goal-run-activation:{goal_run_id}:{role_key}");
    let scope = bind_request_resource_scope(
        data_dir,
        identity,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        owner_ref,
        owner_ref,
        &idempotency_key,
    )
    .map_err(scope_refusal_reply)?;
    let tail = stream_tail(LEASE_RESOURCE_KIND, &lease_ref);
    match prior_admission_for_key_on_stream(
        data_dir,
        identity,
        &scope,
        LEASE_RESOURCE_KIND,
        &lease_ref,
        OWNER_NAMESPACE,
        &tail,
        &idempotency_key,
    ) {
        Ok(Some(prior)) => {
            return Ok(prior
                .operation
                .payload
                .get("context_lease")
                .cloned()
                .unwrap_or(record));
        }
        Ok(None) => {}
        Err(error) => return Err(mutation_refusal_reply(error)),
    }

    let recorded_at_ms = now_ms();
    let payload = json!({
        "context_lease": record,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    admit_owner_scoped_mutation(
        data_dir,
        true,
        ScopedMutation {
            identity,
            scope: &scope,
            resource_kind: LEASE_RESOURCE_KIND,
            resource_ref: &lease_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: LEASE_ADMITTED_OP,
            expected_head: None,
            payload: &payload,
            idempotency_key: &idempotency_key,
            recorded_at_ms,
        },
    )
    .map_err(mutation_refusal_reply)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_body() -> Value {
        json!({
            "context_lease_id": "context-lease://cl_gr_1_implementer",
            "context_cell_ref": "context-cell://cc_gr_1_implementer",
            "issued_to_ref": "context-cell://cc_gr_1_implementer",
            "lease_kind": "worktree",
            "allowed_ref_patterns": ["workspace://goal-run/gr_1/implementer"],
            "denied_ref_patterns": ["secret://"],
            "authority_scope_refs": [],
            "budget_ref": null,
            "ttl_seconds": 3600,
            "receipt_required": true,
            "leased_refs": ["workspace://goal-run/gr_1/implementer"],
            "information_flow_label_refs": [],
            "permitted_recipient_roles": ["implementer"],
        })
    }

    #[test]
    fn a_built_lease_satisfies_its_registered_contract_and_seals_itself() {
        let record = build_lease(&lease_body(), "gr_1").expect("the lease is admissible");
        assert_eq!(text(&record, "work_subject_ref"), "goal://gr_1");
        assert_eq!(text(&record, "status"), "active");
        assert!(text(&record, "receipt_root").starts_with("sha256:"));
        // Server-resolved members are the daemon's, never the caller's (INV-37).
        assert_eq!(record.get("successor_of"), Some(&Value::Null));
    }

    #[test]
    fn a_lease_issued_to_a_reusable_harness_profile_is_refused_by_the_contract() {
        // The defect this unit found in the activation lane: `"issued_to": profile_ref` issued a
        // lease to a reusable HarnessProfile, which canon forbids as a lease subject.
        let mut body = lease_body();
        body["issued_to_ref"] = json!("harness-profile://acme/claude-code");
        assert!(build_lease(&body, "gr_1").is_err());
    }

    #[test]
    fn a_lease_naming_a_view_family_head_is_refused_and_a_revision_is_admitted() {
        let mut body = lease_body();
        body["leased_refs"] = json!(["view://acme/contacts"]);
        assert!(build_lease(&body, "gr_1").is_err());
        body["leased_refs"] = json!(["view://acme/contacts/revision/3"]);
        assert!(build_lease(&body, "gr_1").is_ok());
    }

    #[test]
    fn the_legacy_underscore_identity_is_refused() {
        let mut body = lease_body();
        body["context_lease_id"] = json!("context_lease://cl_gr_1_implementer");
        assert!(build_lease(&body, "gr_1").is_err());
    }

    #[test]
    fn a_request_that_declares_an_inherited_dimension_is_refused_by_name() {
        let mut body = lease_body();
        body["data_class"] = json!("confidential");
        let refusal = refuse_unknown_request_fields(&body, LEASE_REQUEST_FIELDS, "context lease")
            .expect_err("a lease may not declare a dimension it inherits");
        assert_eq!(refusal.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn narrowing_subtracts_and_every_widening_member_refuses_by_name() {
        let prior = build_lease(&lease_body(), "gr_1").expect("admissible");
        for member in [
            "leased_refs",
            "allowed_ref_patterns",
            "authority_scope_refs",
            "information_flow_label_refs",
            "permitted_recipient_roles",
        ] {
            let mut next = prior.clone();
            let widened = match member {
                "permitted_recipient_roles" => json!(["implementer", "reviewer"]),
                "information_flow_label_refs" => json!(["ifc-label://acme/1"]),
                "authority_scope_refs" => json!(["authority://acme/extra"]),
                _ => json!([
                    "workspace://goal-run/gr_1/implementer",
                    "workspace://elsewhere"
                ]),
            };
            next[member] = widened;
            assert!(
                refuse_widening(&prior, &next).is_err(),
                "{member} widened without a refusal"
            );
        }
        // The same members SHRINKING are admitted.
        let mut narrowed = prior.clone();
        narrowed["permitted_recipient_roles"] = json!([]);
        assert!(refuse_widening(&prior, &narrowed).is_ok());
    }

    #[test]
    fn a_dropped_denial_and_an_extended_ttl_are_both_widenings() {
        let prior = build_lease(&lease_body(), "gr_1").expect("admissible");
        let mut dropped = prior.clone();
        dropped["denied_ref_patterns"] = json!([]);
        assert!(refuse_widening(&prior, &dropped).is_err());
        let mut extended = prior.clone();
        extended["ttl_seconds"] = json!(7200);
        assert!(refuse_widening(&prior, &extended).is_err());
        let mut unbounded = prior.clone();
        unbounded["ttl_seconds"] = Value::Null;
        assert!(refuse_widening(&prior, &unbounded).is_err());
        let mut shortened = prior.clone();
        shortened["ttl_seconds"] = json!(60);
        assert!(refuse_widening(&prior, &shortened).is_ok());
    }

    #[test]
    fn the_handoff_non_grants_are_constant_and_satisfy_the_contract() {
        let record = sealed(json!({
            "schema_version": HANDOFF_SCHEMA_VERSION,
            "handoff_id": "handoff://ho_1",
            "work_subject_ref": "goal://gr_1",
            "from_context_cell_ref": "context-cell://cc_gr_1_conductor",
            "to_context_cell_ref": "context-cell://cc_gr_1_implementer",
            "handoff_kind": "task_brief",
            "payload_ref": "task-brief://tb_1",
            "context_lease_refs": [],
            "acceptance_refs": [],
            "receipt_refs": [],
            "non_grants": handoff_non_grants(),
            "successor_of": Value::Null,
            "status": "sent",
        }));
        assert!(validate_against_contract(
            HANDOFF_CONTRACT_ID,
            &record,
            "context_handoff_contract_invalid"
        )
        .is_ok());
        let mut weakened = record.clone();
        weakened["non_grants"]["authority_widening"] = json!("scoped");
        assert!(validate_against_contract(
            HANDOFF_CONTRACT_ID,
            &weakened,
            "context_handoff_contract_invalid"
        )
        .is_err());
    }
}
