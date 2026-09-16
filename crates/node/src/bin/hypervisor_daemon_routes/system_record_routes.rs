//! System-scoped application records — the generic contract-typed record seam under a bounded
//! System (register R-172, slice S1; the platform guarantee M04.4 names as the generalized
//! admitted-record contract and ADR 0030 names as "Agentgres operation-backed admission").
//!
//! An application composes its orchestrations from daemon primitives (System genesis and its
//! transition chain, threads and forks, managed sessions and harness bindings, the work-lifecycle
//! plane) and records its OWN typed vocabulary through this one seam: any registered contract
//! whose shape carries a `SystemScopedObjectBinding` is admitted here as an ordinary
//! `event_stream.*` operation on the shared owner-scoped write path — exact heads, idempotent
//! replay, receipts, the same tenant scope discipline every other family uses. The platform
//! knows no application vocabulary: it validates by contract id, derives the binding, and keeps
//! the chain. Nothing here names, models or projects what an application builds over it.
//!
//! Refused by name: a binding the caller authored (it is derived), an identity the record does
//! not carry, a contract the registry does not know, a contract whose shape carries no binding
//! (it has no place under a System), a System that is not active, a stale head.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde_json::{json, Value};

use super::model_route_rights_routes::{bad, head_assertion, require_exact_head, AdmittedRecord};
use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, mutation_refusal_reply, read_owner_scoped_history,
    require_write_caller, scope_refusal_reply, stream_tail, ScopedMutation, WriteCaller,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::DaemonState;

type Reply = (StatusCode, Json<Value>);

pub(crate) const OWNER_NAMESPACE: &str = "system-records";
pub(crate) const RESOURCE_KIND: &str = "system_record";
pub(crate) const ADMIT_OP: &str = "event_stream.system_record_admitted";
pub(crate) const PAYLOAD_SCHEMA: &str = "ioi.hypervisor.system-record-admission.v1";
const CODE_PREFIX: &str = "system_record";
const SYSTEM_BINDING_SCHEMA: &str = "ioi.foundations.system-scoped-object-binding.v1";
const REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "contract_id",
    "object_id",
    "parent_scope_ref",
    "record",
    "expected_head",
];

fn code(suffix: &str) -> String {
    format!("{CODE_PREFIX}_{suffix}")
}

fn refuse(suffix: &str, message: impl Into<String>) -> Reply {
    bad(StatusCode::UNPROCESSABLE_ENTITY, &code(suffix), message)
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

fn slug(reference: &str) -> String {
    reference
        .replacen("://", "-", 1)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

/// The resource one record occupies under its System: the System, the contract and the record's
/// own identity — so two contracts may share an id, and two Systems may hold the same contract.
pub(crate) fn resource_ref(system_id: &str, contract_id: &str, object_id: &str) -> String {
    format!("{system_id}/{}/{}", slug(contract_id), slug(object_id))
}

/// Which top-level member of the record carries `object_id`: exactly one `*_id` string member
/// must equal it. Identity is the record's own, never chosen beside it.
pub(crate) fn identity_member(record: &Value, object_id: &str) -> Result<String, String> {
    let Some(map) = record.as_object() else {
        return Err("the record must be a JSON object".into());
    };
    let carriers: Vec<&String> = map
        .iter()
        .filter(|(key, value)| key.ends_with("_id") && value.as_str() == Some(object_id))
        .map(|(key, _)| key)
        .collect();
    match carriers.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!(
            "no `*_id` member of the record carries object_id {object_id:?}; the identity this seam admits is the record's own"
        )),
        many => Err(format!(
            "object_id {object_id:?} is carried by {} members ({}); one record has one identity",
            many.len(),
            many.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// The binding this seam derives and the record never authors: the System, the parent scope,
/// the resolved principal, and a payload root over the record with the binding absent.
pub(crate) fn derive_binding(
    record: &Value,
    system_id: &str,
    parent_scope_ref: &str,
    principal_ref: &str,
    created_at: &str,
) -> Result<Value, String> {
    let mut body = record.clone();
    if let Some(map) = body.as_object_mut() {
        map.insert("system_binding".into(), Value::Null);
    }
    let bytes = serde_jcs::to_vec(&body).map_err(|error| error.to_string())?;
    let payload_root = format!(
        "sha256:{}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes))
    );
    Ok(json!({
        "schema_version": SYSTEM_BINDING_SCHEMA,
        "system_id": system_id,
        "parent_scope_ref": parent_scope_ref,
        "proposed_or_issued_by_ref": principal_ref,
        "payload_root": payload_root,
        "created_at": created_at,
        "updated_at": Value::Null,
    }))
}

/// Every revision's `receipt_ref` and `operation_ref` are DERIVED here from the projection's own
/// coordinates, exactly as the admit reply derives them, so a reader re-attaching after a restart
/// can cite the receipt of an earlier admission without having witnessed it. The R-172 S3 driven
/// gate found the chain view served neither: a decision that must cite the receipt of the
/// submission it answers, and an activation that must name the receipts of the acceptances, had
/// nothing to cite.
fn project(history: &[agentgres::mux::ExactProjection], stream_tail: &str) -> Vec<AdmittedRecord> {
    history
        .iter()
        .map(|entry| AdmittedRecord {
            record: entry
                .operation
                .payload
                .get("record")
                .cloned()
                .unwrap_or(Value::Null),
            admission: json!({
                "seq": entry.seq,
                "head": entry.head,
                "admission_batch_seq": entry.admission_batch_seq,
                "admission_root": entry.admission_root,
                "terminal_root": entry.terminal_root,
                "op_kind": entry.operation.op_kind,
                "object_ref": entry.operation.object_ref,
                "contract_id": entry.operation.payload.get("contract_id").cloned().unwrap_or(Value::Null),
                "idempotency_key": entry.operation.idem_key,
                "recorded_at_ms": entry.operation.recorded_at_ms,
                "system_binding": entry.operation.payload.pointer("/record/system_binding").cloned().unwrap_or(Value::Null),
                "operation_ref": agentgres::refs::event_stream_operation_ref(OWNER_NAMESPACE, stream_tail, entry.seq, &entry.head),
                "receipt_ref": agentgres::refs::event_stream_receipt_ref(OWNER_NAMESPACE, stream_tail, entry.admission_batch_seq, &entry.admission_root),
            }),
            head: entry.head.clone(),
            recorded_at_ms: entry
                .operation
                .payload
                .get("recorded_at_ms")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        })
        .collect()
}

fn read_records(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    resource: &str,
) -> Result<Vec<AdmittedRecord>, Reply> {
    let tail = stream_tail(RESOURCE_KIND, resource);
    let history = read_owner_scoped_history(
        data_dir,
        identity,
        scope,
        RESOURCE_KIND,
        resource,
        OWNER_NAMESPACE,
        &tail,
    )
    .map_err(mutation_refusal_reply)?;
    Ok(project(&history, &tail))
}

fn family_view(stream: &[AdmittedRecord]) -> Value {
    json!({
        "ok": true,
        "current": stream.last().map(|entry| entry.record.clone()),
        "revisions": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
        "admissions": stream.iter().map(|entry| entry.admission.clone()).collect::<Vec<_>>(),
        "head": stream.last().map(|entry| entry.head.clone()),
    })
}

/// The System must be ACTIVE: its genesis admitted and activated. The platform's own check,
/// applied here exactly as the System planes apply it; a System that is not active holds no
/// application records.
fn require_active_system(data_dir: &str, system_id: &str) -> Result<(), Reply> {
    if !system_id.starts_with("system://") {
        return Err(refuse(
            "system_ref_invalid",
            "the path names a system:// ref",
        ));
    }
    super::system_activation_routes::load_active_system_graph(data_dir, system_id)
        .map(|_| ())
        .map_err(|(inner, message)| {
            bad(
                StatusCode::CONFLICT,
                &code("system_not_active"),
                format!("no ACTIVE bounded System answers to {system_id} ({inner}: {message}); application records exist only under an active System"),
            )
        })
}

struct Parsed {
    contract_id: String,
    object_id: String,
    parent_scope_ref: String,
    record: Value,
}

fn parse(body: &Value, system_id: &str) -> Result<Parsed, Reply> {
    let Some(map) = body.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &code("request_body_not_object"),
            "the request body must be a JSON object",
        ));
    };
    let unknown: Vec<String> = map
        .keys()
        .filter(|key| !REQUEST_FIELDS.contains(&key.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &code("request_unknown_field"),
            format!(
                "this seam does not admit field(s): {}; the binding, the head and the receipts are derived, never authored",
                unknown.join(", ")
            ),
        ));
    }
    let contract_id = text(body, "contract_id");
    if !contract_id.starts_with("schema://") {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &code("contract_required"),
            "contract_id is the registered schema:// id of the record's contract",
        ));
    }
    let object_id = text(body, "object_id");
    if object_id.is_empty() || object_id.len() > 500 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &code("object_id_required"),
            "object_id is the record's own identity value (its `*_id` member)",
        ));
    }
    let parent_scope_ref = match body.get("parent_scope_ref") {
        None | Some(Value::Null) => system_id.to_string(),
        Some(Value::String(value)) if value.contains("://") && value.len() <= 500 => value.clone(),
        Some(_) => return Err(bad(
            StatusCode::BAD_REQUEST,
            &code("parent_scope_invalid"),
            "parent_scope_ref is a scheme:// ref under this System, or null for the System itself",
        )),
    };
    let record = body.get("record").cloned().unwrap_or(Value::Null);
    if !record.is_object() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &code("record_required"),
            "record is the JSON object to admit under the contract",
        ));
    }
    if record
        .get("system_binding")
        .is_some_and(|value| !value.is_null())
    {
        return Err(refuse(
            "binding_authored",
            "system_binding is derived by this seam from the System, the parent scope and the resolved principal; a caller-authored binding is refused, never corrected",
        ));
    }
    Ok(Parsed {
        contract_id,
        object_id,
        parent_scope_ref,
        record,
    })
}

/// POST /v1/hypervisor/autonomous-systems/:id/records
pub(crate) async fn handle_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(system_id): Path<String>,
    body: axum::body::Bytes,
) -> Reply {
    // The caller is resolved before the body is parsed: an anonymous request answers 401 whether
    // or not it carried JSON.
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let parsed = match parse(&body, &system_id) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    if let Err(response) = require_active_system(&st.data_dir, &system_id) {
        return response;
    }
    let identity_member = match identity_member(&parsed.record, &parsed.object_id) {
        Ok(member) => member,
        Err(reason) => return refuse("identity_unresolved", reason),
    };
    let recorded_at_ms = now_ms();
    let created_at = match super::system_activation_routes::ms_to_timestamp(recorded_at_ms) {
        Ok(stamp) => stamp,
        Err((_, message)) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &code("stamp_failed"),
                message,
            )
        }
    };
    let mut record = parsed.record.clone();
    let binding = match derive_binding(
        &record,
        &system_id,
        &parsed.parent_scope_ref,
        &caller.identity.principal_ref,
        &created_at,
    ) {
        Ok(binding) => binding,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &code("binding_failed"),
                reason,
            )
        }
    };
    record["system_binding"] = binding;
    if let Err(reason) = validate_architecture_contract(&parsed.contract_id, &record) {
        if reason.starts_with("unknown contract") {
            return refuse(
                "contract_unknown",
                format!(
                    "{} is not a registered contract; this seam admits registered shapes only",
                    parsed.contract_id
                ),
            );
        }
        if reason.contains("system_binding") {
            return refuse(
                "contract_unscoped",
                format!(
                    "{} carries no SystemScopedObjectBinding, so it has no place under a System ({reason})",
                    parsed.contract_id
                ),
            );
        }
        return refuse(
            "not_registered_valid",
            format!(
                "this record does not satisfy {}: {reason}",
                parsed.contract_id
            ),
        );
    }
    let resource = resource_ref(&system_id, &parsed.contract_id, &parsed.object_id);
    let genesis = body.get("expected_head").map_or(true, Value::is_null);
    let scope = if genesis {
        match bind_request_resource_scope(
            &st.data_dir,
            &caller.identity,
            RESOURCE_KIND,
            &resource,
            &caller.owner_ref,
            &caller.owner_ref,
            &caller.idempotency_key,
        ) {
            Ok(scope) => scope,
            Err(error) => return scope_refusal_reply(error),
        }
    } else {
        match authorize_request_resource_scope(
            &st.data_dir,
            &caller.identity,
            RESOURCE_KIND,
            &resource,
            Some(caller.owner_ref.as_str()),
        ) {
            Ok(scope) => scope,
            Err(error) => return scope_refusal_reply(error),
        }
    };
    let stream = match read_records(&st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    // An exact retry replays the ORIGINAL admission: the same idempotency key with the same logical
    // record answers with the fact already admitted; the same key over a different record is a
    // reused key, refused by name. Replay is decided before any head is compared, because a retry
    // after an ambiguous response observes a newer head and is still the same command.
    if let Some(prior) = stream.iter().find(|entry| {
        entry
            .admission
            .get("idempotency_key")
            .and_then(Value::as_str)
            == Some(caller.idempotency_key.as_str())
    }) {
        let mut prior_record = prior.record.clone();
        if let Some(map) = prior_record.as_object_mut() {
            map.remove("system_binding");
        }
        if prior_record != parsed.record {
            return bad(
                StatusCode::CONFLICT,
                &code("idempotency_key_reused"),
                "this idempotency key already admitted a different record; a retry repeats the same command exactly",
            );
        }
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "replayed": true,
                "system_id": system_id,
                "contract_id": parsed.contract_id,
                "resource_ref": resource,
                "record": prior.record,
                "admission": prior.admission,
                "expected_head_for_successor": stream.last().map(|e| e.head.clone()),
                "receipt_ref": prior.admission.get("receipt_ref").cloned().unwrap_or(Value::Null),
                "operation_ref": prior.admission.get("operation_ref").cloned().unwrap_or(Value::Null),
            })),
        );
    }
    let expected_head = match head_assertion(&body, CODE_PREFIX) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, CODE_PREFIX) {
        return response;
    }
    let payload = json!({
        "schema_version": PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": resource,
        "system_id": system_id,
        "contract_id": parsed.contract_id,
        "identity_member": identity_member,
        "parent_scope_ref": parsed.parent_scope_ref,
        "recorded_at_ms": recorded_at_ms,
        "record": record,
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        genesis,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RESOURCE_KIND,
            resource_ref: &resource,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &stream_tail(RESOURCE_KIND, &resource),
            op_kind: ADMIT_OP,
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    let stream = match read_records(&st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.head == commit.projection.head)
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            &code("projection_disagrees_with_ack"),
            "the admitted head is absent from this record's projection",
        );
    };
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "system_id": system_id,
            "contract_id": parsed.contract_id,
            "resource_ref": resource,
            "record": entry.record,
            "admission": entry.admission,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
        })),
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct ListQuery {
    pub(crate) contract_id: Option<String>,
}

/// GET /v1/hypervisor/autonomous-systems/:id/records[?contract_id=] — the current head of every
/// record this identity may read under the System.
pub(crate) async fn handle_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(system_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let refs = match authorized_request_resource_refs(&st.data_dir, &identity, RESOURCE_KIND) {
        Ok(refs) => refs,
        Err(error) => return scope_refusal_reply(error),
    };
    let prefix = format!("{system_id}/");
    let contract_prefix = query
        .contract_id
        .as_deref()
        .map(|c| format!("{system_id}/{}/", slug(c)));
    let mut held = Vec::new();
    for resource in refs.into_iter().filter(|r| r.starts_with(&prefix)) {
        if let Some(cp) = &contract_prefix {
            if !resource.starts_with(cp) {
                continue;
            }
        }
        let scope = match authorize_request_resource_scope(
            &st.data_dir,
            &identity,
            RESOURCE_KIND,
            &resource,
            None,
        ) {
            Ok(scope) => scope,
            Err(error) => return scope_refusal_reply(error),
        };
        match read_records(&st.data_dir, &identity, &scope, &resource) {
            Ok(stream) if !stream.is_empty() => held.push(json!({
                "resource_ref": resource,
                "contract_id": stream.last().and_then(|e| e.admission.get("contract_id").cloned()),
                "current": stream.last().map(|e| e.record.clone()),
                "head": stream.last().map(|e| e.head.clone()),
                "revisions": stream.len(),
            })),
            Ok(_) => {}
            Err(response) => return response,
        }
    }
    let count = held.len();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "system_id": system_id, "records": held, "count": count })),
    )
}

/// GET /v1/hypervisor/autonomous-systems/:id/records/:contract/:object — one record's chain.
pub(crate) async fn handle_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((system_id, contract, object)): Path<(String, String, String)>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let resource = format!("{system_id}/{contract}/{object}");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        RESOURCE_KIND,
        &resource,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    match read_records(&st.data_dir, &identity, &scope, &resource) {
        Ok(stream) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &code("absent"),
            "no record answers to that contract and identity under this System",
        ),
        Ok(stream) => (StatusCode::OK, Json(family_view(&stream))),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_the_records_own_single_id_member() {
        let record = json!({ "thing_id": "thing://x/1", "title": "t" });
        assert_eq!(identity_member(&record, "thing://x/1").unwrap(), "thing_id");
        assert!(
            identity_member(&record, "thing://x/2").is_err(),
            "an id the record does not carry"
        );
        let twice = json!({ "a_id": "same", "b_id": "same" });
        assert!(
            identity_member(&twice, "same").is_err(),
            "two carriers is not one identity"
        );
        assert!(identity_member(&json!([]), "x").is_err());
    }

    #[test]
    fn the_binding_is_derived_over_the_record_with_the_binding_absent() {
        let record = json!({ "attempt_id": "attempt://a/1", "method": "m" });
        let a = derive_binding(
            &record,
            "system://s",
            "outcome-scope://p",
            "user://u",
            "2026-09-16T00:00:00Z",
        )
        .unwrap();
        let with_null =
            json!({ "attempt_id": "attempt://a/1", "method": "m", "system_binding": null });
        let b = derive_binding(
            &with_null,
            "system://s",
            "outcome-scope://p",
            "user://u",
            "2026-09-16T00:00:00Z",
        )
        .unwrap();
        assert_eq!(
            a["payload_root"], b["payload_root"],
            "the binding is never part of its own root"
        );
        assert_eq!(a["system_id"], "system://s");
        assert_eq!(a["parent_scope_ref"], "outcome-scope://p");
        assert_eq!(a["proposed_or_issued_by_ref"], "user://u");
        let moved = derive_binding(
            &json!({ "attempt_id": "attempt://a/1", "method": "changed" }),
            "system://s",
            "outcome-scope://p",
            "user://u",
            "2026-09-16T00:00:00Z",
        )
        .unwrap();
        assert_ne!(moved["payload_root"], a["payload_root"]);
    }

    #[test]
    fn the_resource_binds_system_contract_and_identity() {
        let r = resource_ref(
            "system://s",
            "schema://ioi/applications/x/attempt/v3",
            "attempt://a/1",
        );
        assert!(r.starts_with("system://s/"));
        assert_ne!(
            r,
            resource_ref(
                "system://t",
                "schema://ioi/applications/x/attempt/v3",
                "attempt://a/1"
            )
        );
        assert_ne!(
            r,
            resource_ref(
                "system://s",
                "schema://ioi/applications/x/finding/v3",
                "attempt://a/1"
            )
        );
    }
}
