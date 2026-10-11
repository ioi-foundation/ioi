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
//!
//! WHO MAY WRITE, AND WHAT A RECORD MAY NAME (R-240, System seam authority). The seam once checked
//! only that the target System was active, so any signed-in principal could admit a record under
//! anyone's System — and, through the Systems projection's retired record-holding clause, see that
//! System afterwards. A write now needs WRITE standing on the System (`system_projection_routes::
//! standing_over`: its admitter or an active administrator, holding its owner tenant); a caller who
//! sees the System but may not write is refused by name, and one who does not see it is answered
//! exactly as if no System answered to the id. A record that names a subject another plane owns
//! (`SUBJECT_BEARING`) may name only a subject its writer can see, decided per subject kind by the
//! owning plane's own read rule (`SUBJECT_KINDS`). Every refusal is decided before the request scope
//! is bound, so a refused write records nothing.

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
use super::system_projection_routes::SystemStanding;
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

/// Where the seam reads a System from: its verified genesis admission and whether it is active. The
/// daemon reads the genesis and activation planes (`DaemonSystems`); a unit test plants both (a
/// verified genesis needs the wallet ceremony), so every decision the seam makes over them — standing,
/// subjects, scope binding, admission — runs unchanged under either.
pub(crate) trait SystemSource {
    fn admission(&self, data_dir: &str, system_id: &str)
        -> Result<Option<Value>, (String, String)>;
    fn activity(&self, data_dir: &str, system_id: &str) -> Result<(), (String, String)>;
}

struct DaemonSystems;

impl SystemSource for DaemonSystems {
    fn admission(
        &self,
        data_dir: &str,
        system_id: &str,
    ) -> Result<Option<Value>, (String, String)> {
        super::system_projection_routes::admission_record(data_dir, system_id)
    }
    fn activity(&self, data_dir: &str, system_id: &str) -> Result<(), (String, String)> {
        super::system_activation_routes::load_active_system_graph(data_dir, system_id).map(|_| ())
    }
}

/// The answer for a System the caller does not see — the SAME body whether no admission answers to
/// the id or one does outside the caller's inventory.
fn system_absent(system_id: &str) -> Reply {
    bad(
        StatusCode::NOT_FOUND,
        &code("system_absent"),
        format!("no System in your inventory answers to {system_id}; records are admitted only under a System you may write under. Nothing was recorded"),
    )
}

/// A record is admitted only under a System the caller may WRITE under, and only while that System
/// is ACTIVE. In order, each refusal recording nothing:
///   * the caller does not see it — 404 `system_record_system_absent` (`system_absent`);
///   * the caller sees it but may not write under it — 403 `system_record_writer_not_authorized`;
///   * it is not active — 409 `system_record_system_not_active`, the platform's own check applied
///     exactly as the System planes apply it (only a writer learns whether a System is active).
fn require_writable_system(
    systems: &dyn SystemSource,
    data_dir: &str,
    identity: &RequestIdentity,
    system_id: &str,
) -> Result<(), Reply> {
    if !system_id.starts_with("system://") {
        return Err(refuse(
            "system_ref_invalid",
            "the path names a system:// ref",
        ));
    }
    let admission = systems
        .admission(data_dir, system_id)
        .map_err(|(inner, message)| {
            bad(
                StatusCode::CONFLICT,
                &code("system_unreadable"),
                format!("the System's admission could not be read ({inner}: {message}); nothing was recorded"),
            )
        })?;
    match super::system_projection_routes::standing_over(data_dir, admission.as_ref(), identity) {
        SystemStanding::Absent => return Err(system_absent(system_id)),
        SystemStanding::Sees => {
            return Err(bad(
                StatusCode::FORBIDDEN,
                &code("writer_not_authorized"),
                format!("you may read {system_id} but not write under it: only the principal that admitted the System, or an administrator of the organization that owns it, admits records under it. Nothing was recorded"),
            ))
        }
        SystemStanding::Writes => {}
    }
    systems.activity(data_dir, system_id).map_err(|(inner, message)| {
        bad(
            StatusCode::CONFLICT,
            &code("system_not_active"),
            format!("no ACTIVE bounded System answers to {system_id} ({inner}: {message}); application records exist only under an active System"),
        )
    })
}

/// A record that NAMES a subject another plane owns: the members carrying the subject's kind and ref,
/// and the status member and value that only RELEASE the subject.
struct SubjectBearing {
    contract_id: &'static str,
    kind_member: &'static str,
    ref_member: &'static str,
    release: (&'static str, &'static str),
}

/// The subject-bearing contracts this seam admits. A record under one of them may name only a subject
/// its writer can see: otherwise anyone could publish, under a System they may write under, a ref to
/// something they cannot read.
const SUBJECT_BEARING: &[SubjectBearing] = &[
    SubjectBearing {
        contract_id: "schema://ioi/components/hypervisor/system-data-attachment/v1",
        kind_member: "subject_kind",
        ref_member: "subject_ref",
        release: ("status", "detached"),
    },
    // v2 succeeds v1 by the `connector` kind (R-240 journey WP-A); its subjects are judged the same way.
    SubjectBearing {
        contract_id: "schema://ioi/components/hypervisor/system-data-attachment/v2",
        kind_member: "subject_kind",
        ref_member: "subject_ref",
        release: ("status", "detached"),
    },
];

/// Whether the caller may see the subject a ref names, by its owning plane's own read rule: `Ok(false)`
/// for an absent and a hidden subject alike; `Err` only when the plane cannot answer.
type SubjectVisible = fn(&str, &RequestIdentity, &str) -> Result<bool, String>;

fn ontology_visible(
    data_dir: &str,
    identity: &RequestIdentity,
    subject: &str,
) -> Result<bool, String> {
    Ok(super::odk_routes::ontology_visible_to(
        data_dir, identity, subject,
    ))
}

fn data_source_visible(
    data_dir: &str,
    identity: &RequestIdentity,
    subject: &str,
) -> Result<bool, String> {
    Ok(super::data_source_routes::source_ref_visible_to(
        data_dir, identity, subject,
    ))
}

/// A connector (`connector:<id>`, one of Connections' connectors) by the connector estate's own read
/// rule: the estate is deployment-wide — its list route serves every registered connector to every
/// caller — so a connector is visible exactly when it is registered, read with the list's own reader.
fn connector_visible(
    data_dir: &str,
    _identity: &RequestIdentity,
    subject: &str,
) -> Result<bool, String> {
    let Some(connector_id) = subject.strip_prefix("connector:") else {
        return Ok(false);
    };
    let canonical = !connector_id.is_empty()
        && connector_id.len() <= 128
        && connector_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    Ok(canonical
        && super::read_record_dir(data_dir, "connectors")
            .iter()
            .any(|record| record["connector_id"].as_str() == Some(connector_id)))
}

/// THE SUBJECT-KIND VISIBILITY TABLE: one row per kind a subject-bearing record may name, each decided
/// by the plane that owns that kind — ontologies by the ODK plane (owner, or a member of the owner's
/// org), data sources by the data-source plane (declared by the caller, or filed in a project it is a
/// member of), connections by the provider-connection plane (a request scope the caller may read),
/// connectors by the connector estate (registered). A kind with no row is refused, never admitted
/// unseen.
const SUBJECT_KINDS: &[(&str, SubjectVisible)] = &[
    ("ontology", ontology_visible),
    ("data_source", data_source_visible),
    (
        "connection",
        super::provider_connection_routes::connection_visible_to,
    ),
    ("connector", connector_visible),
];

/// A subject-bearing record names only a subject its writer can see, answered exactly as an absent one
/// when it cannot. The one exception is a successor that only RELEASES the subject the chain already
/// names: losing sight of a subject must never trap its attachment. Re-attaching, or naming any other
/// subject, is decided afresh.
fn require_visible_subject(
    data_dir: &str,
    identity: &RequestIdentity,
    contract_id: &str,
    record: &Value,
    current: Option<&Value>,
) -> Result<(), Reply> {
    let Some(rule) = SUBJECT_BEARING
        .iter()
        .find(|rule| rule.contract_id == contract_id)
    else {
        return Ok(());
    };
    let kind = text(record, rule.kind_member);
    let subject = text(record, rule.ref_member);
    let (status_member, released) = rule.release;
    let releases_current = text(record, status_member) == released
        && current.is_some_and(|prior| {
            text(prior, rule.kind_member) == kind && text(prior, rule.ref_member) == subject
        });
    if releases_current {
        return Ok(());
    }
    let Some((_, visible)) = SUBJECT_KINDS.iter().find(|(name, _)| *name == kind) else {
        return Err(refuse(
            "subject_kind_unruled",
            format!("{contract_id} names a subject of kind {kind:?}, which no plane's read rule decides here; it is refused rather than admitted unseen. Nothing was recorded"),
        ));
    };
    match visible(data_dir, identity, &subject) {
        Ok(true) => Ok(()),
        Ok(false) => Err(refuse(
            "subject_unknown",
            format!("no {kind} you can see answers to {subject}; a record names only a subject its writer may read. Nothing was recorded"),
        )),
        Err(message) => Err(bad(
            StatusCode::SERVICE_UNAVAILABLE,
            &code("subject_unreadable"),
            format!("whether you may see {subject} could not be read ({message}); nothing was recorded"),
        )),
    }
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
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    admit(&DaemonSystems, &st.data_dir, &headers, &system_id, &body)
}

fn admit(
    systems: &dyn SystemSource,
    data_dir: &str,
    headers: &HeaderMap,
    system_id: &str,
    body: &Value,
) -> Reply {
    // The caller is resolved before the body is parsed: an anonymous request answers 401 whether
    // or not it carried JSON.
    let caller: WriteCaller = match require_write_caller(data_dir, headers, body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let parsed = match parse(body, system_id) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    if let Err(response) = require_writable_system(systems, data_dir, &caller.identity, system_id) {
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
        system_id,
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
    let resource = resource_ref(system_id, &parsed.contract_id, &parsed.object_id);
    let genesis = body.get("expected_head").map_or(true, Value::is_null);
    let scope = if genesis {
        // Decided BEFORE the scope is bound: binding it is a write, and a refusal records nothing.
        if let Err(response) = require_visible_subject(
            data_dir,
            &caller.identity,
            &parsed.contract_id,
            &parsed.record,
            None,
        ) {
            return response;
        }
        match bind_request_resource_scope(
            data_dir,
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
            data_dir,
            &caller.identity,
            RESOURCE_KIND,
            &resource,
            Some(caller.owner_ref.as_str()),
        ) {
            Ok(scope) => scope,
            Err(error) => return scope_refusal_reply(error),
        }
    };
    let stream = match read_records(data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    // A successor is decided against the subject its chain already names (a release of it stays
    // admissible when the writer has since lost sight of it); nothing above wrote.
    if !genesis {
        if let Err(response) = require_visible_subject(
            data_dir,
            &caller.identity,
            &parsed.contract_id,
            &parsed.record,
            stream.last().map(|entry| &entry.record),
        ) {
            return response;
        }
    }
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
        data_dir,
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
    let stream = match read_records(data_dir, &caller.identity, &scope, &resource) {
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

#[cfg(test)]
mod authority_tests {
    //! Who may admit a record under a System, and which subjects a record may name (R-240, System
    //! seam authority), over real principals: principal records, live memberships in the membership
    //! registry and bearer sessions, resolved through the canonical identity seam exactly as a request
    //! is. The System's genesis admission is planted (a verified genesis needs the wallet ceremony);
    //! everything after it — standing, the subject planes, the scope binding and the substrate
    //! admission — is the daemon's own.
    use super::*;

    const SYSTEM: &str = "system://acme/lending";
    const ATTACHMENT: &str = "schema://ioi/components/hypervisor/system-data-attachment/v1";

    struct Planted {
        admission: Option<Value>,
        active: bool,
    }

    impl SystemSource for Planted {
        fn admission(&self, _: &str, system_id: &str) -> Result<Option<Value>, (String, String)> {
            Ok(self
                .admission
                .clone()
                .filter(|record| record["system_id"] == json!(system_id)))
        }
        fn activity(&self, _: &str, system_id: &str) -> Result<(), (String, String)> {
            if self.active {
                Ok(())
            } else {
                Err((
                    "system_activation_not_active".into(),
                    format!("{system_id} is admitted, not activated"),
                ))
            }
        }
    }

    /// A genesis record as admission writes it: a project:// proposer, the admitting person and that
    /// person's one org:// tenant as owner.
    fn admitted_by(principal_ref: &str, owner_ref: &str, active: bool) -> Planted {
        Planted {
            admission: Some(json!({
                "system_id": SYSTEM,
                "proposed_by_ref": "project://acme/lending-operator",
                "governing_authority_ref": "org://acme/risk",
                "admitted_by_principal_ref": principal_ref,
                "owner_ref": owner_ref
            })),
            active,
        }
    }
    fn lending() -> Planted {
        admitted_by("user://owner", "org://local", true)
    }
    fn nothing() -> Planted {
        Planted {
            admission: None,
            active: false,
        }
    }

    /// A principal with the given role and live memberships, signed in with a bearer session.
    fn session(data_dir: &str, principal_id: &str, role: &str, tenants: &[&str]) -> HeaderMap {
        super::super::persist_record(
            data_dir,
            "principals",
            principal_id,
            &json!({ "schema_version": "ioi.hypervisor.principal.v1", "principal_id": principal_id,
                     "email": format!("{principal_id}@example.test"), "name": principal_id, "role": role,
                     "status": "active", "source": "test",
                     "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z" }),
        )
        .unwrap();
        let principal_ref = format!("user://{principal_id}");
        for tenant in tenants {
            member(data_dir, &principal_ref, tenant, "active", 0);
        }
        let token = format!("token-{principal_id}");
        super::super::persist_record(
            data_dir,
            "sessions",
            &format!("session-{principal_id}"),
            &json!({ "session_id": format!("session-{principal_id}"), "token_hash": super::super::sha256_hex_str(&token),
                     "principal_id": principal_id, "source": "test",
                     "created_at": "2026-01-01T00:00:00Z", "expires_at": "9999-12-31T23:59:59Z" }),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }
    fn member(data_dir: &str, principal_ref: &str, tenant: &str, status: &str, revision: u64) {
        super::super::lifecycle_routes::apply_membership_transition(
            data_dir,
            principal_ref,
            principal_ref,
            tenant,
            if tenant.starts_with("org://") {
                "organization"
            } else {
                "project"
            },
            status,
            revision,
            &format!("test-{principal_ref}-{tenant}-{status}"),
            "test membership",
            "deployment_bootstrap",
        )
        .unwrap();
    }
    fn who(data_dir: &str, headers: &HeaderMap) -> RequestIdentity {
        resolve_request_identity(data_dir, headers).expect("a signed-in principal")
    }

    fn attachment_id(subject_ref: &str) -> String {
        let digest = <sha2::Sha256 as sha2::Digest>::digest(format!("{SYSTEM}\u{0}{subject_ref}"));
        format!(
            "system-data-attachment://sda_{}",
            &hex::encode(digest)[..16]
        )
    }
    fn attach_body(
        owner_ref: &str,
        kind: &str,
        subject_ref: &str,
        status: &str,
        expected_head: Option<&str>,
    ) -> Value {
        let id = attachment_id(subject_ref);
        json!({
            "owner_ref": owner_ref,
            "idempotency_key": format!("attach-{}-{status}-{}", &id[30..], expected_head.unwrap_or("genesis").len()),
            "contract_id": ATTACHMENT,
            "object_id": id,
            "parent_scope_ref": null,
            "record": { "schema_version": "ioi.hypervisor.system-data-attachment.v1", "attachment_id": id,
                        "subject_kind": kind, "subject_ref": subject_ref, "status": status },
            "expected_head": expected_head,
        })
    }
    fn post(
        systems: &dyn SystemSource,
        data_dir: &str,
        headers: &HeaderMap,
        body: &Value,
    ) -> (StatusCode, Value) {
        let (status, Json(reply)) = admit(systems, data_dir, headers, SYSTEM, body);
        (status, reply)
    }
    fn code_of(reply: &Value) -> &str {
        reply
            .pointer("/error/code")
            .or_else(|| reply.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("")
    }
    fn ontology(data_dir: &str, owner: &RequestIdentity, domain: &str) -> String {
        let (status, Json(reply)) = super::super::odk_routes::create_ontology(
            data_dir,
            owner,
            &json!({ "domain": domain }),
        );
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        format!("ontology://{}", reply["ontology"]["id"].as_str().unwrap())
    }
    fn source(data_dir: &str, principal_ref: &str, body: Value) -> String {
        let (status, Json(reply)) =
            super::super::data_source_routes::create_data_source(data_dir, principal_ref, &body);
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        reply["data_source"]["source_ref"]
            .as_str()
            .unwrap()
            .to_string()
    }
    /// Every byte the data directory holds, by path: a refused write must leave it unchanged. The
    /// substrate is opened first (its first read creates its empty log), so what is compared is a
    /// settled store and any byte a refusal adds is a write.
    fn fingerprint(data_dir: &str) -> std::collections::BTreeMap<String, Vec<u8>> {
        authorized_request_resource_refs(
            data_dir,
            &super::super::substrate_store::request_identity_for_test("user://reader", []),
            RESOURCE_KIND,
        )
        .expect("the substrate opens");
        fn walk(dir: &std::path::Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    out.insert(path.display().to_string(), bytes);
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(std::path::Path::new(data_dir), &mut out);
        out
    }

    #[test]
    fn an_outsider_is_answered_as_if_the_system_were_not_there_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        session(d, "owner", "member", &["org://local"]);
        let mallory = session(d, "mallory", "member", &["project://elsewhere"]);
        let stranger = session(d, "stranger", "admin", &["project://elsewhere"]);
        // A subject mallory CAN see, so the System is the only thing refused.
        let hers = source(
            d,
            "user://mallory",
            json!({ "name": "hers", "kind": "file_drop" }),
        );
        let body = attach_body(
            "project://elsewhere",
            "data_source",
            &hers,
            "attached",
            None,
        );
        let before = fingerprint(d);

        let planted = post(&lending(), d, &mallory, &body);
        assert_eq!(planted.0, StatusCode::NOT_FOUND, "{}", planted.1);
        assert_eq!(code_of(&planted.1), "system_record_system_absent");
        assert_eq!(
            planted,
            post(&nothing(), d, &mallory, &body),
            "a System outside the caller's inventory answers byte for byte as one no admission answers to"
        );
        let (status, reply) = post(&lending(), d, &stranger, &body);
        assert_eq!(
            (status, code_of(&reply)),
            (StatusCode::NOT_FOUND, "system_record_system_absent"),
            "an admin role is not a key to another org's Systems: {reply}"
        );
        assert_eq!(fingerprint(d), before, "a refused write records nothing");
        assert!(
            authorized_request_resource_refs(d, &who(d, &mallory), RESOURCE_KIND)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_member_who_sees_the_system_may_not_write_under_it() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        session(d, "owner", "member", &["org://local"]);
        let colleague = session(d, "colleague", "member", &["org://local"]);
        let theirs = source(
            d,
            "user://colleague",
            json!({ "name": "theirs", "kind": "file_drop" }),
        );
        let before = fingerprint(d);
        let (status, reply) = post(
            &lending(),
            d,
            &colleague,
            &attach_body("org://local", "data_source", &theirs, "attached", None),
        );
        assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
        assert_eq!(code_of(&reply), "system_record_writer_not_authorized");
        assert_eq!(fingerprint(d), before, "a refused write records nothing");
        assert_eq!(
            super::super::system_projection_routes::standing_over(
                d,
                lending().admission.as_ref(),
                &who(d, &colleague)
            ),
            SystemStanding::Sees,
            "the colleague still sees the System"
        );
    }

    #[test]
    fn the_admitter_and_an_org_administrator_admit_and_an_inactive_system_refuses_even_them() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let owner = session(d, "owner", "member", &["org://local"]);
        let root = session(d, "root", "admin", &["org://local"]);
        let lending_ontology = ontology(d, &who(d, &owner), "lending");
        let body = attach_body(
            "org://local",
            "ontology",
            &lending_ontology,
            "attached",
            None,
        );

        let (status, reply) = post(
            &admitted_by("user://owner", "org://local", false),
            d,
            &owner,
            &body,
        );
        assert_eq!(
            (status, code_of(&reply)),
            (StatusCode::CONFLICT, "system_record_system_not_active"),
            "{reply}"
        );

        let (status, reply) = post(&lending(), d, &owner, &body);
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        assert_eq!(
            reply["record"]["system_binding"]["proposed_or_issued_by_ref"],
            json!("user://owner")
        );
        let (status, reply) = post(&lending(), d, &owner, &body);
        assert_eq!(
            (status, reply["replayed"].clone()),
            (StatusCode::OK, json!(true))
        );

        let desk = source(
            d,
            "user://root",
            json!({ "name": "desk", "kind": "file_drop" }),
        );
        let (status, reply) = post(
            &lending(),
            d,
            &root,
            &attach_body("org://local", "data_source", &desk, "attached", None),
        );
        assert_eq!(
            status,
            StatusCode::CREATED,
            "an administrator of the owner org writes: {reply}"
        );
        assert_eq!(
            reply["record"]["system_binding"]["proposed_or_issued_by_ref"],
            json!("user://root")
        );
    }

    #[test]
    fn a_record_names_only_a_subject_its_writer_can_see() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let owner = session(d, "owner", "member", &["org://local"]);
        let mallory = session(d, "mallory", "member", &["project://elsewhere"]);
        session(d, "colleague", "member", &["org://local"]);
        let hidden_ontology = ontology(d, &who(d, &mallory), "private");
        let hidden_source = source(
            d,
            "user://colleague",
            json!({ "name": "theirs", "kind": "file_drop" }),
        );
        let before = fingerprint(d);

        let (status, hidden) = post(
            &lending(),
            d,
            &owner,
            &attach_body(
                "org://local",
                "ontology",
                &hidden_ontology,
                "attached",
                None,
            ),
        );
        assert_eq!(
            (status, code_of(&hidden)),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "system_record_subject_unknown"
            ),
            "{hidden}"
        );
        let nowhere = "ontology://ont_0000000000000000";
        let (status, absent) = post(
            &lending(),
            d,
            &owner,
            &attach_body("org://local", "ontology", nowhere, "attached", None),
        );
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            hidden["error"]["message"]
                .as_str()
                .unwrap()
                .replace(&hidden_ontology, "<subject>"),
            absent["error"]["message"]
                .as_str()
                .unwrap()
                .replace(nowhere, "<subject>"),
            "a hidden subject answers exactly as one that is not there"
        );
        for (kind, subject) in [
            ("data_source", hidden_source.as_str()),
            ("connection", "connection://provider/cnx_x/user-owner"),
        ] {
            let (status, reply) = post(
                &lending(),
                d,
                &owner,
                &attach_body("org://local", kind, subject, "attached", None),
            );
            assert_eq!(
                (status, code_of(&reply)),
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "system_record_subject_unknown"
                ),
                "{kind}: {reply}"
            );
        }
        assert_eq!(fingerprint(d), before, "a refused write records nothing");

        let mine = source(
            d,
            "user://owner",
            json!({ "name": "mine", "kind": "file_drop" }),
        );
        let (status, reply) = post(
            &lending(),
            d,
            &owner,
            &attach_body("org://local", "data_source", &mine, "attached", None),
        );
        assert_eq!(status, StatusCode::CREATED, "{reply}");
    }

    /// v2 (R-240 journey WP-A): a connector is one of a System's connections — admitted when it is a
    /// registered connector, refused exactly as an absent subject otherwise, and never under v1.
    #[test]
    fn a_v2_attachment_names_a_registered_connector_and_v1_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let owner = session(d, "owner", "member", &["org://local"]);
        super::super::persist_record(
            d,
            "connectors",
            "conn_walk",
            &json!({ "connector_id": "conn_walk", "name": "walk" }),
        )
        .unwrap();
        let v2 = |subject: &str| {
            let mut body = attach_body("org://local", "connector", subject, "attached", None);
            body["contract_id"] =
                json!("schema://ioi/components/hypervisor/system-data-attachment/v2");
            body["record"]["schema_version"] = json!("ioi.hypervisor.system-data-attachment.v2");
            body
        };
        let before = fingerprint(d);
        let (status, unknown) = post(&lending(), d, &owner, &v2("connector:conn_other"));
        assert_eq!(
            (status, code_of(&unknown)),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "system_record_subject_unknown"
            ),
            "{unknown}"
        );
        // v1's wire is frozen: its schema has no connector kind.
        let (status, under_v1) = post(
            &lending(),
            d,
            &owner,
            &attach_body(
                "org://local",
                "connector",
                "connector:conn_walk",
                "attached",
                None,
            ),
        );
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{under_v1}");
        assert_eq!(
            code_of(&under_v1),
            "system_record_not_registered_valid",
            "{under_v1}"
        );
        assert_eq!(fingerprint(d), before, "a refused write records nothing");
        let (status, admitted) = post(&lending(), d, &owner, &v2("connector:conn_walk"));
        assert_eq!(status, StatusCode::CREATED, "{admitted}");
        assert_eq!(
            admitted["record"]["subject_ref"], "connector:conn_walk",
            "{admitted}"
        );
    }

    #[test]
    fn a_successor_may_release_the_subject_it_names_but_never_swap_in_one_its_writer_cannot_see() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let owner = session(d, "owner", "member", &["org://local", "project://desk"]);
        let mallory = session(d, "mallory", "member", &["project://elsewhere"]);
        let filed = source(
            d,
            "user://mallory",
            json!({ "name": "desk", "kind": "file_drop", "project_ref": "project://desk" }),
        );
        let (status, first) = post(
            &lending(),
            d,
            &owner,
            &attach_body("org://local", "data_source", &filed, "attached", None),
        );
        assert_eq!(status, StatusCode::CREATED, "{first}");
        let head = first["expected_head_for_successor"]
            .as_str()
            .unwrap()
            .to_string();
        let object = first["record"]["attachment_id"]
            .as_str()
            .unwrap()
            .to_string();

        // The owner leaves the project the source is filed in: it no longer sees the source.
        member(d, "user://owner", "project://desk", "revoked", 1);
        let owner = who(d, &owner);
        assert!(!super::super::data_source_routes::source_ref_visible_to(
            d, &owner, &filed
        ));
        let owner = session_headers("owner");

        let successor = |status_value: &str, kind: &str, subject: &str| {
            let mut body = attach_body("org://local", kind, subject, status_value, Some(&head));
            body["object_id"] = json!(object);
            body["record"]["attachment_id"] = json!(object);
            body
        };
        let before = fingerprint(d);
        let (status, reply) = post(
            &lending(),
            d,
            &owner,
            &successor("attached", "data_source", &filed),
        );
        assert_eq!(
            (status, code_of(&reply)),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "system_record_subject_unknown"
            ),
            "re-attaching is decided afresh: {reply}"
        );
        let hers = ontology(d, &who(d, &mallory), "private");
        let after_setup = fingerprint(d);
        let (status, reply) = post(
            &lending(),
            d,
            &owner,
            &successor("detached", "ontology", &hers),
        );
        assert_eq!(
            (status, code_of(&reply)),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "system_record_subject_unknown"
            ),
            "a release names the chain's OWN subject, never a new one: {reply}"
        );
        assert_ne!(
            before, after_setup,
            "(the second subject's creation is the only write)"
        );
        assert_eq!(
            fingerprint(d),
            after_setup,
            "a refused write records nothing"
        );

        let (status, reply) = post(
            &lending(),
            d,
            &owner,
            &successor("detached", "data_source", &filed),
        );
        assert_eq!(
            status,
            StatusCode::CREATED,
            "losing sight of a subject never traps its attachment: {reply}"
        );
        assert_eq!(reply["record"]["status"], json!("detached"));
    }

    /// The headers of a principal `session` already signed in (its token is derived from its id).
    fn session_headers(principal_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer token-{principal_id}").parse().unwrap(),
        );
        headers
    }

    /// Before this fix the seam checked only that the System was active, so a record may already sit
    /// under a System its holder does not own. Holding it grants no sight of the System (the Systems
    /// projection's record-holding clause is retired) and no standing to write more; the record itself
    /// stays readable to its holder through the seam's own scope.
    #[test]
    fn a_record_planted_before_the_fix_grants_no_sight_of_the_system() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        session(d, "owner", "member", &["org://local"]);
        let mallory = session(d, "mallory", "member", &["project://elsewhere"]);
        let hers = source(
            d,
            "user://mallory",
            json!({ "name": "hers", "kind": "file_drop" }),
        );
        // The plant, as the old seam admitted it: under THIS System id, through the owner-scoped write
        // path, bound to mallory's own tenant.
        let (status, reply) = post(
            &admitted_by("user://mallory", "project://elsewhere", true),
            d,
            &mallory,
            &attach_body(
                "project://elsewhere",
                "data_source",
                &hers,
                "attached",
                None,
            ),
        );
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        let held = authorized_request_resource_refs(d, &who(d, &mallory), RESOURCE_KIND).unwrap();
        assert!(held
            .iter()
            .any(|resource| resource.starts_with(&format!("{SYSTEM}/"))));

        let genuine = lending();
        assert_eq!(
            super::super::system_projection_routes::standing_over(
                d,
                genuine.admission.as_ref(),
                &who(d, &mallory)
            ),
            SystemStanding::Absent,
            "the plant is not a key to the System"
        );
        let (status, reply) = post(
            &genuine,
            d,
            &mallory,
            &attach_body(
                "project://elsewhere",
                "data_source",
                &hers,
                "detached",
                None,
            ),
        );
        assert_eq!(
            (status, code_of(&reply)),
            (StatusCode::NOT_FOUND, "system_record_system_absent"),
            "{reply}"
        );
    }
}
