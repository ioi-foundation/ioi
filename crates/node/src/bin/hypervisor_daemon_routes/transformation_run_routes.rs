//! TransformationRun + receipts — the THIRD ODK authority-crossing rung, and the first that says
//! "a run may exist". In v1 a run is an AUDITABLE PLAN / DRY-RUN ONLY: it validates the declared
//! source shape, the mapped ontology properties, the policy envelope, the requested operation, the
//! output intent, and the receipt obligations — and emits receipts for every act. It does NOT say
//! "the system can pull from Postgres/S3/API and mint semantic objects": there is no live source
//! contact, no extraction, no object instances, no explorer rows, no connector credentials. Live
//! reads are a FUTURE connector-adapter cut, after credentials get an authority-crossing story.
//!
//! A run references one READY ConnectorMapping (#13) and one READY PolicyBoundDataView (#14) that
//! binds the SAME mapping and allows `transform`. Requested fields must sit inside the policy scope;
//! the purpose must match the policy purpose; a high-risk output intent (export/train/evaluate
//! bundles) is admitted only when the view authorizes that downstream operation with named receipt
//! obligations. Authorization is CHECKED against the gate — never invented here.
//!
//! Lifecycle (explicit): `planned` → `dry_run_ready` | `blocked` | `cancelled`.
//! `executed` / `materialized` are RESERVED for the future connector-adapter cut and never set here.
//! Every create, dry-run, block, cancel, patch — and every FAILED validation — emits a receipt.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

// ============ M05.7 · THE v1 TRANSFORMATION-RUN OWNER SEAM — OWNER-SCOPED, THEN RESOLVABLE =======
//
// The same defect and the same remedy as the v1 ConnectorMapping lane. This lane took no identity,
// persisted into a flat record directory by overwrite, and its registered v1 contract is closed with
// no owner, tenant or principal member — so a v2 convergence naming a v1 run had nothing stored to
// check and could only ever have DISCLAIMED custody. The write now crosses the shared owner-scoped
// admission boundary, which is what creates the fact a proof later reads.
//
// THE v1 RECORD IS UNCHANGED, BYTE FOR BYTE. The owner rides on an admission ENVELOPE carrying the
// registered v1 record verbatim, so the chain payload, the row and the contract are one set of bytes
// and a commitment over the stored record needs no projection step to disagree about.
//
// EVERY STATE MOVE IS ADMITTED, NOT JUST THE FIRST. A v1 run's row is overwritten by dry-run, cancel
// and patch alike, each bumping `revision` in place. Admitting all of them is what makes the chain
// hold every revision immutably, so "the exact stored revision and its hash" is answerable and a
// convergence cannot be pointed at a revision that was silently replaced underneath it.

const RUN_V1_SCOPE_KIND: &str = "hypervisor-odk-transformation-run";
const RUN_V1_OWNER_NAMESPACE: &str = "hypervisor-odk-transformation-run-v1";
const RUN_V1_ADMISSION_SCHEMA: &str = "ioi.hypervisor.odk.transformation-run-v1-admission.v1";
const RUN_V1_CONTRACT_ID: &str = "schema://ioi/foundations/objects/transformation-run/v1";
const RUN_V1_RECORD_KEY: &str = "transformation_run_record";
const RUN_V1_ADMIT_OP: &str = "event_stream.hypervisor_odk_transformation_run_admitted";
const RUN_V1_REVISE_OP: &str = "event_stream.hypervisor_odk_transformation_run_revised";
/// The scheme the record ACTUALLY stores in its own `ref`.
const RUN_V1_STORED_SCHEME: &str = "transformation-run";

fn run_v1_refusal(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

fn run_v1_chain_refusal(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

/// The commitment over one stored v1 run's exact bytes, canonicalized. No field list: the record is
/// committed whole, so an edit to an enumeration here cannot change what a proof claims to have seen.
fn run_v1_content_hash(record: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    use sha2::Digest;
    serde_jcs::to_vec(record)
        .map(|bytes| format!("sha256:{:x}", sha2::Sha256::digest(&bytes)))
        .map_err(|error| {
            run_v1_chain_refusal(
                "transformation_run_v1_projection_failed",
                &format!("the stored record could not be canonicalized: {error}"),
            )
        })
}

fn run_v1_stream_tail(resource_ref: &str) -> String {
    use sha2::Digest;
    format!(
        "{RUN_V1_SCOPE_KIND}.{:x}",
        sha2::Sha256::digest(resource_ref.as_bytes())
    )
}

struct RunV1WriteCaller {
    identity: super::substrate_store::RequestIdentity,
    owner_ref: String,
    idempotency_key: String,
}

/// Identity and owner, resolved BEFORE the record or its receipt is built.
fn run_v1_write_caller(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
    previous_owner_ref: Option<&str>,
) -> Result<RunV1WriteCaller, (StatusCode, Json<Value>)> {
    let identity = super::substrate_store::resolve_request_identity(data_dir, headers)
        .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();
    if idempotency_key.is_empty() {
        return Err(run_v1_refusal(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried write cannot apply twice",
        ));
    }
    let owner_ref = match previous_owner_ref {
        Some(existing) => existing.to_owned(),
        None => body
            .get("owner_ref")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_owned(),
    };
    if owner_ref.is_empty() {
        return Err(run_v1_refusal(
            "transformation_run_owner_ref_required",
            "owner_ref is required: this record is owned by exactly one org:// or project://, and an unowned record can never be custody-proved",
        ));
    }
    Ok(RunV1WriteCaller {
        identity,
        owner_ref,
        idempotency_key,
    })
}

fn admit_run_v1(
    data_dir: &str,
    caller: &RunV1WriteCaller,
    resource_ref: &str,
    record: &Value,
    genesis: bool,
) -> Result<super::mutation_event_foundation::MutationCommit, (StatusCode, Json<Value>)> {
    let identity = caller.identity.clone();
    let owner_ref = caller.owner_ref.clone();
    let idempotency_key = caller.idempotency_key.as_str();
    let scope = if genesis {
        super::substrate_store::bind_request_resource_scope(
            data_dir,
            &identity,
            RUN_V1_SCOPE_KIND,
            resource_ref,
            &owner_ref,
            &owner_ref,
            idempotency_key,
        )
    } else {
        super::substrate_store::authorize_request_resource_scope(
            data_dir,
            &identity,
            RUN_V1_SCOPE_KIND,
            resource_ref,
            Some(&owner_ref),
        )
    }
    .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let tail = run_v1_stream_tail(resource_ref);
    let expected_head = if genesis {
        None
    } else {
        super::mutation_event_foundation::read_owner_scoped_history(
            data_dir,
            &identity,
            &scope,
            RUN_V1_SCOPE_KIND,
            resource_ref,
            RUN_V1_OWNER_NAMESPACE,
            &tail,
        )
        .map_err(super::mutation_event_foundation::mutation_refusal_reply)?
        .last()
        .map(|entry| entry.head.clone())
    };
    let payload = json!({
        "schema_version": RUN_V1_ADMISSION_SCHEMA,
        "owner_ref": owner_ref,
        "resource_ref": resource_ref,
        RUN_V1_RECORD_KEY: record,
    });
    super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        genesis,
        super::mutation_event_foundation::ScopedMutation {
            identity: &identity,
            scope: &scope,
            resource_kind: RUN_V1_SCOPE_KIND,
            resource_ref,
            owner_namespace: RUN_V1_OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: if genesis {
                RUN_V1_ADMIT_OP
            } else {
                RUN_V1_REVISE_OP
            },
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key,
            recorded_at_ms: 0,
        },
    )
    .map_err(super::mutation_event_foundation::mutation_refusal_reply)
}

/// Admit a STATE MOVE on an already-admitted run — dry-run, cancel, patch.
///
/// THESE PATHS CARRY NO IDEMPOTENCY KEY BECAUSE THEY CARRY NO BODY, and inventing a request field
/// for them would change a route shape that existing callers depend on. The key is DERIVED instead,
/// from the three things that actually identify the state move: the operation, the run, and the
/// revision it produces. A retry of the same move at the same revision therefore replays rather than
/// appending a second identical revision, which is the property the key exists to provide.
///
/// The owner is resolved from the admitted predecessor, never taken from the request, so a state
/// move cannot relocate a run between owners.
fn admit_run_v1_state_move(
    data_dir: &str,
    headers: &HeaderMap,
    run_ref: &str,
    record: &Value,
    op_label: &str,
) -> Result<super::mutation_event_foundation::MutationCommit, (StatusCode, Json<Value>)> {
    let identity = super::substrate_store::resolve_request_identity(data_dir, headers)
        .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let admitted = resolve_stored_transformation_run_v1(data_dir, &identity, None, run_ref, None)?;
    let revision = record.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let caller = RunV1WriteCaller {
        identity,
        owner_ref: admitted.owner_ref.clone(),
        idempotency_key: format!("{op_label}:{run_ref}:revision:{revision}"),
    };
    admit_run_v1(data_dir, &caller, run_ref, record, false)
}

/// ONE stored v1 TransformationRun, resolved from the owner-scoped chain.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedTransformationRunV1 {
    pub(crate) run_ref: String,
    pub(crate) owner_ref: String,
    pub(crate) principal_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) schema_version: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) admitted_head: String,
    pub(crate) admitted_revision: u64,
    pub(crate) index_state: &'static str,
}

/// Resolve the exact stored v1 TransformationRun a caller names, or refuse by name.
///
/// `expected_revision` names an EXACT admitted revision, which matters more here than anywhere else:
/// a v1 run's row is rewritten by dry-run and cancel, so "the run I converged" and "the run as it
/// stands now" are routinely different bytes under one ref.
pub(crate) fn resolve_stored_transformation_run_v1(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    expected_owner_ref: Option<&str>,
    run_ref: &str,
    expected_revision: Option<u64>,
) -> Result<ResolvedTransformationRunV1, (StatusCode, Json<Value>)> {
    let Some((RUN_V1_STORED_SCHEME, id)) = run_ref
        .split_once("://")
        .filter(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty())
    else {
        return Err(run_v1_refusal(
            "transformation_run_v1_ref_not_canonical",
            "a stored v1 transformation run is addressed as 'transformation-run://<id>' — the scheme it was admitted under, not the successor's 'transform://'",
        ));
    };
    let scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        RUN_V1_SCOPE_KIND,
        run_ref,
        expected_owner_ref,
    )
    .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        data_dir,
        identity,
        &scope,
        RUN_V1_SCOPE_KIND,
        run_ref,
        RUN_V1_OWNER_NAMESPACE,
        &run_v1_stream_tail(run_ref),
    )
    .map_err(super::mutation_event_foundation::mutation_refusal_reply)?;
    if history.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "transformation_run_v1_not_found",
                    "message": "this transformation run has no admitted history — an absent predecessor is a typed absence, never an empty success"
                }
            })),
        ));
    }
    let entry = match expected_revision {
        None => history.last().expect("history is non-empty"),
        Some(wanted) => history
            .iter()
            .find(|entry| {
                entry
                    .operation
                    .payload
                    .pointer(&format!("/{RUN_V1_RECORD_KEY}/revision"))
                    .and_then(Value::as_u64)
                    == Some(wanted)
            })
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "ok": false,
                        "error": {
                            "code": "transformation_run_v1_revision_absent",
                            "message": format!("this transformation run has no admitted revision {wanted}; an absent revision is a typed absence, never the nearest one")
                        }
                    })),
                )
            })?,
    };
    let envelope = &entry.operation.payload;
    if envelope.get("schema_version").and_then(Value::as_str) != Some(RUN_V1_ADMISSION_SCHEMA) {
        return Err(run_v1_chain_refusal(
            "transformation_run_v1_admission_unsupported",
            "the chain holds an admission envelope this build does not project; an unrecognised stored shape is refused rather than read as though it were understood",
        ));
    }
    let owner_ref = envelope
        .get("owner_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(record) = envelope.get(RUN_V1_RECORD_KEY).cloned() else {
        return Err(run_v1_chain_refusal(
            "transformation_run_v1_projection_failed",
            "the admission envelope carries no transformation run record",
        ));
    };
    let schema_version = record
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if schema_version != RUN_SCHEMA {
        return Err(run_v1_chain_refusal(
            "transformation_run_v1_version_unsupported",
            "the chain holds a transformation run admitted under a version this build neither authors nor projects",
        ));
    }
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        RUN_V1_CONTRACT_ID,
        &record,
    )
    .map_err(|reason| {
        run_v1_chain_refusal(
            "transformation_run_v1_projection_failed",
            &format!("the stored record does not satisfy {RUN_V1_CONTRACT_ID}: {reason}"),
        )
    })?;
    if record.get("ref").and_then(Value::as_str) != Some(run_ref) {
        return Err(run_v1_chain_refusal(
            "transformation_run_v1_ref_binding_disagrees",
            "the admitted record's own ref is not the ref this scope resolves; the binding between the stored ref and the admitted scope is broken",
        ));
    }
    let content_hash = run_v1_content_hash(&record)?;
    let admitted_revision = record.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let index_state = if expected_revision.is_some_and(|wanted| wanted < history.len() as u64) {
        "superseded_revision_read_from_agentgres"
    } else {
        match load_run(data_dir, id) {
            None => "absent_rebuilt_from_agentgres",
            Some(row) if row == record => "agreed_with_agentgres",
            Some(_) => "stale_rebuilt_from_agentgres",
        }
    };
    Ok(ResolvedTransformationRunV1 {
        run_ref: run_ref.to_owned(),
        owner_ref,
        principal_ref: scope.principal_ref.clone(),
        tenant_ref: scope.tenant_ref.clone(),
        schema_version,
        record,
        content_hash,
        admitted_head: entry.head.clone(),
        admitted_revision,
        index_state,
    })
}

const RUN_SCHEMA: &str = "ioi.hypervisor.odk.transformation-run.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.transformation-run-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.transformation-runs-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-transformation-runs";
const RECEIPT_DIR: &str = "odk-transformation-run-receipts";

/// v1 lifecycle. `executed`/`materialized` are reserved for a future connector-adapter cut.
const LIFECYCLE_STATES: &[&str] = &["planned", "dry_run_ready", "blocked", "cancelled"];
const RESERVED_STATES: &[&str] = &["executed", "materialized"];
/// Declared output intents a plan may target. Nothing is produced here — intent only.
const OUTPUT_INTENTS: &[&str] = &[
    "ontology_objects",
    "projection",
    "evaluation_dataset",
    "training_material",
    "export_bundle",
];
/// The downstream policy operation a high-risk intent requires the view to authorize.
fn intent_downstream_op(intent: &str) -> Option<&'static str> {
    match intent {
        "evaluation_dataset" => Some("evaluate"),
        "training_material" => Some("train"),
        "export_bundle" => Some("export"),
        _ => None,
    }
}
/// The still-missing contract downstream of this rung.
const MISSING_CONTRACTS: &[&str] = &["OntologyProjection"];
/// Body keys that would be a plaintext secret — rejected outright.
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];
/// Body keys that would smuggle a raw source query into a plan — rejected outright.
const RAW_QUERY_KEYS: &[&str] = &["query", "sql", "raw_query", "statement", "command"];

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}
fn str_list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
type VErr = (String, String);
fn verr(code: &str, msg: String) -> VErr {
    (code.to_string(), msg)
}

fn load_mapping(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::connector_mapping_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn load_view(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::policy_bound_data_view_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn load_run(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn health_status(rec: &Value) -> String {
    rec.pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("incomplete")
        .to_string()
}
fn view_scope(view: &Value) -> Vec<String> {
    view.get("property_scope")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
/// Find the mapping binding (source_field, source_type) for a property id, across key/title/fields.
fn mapping_binding(mapping: &Value, property_id: &str) -> Option<(String, String)> {
    let pick = |m: &Value| -> Option<(String, String)> {
        if m.get("property_id").and_then(|v| v.as_str()) == Some(property_id) {
            Some((s(m, "source_field", ""), s(m, "source_type", "string")))
        } else {
            None
        }
    };
    for k in ["key_mapping", "title_mapping"] {
        if let Some(found) = mapping.get(k).and_then(|m| pick(m)) {
            return Some(found);
        }
    }
    mapping
        .get("field_mappings")?
        .as_array()?
        .iter()
        .find_map(pick)
}

/// The validated inputs a run needs, resolved from the current daemon state.
struct RunInputs {
    mapping: Value,
    view: Value,
    requested_fields: Vec<String>,
    purpose: String,
    output_intent: String,
}

/// Validate a run body fail-closed against CURRENT mapping/view state. Used at create, patch, and
/// dry-run — the same gate every time, never a cached approval. NO source contact anywhere.
fn validate_inputs(data_dir: &str, body: &Value) -> Result<RunInputs, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr("transformation_run_plaintext_secret_rejected", "A run plan never carries credentials — credential crossing is a future connector-adapter cut.".into()));
        }
        if RAW_QUERY_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr("transformation_run_raw_query_rejected", "A run plan never carries a raw source query — extraction semantics live behind the declared mapping, not ad-hoc query bodies.".into()));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "transformation_run_name_required",
            "A transformation run requires a name.".into(),
        ));
    }
    // Ready mapping.
    let mapping_id = opt_s(body, "connector_mapping_id").unwrap_or_default();
    let mapping = load_mapping(data_dir, &mapping_id).ok_or_else(|| {
        verr(
            "transformation_run_mapping_unknown",
            format!("connector_mapping_id '{mapping_id}' does not resolve to a declared mapping"),
        )
    })?;
    if health_status(&mapping) != "ready" {
        return Err(verr(
            "transformation_run_mapping_not_ready",
            format!("mapping '{mapping_id}' is not ready — a run plans only over validated shape"),
        ));
    }
    // Ready view, binding the SAME mapping, allowing transform.
    let view_id = opt_s(body, "policy_view_id").unwrap_or_default();
    let view = load_view(data_dir, &view_id).ok_or_else(|| {
        verr(
            "transformation_run_policy_view_unknown",
            format!(
                "policy_view_id '{view_id}' does not resolve to a declared policy-bound data view"
            ),
        )
    })?;
    if health_status(&view) != "ready" {
        return Err(verr("transformation_run_policy_view_not_ready", format!("policy view '{view_id}' is not ready — a run is gated on a ready capability envelope")));
    }
    if view.get("connector_mapping_id").and_then(|v| v.as_str()) != Some(mapping_id.as_str()) {
        return Err(verr(
            "transformation_run_policy_view_mapping_mismatch",
            "the policy view does not bind the referenced mapping — a run cannot mix gates".into(),
        ));
    }
    let ops: Vec<String> = str_list(&view, "allowed_operations");
    // v1 supports only `transform` — and the view must authorize it.
    let operation = opt_s(body, "operation").unwrap_or_else(|| "transform".into());
    if operation != "transform" {
        return Err(verr("transformation_run_operation_unsupported", format!("operation '{operation}' is not supported in v1 — only 'transform' plans exist (execution kinds are a future cut)")));
    }
    if !ops.iter().any(|o| o == "transform") {
        return Err(verr(
            "transformation_run_operation_not_authorized",
            "the policy view does not authorize 'transform' over this mapping".into(),
        ));
    }
    // Requested fields ⊆ policy scope (which is itself ⊆ mapped properties). Empty → the full scope.
    let scope = view_scope(&view);
    let mut requested_fields = str_list(body, "requested_fields");
    if requested_fields.is_empty() {
        requested_fields = scope.clone();
    }
    for f in &requested_fields {
        if !scope.iter().any(|x| x == f) {
            return Err(verr("transformation_run_field_unscoped", format!("requested field '{f}' is outside the policy view's property scope — a run cannot widen its gate")));
        }
    }
    // Purpose: inherited when absent; must MATCH the policy purpose when provided.
    let view_purpose = s(&view, "purpose", "");
    let purpose = opt_s(body, "purpose").unwrap_or_else(|| view_purpose.clone());
    if purpose != view_purpose {
        return Err(verr(
            "transformation_run_purpose_mismatch",
            format!(
                "run purpose '{purpose}' does not match the policy view's purpose '{view_purpose}'"
            ),
        ));
    }
    // Output intent: enum only; a high-risk intent needs the view to authorize its downstream op
    // WITH a named receipt obligation (checked against the gate — belt and braces).
    let output_intent = opt_s(body, "output_intent").unwrap_or_else(|| "ontology_objects".into());
    if !OUTPUT_INTENTS.contains(&output_intent.as_str()) {
        return Err(verr(
            "transformation_run_output_intent_invalid",
            format!("output_intent '{output_intent}' must be one of {OUTPUT_INTENTS:?}"),
        ));
    }
    if let Some(op) = intent_downstream_op(&output_intent) {
        if !ops.iter().any(|o| o == op) {
            return Err(verr("transformation_run_intent_not_authorized", format!("output intent '{output_intent}' implies downstream '{op}' which the policy view does not authorize")));
        }
        let obligations = str_list(&view, "receipt_obligations");
        if !obligations.iter().any(|o| o.to_lowercase().contains(op)) {
            return Err(verr("transformation_run_receipt_obligation_required", format!("output intent '{output_intent}' is high-risk and the policy view carries no receipt obligation naming '{op}'")));
        }
    }
    Ok(RunInputs {
        mapping,
        view,
        requested_fields,
        purpose,
        output_intent,
    })
}

fn run_receipt(
    data_dir: &str,
    run_ref: &str,
    op: &str,
    outcome: &str,
    summary: &str,
) -> std::io::Result<Value> {
    let id = format!("trr_{:x}", nanos());
    let receipt_ref = format!("agentgres://transformation-run-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "transformation_run_ref": run_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
    });
    // W1.2 / MEF-GAP-008 — every act on a run is receipted; a discarded receipt breaks that
    // invariant, so the caller fails closed rather than returning an unreceipted effect.
    persist_record(data_dir, RECEIPT_DIR, &id, &rec)?;
    Ok(rec)
}
/// The uniform 500 for a dropped run receipt (W1.2 / MEF-GAP-008).
fn receipt_persist_failed() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(
            json!({ "ok": false, "code": "transformation_run_receipt_persistence_failed",
        "message": "the run receipt did not commit — refused rather than returning an unreceipted effect" }),
        ),
    )
}
/// The uniform 500 for a dropped run record write (W1.2 / MEF-GAP-008).
fn run_persist_failed() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(
            json!({ "ok": false, "code": "transformation_run_persistence_failed",
        "message": "the transformation run did not commit — no state change was recorded" }),
        ),
    )
}
/// Append a history entry + receipt ref to a run record (bounded history).
fn push_history(record: &mut Value, op: &str, summary: &str, receipt_ref: Value) {
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut hist = record
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": op, "at": iso_now(), "summary": summary, "receipt_ref": receipt_ref.clone() }));
    let len = hist.len();
    if len > 20 {
        hist = hist[len - 20..].to_vec();
    }
    record["history"] = json!(hist);
    let mut refs = record
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.push(receipt_ref);
    record["receipt_refs"] = json!(refs);
}
fn bad(data_dir: &str, op: &str, err: VErr) -> (StatusCode, Json<Value>) {
    // Failed validation is itself receipted (the audit trail records what was refused and why).
    // W1.2 / MEF-GAP-008 — the overview claims every failed validation is receipted, so a dropped
    // rejection receipt fails closed (500) rather than rejecting off the record.
    if run_receipt(
        data_dir,
        "transformation-run://unadmitted",
        op,
        &err.0,
        &err.1,
    )
    .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "transformation_run_receipt_persistence_failed",
            "message": "the rejection was not receipted — the audit trail requires every failed validation to be receipted" }),
            ),
        );
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })),
    )
}

/// GET /v1/hypervisor/odk/transformation-runs — declared run plans (newest first).
pub(crate) async fn handle_runs_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(
        json!({ "ok": true, "schema_version": RUN_SCHEMA, "transformation_runs": items, "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/transformation-runs/overview — lifecycle vocab + counts + honest gaps.
pub(crate) async fn handle_runs_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by = |status: &str| {
        items
            .iter()
            .filter(|r| s(r, "status", "") == status)
            .count()
    };
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "transformation_runs": items.len(),
        "lifecycle": { "planned": by("planned"), "dry_run_ready": by("dry_run_ready"), "blocked": by("blocked"), "cancelled": by("cancelled") },
        "lifecycle_states": LIFECYCLE_STATES,
        "reserved_states": { "states": RESERVED_STATES, "note": "reserved for a future connector-adapter cut — never set by this plane" },
        "output_intents": OUTPUT_INTENTS,
        "missing_contracts": MISSING_CONTRACTS,
        "governance_gaps": [
            "PLAN / DRY-RUN only — a run validates shape, gate, and intent and emits receipts; it never contacts a source or moves data",
            "live source reads are a NAMED GAP: they arrive with a future connector-adapter cut, after credentials get an authority-crossing story",
            "no object plane is produced — object_instances stays 0 until an OntologyProjection exists",
            "every create, dry-run, block, cancel, and FAILED validation is receipted"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/transformation-runs/:id.
pub(crate) async fn handle_run_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_run(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "transformation_run": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/transformation-runs/:id/history — embedded history + persisted receipts.
pub(crate) async fn handle_run_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    let rref = r
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| {
        x.get("transformation_run_ref").and_then(|v| v.as_str()) == Some(rref.as_str())
    });
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "transformation_run_ref": rref, "revision": r.get("revision"), "status": r.get("status"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// POST /v1/hypervisor/odk/transformation-runs — admit a run PLAN (fail-closed, receipted, inert).
pub(crate) async fn handle_run_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // IDENTITY FIRST — before validation, and before a receipt is written for a run plan that will
    // not be admitted.
    let caller = match run_v1_write_caller(&st.data_dir, &headers, &body, None) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let inputs = match validate_inputs(&st.data_dir, &body) {
        Ok(i) => i,
        Err(e) => return bad(&st.data_dir, "create_rejected", e),
    };
    let id = format!("trun_{:x}", nanos());
    let now = iso_now();
    let rref = format!("transformation-run://{id}");
    let receipt = match run_receipt(
        &st.data_dir,
        &rref,
        "created",
        "ok",
        "TransformationRun plan admitted",
    ) {
        Ok(r) => r,
        Err(_) => return receipt_persist_failed(),
    };
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let record = json!({
        "schema_version": RUN_SCHEMA,
        "object": "ioi.hypervisor.odk.transformation_run",
        "id": id,
        "ref": rref,
        "name": s(&body, "name", "transformation-run"),
        "description": s(&body, "description", ""),
        "status": "planned",
        "operation": "transform",
        "connector_mapping_id": inputs.mapping.get("id").cloned().unwrap_or(Value::Null),
        "connector_mapping_ref": inputs.mapping.get("ref").cloned().unwrap_or(Value::Null),
        "policy_view_id": inputs.view.get("id").cloned().unwrap_or(Value::Null),
        "policy_view_ref": inputs.view.get("ref").cloned().unwrap_or(Value::Null),
        "ontology_ref": inputs.mapping.get("ontology_ref").cloned().unwrap_or(Value::Null),
        "object_type_id": inputs.mapping.get("object_type_id").cloned().unwrap_or(Value::Null),
        "requested_fields": inputs.requested_fields,
        "purpose": inputs.purpose,
        "output_intent": inputs.output_intent,
        "plan": Value::Null,
        "execution": { "source_contacted": false, "data_moved": false, "object_instances": 0, "note": "plan/dry-run only — live reads are a future connector-adapter cut" },
        "missing_contracts": MISSING_CONTRACTS,
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "TransformationRun plan admitted", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    // The chain is the admission; the row is the projection.
    let commit = match admit_run_v1(&st.data_dir, &caller, &rref, &record, true) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if persist_record(&st.data_dir, RECORD_DIR, &id, &record).is_err() {
        return run_persist_failed();
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "transformation_run": record,
            "replayed": commit.replayed,
            "owner_ref": caller.owner_ref,
            "admitted_head": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
        })),
    )
}

/// POST /v1/hypervisor/odk/transformation-runs/:id/dry-run — recompute the gate against CURRENT
/// state and produce the auditable plan. Receipt is written BEFORE the plan is registered. If the
/// referenced truth drifted (mapping/view gone or degraded), the run is BLOCKED with named reasons.
pub(crate) async fn handle_run_dry_run(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    if s(&record, "status", "") == "cancelled" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "transformation_run_cancelled_immutable", "message": "a cancelled run is immutable" } }),
            ),
        );
    }
    let rref = s(&record, "ref", "");
    // Re-validate against the CURRENT mapping/view — the gate is checked every time, never cached.
    let revalidation_body = json!({
        "name": record.get("name").cloned().unwrap_or(Value::Null),
        "connector_mapping_id": record.get("connector_mapping_id").cloned().unwrap_or(Value::Null),
        "policy_view_id": record.get("policy_view_id").cloned().unwrap_or(Value::Null),
        "requested_fields": record.get("requested_fields").cloned().unwrap_or(json!([])),
        "purpose": record.get("purpose").cloned().unwrap_or(Value::Null),
        "output_intent": record.get("output_intent").cloned().unwrap_or(Value::Null),
    });
    match validate_inputs(&st.data_dir, &revalidation_body) {
        Err((code, msg)) => {
            let receipt = match run_receipt(&st.data_dir, &rref, "dry_run_blocked", &code, &msg) {
                Ok(r) => r,
                Err(_) => return receipt_persist_failed(),
            };
            let summary = format!("blocked: {code}");
            record["status"] = json!("blocked");
            record["blocked_reasons"] = json!([{ "code": code, "message": msg }]);
            record["updated_at"] = json!(iso_now());
            push_history(
                &mut record,
                "dry_run_blocked",
                &summary,
                receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
            );
            // EVERY STATE MOVE IS ADMITTED. A row rewritten without an admission would leave the
            // chain holding bytes the row no longer has, and a convergence would then be proved
            // against a revision that was silently replaced underneath it.
            if let Err(response) =
                admit_run_v1_state_move(&st.data_dir, &headers, &rref, &record, "dry_run_blocked")
            {
                return response;
            }
            if persist_record(&st.data_dir, RECORD_DIR, &id, &record).is_err() {
                return run_persist_failed();
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "transformation_run": record })),
            )
        }
        Ok(inputs) => {
            // Build the auditable plan from DECLARED truth only (no source contact anywhere).
            let fields: Vec<Value> = inputs
                .requested_fields
                .iter()
                .filter_map(|pid| {
                    mapping_binding(&inputs.mapping, pid).map(|(sf, st_)| json!({ "property_id": pid, "source_field": sf, "source_type": st_ }))
                })
                .collect();
            let plan = json!({
                "source": {
                    "data_source_ref": inputs.mapping.get("data_source_ref").cloned().unwrap_or(Value::Null),
                    "declared_endpoint_only": true
                },
                "object_type_id": inputs.mapping.get("object_type_id").cloned().unwrap_or(Value::Null),
                "fields": fields,
                "policy_gate": {
                    "policy_view_ref": inputs.view.get("ref").cloned().unwrap_or(Value::Null),
                    "purpose": inputs.purpose,
                    "receipt_obligations": inputs.view.get("receipt_obligations").cloned().unwrap_or(json!([]))
                },
                "output_intent": inputs.output_intent,
                "would_contact_source": false,
                "object_instances": 0,
                "receipts_before_output": true
            });
            // Receipt FIRST, then the plan lands on the record — output is never registered unreceipted.
            let receipt = match run_receipt(
                &st.data_dir,
                &rref,
                "dry_run",
                "ok",
                "dry-run plan validated against the current gate",
            ) {
                Ok(r) => r,
                Err(_) => return receipt_persist_failed(),
            };
            record["status"] = json!("dry_run_ready");
            record["plan"] = plan;
            record["blocked_reasons"] = json!([]);
            record["updated_at"] = json!(iso_now());
            push_history(
                &mut record,
                "dry_run",
                "dry-run plan validated against the current gate",
                receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
            );
            // EVERY STATE MOVE IS ADMITTED. A row rewritten without an admission would leave the
            // chain holding bytes the row no longer has, and a convergence would then be proved
            // against a revision that was silently replaced underneath it.
            if let Err(response) =
                admit_run_v1_state_move(&st.data_dir, &headers, &rref, &record, "dry_run")
            {
                return response;
            }
            if persist_record(&st.data_dir, RECORD_DIR, &id, &record).is_err() {
                return run_persist_failed();
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "transformation_run": record })),
            )
        }
    }
}

/// POST /v1/hypervisor/odk/transformation-runs/:id/cancel — terminal, receipted.
pub(crate) async fn handle_run_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    if s(&record, "status", "") == "cancelled" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "transformation_run_cancelled_immutable", "message": "the run is already cancelled" } }),
            ),
        );
    }
    let rref = s(&record, "ref", "");
    let receipt = match run_receipt(
        &st.data_dir,
        &rref,
        "cancelled",
        "ok",
        "TransformationRun plan cancelled",
    ) {
        Ok(r) => r,
        Err(_) => return receipt_persist_failed(),
    };
    record["status"] = json!("cancelled");
    record["updated_at"] = json!(iso_now());
    push_history(
        &mut record,
        "cancelled",
        "TransformationRun plan cancelled",
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    // EVERY STATE MOVE IS ADMITTED. A row rewritten without an admission would leave the
    // chain holding bytes the row no longer has, and a convergence would then be proved
    // against a revision that was silently replaced underneath it.
    if let Err(response) =
        admit_run_v1_state_move(&st.data_dir, &headers, &rref, &record, "cancelled")
    {
        return response;
    }
    if persist_record(&st.data_dir, RECORD_DIR, &id, &record).is_err() {
        return run_persist_failed();
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "transformation_run": record })),
    )
}

/// PATCH — plan-affecting changes re-validate against the CURRENT gate and reset the plan to
/// `planned` (a stale plan never survives an edit). Malformed patch changes nothing.
pub(crate) async fn handle_run_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(patch): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(existing) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    if s(&existing, "status", "") == "cancelled" {
        return (
            StatusCode::OK,
            Json(
                json!({ "ok": false, "error": { "code": "transformation_run_cancelled_immutable", "message": "a cancelled run is immutable" } }),
            ),
        );
    }
    let plan_keys = [
        "connector_mapping_id",
        "policy_view_id",
        "requested_fields",
        "purpose",
        "output_intent",
        "operation",
    ];
    let plan_affecting = plan_keys.iter().any(|k| patch.get(*k).is_some());
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "connector_mapping_id",
        "policy_view_id",
        "requested_fields",
        "purpose",
        "output_intent",
        "operation",
    ] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    let inputs = match validate_inputs(&st.data_dir, &merged) {
        Ok(i) => i,
        Err(e) => {
            // W1.2 / MEF-GAP-008 — the rejection receipt is the audit trail; fail closed if it drops.
            if run_receipt(
                &st.data_dir,
                &s(&existing, "ref", ""),
                "patch_rejected",
                &e.0,
                &e.1,
            )
            .is_err()
            {
                return receipt_persist_failed();
            }
            return (
                StatusCode::OK,
                Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })),
            );
        }
    };
    let mut record = existing;
    if let Some(v) = patch.get("name") {
        record["name"] = v.clone();
    }
    if let Some(v) = patch.get("description") {
        record["description"] = v.clone();
    }
    if plan_affecting {
        record["connector_mapping_id"] = inputs.mapping.get("id").cloned().unwrap_or(Value::Null);
        record["connector_mapping_ref"] = inputs.mapping.get("ref").cloned().unwrap_or(Value::Null);
        record["policy_view_id"] = inputs.view.get("id").cloned().unwrap_or(Value::Null);
        record["policy_view_ref"] = inputs.view.get("ref").cloned().unwrap_or(Value::Null);
        record["ontology_ref"] = inputs
            .mapping
            .get("ontology_ref")
            .cloned()
            .unwrap_or(Value::Null);
        record["object_type_id"] = inputs
            .mapping
            .get("object_type_id")
            .cloned()
            .unwrap_or(Value::Null);
        record["requested_fields"] = json!(inputs.requested_fields);
        record["purpose"] = json!(inputs.purpose);
        record["output_intent"] = json!(inputs.output_intent);
        record["status"] = json!("planned");
        record["plan"] = Value::Null;
        record["blocked_reasons"] = json!([]);
    }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    record["updated_at"] = json!(iso_now());
    let receipt = match run_receipt(
        &st.data_dir,
        &s(&record, "ref", ""),
        "patched",
        "ok",
        if plan_affecting {
            "plan-affecting edit — plan reset to planned"
        } else {
            "metadata edit"
        },
    ) {
        Ok(r) => r,
        Err(_) => return receipt_persist_failed(),
    };
    push_history(
        &mut record,
        "patched",
        if plan_affecting {
            "plan-affecting edit — plan reset to planned"
        } else {
            "metadata edit"
        },
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    // EVERY STATE MOVE IS ADMITTED, patches included: a metadata edit still produces a new stored
    // revision, and a convergence naming the old one must be able to tell that it moved.
    if let Err(response) = admit_run_v1_state_move(
        &st.data_dir,
        &headers,
        &s(&record, "ref", ""),
        &record,
        "patched",
    ) {
        return response;
    }
    if persist_record(&st.data_dir, RECORD_DIR, &id, &record).is_err() {
        return run_persist_failed();
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "transformation_run": record })),
    )
}

/// DELETE — receipted removal of the plan record.
pub(crate) async fn handle_run_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let rref = load_run(&st.data_dir, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("transformation-run://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        // W1.2 / MEF-GAP-008 — receipted removal is the declared effect: the record IS gone, so the
        // 500 states removed:true honestly while flagging the missing deletion receipt.
        if run_receipt(
            &st.data_dir,
            &rref,
            "deleted",
            "ok",
            "TransformationRun plan removed",
        )
        .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "transformation_run_receipt_persistence_failed",
                "message": "the plan record was removed but its deletion receipt did not commit — receipted removal is the declared effect", "removed": true, "id": id }),
                ),
            );
        }
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": removed, "removed": removed, "id": id })),
    )
}

#[cfg(test)]
mod transformation_run_tests {
    use super::*;

    #[test]
    fn lifecycle_states_and_reserved_are_explicit() {
        assert_eq!(
            LIFECYCLE_STATES,
            &["planned", "dry_run_ready", "blocked", "cancelled"]
        );
        assert_eq!(RESERVED_STATES, &["executed", "materialized"]);
        assert_eq!(MISSING_CONTRACTS, &["OntologyProjection"]);
    }

    #[test]
    fn high_risk_intents_map_to_downstream_ops() {
        assert_eq!(intent_downstream_op("export_bundle"), Some("export"));
        assert_eq!(intent_downstream_op("training_material"), Some("train"));
        assert_eq!(intent_downstream_op("evaluation_dataset"), Some("evaluate"));
        assert_eq!(intent_downstream_op("ontology_objects"), None);
        assert_eq!(intent_downstream_op("projection"), None);
    }

    #[test]
    fn raw_query_and_secret_keys_are_named() {
        assert!(RAW_QUERY_KEYS.contains(&"sql"));
        assert!(RAW_QUERY_KEYS.contains(&"raw_query"));
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"api_key"));
    }

    #[test]
    fn mapping_binding_resolves_across_key_title_fields() {
        let mapping = json!({
            "key_mapping": { "property_id": "loan_id", "source_field": "id", "source_type": "string" },
            "title_mapping": { "property_id": "title", "source_field": "disp", "source_type": "string" },
            "field_mappings": [{ "property_id": "amount", "source_field": "amt", "source_type": "double" }]
        });
        assert_eq!(mapping_binding(&mapping, "loan_id").unwrap().0, "id");
        assert_eq!(mapping_binding(&mapping, "amount").unwrap().0, "amt");
        assert!(mapping_binding(&mapping, "ghost").is_none());
    }
}
