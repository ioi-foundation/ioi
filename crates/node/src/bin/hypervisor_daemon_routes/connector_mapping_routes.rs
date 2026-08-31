//! ConnectorMapping — the FIRST inert authority-crossing brick. A mapping DECLARES how one registered
//! data source's fields would bind to one canonical ontology object type's typed properties. It is a
//! validated, receipted DECLARATION only:
//!   * it references a declared `data_source_id` (#10 registry) and a typed `ontology_ref` /
//!     `object_type_id` (#11 ontology-manager contract);
//!   * it stays INERT — no extraction, no source read, no object instances, no explorer rows, no data
//!     movement. `object_instances` is always 0.
//!
//! It is the first rung of a ladder the surface names honestly: ConnectorMapping (this) → then
//! PolicyBoundDataView (the authority gate) → then TransformationRun + receipts (auditable runs) →
//! then OntologyProjection (the model → explorer/runtime bridge). Nothing downstream of this rung
//! exists yet; declaring a mapping never authorizes or runs anything.
//!
//! Fail-closed at write: known source, known ontology/object, known property ids, compatible source
//! type → property base value type, single-valued only (scalar properties), no duplicate target
//! property, required key + title mappings present, and NO credential material in the body.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

// ============ M05.7 · THE v1 CONNECTOR-MAPPING OWNER SEAM — OWNER-SCOPED, THEN RESOLVABLE ========
//
// WHY THIS LANE CHANGED AT ALL. A v2 convergence has to prove the caller holds the v1 predecessor it
// names. For the ODK DataRecipe lane that was already possible, because its writes cross the shared
// owner-scoped admission boundary and a scope record pins principal, tenant and owner. This lane had
// none of that: it took no identity at all — `handle_connector_mapping_create(State, Json(body))`
// never saw a caller — persisted into a flat record directory by overwrite, and its registered v1
// contract is closed with no owner, tenant or principal member. There was therefore NOTHING STORED
// for a custody proof to check, and no seam this module could publish that would not be inventing
// the very fact it claimed to verify. Owner-scoping the WRITE is the only thing that creates it.
//
// THE v1 RECORD ITSELF IS UNCHANGED, BYTE FOR BYTE. v1 is read-only and v2 is the only authorable
// contract, so the owner binding may not edit the record: an owner member added here would be a
// contract change to a closed registered predecessor. Instead the admitted payload is an ENVELOPE
// that carries the v1 record VERBATIM under its own key with the owner beside it. The chain payload,
// the record directory row and the registered v1 record are then the same bytes, which is what lets
// a custody commitment be taken over the stored record with no projection step to disagree about.
//
// IMMUTABILITY COMES FROM THE CHAIN, NOT FROM THE ROW. A v1 mapping is patched IN PLACE — revision 2
// overwrites revision 1's bytes and revision 1 becomes unaddressable in the row. Every admission is
// appended, so the CHAIN holds each revision immutably even though the row does not, and an exact
// revision is resolvable from it. That is what makes "the exact stored revision and its hash" a
// thing this module can answer rather than a thing it has to disclaim.

/// The scope kind this family reserves. Distinct from the record directory: one is an authority
/// fact, the other is a rebuildable projection, and conflating them is what made the row
/// load-bearing for an admission decision everywhere else this pattern was missing.
const MAPPING_V1_SCOPE_KIND: &str = "hypervisor-odk-connector-mapping";
const MAPPING_V1_OWNER_NAMESPACE: &str = "hypervisor-odk-connector-mapping-v1";
const MAPPING_V1_ADMISSION_SCHEMA: &str = "ioi.hypervisor.odk.connector-mapping-v1-admission.v1";
const MAPPING_V1_CONTRACT_ID: &str = "schema://ioi/foundations/objects/connector-mapping/v1";
const MAPPING_V1_RECORD_KEY: &str = "connector_mapping_record";
const MAPPING_V1_ADMIT_OP: &str = "event_stream.hypervisor_odk_connector_mapping_admitted";
const MAPPING_V1_REVISE_OP: &str = "event_stream.hypervisor_odk_connector_mapping_revised";
/// The scheme the record ACTUALLY stores in its own `ref`.
const MAPPING_V1_STORED_SCHEME: &str = "connector-mapping";

fn mapping_v1_refusal(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

/// A chain holding something this build cannot project is a SERVER-side fact, never a caller error.
fn mapping_v1_chain_refusal(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

/// The commitment over one stored v1 record's exact bytes, canonicalized.
///
/// No field list: the record is committed as a whole, so a later edit to an enumeration here cannot
/// silently change what a custody proof claims to have seen.
fn mapping_v1_content_hash(record: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    use sha2::Digest;
    serde_jcs::to_vec(record)
        .map(|bytes| format!("sha256:{:x}", sha2::Sha256::digest(&bytes)))
        .map_err(|error| {
            mapping_v1_chain_refusal(
                "connector_mapping_v1_projection_failed",
                &format!("the stored record could not be canonicalized: {error}"),
            )
        })
}

fn mapping_v1_stream_tail(resource_ref: &str) -> String {
    use sha2::Digest;
    format!(
        "{MAPPING_V1_SCOPE_KIND}.{:x}",
        sha2::Sha256::digest(resource_ref.as_bytes())
    )
}

/// Cross the SHARED owner-scoped admission boundary for one v1 mapping revision.
///
/// The caller supplies the owner it is writing under and the key that makes a retry replay rather
/// than admit twice — the same contract every other owner-scoped lane in this estate requires. There
/// is no unowned path: a write that cannot name an owner cannot be custody-proved later, and
/// admitting it anyway would put a record on the chain that no convergence could ever use.
/// WHAT A CALLER MUST PRESENT BEFORE ANY v1 MAPPING WRITE, resolved BEFORE the record or its receipt
/// is built. Identity and owner are the cheapest refusals available and the ones a caller is owed
/// first; resolving them later would let an unauthenticated request leave a persisted receipt behind
/// for a mapping that was never admitted.
struct MappingV1WriteCaller {
    identity: super::substrate_store::RequestIdentity,
    owner_ref: String,
    idempotency_key: String,
}

fn mapping_v1_write_caller(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
    previous_owner_ref: Option<&str>,
) -> Result<MappingV1WriteCaller, (StatusCode, Json<Value>)> {
    let identity = super::substrate_store::resolve_request_identity(data_dir, headers)
        .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();
    if idempotency_key.is_empty() {
        return Err(mapping_v1_refusal(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried write cannot apply twice",
        ));
    }
    // A REVISION MAY NOT MOVE A RESOURCE BETWEEN OWNERS, so on a successor the owner comes from the
    // admitted predecessor rather than from the request body.
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
        return Err(mapping_v1_refusal(
            "connector_mapping_owner_ref_required",
            "owner_ref is required: this record is owned by exactly one org:// or project://, and an unowned record can never be custody-proved",
        ));
    }
    Ok(MappingV1WriteCaller {
        identity,
        owner_ref,
        idempotency_key,
    })
}

fn admit_mapping_v1(
    data_dir: &str,
    caller: &MappingV1WriteCaller,
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
            MAPPING_V1_SCOPE_KIND,
            resource_ref,
            &owner_ref,
            &owner_ref,
            idempotency_key,
        )
    } else {
        super::substrate_store::authorize_request_resource_scope(
            data_dir,
            &identity,
            MAPPING_V1_SCOPE_KIND,
            resource_ref,
            Some(&owner_ref),
        )
    }
    .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let tail = mapping_v1_stream_tail(resource_ref);
    let expected_head = if genesis {
        None
    } else {
        super::mutation_event_foundation::read_owner_scoped_history(
            data_dir,
            &identity,
            &scope,
            MAPPING_V1_SCOPE_KIND,
            resource_ref,
            MAPPING_V1_OWNER_NAMESPACE,
            &tail,
        )
        .map_err(super::mutation_event_foundation::mutation_refusal_reply)?
        .last()
        .map(|entry| entry.head.clone())
    };
    // THE ENVELOPE CARRIES THE OWNER; THE RECORD STAYS THE REGISTERED v1 RECORD, VERBATIM.
    let payload = json!({
        "schema_version": MAPPING_V1_ADMISSION_SCHEMA,
        "owner_ref": owner_ref,
        "resource_ref": resource_ref,
        MAPPING_V1_RECORD_KEY: record,
    });
    super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        genesis,
        super::mutation_event_foundation::ScopedMutation {
            identity: &identity,
            scope: &scope,
            resource_kind: MAPPING_V1_SCOPE_KIND,
            resource_ref,
            owner_namespace: MAPPING_V1_OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: if genesis {
                MAPPING_V1_ADMIT_OP
            } else {
                MAPPING_V1_REVISE_OP
            },
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key,
            recorded_at_ms: 0,
        },
    )
    .map_err(super::mutation_event_foundation::mutation_refusal_reply)
}

/// ONE stored v1 ConnectorMapping, resolved from the owner-scoped chain for a caller entitled to it.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedConnectorMappingV1 {
    /// The ref the record ACTUALLY stores, never rewritten into the successor's scheme.
    pub(crate) mapping_ref: String,
    pub(crate) owner_ref: String,
    pub(crate) principal_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) schema_version: String,
    /// The registered v1 record, byte-exact as the chain holds it.
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) admitted_head: String,
    /// The record's OWN `revision`, resolved from the admitted entry rather than from the row.
    pub(crate) admitted_revision: u64,
    pub(crate) index_state: &'static str,
}

/// Resolve the exact stored v1 ConnectorMapping a caller names, or refuse by name.
///
/// `expected_revision` names an EXACT admitted revision. A v1 mapping is patched in place, so the
/// row only ever holds the newest bytes — but every revision was admitted, so the chain can answer
/// for one exactly. Naming a revision the chain does not hold is a typed refusal, never the nearest
/// one, because converging "whichever revision is current" is the drift the v2 contract exists to
/// end.
pub(crate) fn resolve_stored_connector_mapping_v1(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    expected_owner_ref: Option<&str>,
    mapping_ref: &str,
    expected_revision: Option<u64>,
) -> Result<ResolvedConnectorMappingV1, (StatusCode, Json<Value>)> {
    let Some((MAPPING_V1_STORED_SCHEME, id)) = mapping_ref
        .split_once("://")
        .filter(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty())
    else {
        return Err(mapping_v1_refusal(
            "connector_mapping_v1_ref_not_canonical",
            "a stored v1 connector mapping is addressed as 'connector-mapping://<id>' — the scheme it was admitted under, not the successor's 'mapping://'",
        ));
    };
    let scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        MAPPING_V1_SCOPE_KIND,
        mapping_ref,
        expected_owner_ref,
    )
    .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        data_dir,
        identity,
        &scope,
        MAPPING_V1_SCOPE_KIND,
        mapping_ref,
        MAPPING_V1_OWNER_NAMESPACE,
        &mapping_v1_stream_tail(mapping_ref),
    )
    .map_err(super::mutation_event_foundation::mutation_refusal_reply)?;
    if history.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "connector_mapping_v1_not_found",
                    "message": "this connector mapping has no admitted history — an absent predecessor is a typed absence, never an empty success"
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
                    .pointer(&format!("/{MAPPING_V1_RECORD_KEY}/revision"))
                    .and_then(Value::as_u64)
                    == Some(wanted)
            })
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "ok": false,
                        "error": {
                            "code": "connector_mapping_v1_revision_absent",
                            "message": format!("this connector mapping has no admitted revision {wanted}; an absent revision is a typed absence, never the nearest one")
                        }
                    })),
                )
            })?,
    };
    let envelope = &entry.operation.payload;
    if envelope.get("schema_version").and_then(Value::as_str) != Some(MAPPING_V1_ADMISSION_SCHEMA) {
        return Err(mapping_v1_chain_refusal(
            "connector_mapping_v1_admission_unsupported",
            "the chain holds an admission envelope this build does not project; an unrecognised stored shape is refused rather than read as though it were understood",
        ));
    }
    let owner_ref = envelope
        .get("owner_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(record) = envelope.get(MAPPING_V1_RECORD_KEY).cloned() else {
        return Err(mapping_v1_chain_refusal(
            "connector_mapping_v1_projection_failed",
            "the admission envelope carries no connector mapping record",
        ));
    };
    let schema_version = record
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if schema_version != MAPPING_SCHEMA {
        return Err(mapping_v1_chain_refusal(
            "connector_mapping_v1_version_unsupported",
            "the chain holds a connector mapping admitted under a version this build neither authors nor projects",
        ));
    }
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        MAPPING_V1_CONTRACT_ID,
        &record,
    )
    .map_err(|reason| {
        mapping_v1_chain_refusal(
            "connector_mapping_v1_projection_failed",
            &format!("the stored record does not satisfy {MAPPING_V1_CONTRACT_ID}: {reason}"),
        )
    })?;
    if record.get("ref").and_then(Value::as_str) != Some(mapping_ref) {
        return Err(mapping_v1_chain_refusal(
            "connector_mapping_v1_ref_binding_disagrees",
            "the admitted record's own ref is not the ref this scope resolves; the binding between the stored ref and the admitted scope is broken",
        ));
    }
    let content_hash = mapping_v1_content_hash(&record)?;
    let admitted_revision = record.get("revision").and_then(Value::as_u64).unwrap_or(0);
    // The row is consulted only to REPORT agreement, after the answer is already computed.
    let index_state = if expected_revision.is_some_and(|wanted| wanted < history.len() as u64) {
        // Resolving a SUPERSEDED revision is a chain read by construction: the row holds only the
        // newest bytes, so reporting agreement here would be reporting it about a different revision.
        "superseded_revision_read_from_agentgres"
    } else {
        match load_mapping(data_dir, id) {
            None => "absent_rebuilt_from_agentgres",
            Some(row) if row == record => "agreed_with_agentgres",
            Some(_) => "stale_rebuilt_from_agentgres",
        }
    };
    Ok(ResolvedConnectorMappingV1 {
        mapping_ref: mapping_ref.to_owned(),
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

const MAPPING_SCHEMA: &str = "ioi.hypervisor.odk.connector-mapping.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.connector-mapping-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.connector-mappings-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-connector-mappings";
const RECEIPT_DIR: &str = "odk-connector-mapping-receipts";

/// Source-field shapes an author may declare (the source's shape, not a live read).
const SOURCE_FIELD_TYPES: &[&str] = &[
    "string",
    "integer",
    "double",
    "boolean",
    "timestamp",
    "date",
    "json",
];
/// The authority contracts still missing downstream of this rung — named honestly on every record.
const MISSING_CONTRACTS: &[&str] = &[
    "PolicyBoundDataView",
    "TransformationRun",
    "OntologyProjection",
];
/// Body keys that would be a plaintext secret — rejected outright (a mapping never carries a credential).
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];

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
type VErr = (String, String);
fn verr(code: &str, msg: String) -> VErr {
    (code.to_string(), msg)
}

/// Is a declared source field type compatible with a property's base value type? Conservative — a
/// source shape only binds where the semantics survive (no lossy or nonsensical coercions).
fn value_compatible(source_type: &str, base: &str) -> bool {
    match source_type {
        "string" => matches!(base, "string" | "markdown" | "enum"),
        "integer" => matches!(base, "integer" | "double"),
        "double" => matches!(base, "double"),
        "boolean" => matches!(base, "boolean"),
        "timestamp" => matches!(base, "timestamp"),
        "date" => matches!(base, "date" | "timestamp"),
        "json" => matches!(base, "markdown" | "attachment" | "geo_point"),
        _ => false,
    }
}

fn load_data_source(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::data_source_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("source_id").and_then(|v| v.as_str()) == Some(id))
}
fn load_ontology(data_dir: &str, oref: &str) -> Option<Value> {
    // Accept either the canonical `ontology://<id>` ref or a bare id.
    read_record_dir(data_dir, crate::odk_routes::KIND_ONT)
        .into_iter()
        .find(|r| {
            r.get("ref").and_then(|v| v.as_str()) == Some(oref)
                || r.get("id").and_then(|v| v.as_str()) == Some(oref)
        })
}
fn find_object_type<'a>(ont: &'a Value, oid: &str) -> Option<&'a Value> {
    ont.pointer("/canonical_object_model/object_types")?
        .as_array()?
        .iter()
        .find(|o| o.get("id").and_then(|x| x.as_str()) == Some(oid))
}
fn find_property<'a>(obj: &'a Value, pid: &str) -> Option<&'a Value> {
    obj.get("properties")?
        .as_array()?
        .iter()
        .find(|p| p.get("id").and_then(|x| x.as_str()) == Some(pid))
}
/// A declared value_type resolves to its base; a base literal resolves to itself. (#11 already
/// validated the ontology, so every property value_type resolves.)
fn resolve_base(ont: &Value, value_type: &str) -> String {
    if let Some(vts) = ont
        .pointer("/canonical_object_model/value_types")
        .and_then(|v| v.as_array())
    {
        if let Some(vt) = vts
            .iter()
            .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(value_type))
        {
            return vt
                .get("base")
                .and_then(|x| x.as_str())
                .unwrap_or("string")
                .to_string();
        }
    }
    value_type.to_string()
}

/// One binding (key / title / field) normalized from the body: (role, source_field, property_id,
/// source_type, source_cardinality).
fn binding_tuple(role: &str, v: &Value) -> (String, String, String, String, String) {
    (
        role.to_string(),
        s(v, "source_field", ""),
        s(v, "property_id", ""),
        s(v, "source_type", "string"),
        s(v, "source_cardinality", "one"),
    )
}

/// Validate a mapping body fail-closed and project its declared record fields + readiness health.
/// INERT: nothing is read from the source; this only checks shape against declared truth.
fn validate_and_project(data_dir: &str, body: &Value) -> Result<Value, VErr> {
    // No credential material ever enters a mapping.
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr(
                "connector_mapping_plaintext_secret_rejected",
                "A connector mapping never carries credentials — the data source holds its own posture.".into(),
            ));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "connector_mapping_name_required",
            "A connector mapping requires a name.".into(),
        ));
    }
    // Known data source (#10).
    let data_source_id = opt_s(body, "data_source_id").unwrap_or_default();
    let ds = load_data_source(data_dir, &data_source_id).ok_or_else(|| {
        verr(
            "connector_mapping_data_source_unknown",
            format!("data_source_id '{data_source_id}' does not resolve to a declared data source"),
        )
    })?;
    // Known ontology + object type (#11).
    let ontology_ref = opt_s(body, "ontology_ref")
        .or_else(|| opt_s(body, "ontology_id"))
        .unwrap_or_default();
    let ont = load_ontology(data_dir, &ontology_ref).ok_or_else(|| {
        verr(
            "connector_mapping_ontology_unknown",
            format!("ontology '{ontology_ref}' does not resolve to a declared ontology"),
        )
    })?;
    let object_type_id = opt_s(body, "object_type_id").unwrap_or_default();
    let obj = find_object_type(&ont, &object_type_id).ok_or_else(|| {
        verr(
            "connector_mapping_object_type_unknown",
            format!("object_type '{object_type_id}' is not declared in the ontology"),
        )
    })?;
    let title_property = obj
        .get("title_property")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Required key + title mappings.
    let key = body.get("key_mapping").filter(|v| v.is_object());
    let key = key.ok_or_else(|| {
        verr(
            "connector_mapping_key_mapping_required",
            "A primary key_mapping (source_field → property_id) is required.".into(),
        )
    })?;
    let title = body.get("title_mapping").filter(|v| v.is_object());
    let title = title.ok_or_else(|| {
        verr(
            "connector_mapping_title_mapping_required",
            "A title_mapping (source_field → property_id) is required.".into(),
        )
    })?;
    // The object must declare a title_property, and the title mapping must target it.
    if title_property.is_empty() {
        return Err(verr("connector_mapping_title_mapping_required", "The object type declares no title_property — declare one in the ontology before mapping.".into()));
    }
    if s(title, "property_id", "") != title_property {
        return Err(verr(
            "connector_mapping_title_mapping_required",
            format!("title_mapping must target the object's title_property '{title_property}'"),
        ));
    }

    // Normalize all bindings and validate each against the typed object.
    let field_mappings: Vec<Value> = body
        .get("field_mappings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut bindings = vec![binding_tuple("key", key), binding_tuple("title", title)];
    bindings.extend(field_mappings.iter().map(|f| binding_tuple("field", f)));

    let mut targets: Vec<String> = Vec::new();
    for (role, source_field, property_id, source_type, source_cardinality) in &bindings {
        if source_field.trim().is_empty() {
            return Err(verr(
                "connector_mapping_source_field_required",
                format!("{role} mapping requires a source_field"),
            ));
        }
        let prop = find_property(obj, property_id).ok_or_else(|| {
            verr("connector_mapping_property_unknown", format!("{role} mapping property '{property_id}' is not a property of object_type '{object_type_id}'"))
        })?;
        if !SOURCE_FIELD_TYPES.contains(&source_type.as_str()) {
            return Err(verr(
                "connector_mapping_source_type_invalid",
                format!("source_type '{source_type}' is not a known source field type"),
            ));
        }
        // Scalar properties only — a repeated source field cannot bind to a single-valued property.
        if source_cardinality == "many" {
            return Err(verr("connector_mapping_cardinality_mismatch", format!("{role} mapping is multi-valued but property '{property_id}' is single-valued (declare a link_type or repeated property first)")));
        }
        if source_cardinality != "one" {
            return Err(verr(
                "connector_mapping_cardinality_invalid",
                format!("source_cardinality '{source_cardinality}' must be 'one' or 'many'"),
            ));
        }
        let base = resolve_base(
            &ont,
            prop.get("value_type")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        if !value_compatible(source_type, &base) {
            return Err(verr("connector_mapping_value_type_incompatible", format!("source_type '{source_type}' is not compatible with property '{property_id}' (base value type '{base}')")));
        }
        if targets.iter().any(|t| t == property_id) {
            return Err(verr(
                "connector_mapping_duplicate_target",
                format!("property '{property_id}' is targeted by more than one mapping"),
            ));
        }
        targets.push(property_id.clone());
    }

    // Readiness — honest: `ready` only when every REQUIRED property is mapped; else `incomplete`
    // (still a valid declared draft). Coverage is reported either way.
    let all_props: Vec<&Value> = obj
        .get("properties")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let total = all_props.len();
    let required_gaps: Vec<String> = all_props
        .iter()
        .filter(|p| p.get("required").and_then(|v| v.as_bool()).unwrap_or(false))
        .filter(|p| {
            let pid = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
            !targets.iter().any(|t| t == pid)
        })
        .map(|p| {
            p.get("name")
                .and_then(|v| v.as_str())
                .or_else(|| p.get("id").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string()
        })
        .collect();
    let status = if required_gaps.is_empty() {
        "ready"
    } else {
        "incomplete"
    };

    Ok(json!({
        "data_source_id": data_source_id,
        "data_source_ref": ds.get("source_ref").cloned().unwrap_or(Value::Null),
        "ontology_ref": ont.get("ref").cloned().unwrap_or(Value::Null),
        "object_type_id": object_type_id,
        "source_dataset": opt_s(body, "source_dataset"),
        "key_mapping": key.clone(),
        "title_mapping": title.clone(),
        "field_mappings": field_mappings,
        "health": {
            "status": status,
            "mapped_properties": targets.len(),
            "total_properties": total,
            "required_gaps": required_gaps,
            "object_instances": 0,
            "authority_crossed": false,
            "missing_contracts": MISSING_CONTRACTS,
            "note": "declaration only — no extraction; authorization requires PolicyBoundDataView, execution requires TransformationRun"
        }
    }))
}

fn mapping_receipt(data_dir: &str, mapping_ref: &str, op: &str, summary: &str) -> Value {
    let id = format!("cmr_{:x}", nanos());
    let receipt_ref = format!("agentgres://connector-mapping-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "connector_mapping_ref": mapping_ref, "op": op, "outcome": "ok", "summary": summary, "at": iso_now()
    });
    // CLASSIFIED — best-effort telemetry/receipt mirror: module-local receipts feed only the
    // history listing; the mapping record itself carries the authoritative history entries.
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
fn load_mapping(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn sorted_mappings(data_dir: &str) -> Vec<Value> {
    let mut items = read_record_dir(data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    items
}
fn bad(err: VErr) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })),
    )
}

/// GET /v1/hypervisor/odk/connector-mappings — declared mappings (newest first).
pub(crate) async fn handle_connector_mappings_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    Json(
        json!({ "ok": true, "schema_version": MAPPING_SCHEMA, "connector_mappings": sorted_mappings(&st.data_dir), "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/connector-mappings/overview — vocab + counts + honest missing-contract ladder.
pub(crate) async fn handle_connector_mappings_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by_status = |status: &str| {
        items
            .iter()
            .filter(|r| r.pointer("/health/status").and_then(|v| v.as_str()) == Some(status))
            .count()
    };
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "connector_mappings": items.len(),
        "health": { "ready": by_status("ready"), "incomplete": by_status("incomplete") },
        "source_field_types": SOURCE_FIELD_TYPES,
        "missing_contracts": MISSING_CONTRACTS,
        "governance_gaps": [
            "INERT: a mapping is a validated declaration only — nothing here reads, extracts, or moves source data",
            "authorization is a NAMED GAP: reads require a future PolicyBoundDataView; execution requires a future TransformationRun",
            "object_instances is always 0 — no object plane is produced until an OntologyProjection exists"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/connector-mappings/:id — one declared mapping.
pub(crate) async fn handle_connector_mapping_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_mapping(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "connector_mapping": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "connector mapping not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/connector-mappings/:id/health — readiness projection.
pub(crate) async fn handle_connector_mapping_health(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_mapping(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(
                json!({ "ok": true, "connector_mapping_ref": r.get("ref"), "revision": r.get("revision"), "health": r.get("health") }),
            ),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "connector mapping not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/connector-mappings/:id/history — embedded history + persisted receipts.
pub(crate) async fn handle_connector_mapping_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = load_mapping(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "connector mapping not found" })),
        );
    };
    let mref = r
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts
        .retain(|x| x.get("connector_mapping_ref").and_then(|v| v.as_str()) == Some(mref.as_str()));
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "connector_mapping_ref": mref, "revision": r.get("revision"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// POST /v1/hypervisor/odk/connector-mappings — declare a mapping (fail-closed, receipted, INERT).
pub(crate) async fn handle_connector_mapping_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // IDENTITY FIRST. An anonymous caller is owed its refusal before any validation runs, and before
    // a receipt is written for a mapping that will not be admitted.
    let caller = match mapping_v1_write_caller(&st.data_dir, &headers, &body, None) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let projected = match validate_and_project(&st.data_dir, &body) {
        Ok(p) => p,
        Err(e) => return bad(e),
    };
    let id = format!("cmap_{:x}", nanos());
    let now = iso_now();
    let mref = format!("connector-mapping://{id}");
    let receipt = mapping_receipt(&st.data_dir, &mref, "created", "ConnectorMapping declared");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut record = json!({
        "schema_version": MAPPING_SCHEMA,
        "object": "ioi.hypervisor.odk.connector_mapping",
        "id": id,
        "ref": mref,
        "name": s(&body, "name", "connector-mapping"),
        "description": s(&body, "description", ""),
        "status": "declared",
        "ingestion": { "wired": false, "note": "declaration only — no extraction, no source read, no object instances" },
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "ConnectorMapping declared", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    // Merge the validated/projected fields (refs, mappings, health) onto the record.
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    // THE CHAIN IS THE ADMISSION; THE ROW IS THE PROJECTION. Crossing the owner-scoped boundary
    // FIRST is what makes the durable truth owner-bound: a refused admission leaves no row, and a
    // row that later disagrees with the chain is reported as stale rather than believed.
    let commit = match admit_mapping_v1(&st.data_dir, &caller, &mref, &record, true) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    // W1.2 / MEF-GAP-008 — this write was discarded. The mapping record gates the whole
    // downstream ladder (materializing-run lease checks, execution bindings, lease plans);
    // a 201 whose persist failed hands back an id every later step will refuse.
    if persist_record(
        &st.data_dir,
        RECORD_DIR,
        record
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        &record,
    )
    .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "connector_mapping_persistence_failed",
                "message": "the mapping was NOT declared — nothing was committed (the created receipt is void)" }),
            ),
        );
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "connector_mapping": record,
            "replayed": commit.replayed,
            "owner_ref": caller.owner_ref,
            "admitted_head": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
        })),
    )
}

/// PATCH — re-validate the merged mapping; a malformed patch changes nothing (no revision bump).
pub(crate) async fn handle_connector_mapping_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(patch): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // THE OWNER OF A SUCCESSOR IS THE ADMITTED PREDECESSOR'S OWNER, resolved from the chain rather
    // than taken from the request, so a patch cannot move a mapping between owners.
    // Identity only — the OWNER is not asked of the caller here, because a successor's owner is the
    // admitted predecessor's owner. Demanding it in the body would let a patch propose one.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::mutation_event_foundation::scope_refusal_reply(error),
    };
    let mapping_ref = format!("{MAPPING_V1_STORED_SCHEME}://{id}");
    let admitted = match resolve_stored_connector_mapping_v1(
        &st.data_dir,
        &identity,
        None,
        &mapping_ref,
        None,
    ) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let caller =
        match mapping_v1_write_caller(&st.data_dir, &headers, &patch, Some(&admitted.owner_ref)) {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    let Some(existing) = load_mapping(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "connector mapping not found" })),
        );
    };
    // Build the merged body from existing declared inputs overlaid with the patch, then re-validate.
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "data_source_id",
        "ontology_ref",
        "object_type_id",
        "source_dataset",
        "key_mapping",
        "title_mapping",
        "field_mappings",
    ] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    let projected = match validate_and_project(&st.data_dir, &merged) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })),
            )
        }
    };
    let mut record = existing;
    if let Some(v) = patch.get("name") {
        record["name"] = v.clone();
    }
    if let Some(v) = patch.get("description") {
        record["description"] = v.clone();
    }
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    let now = iso_now();
    record["updated_at"] = json!(now.clone());
    let mref = record
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt = mapping_receipt(
        &st.data_dir,
        &mref,
        "patched",
        "ConnectorMapping re-declared",
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut hist = record
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": "patched", "at": now, "summary": "ConnectorMapping re-declared", "receipt_ref": receipt_ref.clone() }));
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
    // W1.2 / MEF-GAP-008 — this write was discarded. A revision bump and re-declared health
    // returned to the caller while the ladder keeps validating against the OLD mapping is a
    // quiet divergence between belief and admitted truth.
    let commit = match admit_mapping_v1(&st.data_dir, &caller, &mapping_ref, &record, false) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if persist_record(&st.data_dir, RECORD_DIR, &id, &record).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "connector_mapping_persistence_failed",
                "message": "the re-declared mapping did NOT commit — the prior revision stands" }),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "connector_mapping": record,
            "replayed": commit.replayed,
            "owner_ref": caller.owner_ref,
            "admitted_head": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
        })),
    )
}

/// DELETE /v1/hypervisor/odk/connector-mappings/:id.
pub(crate) async fn handle_connector_mapping_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod connector_mapping_tests {
    use super::*;

    #[test]
    fn value_compat_is_conservative() {
        assert!(value_compatible("string", "enum"));
        assert!(value_compatible("integer", "double"));
        assert!(value_compatible("date", "timestamp"));
        assert!(!value_compatible("string", "double"));
        assert!(!value_compatible("double", "integer"));
        assert!(!value_compatible("boolean", "string"));
    }

    #[test]
    fn resolve_base_prefers_declared_value_type_then_literal() {
        let ont = json!({ "canonical_object_model": { "value_types": [{ "id": "money", "base": "double" }] } });
        assert_eq!(resolve_base(&ont, "money"), "double");
        assert_eq!(resolve_base(&ont, "string"), "string");
    }

    #[test]
    fn source_field_types_and_missing_contracts_are_named() {
        assert!(SOURCE_FIELD_TYPES.contains(&"timestamp"));
        assert_eq!(
            MISSING_CONTRACTS,
            &[
                "PolicyBoundDataView",
                "TransformationRun",
                "OntologyProjection"
            ]
        );
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"password"));
    }
}
