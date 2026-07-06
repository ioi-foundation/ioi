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
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const MAPPING_SCHEMA: &str = "ioi.hypervisor.odk.connector-mapping.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.connector-mapping-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.connector-mappings-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-connector-mappings";
const RECEIPT_DIR: &str = "odk-connector-mapping-receipts";

/// Source-field shapes an author may declare (the source's shape, not a live read).
const SOURCE_FIELD_TYPES: &[&str] = &["string", "integer", "double", "boolean", "timestamp", "date", "json"];
/// The authority contracts still missing downstream of this rung — named honestly on every record.
const MISSING_CONTRACTS: &[&str] = &["PolicyBoundDataView", "TransformationRun", "OntologyProjection"];
/// Body keys that would be a plaintext secret — rejected outright (a mapping never carries a credential).
const PLAINTEXT_SECRET_KEYS: &[&str] = &["secret", "password", "api_key", "apikey", "token", "credential"];

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
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
    read_record_dir(data_dir, crate::odk_routes::KIND_ONT).into_iter().find(|r| {
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
    obj.get("properties")?.as_array()?.iter().find(|p| p.get("id").and_then(|x| x.as_str()) == Some(pid))
}
/// A declared value_type resolves to its base; a base literal resolves to itself. (#11 already
/// validated the ontology, so every property value_type resolves.)
fn resolve_base(ont: &Value, value_type: &str) -> String {
    if let Some(vts) = ont.pointer("/canonical_object_model/value_types").and_then(|v| v.as_array()) {
        if let Some(vt) = vts.iter().find(|v| v.get("id").and_then(|x| x.as_str()) == Some(value_type)) {
            return vt.get("base").and_then(|x| x.as_str()).unwrap_or("string").to_string();
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
        if PLAINTEXT_SECRET_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr(
                "connector_mapping_plaintext_secret_rejected",
                "A connector mapping never carries credentials — the data source holds its own posture.".into(),
            ));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr("connector_mapping_name_required", "A connector mapping requires a name.".into()));
    }
    // Known data source (#10).
    let data_source_id = opt_s(body, "data_source_id").unwrap_or_default();
    let ds = load_data_source(data_dir, &data_source_id).ok_or_else(|| {
        verr("connector_mapping_data_source_unknown", format!("data_source_id '{data_source_id}' does not resolve to a declared data source"))
    })?;
    // Known ontology + object type (#11).
    let ontology_ref = opt_s(body, "ontology_ref").or_else(|| opt_s(body, "ontology_id")).unwrap_or_default();
    let ont = load_ontology(data_dir, &ontology_ref).ok_or_else(|| {
        verr("connector_mapping_ontology_unknown", format!("ontology '{ontology_ref}' does not resolve to a declared ontology"))
    })?;
    let object_type_id = opt_s(body, "object_type_id").unwrap_or_default();
    let obj = find_object_type(&ont, &object_type_id).ok_or_else(|| {
        verr("connector_mapping_object_type_unknown", format!("object_type '{object_type_id}' is not declared in the ontology"))
    })?;
    let title_property = obj.get("title_property").and_then(|v| v.as_str()).unwrap_or("");

    // Required key + title mappings.
    let key = body.get("key_mapping").filter(|v| v.is_object());
    let key = key.ok_or_else(|| verr("connector_mapping_key_mapping_required", "A primary key_mapping (source_field → property_id) is required.".into()))?;
    let title = body.get("title_mapping").filter(|v| v.is_object());
    let title = title.ok_or_else(|| verr("connector_mapping_title_mapping_required", "A title_mapping (source_field → property_id) is required.".into()))?;
    // The object must declare a title_property, and the title mapping must target it.
    if title_property.is_empty() {
        return Err(verr("connector_mapping_title_mapping_required", "The object type declares no title_property — declare one in the ontology before mapping.".into()));
    }
    if s(title, "property_id", "") != title_property {
        return Err(verr("connector_mapping_title_mapping_required", format!("title_mapping must target the object's title_property '{title_property}'")));
    }

    // Normalize all bindings and validate each against the typed object.
    let field_mappings: Vec<Value> = body.get("field_mappings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut bindings = vec![binding_tuple("key", key), binding_tuple("title", title)];
    bindings.extend(field_mappings.iter().map(|f| binding_tuple("field", f)));

    let mut targets: Vec<String> = Vec::new();
    for (role, source_field, property_id, source_type, source_cardinality) in &bindings {
        if source_field.trim().is_empty() {
            return Err(verr("connector_mapping_source_field_required", format!("{role} mapping requires a source_field")));
        }
        let prop = find_property(obj, property_id).ok_or_else(|| {
            verr("connector_mapping_property_unknown", format!("{role} mapping property '{property_id}' is not a property of object_type '{object_type_id}'"))
        })?;
        if !SOURCE_FIELD_TYPES.contains(&source_type.as_str()) {
            return Err(verr("connector_mapping_source_type_invalid", format!("source_type '{source_type}' is not a known source field type")));
        }
        // Scalar properties only — a repeated source field cannot bind to a single-valued property.
        if source_cardinality == "many" {
            return Err(verr("connector_mapping_cardinality_mismatch", format!("{role} mapping is multi-valued but property '{property_id}' is single-valued (declare a link_type or repeated property first)")));
        }
        if source_cardinality != "one" {
            return Err(verr("connector_mapping_cardinality_invalid", format!("source_cardinality '{source_cardinality}' must be 'one' or 'many'")));
        }
        let base = resolve_base(&ont, prop.get("value_type").and_then(|v| v.as_str()).unwrap_or(""));
        if !value_compatible(source_type, &base) {
            return Err(verr("connector_mapping_value_type_incompatible", format!("source_type '{source_type}' is not compatible with property '{property_id}' (base value type '{base}')")));
        }
        if targets.iter().any(|t| t == property_id) {
            return Err(verr("connector_mapping_duplicate_target", format!("property '{property_id}' is targeted by more than one mapping")));
        }
        targets.push(property_id.clone());
    }

    // Readiness — honest: `ready` only when every REQUIRED property is mapped; else `incomplete`
    // (still a valid declared draft). Coverage is reported either way.
    let all_props: Vec<&Value> = obj.get("properties").and_then(|v| v.as_array()).map(|a| a.iter().collect()).unwrap_or_default();
    let total = all_props.len();
    let required_gaps: Vec<String> = all_props
        .iter()
        .filter(|p| p.get("required").and_then(|v| v.as_bool()).unwrap_or(false))
        .filter(|p| {
            let pid = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
            !targets.iter().any(|t| t == pid)
        })
        .map(|p| p.get("name").and_then(|v| v.as_str()).or_else(|| p.get("id").and_then(|v| v.as_str())).unwrap_or("").to_string())
        .collect();
    let status = if required_gaps.is_empty() { "ready" } else { "incomplete" };

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
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
fn load_mapping(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR).into_iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn sorted_mappings(data_dir: &str) -> Vec<Value> {
    let mut items = read_record_dir(data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    items
}
fn bad(err: VErr) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })))
}

/// GET /v1/hypervisor/odk/connector-mappings — declared mappings (newest first).
pub(crate) async fn handle_connector_mappings_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "schema_version": MAPPING_SCHEMA, "connector_mappings": sorted_mappings(&st.data_dir), "runtimeTruthSource": "daemon-runtime" }))
}

/// GET /v1/hypervisor/odk/connector-mappings/overview — vocab + counts + honest missing-contract ladder.
pub(crate) async fn handle_connector_mappings_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by_status = |status: &str| items.iter().filter(|r| r.pointer("/health/status").and_then(|v| v.as_str()) == Some(status)).count();
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
pub(crate) async fn handle_connector_mapping_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    match load_mapping(&st.data_dir, &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "ok": true, "connector_mapping": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector mapping not found" }))),
    }
}

/// GET /v1/hypervisor/odk/connector-mappings/:id/health — readiness projection.
pub(crate) async fn handle_connector_mapping_health(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    match load_mapping(&st.data_dir, &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "ok": true, "connector_mapping_ref": r.get("ref"), "revision": r.get("revision"), "health": r.get("health") }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector mapping not found" }))),
    }
}

/// GET /v1/hypervisor/odk/connector-mappings/:id/history — embedded history + persisted receipts.
pub(crate) async fn handle_connector_mapping_history(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(r) = load_mapping(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector mapping not found" })));
    };
    let mref = r.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| x.get("connector_mapping_ref").and_then(|v| v.as_str()) == Some(mref.as_str()));
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (StatusCode::OK, Json(json!({ "ok": true, "connector_mapping_ref": mref, "revision": r.get("revision"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts })))
}

/// POST /v1/hypervisor/odk/connector-mappings — declare a mapping (fail-closed, receipted, INERT).
pub(crate) async fn handle_connector_mapping_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
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
    let _ = persist_record(&st.data_dir, RECORD_DIR, record.get("id").and_then(|v| v.as_str()).unwrap_or_default(), &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "connector_mapping": record })))
}

/// PATCH — re-validate the merged mapping; a malformed patch changes nothing (no revision bump).
pub(crate) async fn handle_connector_mapping_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(patch): Json<Value>) -> Json<Value> {
    let Some(existing) = load_mapping(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "connector mapping not found" }));
    };
    // Build the merged body from existing declared inputs overlaid with the patch, then re-validate.
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in ["name", "description", "data_source_id", "ontology_ref", "object_type_id", "source_dataset", "key_mapping", "title_mapping", "field_mappings"] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    let projected = match validate_and_project(&st.data_dir, &merged) {
        Ok(p) => p,
        Err(e) => return Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })),
    };
    let mut record = existing;
    if let Some(v) = patch.get("name") { record["name"] = v.clone(); }
    if let Some(v) = patch.get("description") { record["description"] = v.clone(); }
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    let now = iso_now();
    record["updated_at"] = json!(now.clone());
    let mref = record.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let receipt = mapping_receipt(&st.data_dir, &mref, "patched", "ConnectorMapping re-declared");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut hist = record.get("history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": "patched", "at": now, "summary": "ConnectorMapping re-declared", "receipt_ref": receipt_ref.clone() }));
    let len = hist.len();
    if len > 20 { hist = hist[len - 20..].to_vec(); }
    record["history"] = json!(hist);
    let mut refs = record.get("receipt_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    refs.push(receipt_ref);
    record["receipt_refs"] = json!(refs);
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "connector_mapping": record }))
}

/// DELETE /v1/hypervisor/odk/connector-mappings/:id.
pub(crate) async fn handle_connector_mapping_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
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
        assert_eq!(MISSING_CONTRACTS, &["PolicyBoundDataView", "TransformationRun", "OntologyProjection"]);
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"password"));
    }
}
