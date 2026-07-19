//! OntologyProjection — the FOURTH and final inert ODK authority-crossing rung. A projection
//! declares the EXPLORER/SEARCH/READ SHAPE for ontology-bound data: "if authorized object data
//! existed, what would this surface be allowed to render, search, filter, relate, and act on?"
//! It binds one ontology object model to the declared semantic-data plane — a ready ConnectorMapping
//! (#13), a ready read-authorizing PolicyBoundDataView (#14), and optionally a dry_run_ready
//! TransformationRun plan (#15) — and declares visible properties, title/key display, facets, sorts,
//! relationship/action/export affordances, and layout.
//!
//! Still INERT: no live connector reads, no credential use, no extraction, no materialization —
//! `object_instances` stays 0 and `materialized` stays false until a FUTURE materializing run
//! executes under credential authority. Affordances are gated hard:
//!   * an action affordance can be ENABLED only with a matching ontology action type AND a policy
//!     view that authorizes the write-ish operation (`transform`);
//!   * a relationship affordance can be DECLARED but never ENABLED in v1 — no object plane resolves
//!     anywhere, so "browse related rows" would be a false promise;
//!   * an export affordance requires export authorization + named receipt obligations on the view.
//!
//! Lifecycle (declarative): `draft` | `ready` | `blocked` | `retired`. Every create/patch/recheck/
//! retire — and every refusal — emits a receipt with bounded history.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const PROJ_SCHEMA: &str = "ioi.hypervisor.odk.ontology-projection.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.ontology-projection-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.ontology-projections-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-ontology-projections";
const RECEIPT_DIR: &str = "odk-ontology-projection-receipts";

/// Declarative lifecycle. There is no "live"/"serving" state — a projection never serves rows here.
const LIFECYCLE_STATES: &[&str] = &["draft", "ready", "blocked", "retired"];
/// Result layouts a projection may declare for the (future) explorer surface.
const LAYOUTS: &[&str] = &["table", "cards", "split"];
/// The authority still missing before any row can exist. Not a contract rung — the live crossing.
const MISSING_AUTHORITY: &str =
    "materializing run under credential authority (live connector read) — a future cut";
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];
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

fn find_by_id(data_dir: &str, dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn load_ontology(data_dir: &str, oref: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::odk_routes::KIND_ONT)
        .into_iter()
        .find(|r| {
            r.get("ref").and_then(|v| v.as_str()) == Some(oref)
                || r.get("id").and_then(|v| v.as_str()) == Some(oref)
        })
}
fn health_status(rec: &Value) -> String {
    rec.pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("incomplete")
        .to_string()
}
/// Every property the mapping actually maps (key + title + fields).
fn mapped_property_ids(mapping: &Value) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for k in ["key_mapping", "title_mapping"] {
        if let Some(pid) = mapping
            .get(k)
            .and_then(|m| m.get("property_id"))
            .and_then(|v| v.as_str())
        {
            ids.push(pid.to_string());
        }
    }
    if let Some(fs) = mapping.get("field_mappings").and_then(|v| v.as_array()) {
        for f in fs {
            if let Some(pid) = f.get("property_id").and_then(|v| v.as_str()) {
                ids.push(pid.to_string());
            }
        }
    }
    ids
}
/// Link types in the ontology that touch this object type (either end).
fn links_touching<'a>(ont: &'a Value, object_type_id: &str) -> Vec<&'a Value> {
    ont.pointer("/canonical_object_model/link_types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|l| {
                    l.get("from").and_then(|v| v.as_str()) == Some(object_type_id)
                        || l.get("to").and_then(|v| v.as_str()) == Some(object_type_id)
                })
                .collect()
        })
        .unwrap_or_default()
}
fn action_types<'a>(ont: &'a Value) -> Vec<&'a Value> {
    ont.pointer("/canonical_object_model/action_types")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// The validated projection shape, resolved from the current daemon state.
struct ProjInputs {
    mapping: Value,
    view: Value,
    run_ref: Value,
    title_field: String,
    key_field: String,
    visible_properties: Vec<String>,
    facet_properties: Vec<String>,
    sort_fields: Vec<String>,
    layout: String,
    action_affordances: Vec<Value>,
    relationship_affordances: Vec<Value>,
    export_affordance_enabled: bool,
}

/// Validate a projection body fail-closed against CURRENT declared truth. No source contact, no
/// materialization — this only checks the declared explorer shape against the ladder beneath it.
fn validate_inputs(data_dir: &str, body: &Value) -> Result<ProjInputs, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr(
                "projection_plaintext_secret_rejected",
                "A projection never carries credentials.".into(),
            ));
        }
        if RAW_QUERY_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr("projection_raw_query_rejected", "A projection never carries a raw source query — its shape comes from the declared ladder.".into()));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "projection_name_required",
            "An ontology projection requires a name.".into(),
        ));
    }
    // Ready mapping.
    let mapping_id = opt_s(body, "connector_mapping_id").unwrap_or_default();
    let mapping = find_by_id(
        data_dir,
        crate::connector_mapping_routes::RECORD_DIR,
        &mapping_id,
    )
    .ok_or_else(|| {
        verr(
            "projection_mapping_unknown",
            format!("connector_mapping_id '{mapping_id}' does not resolve to a declared mapping"),
        )
    })?;
    if health_status(&mapping) != "ready" {
        return Err(verr(
            "projection_mapping_not_ready",
            format!("mapping '{mapping_id}' is not ready"),
        ));
    }
    // Ready view, same mapping, read-authorizing.
    let view_id = opt_s(body, "policy_view_id").unwrap_or_default();
    let view = find_by_id(
        data_dir,
        crate::policy_bound_data_view_routes::RECORD_DIR,
        &view_id,
    )
    .ok_or_else(|| {
        verr(
            "projection_policy_view_unknown",
            format!(
                "policy_view_id '{view_id}' does not resolve to a declared policy-bound data view"
            ),
        )
    })?;
    if health_status(&view) != "ready" {
        return Err(verr(
            "projection_policy_view_not_ready",
            format!("policy view '{view_id}' is not ready"),
        ));
    }
    if view.get("connector_mapping_id").and_then(|v| v.as_str()) != Some(mapping_id.as_str()) {
        return Err(verr(
            "projection_policy_view_mapping_mismatch",
            "the policy view does not bind the referenced mapping".into(),
        ));
    }
    let ops = str_list(&view, "allowed_operations");
    if !ops.iter().any(|o| o == "read") {
        return Err(verr("projection_read_not_authorized", "the policy view does not authorize 'read' — a projection is a read/search shape and needs a read-authorizing gate".into()));
    }
    // Optional run: must exist, be dry_run_ready, and bind the same mapping.
    let mut run_ref = Value::Null;
    if let Some(run_id) = opt_s(body, "transformation_run_id") {
        let run = find_by_id(
            data_dir,
            crate::transformation_run_routes::RECORD_DIR,
            &run_id,
        )
        .ok_or_else(|| {
            verr(
                "projection_run_unknown",
                format!("transformation_run_id '{run_id}' does not resolve to a declared run"),
            )
        })?;
        if s(&run, "status", "") != "dry_run_ready" {
            return Err(verr("projection_run_not_ready", format!("transformation run '{run_id}' is not dry_run_ready — a projection may only cite a validated plan")));
        }
        if run.get("connector_mapping_id").and_then(|v| v.as_str()) != Some(mapping_id.as_str()) {
            return Err(verr(
                "projection_run_mismatch",
                "the transformation run does not bind the referenced mapping".into(),
            ));
        }
        run_ref = run.get("ref").cloned().unwrap_or(Value::Null);
    }
    // Ontology + object type still declared (the semantic model is live truth, not a cached copy).
    let ontology_ref = s(&mapping, "ontology_ref", "");
    let object_type_id = s(&mapping, "object_type_id", "");
    let ont = load_ontology(data_dir, &ontology_ref).ok_or_else(|| {
        verr(
            "projection_object_type_unknown",
            format!("ontology '{ontology_ref}' no longer resolves"),
        )
    })?;
    let obj_exists = ont
        .pointer("/canonical_object_model/object_types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .any(|o| o.get("id").and_then(|x| x.as_str()) == Some(object_type_id.as_str()))
        })
        .unwrap_or(false);
    if !obj_exists {
        return Err(verr(
            "projection_object_type_unknown",
            format!("object_type '{object_type_id}' is no longer declared in the ontology"),
        ));
    }

    // Display fields: everything rendered must be mapped AND policy-scoped (scope ⊆ mapped already).
    let scope = str_list(&view, "property_scope");
    let mapped = mapped_property_ids(&mapping);
    let in_scope = |pid: &str| scope.iter().any(|x| x == pid) && mapped.iter().any(|x| x == pid);
    let key_default = mapping
        .pointer("/key_mapping/property_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title_default = mapping
        .pointer("/title_mapping/property_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title_field = opt_s(body, "title_field").unwrap_or(title_default);
    let key_field = opt_s(body, "key_field").unwrap_or(key_default);
    if title_field.is_empty() || key_field.is_empty() {
        return Err(verr(
            "projection_title_key_required",
            "a projection requires title and key display fields".into(),
        ));
    }
    let visible_properties = if body.get("visible_properties").is_some() {
        str_list(body, "visible_properties")
    } else {
        scope.clone()
    };
    let facet_properties = str_list(body, "facet_properties");
    let sort_fields = str_list(body, "sort_fields");
    for (label, list) in [
        ("title_field", &vec![title_field.clone()]),
        ("key_field", &vec![key_field.clone()]),
        ("visible_properties", &visible_properties),
        ("facet_properties", &facet_properties),
        ("sort_fields", &sort_fields),
    ] {
        for pid in list {
            if !in_scope(pid) {
                return Err(verr("projection_property_unscoped", format!("{label} '{pid}' is not mapped + policy-scoped — a projection cannot render unauthorized data")));
            }
        }
    }
    // Layout enum.
    let layout = opt_s(body, "layout").unwrap_or_else(|| "table".into());
    if !LAYOUTS.contains(&layout.as_str()) {
        return Err(verr(
            "projection_layout_invalid",
            format!("layout '{layout}' must be one of {LAYOUTS:?}"),
        ));
    }
    // Action affordances: known action type applying to this object (or a function); ENABLED needs
    // the view to authorize the write-ish operation.
    let acts = action_types(&ont);
    let action_affordances: Vec<Value> = body
        .get("action_affordances")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for a in &action_affordances {
        let aid = s(a, "action_type_id", "");
        let found = acts
            .iter()
            .find(|x| x.get("id").and_then(|v| v.as_str()) == Some(aid.as_str()));
        let Some(found) = found else {
            return Err(verr(
                "projection_action_affordance_unknown",
                format!("action affordance '{aid}' is not a declared action type"),
            ));
        };
        let applies_to = found
            .get("applies_to")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let kind = found.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "function" && applies_to != object_type_id {
            return Err(verr(
                "projection_action_affordance_unknown",
                format!("action '{aid}' does not apply to object_type '{object_type_id}'"),
            ));
        }
        if a.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
            && !ops.iter().any(|o| o == "transform")
        {
            return Err(verr("projection_action_affordance_not_authorized", format!("action affordance '{aid}' cannot be enabled — the policy view does not authorize 'transform' (writeback)")));
        }
    }
    // Relationship affordances: known link touching this object; NEVER enabled in v1 — no object
    // plane resolves anywhere, so "browse related rows" would be a false promise.
    let links = links_touching(&ont, &object_type_id);
    let relationship_affordances: Vec<Value> = body
        .get("relationship_affordances")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for l in &relationship_affordances {
        let lid = s(l, "link_type_id", "");
        if !links
            .iter()
            .any(|x| x.get("id").and_then(|v| v.as_str()) == Some(lid.as_str()))
        {
            return Err(verr("projection_link_affordance_unknown", format!("relationship affordance '{lid}' is not a declared link type touching '{object_type_id}'")));
        }
        if l.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(verr("projection_link_affordance_unresolved", format!("relationship affordance '{lid}' cannot be enabled — no object plane resolves rows anywhere (materialization is a future cut); declare it, don't promise it")));
        }
    }
    // Export affordance: needs export authorization + named receipt obligation on the view.
    let export_affordance_enabled = body
        .get("export_affordance_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if export_affordance_enabled {
        let obligations = str_list(&view, "receipt_obligations");
        if !ops.iter().any(|o| o == "export")
            || !obligations
                .iter()
                .any(|o| o.to_lowercase().contains("export"))
        {
            return Err(verr("projection_export_affordance_not_authorized", "an export affordance requires the policy view to authorize 'export' with a named receipt obligation".into()));
        }
    }
    Ok(ProjInputs {
        mapping,
        view,
        run_ref,
        title_field,
        key_field,
        visible_properties,
        facet_properties,
        sort_fields,
        layout,
        action_affordances,
        relationship_affordances,
        export_affordance_enabled,
    })
}

/// Honest readiness — ready only with ≥1 visible property (everything else was enforced at write).
fn project_health(inputs: &ProjInputs) -> Value {
    let mut gaps: Vec<String> = Vec::new();
    if inputs.visible_properties.is_empty() {
        gaps.push(
            "no visible properties declared — an explorer shape with nothing to render".into(),
        );
    }
    let status = if gaps.is_empty() {
        "ready"
    } else {
        "incomplete"
    };
    json!({
        "status": status,
        "gaps": gaps,
        "visible_properties": inputs.visible_properties.len(),
        "object_instances": 0,
        "materialized": false,
        "missing_authority": MISSING_AUTHORITY,
        "note": "projection declared, no materialized objects — object_instances stays 0 until a future materializing run executes under credential authority"
    })
}

fn proj_receipt(data_dir: &str, proj_ref: &str, op: &str, outcome: &str, summary: &str) -> Value {
    let id = format!("opr_{:x}", nanos());
    let receipt_ref = format!("agentgres://ontology-projection-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "ontology_projection_ref": proj_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
    });
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
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
/// Merge validated inputs onto a record (shared by create + patch + recheck).
fn apply_inputs(record: &mut Value, inputs: &ProjInputs) {
    let mut health = project_health(inputs);
    // Materialized state survives re-validation: a registered, receipted object set is truth until
    // its set is removed — a shape edit never silently zeroes real instances.
    if record
        .pointer("/health/materialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        health["object_instances"] = record
            .pointer("/health/object_instances")
            .cloned()
            .unwrap_or(json!(0));
        health["materialized"] = json!(true);
    }
    let status = if health["status"] == "ready" {
        "ready"
    } else {
        "draft"
    };
    record["connector_mapping_id"] = inputs.mapping.get("id").cloned().unwrap_or(Value::Null);
    record["connector_mapping_ref"] = inputs.mapping.get("ref").cloned().unwrap_or(Value::Null);
    record["policy_view_id"] = inputs.view.get("id").cloned().unwrap_or(Value::Null);
    record["policy_view_ref"] = inputs.view.get("ref").cloned().unwrap_or(Value::Null);
    record["transformation_run_ref"] = inputs.run_ref.clone();
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
    record["title_field"] = json!(inputs.title_field);
    record["key_field"] = json!(inputs.key_field);
    record["visible_properties"] = json!(inputs.visible_properties);
    record["facet_properties"] = json!(inputs.facet_properties);
    record["sort_fields"] = json!(inputs.sort_fields);
    record["layout"] = json!(inputs.layout);
    record["action_affordances"] = json!(inputs.action_affordances);
    record["relationship_affordances"] = json!(inputs.relationship_affordances);
    record["export_affordance_enabled"] = json!(inputs.export_affordance_enabled);
    record["health"] = health;
    record["status"] = json!(status);
    record["blocked_reasons"] = json!([]);
}
fn bad(data_dir: &str, op: &str, err: VErr) -> (StatusCode, Json<Value>) {
    let _ = proj_receipt(
        data_dir,
        "ontology-projection://unadmitted",
        op,
        &err.0,
        &err.1,
    );
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })),
    )
}
/// The body a stored record re-validates as (its own declared inputs).
fn body_of(record: &Value) -> Value {
    let mut body = json!({});
    let bo = body.as_object_mut().unwrap();
    for k in [
        "name",
        "connector_mapping_id",
        "policy_view_id",
        "title_field",
        "key_field",
        "visible_properties",
        "facet_properties",
        "sort_fields",
        "layout",
        "action_affordances",
        "relationship_affordances",
        "export_affordance_enabled",
    ] {
        if let Some(v) = record.get(k) {
            bo.insert(k.to_string(), v.clone());
        }
    }
    // The optional run is stored as a ref — recover its id for re-validation.
    if let Some(rref) = record
        .get("transformation_run_ref")
        .and_then(|v| v.as_str())
    {
        if let Some(id) = rref.strip_prefix("transformation-run://") {
            bo.insert("transformation_run_id".into(), json!(id));
        }
    }
    body
}

/// GET /v1/hypervisor/odk/ontology-projections.
pub(crate) async fn handle_projections_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(
        json!({ "ok": true, "schema_version": PROJ_SCHEMA, "ontology_projections": items, "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/ontology-projections/overview.
pub(crate) async fn handle_projections_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
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
        "ontology_projections": items.len(),
        "lifecycle": { "draft": by("draft"), "ready": by("ready"), "blocked": by("blocked"), "retired": by("retired") },
        "lifecycle_states": LIFECYCLE_STATES,
        "layouts": LAYOUTS,
        "missing_authority": MISSING_AUTHORITY,
        "governance_gaps": [
            "PROJECTION declared, no materialized objects — this is the read/search SHAPE, never rows",
            "object_instances stays 0 everywhere until a future materializing run executes under credential authority",
            "relationship affordances are declare-only in v1 — no object plane resolves rows anywhere, so enabling one would be a false promise",
            "every create, patch, recheck, retire — and every refusal — is receipted"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/ontology-projections/:id.
pub(crate) async fn handle_projection_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match find_by_id(&st.data_dir, RECORD_DIR, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "ontology_projection": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "ontology projection not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/ontology-projections/:id/history.
pub(crate) async fn handle_projection_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = find_by_id(&st.data_dir, RECORD_DIR, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "ontology projection not found" })),
        );
    };
    let pref = s(&r, "ref", "");
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| {
        x.get("ontology_projection_ref").and_then(|v| v.as_str()) == Some(pref.as_str())
    });
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "ontology_projection_ref": pref, "revision": r.get("revision"), "status": r.get("status"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// POST /v1/hypervisor/odk/ontology-projections — declare a projection (fail-closed, receipted).
pub(crate) async fn handle_projection_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let inputs = match validate_inputs(&st.data_dir, &body) {
        Ok(i) => i,
        Err(e) => return bad(&st.data_dir, "create_rejected", e),
    };
    let id = format!("oproj_{:x}", nanos());
    let now = iso_now();
    let pref = format!("ontology-projection://{id}");
    let receipt = proj_receipt(
        &st.data_dir,
        &pref,
        "created",
        "ok",
        "OntologyProjection declared",
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut record = json!({
        "schema_version": PROJ_SCHEMA,
        "object": "ioi.hypervisor.odk.ontology_projection",
        "id": id,
        "ref": pref,
        "name": s(&body, "name", "ontology-projection"),
        "description": s(&body, "description", ""),
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "OntologyProjection declared", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    apply_inputs(&mut record, &inputs);
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "ontology_projection": record })),
    )
}

/// PATCH — re-validate the merged shape; a malformed patch is a receipted refusal, no state change.
pub(crate) async fn handle_projection_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(patch): Json<Value>,
) -> Json<Value> {
    let Some(existing) = find_by_id(&st.data_dir, RECORD_DIR, &id) else {
        return Json(json!({ "ok": false, "reason": "ontology projection not found" }));
    };
    if s(&existing, "status", "") == "retired" {
        return Json(
            json!({ "ok": false, "error": { "code": "projection_retired_immutable", "message": "a retired projection is immutable" } }),
        );
    }
    let mut merged = body_of(&existing);
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "connector_mapping_id",
        "policy_view_id",
        "transformation_run_id",
        "title_field",
        "key_field",
        "visible_properties",
        "facet_properties",
        "sort_fields",
        "layout",
        "action_affordances",
        "relationship_affordances",
        "export_affordance_enabled",
    ] {
        if let Some(v) = patch.get(k) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    let inputs = match validate_inputs(&st.data_dir, &merged) {
        Ok(i) => i,
        Err(e) => {
            let _ = proj_receipt(
                &st.data_dir,
                &s(&existing, "ref", ""),
                "patch_rejected",
                &e.0,
                &e.1,
            );
            return Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } }));
        }
    };
    let mut record = existing;
    if let Some(v) = patch.get("name") {
        record["name"] = v.clone();
    }
    if let Some(v) = patch.get("description") {
        record["description"] = v.clone();
    }
    apply_inputs(&mut record, &inputs);
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    record["updated_at"] = json!(iso_now());
    let receipt = proj_receipt(
        &st.data_dir,
        &s(&record, "ref", ""),
        "patched",
        "ok",
        "OntologyProjection re-declared",
    );
    push_history(
        &mut record,
        "patched",
        "OntologyProjection re-declared",
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "ontology_projection": record }))
}

/// POST /:id/recheck — re-validate against CURRENT declared truth; drift → blocked, named.
pub(crate) async fn handle_projection_recheck(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = find_by_id(&st.data_dir, RECORD_DIR, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "ontology projection not found" })),
        );
    };
    if s(&record, "status", "") == "retired" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "projection_retired_immutable", "message": "a retired projection is immutable" } }),
            ),
        );
    }
    let pref = s(&record, "ref", "");
    match validate_inputs(&st.data_dir, &body_of(&record)) {
        Err((code, msg)) => {
            let receipt = proj_receipt(&st.data_dir, &pref, "recheck_blocked", &code, &msg);
            let summary = format!("blocked: {code}");
            record["status"] = json!("blocked");
            record["blocked_reasons"] = json!([{ "code": code, "message": msg }]);
            record["updated_at"] = json!(iso_now());
            push_history(
                &mut record,
                "recheck_blocked",
                &summary,
                receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
            );
            let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "ontology_projection": record })),
            )
        }
        Ok(inputs) => {
            let receipt = proj_receipt(
                &st.data_dir,
                &pref,
                "recheck",
                "ok",
                "projection re-validated against the current ladder",
            );
            apply_inputs(&mut record, &inputs);
            record["updated_at"] = json!(iso_now());
            push_history(
                &mut record,
                "recheck",
                "projection re-validated against the current ladder",
                receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
            );
            let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "ontology_projection": record })),
            )
        }
    }
}

/// POST /:id/retire — declarative end-of-life, receipted; retired is immutable.
pub(crate) async fn handle_projection_retire(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = find_by_id(&st.data_dir, RECORD_DIR, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "ontology projection not found" })),
        );
    };
    if s(&record, "status", "") == "retired" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "projection_retired_immutable", "message": "the projection is already retired" } }),
            ),
        );
    }
    let receipt = proj_receipt(
        &st.data_dir,
        &s(&record, "ref", ""),
        "retired",
        "ok",
        "OntologyProjection retired",
    );
    record["status"] = json!("retired");
    record["updated_at"] = json!(iso_now());
    push_history(
        &mut record,
        "retired",
        "OntologyProjection retired",
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "ontology_projection": record })),
    )
}

/// DELETE — receipted removal.
pub(crate) async fn handle_projection_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let pref = find_by_id(&st.data_dir, RECORD_DIR, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("ontology-projection://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        let _ = proj_receipt(
            &st.data_dir,
            &pref,
            "deleted",
            "ok",
            "OntologyProjection removed",
        );
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod ontology_projection_tests {
    use super::*;

    #[test]
    fn lifecycle_and_layouts_are_declarative() {
        assert_eq!(LIFECYCLE_STATES, &["draft", "ready", "blocked", "retired"]);
        assert_eq!(LAYOUTS, &["table", "cards", "split"]);
        assert!(MISSING_AUTHORITY.contains("credential authority"));
    }

    #[test]
    fn links_touching_matches_either_end() {
        let ont = json!({ "canonical_object_model": { "link_types": [
            { "id": "held_by", "from": "loan", "to": "borrower" },
            { "id": "unrelated", "from": "a", "to": "b" }
        ] } });
        assert_eq!(links_touching(&ont, "loan").len(), 1);
        assert_eq!(links_touching(&ont, "borrower").len(), 1);
        assert_eq!(links_touching(&ont, "z").len(), 0);
    }

    #[test]
    fn body_of_recovers_run_id_from_ref() {
        let rec = json!({ "name": "p", "transformation_run_ref": "transformation-run://trun_9" });
        let b = body_of(&rec);
        assert_eq!(
            b.get("transformation_run_id").and_then(|v| v.as_str()),
            Some("trun_9")
        );
    }

    #[test]
    fn raw_query_and_secret_keys_are_named() {
        assert!(RAW_QUERY_KEYS.contains(&"sql"));
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"token"));
    }
}
