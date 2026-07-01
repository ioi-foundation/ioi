//! ODK (Ontology Development Kit) object plane — FOUNDATION cut (daemon-first, draft-only).
//!
//! ODK is the dependency hub the rest of the domain stack stands on: Domain Apps, Data Recipes,
//! ontology-bound evals, generated app surfaces, worker/package skeletons, and marketplace-ready
//! ontology packs. This cut builds the PLANE, not a surface: four real durable DRAFT objects plus a
//! read projection (`overview`) bound to EXISTING real substrate (environment classes, Foundry
//! specs/run-plans, Work Ledger, connectors).
//!
//! Deliberately inert:
//!   * no transformation runs, no generated React/UI artifacts;
//!   * no Domain App creation (DomainApp is NOT a durable object yet — a descriptor may declare
//!     `composition_pattern: domain_app`, but real Domain Apps come in a later plane/surface);
//!   * no training/eval execution; no authority crossing.
//! Every object is `status: "draft"`. No serve `/__ioi/odk` surface in this cut — plane first.
//!
//! Objects (record kinds): DomainOntology · DataRecipe · OntologyDevelopmentKitManifest ·
//! OntologySurfaceDescriptor. Cross-references use canonical prefixed URIs minted at create:
//!   ontology://<id> · recipe://<id> · odk://<id> · surface-descriptor://<id>
//! A reference that uses one of those four ODK schemes is LOCAL and must resolve to a stored record;
//! any other ref form is treated as an external named ref (allowed, not pretended to resolve).

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const KIND_ONT: &str = "odk-domain-ontologies";
const KIND_RECIPE: &str = "odk-data-recipes";
const KIND_MANIFEST: &str = "odk-manifests";
const KIND_SD: &str = "odk-surface-descriptors";

/// The canonical composition patterns a surface descriptor may declare.
const COMPOSITION_PATTERNS: &[&str] = &[
    "list_detail",
    "object_view",
    "object_editor",
    "graph",
    "wizard",
    "review_inbox",
    "monitoring_console",
    "dashboard",
    "data_recipe_builder",
    "connector_mapping_editor",
    "domain_app",
];
/// Output kinds a DataRecipe may target (named — nothing is transformed here).
const RECIPE_OUTPUT_KINDS: &[&str] = &[
    "ontology_objects",
    "projection",
    "evaluation_dataset",
    "training_material",
];

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}
fn bad(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}
fn str_refs(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Map an ODK ref scheme to its local record kind (None = not an ODK-local scheme).
fn local_kind_for_scheme(scheme: &str) -> Option<&'static str> {
    match scheme {
        "ontology" => Some(KIND_ONT),
        "recipe" => Some(KIND_RECIPE),
        "odk" => Some(KIND_MANIFEST),
        "surface-descriptor" => Some(KIND_SD),
        _ => None,
    }
}
/// Split "<scheme>://<rest>" into its parts (both non-empty), else None.
fn split_ref(r: &str) -> Option<(&str, &str)> {
    r.split_once("://")
        .filter(|(s, rest)| !s.is_empty() && !rest.is_empty())
}

/// Resolve any ref that uses an ODK-local scheme; external refs pass through unchecked.
fn resolve_local_ref(data_dir: &str, r: &str) -> Result<(), (String, String)> {
    if let Some((scheme, rest)) = split_ref(r) {
        if let Some(kind) = local_kind_for_scheme(scheme) {
            if load(data_dir, kind, rest).is_none() {
                return Err((
                    "odk_ref_unresolved".into(),
                    format!("local ODK ref '{r}' does not resolve to a {scheme} record"),
                ));
            }
        }
    }
    Ok(())
}
/// A required, typed ref: must carry `expected_scheme://` AND resolve locally.
fn require_local_ref(
    data_dir: &str,
    r: &str,
    expected_scheme: &str,
    label: &str,
) -> Result<(), (String, String)> {
    match split_ref(r) {
        Some((scheme, rest)) if scheme == expected_scheme => {
            let kind = local_kind_for_scheme(scheme).unwrap_or("");
            if load(data_dir, kind, rest).is_none() {
                Err((
                    "odk_ref_unresolved".into(),
                    format!("{label} '{r}' does not resolve to a local {expected_scheme} record"),
                ))
            } else {
                Ok(())
            }
        }
        _ => Err((
            "odk_ref_prefix_invalid".into(),
            format!("{label} must be a '{expected_scheme}://' ref"),
        )),
    }
}
/// A list of required typed refs (optionally non-empty), each validated as local + resolving.
fn require_local_ref_list(
    data_dir: &str,
    refs: &[String],
    scheme: &str,
    label: &str,
    require_nonempty: bool,
) -> Result<(), (String, String)> {
    if require_nonempty && refs.is_empty() {
        return Err((
            "odk_refs_required".into(),
            format!("at least one {label} ({scheme}://…) is required"),
        ));
    }
    for r in refs {
        require_local_ref(data_dir, r, scheme, label)?;
    }
    Ok(())
}
/// Arbitrary named refs: only ODK-local-scheme ones are resolved; everything else is allowed.
fn check_named_refs(data_dir: &str, refs: &[String]) -> Result<(), (String, String)> {
    for r in refs {
        resolve_local_ref(data_dir, r)?;
    }
    Ok(())
}

/// GET the daemon's own loopback API for substrate counts (no duplicated catalogs).
async fn get_json(base: &str, path: &str) -> Value {
    match reqwest::Client::new()
        .get(format!("{base}{path}"))
        .send()
        .await
    {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    }
}
fn as_list(v: &Value) -> Vec<Value> {
    if let Some(a) = v.as_array() {
        return a.clone();
    }
    if let Some(obj) = v.as_object() {
        for val in obj.values() {
            if let Some(a) = val.as_array() {
                return a.clone();
            }
        }
    }
    Vec::new()
}
fn sort_by_updated(list: &mut [Value]) {
    list.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
}
fn json_get(data_dir: &str, kind: &str, key: &str, id: &str) -> Json<Value> {
    match load(data_dir, kind, id) {
        Some(r) => Json(json!({ "ok": true, key: r })),
        None => Json(json!({ "ok": false, "reason": format!("{key} not found") })),
    }
}
fn json_del(data_dir: &str, kind: &str, id: &str) -> Json<Value> {
    let removed = remove_record(data_dir, kind, id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

// =================================== OVERVIEW ====================================================

/// GET /v1/hypervisor/odk/overview — real substrate counts + ODK object counts + the canonical
/// composition patterns + recents. Read projection; nothing is transformed, generated, or promoted.
pub(crate) async fn handle_odk_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let base = st.base_url.clone();
    let env_classes = as_list(&get_json(&base, "/v1/hypervisor/environment-classes").await);
    let foundry_specs = as_list(&get_json(&base, "/v1/hypervisor/foundry/specs").await);
    let foundry_plans = as_list(&get_json(&base, "/v1/hypervisor/foundry/run-plans").await);
    let ledger = as_list(&get_json(&base, "/v1/hypervisor/work-ledger").await);
    let connectors = as_list(&get_json(&base, "/v1/hypervisor/connectors").await);

    let ontologies = read_record_dir(&st.data_dir, KIND_ONT);
    let recipes = read_record_dir(&st.data_dir, KIND_RECIPE);
    let manifests = read_record_dir(&st.data_dir, KIND_MANIFEST);
    let descriptors = read_record_dir(&st.data_dir, KIND_SD);

    let slim = |r: &Value, name_key: &str| {
        json!({
            "id": r.get("id").cloned().unwrap_or(Value::Null),
            "ref": r.get("ref").cloned().unwrap_or(Value::Null),
            "name": r.get(name_key).cloned().or_else(|| r.get("name").cloned()).unwrap_or(Value::Null),
            "status": r.get("status").cloned().unwrap_or(Value::Null),
            "updated_at": r.get("updated_at").cloned().unwrap_or(Value::Null),
        })
    };
    let recents = |list: &[Value], name_key: &str| {
        let mut s: Vec<Value> = list.iter().map(|r| slim(r, name_key)).collect();
        sort_by_updated(&mut s);
        s.truncate(6);
        s
    };

    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.odk.overview.v1",
        "status_note": "ODK foundation: ontologies, recipes, manifests and surface descriptors are drafts. No transformation runs, no generated UI artifacts, no Domain App creation, no training/eval execution in this plane.",
        "substrate": {
            "environment_classes": env_classes.len(),
            "foundry_specs": foundry_specs.len(),
            "foundry_run_plans": foundry_plans.len(),
            "work_ledger_entries": ledger.len(),
            "connectors": connectors.len()
        },
        "odk": {
            "domain_ontologies": ontologies.len(),
            "data_recipes": recipes.len(),
            "manifests": manifests.len(),
            "surface_descriptors": descriptors.len()
        },
        "composition_patterns": COMPOSITION_PATTERNS,
        "recipe_output_kinds": RECIPE_OUTPUT_KINDS,
        "recent_ontologies": recents(&ontologies, "domain"),
        "recent_data_recipes": recents(&recipes, "name"),
        "recent_manifests": recents(&manifests, "name"),
        "recent_surface_descriptors": recents(&descriptors, "name")
    }))
}

// ================================ DOMAIN ONTOLOGY ================================================

pub(crate) async fn handle_odk_ontology_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_ONT);
    if let Some(domain) = q.get("domain").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|o| o.get("domain").and_then(|v| v.as_str()) == Some(domain));
    }
    sort_by_updated(&mut items);
    Json(json!({ "ok": true, "ontologies": items }))
}

/// POST /v1/hypervisor/odk/domain-ontologies — create a DomainOntology DRAFT. The semantic root:
/// it embeds the CanonicalObjectModel (objects/actions/events/states/roles), kept lightweight.
pub(crate) async fn handle_odk_ontology_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let domain = body
        .get("domain")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(domain) = domain else {
        return bad(
            "odk_domain_required",
            "A DomainOntology must declare a non-empty domain.",
        );
    };
    let id = format!("ont_{:x}", nanos());
    let now = iso_now();
    let com = body.get("canonical_object_model").cloned().unwrap_or_else(|| {
        json!({ "objects": [], "actions": [], "events": [], "states": [], "roles": [] })
    });
    let record = json!({
        "schema_version": "ioi.hypervisor.odk.domain-ontology.v1",
        "object": "ioi.hypervisor.odk.domain_ontology",
        "id": id,
        "ref": format!("ontology://{id}"),
        "domain": domain,
        "version": body.get("version").and_then(|v| v.as_str()).unwrap_or("0.1.0"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        // CanonicalObjectModel embedded (draft, lightweight — not a separate lifecycle table yet).
        "canonical_object_model": com,
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_ONT, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "ontology": record })))
}

pub(crate) async fn handle_odk_ontology_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_get(&st.data_dir, KIND_ONT, "ontology", &id)
}

pub(crate) async fn handle_odk_ontology_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut o) = load(&st.data_dir, KIND_ONT, &id) else {
        return Json(json!({ "ok": false, "reason": "ontology not found" }));
    };
    for key in ["domain", "version", "description", "canonical_object_model"] {
        if let Some(v) = body.get(key) {
            o[key] = v.clone();
        }
    }
    o["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_ONT, &id, &o);
    Json(json!({ "ok": true, "ontology": o }))
}

pub(crate) async fn handle_odk_ontology_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_ONT, &id)
}

// =================================== DATA RECIPE ================================================

pub(crate) async fn handle_odk_recipe_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_RECIPE);
    if let Some(oref) = q
        .get("ontology_ref")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|r| r.get("ontology_ref").and_then(|v| v.as_str()) == Some(oref));
    }
    sort_by_updated(&mut items);
    Json(json!({ "ok": true, "data_recipes": items }))
}

/// POST /v1/hypervisor/odk/data-recipes — create a DataRecipe DRAFT bound to an ontology. A
/// repeatable transformation recipe (source/connector/trace/artifact refs → ontology-bound objects/
/// projections/eval datasets/training material). Nothing is transformed here.
pub(crate) async fn handle_odk_recipe_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ontology_ref = body
        .get("ontology_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if let Err((c, m)) = require_local_ref(&st.data_dir, ontology_ref, "ontology", "ontology_ref") {
        return bad(&c, &m);
    }
    let output_kind = body
        .get("output_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("ontology_objects")
        .to_string();
    if !RECIPE_OUTPUT_KINDS.contains(&output_kind.as_str()) {
        return bad(
            "odk_output_kind_invalid",
            &format!("output_kind must be one of {RECIPE_OUTPUT_KINDS:?}"),
        );
    }
    // Named refs (sources, projections, eval datasets, worker plans, workflow schemas): resolved
    // only when they use an ODK-local scheme.
    for key in [
        "source_refs",
        "projection_refs",
        "evaluation_dataset_refs",
        "worker_plan_refs",
        "workflow_schema_refs",
    ] {
        if let Err((c, m)) = check_named_refs(&st.data_dir, &str_refs(&body, key)) {
            return bad(&c, &m);
        }
    }
    let id = format!("recipe_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.odk.data-recipe.v1",
        "object": "ioi.hypervisor.odk.data_recipe",
        "id": id,
        "ref": format!("recipe://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("data-recipe"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        "ontology_ref": ontology_ref,
        "output_kind": output_kind,
        "source_refs": str_refs(&body, "source_refs"),
        // ConnectorMapping + PolicyBoundDataView embedded (opaque arrays — not separate tables yet).
        "connector_mappings": body.get("connector_mappings").cloned().unwrap_or_else(|| json!([])),
        "policy_bound_views": body.get("policy_bound_views").cloned().unwrap_or_else(|| json!([])),
        // Named refs only (OntologyProjection / EvaluationDataset / OntologyToWorkerPlan / WorkflowSchema).
        "projection_refs": str_refs(&body, "projection_refs"),
        "evaluation_dataset_refs": str_refs(&body, "evaluation_dataset_refs"),
        "worker_plan_refs": str_refs(&body, "worker_plan_refs"),
        "workflow_schema_refs": str_refs(&body, "workflow_schema_refs"),
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_RECIPE, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "data_recipe": record })),
    )
}

pub(crate) async fn handle_odk_recipe_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_get(&st.data_dir, KIND_RECIPE, "data_recipe", &id)
}

pub(crate) async fn handle_odk_recipe_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut r) = load(&st.data_dir, KIND_RECIPE, &id) else {
        return Json(json!({ "ok": false, "reason": "data_recipe not found" }));
    };
    if let Some(ok) = body.get("output_kind").and_then(|v| v.as_str()) {
        if !RECIPE_OUTPUT_KINDS.contains(&ok) {
            return Json(json!({ "ok": false, "error": { "code": "odk_output_kind_invalid", "message": format!("output_kind must be one of {RECIPE_OUTPUT_KINDS:?}") } }));
        }
    }
    if let Some(oref) = body.get("ontology_ref").and_then(|v| v.as_str()) {
        if let Err((c, m)) = require_local_ref(&st.data_dir, oref, "ontology", "ontology_ref") {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    for key in [
        "source_refs",
        "projection_refs",
        "evaluation_dataset_refs",
        "worker_plan_refs",
        "workflow_schema_refs",
    ] {
        if body.get(key).is_some() {
            if let Err((c, m)) = check_named_refs(&st.data_dir, &str_refs(&body, key)) {
                return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
            }
        }
    }
    for key in [
        "name",
        "description",
        "ontology_ref",
        "output_kind",
        "source_refs",
        "connector_mappings",
        "policy_bound_views",
        "projection_refs",
        "evaluation_dataset_refs",
        "worker_plan_refs",
        "workflow_schema_refs",
    ] {
        if let Some(v) = body.get(key) {
            r[key] = v.clone();
        }
    }
    r["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_RECIPE, &id, &r);
    Json(json!({ "ok": true, "data_recipe": r }))
}

pub(crate) async fn handle_odk_recipe_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_RECIPE, &id)
}

// ============================ ODK MANIFEST (builder/conformance) ================================

pub(crate) async fn handle_odk_manifest_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_MANIFEST);
    sort_by_updated(&mut items);
    Json(json!({ "ok": true, "manifests": items }))
}

/// POST /v1/hypervisor/odk/manifests — create an OntologyDevelopmentKitManifest DRAFT bundling
/// ontology refs (required, ≥1) + recipe + surface-descriptor refs + named contract refs.
pub(crate) async fn handle_odk_manifest_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ontology_refs = str_refs(&body, "ontology_refs");
    if let Err((c, m)) =
        require_local_ref_list(&st.data_dir, &ontology_refs, "ontology", "ontology_ref", true)
    {
        return bad(&c, &m);
    }
    let recipe_refs = str_refs(&body, "recipe_refs");
    if let Err((c, m)) =
        require_local_ref_list(&st.data_dir, &recipe_refs, "recipe", "recipe_ref", false)
    {
        return bad(&c, &m);
    }
    let sd_refs = str_refs(&body, "surface_descriptor_refs");
    if let Err((c, m)) = require_local_ref_list(
        &st.data_dir,
        &sd_refs,
        "surface-descriptor",
        "surface_descriptor_ref",
        false,
    ) {
        return bad(&c, &m);
    }
    for key in ["eval_refs", "worker_plan_refs", "mcp_operator_contracts"] {
        if let Err((c, m)) = check_named_refs(&st.data_dir, &str_refs(&body, key)) {
            return bad(&c, &m);
        }
    }
    let id = format!("odk_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.odk.manifest.v1",
        "object": "ioi.hypervisor.odk.manifest",
        "id": id,
        "ref": format!("odk://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("odk-manifest"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        "ontology_refs": ontology_refs,
        "recipe_refs": recipe_refs,
        "surface_descriptor_refs": sd_refs,
        "connector_mappings": body.get("connector_mappings").cloned().unwrap_or_else(|| json!([])),
        "policy_bound_views": body.get("policy_bound_views").cloned().unwrap_or_else(|| json!([])),
        // Named refs only (eval suites, worker plans, MCP/operator contracts).
        "eval_refs": str_refs(&body, "eval_refs"),
        "worker_plan_refs": str_refs(&body, "worker_plan_refs"),
        "mcp_operator_contracts": str_refs(&body, "mcp_operator_contracts"),
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_MANIFEST, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "manifest": record })))
}

pub(crate) async fn handle_odk_manifest_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_get(&st.data_dir, KIND_MANIFEST, "manifest", &id)
}

pub(crate) async fn handle_odk_manifest_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut man) = load(&st.data_dir, KIND_MANIFEST, &id) else {
        return Json(json!({ "ok": false, "reason": "manifest not found" }));
    };
    // Re-validate any ref set that is being changed (ontology_refs stays required-nonempty).
    if body.get("ontology_refs").is_some() {
        if let Err((c, m)) = require_local_ref_list(
            &st.data_dir,
            &str_refs(&body, "ontology_refs"),
            "ontology",
            "ontology_ref",
            true,
        ) {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    if body.get("recipe_refs").is_some() {
        if let Err((c, m)) = require_local_ref_list(
            &st.data_dir,
            &str_refs(&body, "recipe_refs"),
            "recipe",
            "recipe_ref",
            false,
        ) {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    if body.get("surface_descriptor_refs").is_some() {
        if let Err((c, m)) = require_local_ref_list(
            &st.data_dir,
            &str_refs(&body, "surface_descriptor_refs"),
            "surface-descriptor",
            "surface_descriptor_ref",
            false,
        ) {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    for key in ["eval_refs", "worker_plan_refs", "mcp_operator_contracts"] {
        if body.get(key).is_some() {
            if let Err((c, m)) = check_named_refs(&st.data_dir, &str_refs(&body, key)) {
                return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
            }
        }
    }
    for key in [
        "name",
        "description",
        "ontology_refs",
        "recipe_refs",
        "surface_descriptor_refs",
        "connector_mappings",
        "policy_bound_views",
        "eval_refs",
        "worker_plan_refs",
        "mcp_operator_contracts",
    ] {
        if let Some(v) = body.get(key) {
            man[key] = v.clone();
        }
    }
    man["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_MANIFEST, &id, &man);
    Json(json!({ "ok": true, "manifest": man }))
}

pub(crate) async fn handle_odk_manifest_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_MANIFEST, &id)
}

// ============================ ONTOLOGY SURFACE DESCRIPTOR =======================================

pub(crate) async fn handle_odk_descriptor_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_SD);
    if let Some(cp) = q
        .get("composition_pattern")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|d| d.get("composition_pattern").and_then(|v| v.as_str()) == Some(cp));
    }
    if let Some(oref) = q
        .get("ontology_ref")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|d| d.get("ontology_ref").and_then(|v| v.as_str()) == Some(oref));
    }
    sort_by_updated(&mut items);
    Json(json!({ "ok": true, "surface_descriptors": items }))
}

/// POST /v1/hypervisor/odk/surface-descriptors — create an OntologySurfaceDescriptor DRAFT bound to
/// an ontology (+ optional recipe refs). `composition_pattern` must be one of the canonical patterns.
/// `domain_app` is allowed as a pattern, but NO DomainApp object is created here.
pub(crate) async fn handle_odk_descriptor_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let pattern = body
        .get("composition_pattern")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !COMPOSITION_PATTERNS.contains(&pattern) {
        return bad(
            "odk_composition_pattern_invalid",
            &format!("composition_pattern must be one of {COMPOSITION_PATTERNS:?}"),
        );
    }
    let ontology_ref = body
        .get("ontology_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if let Err((c, m)) = require_local_ref(&st.data_dir, ontology_ref, "ontology", "ontology_ref") {
        return bad(&c, &m);
    }
    let recipe_refs = str_refs(&body, "recipe_refs");
    if let Err((c, m)) =
        require_local_ref_list(&st.data_dir, &recipe_refs, "recipe", "recipe_ref", false)
    {
        return bad(&c, &m);
    }
    let id = format!("sd_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.odk.surface-descriptor.v1",
        "object": "ioi.hypervisor.odk.surface_descriptor",
        "id": id,
        "ref": format!("surface-descriptor://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("surface-descriptor"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        "composition_pattern": pattern,
        "ontology_ref": ontology_ref,
        "recipe_refs": recipe_refs,
        // Opaque view configuration (no generated UI artifact is produced).
        "view_config": body.get("view_config").cloned().unwrap_or_else(|| json!({})),
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_SD, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "surface_descriptor": record })),
    )
}

pub(crate) async fn handle_odk_descriptor_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_get(&st.data_dir, KIND_SD, "surface_descriptor", &id)
}

pub(crate) async fn handle_odk_descriptor_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut d) = load(&st.data_dir, KIND_SD, &id) else {
        return Json(json!({ "ok": false, "reason": "surface_descriptor not found" }));
    };
    if let Some(cp) = body.get("composition_pattern").and_then(|v| v.as_str()) {
        if !COMPOSITION_PATTERNS.contains(&cp) {
            return Json(json!({ "ok": false, "error": { "code": "odk_composition_pattern_invalid", "message": format!("composition_pattern must be one of {COMPOSITION_PATTERNS:?}") } }));
        }
    }
    if let Some(oref) = body.get("ontology_ref").and_then(|v| v.as_str()) {
        if let Err((c, m)) = require_local_ref(&st.data_dir, oref, "ontology", "ontology_ref") {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    if body.get("recipe_refs").is_some() {
        if let Err((c, m)) = require_local_ref_list(
            &st.data_dir,
            &str_refs(&body, "recipe_refs"),
            "recipe",
            "recipe_ref",
            false,
        ) {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    for key in [
        "name",
        "description",
        "composition_pattern",
        "ontology_ref",
        "recipe_refs",
        "view_config",
    ] {
        if let Some(v) = body.get(key) {
            d[key] = v.clone();
        }
    }
    d["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_SD, &id, &d);
    Json(json!({ "ok": true, "surface_descriptor": d }))
}

pub(crate) async fn handle_odk_descriptor_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_SD, &id)
}

#[cfg(test)]
mod odk_tests {
    use super::*;

    #[test]
    fn split_ref_parses_scheme_and_rest() {
        assert_eq!(split_ref("ontology://ont_1"), Some(("ontology", "ont_1")));
        assert_eq!(split_ref("surface-descriptor://sd_9"), Some(("surface-descriptor", "sd_9")));
        assert_eq!(split_ref("no-scheme"), None);
        assert_eq!(split_ref("ontology://"), None);
        assert_eq!(split_ref("://x"), None);
    }

    #[test]
    fn local_scheme_mapping_is_exhaustive_and_rejects_unknown() {
        assert_eq!(local_kind_for_scheme("ontology"), Some(KIND_ONT));
        assert_eq!(local_kind_for_scheme("recipe"), Some(KIND_RECIPE));
        assert_eq!(local_kind_for_scheme("odk"), Some(KIND_MANIFEST));
        assert_eq!(local_kind_for_scheme("surface-descriptor"), Some(KIND_SD));
        assert_eq!(local_kind_for_scheme("http"), None);
        assert_eq!(local_kind_for_scheme("dataset"), None);
    }

    #[test]
    fn composition_pattern_enum_validates() {
        assert!(COMPOSITION_PATTERNS.contains(&"list_detail"));
        assert!(COMPOSITION_PATTERNS.contains(&"domain_app"));
        assert!(!COMPOSITION_PATTERNS.contains(&"laser"));
    }

    #[test]
    fn require_local_ref_rejects_wrong_prefix() {
        // wrong scheme -> prefix invalid (no data access needed for the prefix branch)
        let err = require_local_ref("/nonexistent", "recipe://r1", "ontology", "ontology_ref").unwrap_err();
        assert_eq!(err.0, "odk_ref_prefix_invalid");
        // right scheme but unresolvable (empty data dir) -> unresolved
        let err = require_local_ref("/nonexistent", "ontology://ont_x", "ontology", "ontology_ref").unwrap_err();
        assert_eq!(err.0, "odk_ref_unresolved");
    }

    #[test]
    fn check_named_refs_ignores_external_but_flags_local_missing() {
        // external named refs (non-ODK scheme or no scheme) are always allowed
        assert!(check_named_refs("/nonexistent", &["s3://bucket/x".into(), "trace-123".into()]).is_ok());
        // an ODK-local scheme that cannot resolve in an empty dir is flagged
        let err = check_named_refs("/nonexistent", &["ontology://ont_missing".into()]).unwrap_err();
        assert_eq!(err.0, "odk_ref_unresolved");
    }

    #[test]
    fn recipe_output_kinds_enum() {
        assert!(RECIPE_OUTPUT_KINDS.contains(&"ontology_objects"));
        assert!(RECIPE_OUTPUT_KINDS.contains(&"training_material"));
        assert!(!RECIPE_OUTPUT_KINDS.contains(&"magic"));
    }
}
