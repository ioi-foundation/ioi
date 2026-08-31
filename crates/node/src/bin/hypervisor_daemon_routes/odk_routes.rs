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

use axum::http::HeaderMap;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

pub(crate) const KIND_ONT: &str = "odk-domain-ontologies";
/// THE ONE SPELLING of the health note. It was written into records at create time and read back
/// verbatim, so a capability landing could not reach an ontology already on disk.
const OBJECT_DATA_NOTE: &str = "this health report is derived from the MODEL ALONE — the function that builds it receives no data directory and counts nothing, so the `object_instances` beside it is a structural zero and NOT a materialization count. Ask the object-instance SEARCH plane for that: it is bound as of next-legs XIII (POST /v1/hypervisor/odk/object-instance-search), walks the materialized-set store, and answers a typed corpus-absent when nothing is materialized";
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

// ---- Ontology-manager contract vocabulary. The DomainOntology carries a typed CanonicalObjectModel
// (value types, object types with typed properties, relation/link types, action/function
// declarations). These enums are the schema-workbench semantics validated fail-closed at write time.
/// Base value types a declared value_type may specialize (an `enum` base must carry `enum_values`).
const BASE_VALUE_TYPES: &[&str] = &[
    "string",
    "integer",
    "double",
    "boolean",
    "timestamp",
    "date",
    "enum",
    "markdown",
    "geo_point",
    "attachment",
];
/// Relation cardinalities a link_type may declare.
const LINK_CARDINALITIES: &[&str] = &["one_to_one", "one_to_many", "many_to_many"];
/// Action/function kinds an action_type may declare (non-`function` kinds require an object target).
const ACTION_KINDS: &[&str] = &[
    "create_object",
    "modify_object",
    "delete_object",
    "function",
];
/// Receipts for ontology create/patch land here (history is also embedded on the record).
pub(crate) const KIND_ONT_RECEIPT: &str = "odk-ontology-receipts";

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
pub(crate) fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
pub(crate) fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
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
fn persist_required(
    data_dir: &str,
    kind: &str,
    id: &str,
    record: &Value,
    code: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": {
                    "code": code,
                    "message": "the durable record could not be committed"
                }
            })),
        )
    })
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
/// Count ontologies whose readiness health matches `status` (records without health read as `empty`).
fn ont_health_count(ontologies: &[Value], status: &str) -> usize {
    ontologies
        .iter()
        .filter(|o| {
            o.get("health")
                .and_then(|h| h.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("empty")
                == status
        })
        .count()
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
        // Ontology-manager contract projections (over ODK — not a second plane).
        "object_model_vocab": {
            "base_value_types": BASE_VALUE_TYPES,
            "link_cardinalities": LINK_CARDINALITIES,
            "action_kinds": ACTION_KINDS
        },
        "ontology_health": {
            "ready": ont_health_count(&ontologies, "ready"),
            "incomplete": ont_health_count(&ontologies, "incomplete"),
            "empty": ont_health_count(&ontologies, "empty")
        },
        "recent_ontologies": recents(&ontologies, "domain"),
        "recent_data_recipes": recents(&recipes, "name"),
        "recent_manifests": recents(&manifests, "name"),
        "recent_surface_descriptors": recents(&descriptors, "name")
    }))
}

// ============================ ONTOLOGY-MANAGER CONTRACT =========================================
//
// The DomainOntology is the semantic spine the rest of the estate leans on, so its typed model is
// validated fail-closed. A CanonicalObjectModel is the four typed collections:
//   value_types   [{ id, name, base, enum_values? }]
//   object_types  [{ id, name, title_property?, properties:[{ id, name, value_type, required? }] }]
//   link_types    [{ id, name, from, to, cardinality }]     (from/to resolve to object_type ids)
//   action_types  [{ id, name, kind, applies_to? }]         (applies_to resolves to an object_type)
// A `value_type` on a property resolves to a base type OR a declared value_type id. Type ids match
// `^[a-z][a-z0-9_]*$`. Legacy string-array keys (objects/actions/events/states/roles) are TOLERATED
// for back-compat but are not a typed model — they count as `empty` health, never validated as types.
// The plane owns NO object instances: `object_instances` is always 0 and explorer rows require a
// real ontology-bound object plane (not built here).

type VErr = (String, String);
fn verr(code: &str, msg: String) -> VErr {
    (code.to_string(), msg)
}
/// Type ids are lowercase-first, then `[a-z0-9_]` — a stable machine identifier (no crate regex dep).
fn valid_type_id(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}
/// A COM collection: absent/null → empty; present must be an array (else a fail-closed error).
fn com_arr<'a>(com: &'a Value, key: &str) -> Result<Vec<&'a Value>, VErr> {
    match com.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => Ok(a.iter().collect()),
        Some(_) => Err(verr(
            "ontology_collection_invalid",
            format!("`{key}` must be an array of typed entries"),
        )),
    }
}
fn entry_id(e: &Value) -> &str {
    e.get("id").and_then(|v| v.as_str()).unwrap_or("")
}
fn entry_name(e: &Value) -> String {
    e.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}
/// Hardened collection bound (#63): a COM collection or per-entry list larger than this is
/// rejected typed, never truncated silently.
const COM_COLLECTION_MAX: usize = 300;
const COM_TEXT_MAX: usize = 2000;
const COM_ID_MAX: usize = 64;
const COM_NAME_MAX: usize = 200;

/// Validate ids (shape + uniqueness) and names (present + unique, case-insensitive) for a collection.
fn check_ids_and_names(entries: &[&Value], label: &str) -> Result<Vec<String>, VErr> {
    if entries.len() > COM_COLLECTION_MAX {
        return Err(verr(
            "ontology_collection_bounds",
            format!("{label} collection exceeds the bound ({COM_COLLECTION_MAX} entries)"),
        ));
    }
    let mut ids: Vec<String> = Vec::new();
    let mut names_lc: Vec<String> = Vec::new();
    for e in entries {
        if !e.is_object() {
            return Err(verr(
                "ontology_entry_invalid",
                format!("every {label} entry must be a typed object"),
            ));
        }
        if let Some(n) = e.get("name") {
            if !n.is_null() && !n.is_string() {
                return Err(verr(
                    "ontology_field_type_invalid",
                    format!("{label} `name` must be a string when present"),
                ));
            }
        }
        if let Some(d) = e.get("description") {
            if !d.is_null() && !d.is_string() {
                return Err(verr(
                    "ontology_field_type_invalid",
                    format!("{label} `description` must be a string when present"),
                ));
            }
            if d.as_str()
                .map(|s| s.chars().count() > COM_TEXT_MAX)
                .unwrap_or(false)
            {
                return Err(verr(
                    "odk_field_too_long",
                    format!(
                        "{label} `description` exceeds the bounded length ({COM_TEXT_MAX} chars)"
                    ),
                ));
            }
        }
        let id = entry_id(e);
        if id.len() > COM_ID_MAX {
            return Err(verr(
                "odk_field_too_long",
                format!("{label} id exceeds the bounded length ({COM_ID_MAX} chars)"),
            ));
        }
        if entry_name(e).chars().count() > COM_NAME_MAX {
            return Err(verr(
                "odk_field_too_long",
                format!("{label} name exceeds the bounded length ({COM_NAME_MAX} chars)"),
            ));
        }
        if !valid_type_id(id) {
            return Err(verr(
                "ontology_type_id_invalid",
                format!("{label} id '{id}' is invalid — must match ^[a-z][a-z0-9_]*$"),
            ));
        }
        if ids.iter().any(|x| x == id) {
            return Err(verr(
                "ontology_duplicate_id",
                format!("duplicate {label} id '{id}'"),
            ));
        }
        let name = entry_name(e);
        if name.trim().is_empty() {
            return Err(verr(
                "ontology_name_required",
                format!("{label} '{id}' requires a name"),
            ));
        }
        let nl = name.to_lowercase();
        if names_lc.iter().any(|x| *x == nl) {
            return Err(verr(
                "ontology_duplicate_name",
                format!("duplicate {label} name '{name}'"),
            ));
        }
        ids.push(id.to_string());
        names_lc.push(nl);
    }
    Ok(ids)
}

/// Validate a CanonicalObjectModel fail-closed and project its readiness health. Returns the health
/// object on success (draft/incomplete are allowed — status is honest), or a typed error to reject.
fn validate_object_model(com: &Value) -> Result<Value, VErr> {
    // A serve-form JSON textarea that failed to parse marks itself so the author sees a clean error.
    if com.get("__json_parse_error").is_some() {
        return Err(verr(
            "ontology_object_model_json_invalid",
            "canonical_object_model must be valid JSON".into(),
        ));
    }
    let value_types = com_arr(com, "value_types")?;
    let object_types = com_arr(com, "object_types")?;
    let link_types = com_arr(com, "link_types")?;
    let action_types = com_arr(com, "action_types")?;

    let value_ids = check_ids_and_names(&value_types, "value_type")?;
    let object_ids = check_ids_and_names(&object_types, "object_type")?;
    let _link_ids = check_ids_and_names(&link_types, "link_type")?;
    let _action_ids = check_ids_and_names(&action_types, "action_type")?;

    // Value types: base must be known; an `enum` base must enumerate its values.
    for vt in &value_types {
        let base = vt.get("base").and_then(|v| v.as_str()).unwrap_or("string");
        if !BASE_VALUE_TYPES.contains(&base) {
            return Err(verr(
                "ontology_value_base_invalid",
                format!(
                    "value_type '{}' base '{base}' is not a known base type",
                    entry_id(vt)
                ),
            ));
        }
        if let Some(ev) = vt.get("enum_values") {
            if !ev.is_null() {
                let Some(arr) = ev.as_array() else {
                    return Err(verr(
                        "ontology_field_type_invalid",
                        format!(
                            "value_type '{}' enum_values must be an array of strings",
                            entry_id(vt)
                        ),
                    ));
                };
                if arr.len() > COM_COLLECTION_MAX {
                    return Err(verr(
                        "ontology_collection_bounds",
                        format!(
                            "value_type '{}' enum_values exceeds the bound ({COM_COLLECTION_MAX})",
                            entry_id(vt)
                        ),
                    ));
                }
                if arr.iter().any(|x| {
                    !x.is_string()
                        || x.as_str()
                            .map(|s| s.is_empty() || s.chars().count() > COM_NAME_MAX)
                            .unwrap_or(true)
                }) {
                    return Err(verr(
                        "ontology_field_type_invalid",
                        format!(
                            "value_type '{}' enum_values must be non-empty bounded strings",
                            entry_id(vt)
                        ),
                    ));
                }
            }
        }
        if base == "enum"
            && !vt
                .get("enum_values")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        {
            return Err(verr(
                "ontology_enum_values_required",
                format!(
                    "enum value_type '{}' must declare non-empty enum_values",
                    entry_id(vt)
                ),
            ));
        }
    }
    let resolves_value =
        |vt: &str| BASE_VALUE_TYPES.contains(&vt) || value_ids.iter().any(|x| x == vt);

    // Object types: typed properties resolve to a value type; title_property resolves to a property.
    let mut gaps: Vec<String> = Vec::new();
    for obj in &object_types {
        let oid = entry_id(obj);
        let oname = entry_name(obj);
        let disp = if oname.is_empty() {
            oid.to_string()
        } else {
            oname
        };
        let props = com_arr(obj, "properties")?;
        let prop_ids = check_ids_and_names(&props, &format!("property (object '{oid}')"))?;
        for p in &props {
            if let Some(r) = p.get("required") {
                if !r.is_null() && !r.is_boolean() {
                    return Err(verr("ontology_field_type_invalid", format!("property '{}' on object '{oid}' `required` must be a boolean when present", entry_id(p))));
                }
            }
            let pvt = p.get("value_type").and_then(|v| v.as_str()).unwrap_or("");
            if pvt.is_empty() {
                return Err(verr(
                    "ontology_property_value_type_required",
                    format!(
                        "property '{}' on object '{oid}' requires a value_type",
                        entry_id(p)
                    ),
                ));
            }
            if !resolves_value(pvt) {
                return Err(verr(
                    "ontology_ref_unresolved",
                    format!(
                        "property '{}' on object '{oid}' references unknown value_type '{pvt}'",
                        entry_id(p)
                    ),
                ));
            }
        }
        if let Some(tpv) = obj.get("title_property") {
            if !tpv.is_null() && !tpv.is_string() {
                return Err(verr(
                    "ontology_field_type_invalid",
                    format!("object '{oid}' `title_property` must be a string when present"),
                ));
            }
        }
        match obj
            .get("title_property")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            Some(tp) if !prop_ids.iter().any(|x| x == tp) => {
                return Err(verr(
                    "ontology_ref_unresolved",
                    format!("object '{oid}' title_property '{tp}' is not one of its properties"),
                ));
            }
            Some(_) => {}
            None => gaps.push(format!("object '{disp}' has no title_property")),
        }
        if prop_ids.is_empty() {
            gaps.push(format!("object '{disp}' has no properties"));
        }
    }

    // Link types: cardinality is enumerated; both ends resolve to declared object types.
    for lk in &link_types {
        let lid = entry_id(lk);
        let card = lk.get("cardinality").and_then(|v| v.as_str()).unwrap_or("");
        if !LINK_CARDINALITIES.contains(&card) {
            return Err(verr(
                "ontology_cardinality_invalid",
                format!(
                    "link_type '{lid}' cardinality '{card}' must be one of {LINK_CARDINALITIES:?}"
                ),
            ));
        }
        for end in ["from", "to"] {
            let t = lk.get(end).and_then(|v| v.as_str()).unwrap_or("");
            if !object_ids.iter().any(|x| x == t) {
                return Err(verr(
                    "ontology_ref_unresolved",
                    format!(
                        "link_type '{lid}' {end} '{t}' does not resolve to a declared object_type"
                    ),
                ));
            }
        }
    }

    // Action/function types: kind is enumerated; object-mutating kinds must target an object type.
    for ac in &action_types {
        let aid = entry_id(ac);
        let kind = ac.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if !ACTION_KINDS.contains(&kind) {
            return Err(verr(
                "ontology_action_kind_invalid",
                format!("action_type '{aid}' kind '{kind}' must be one of {ACTION_KINDS:?}"),
            ));
        }
        let applies_to = ac.get("applies_to").and_then(|v| v.as_str()).unwrap_or("");
        if !applies_to.is_empty() && !object_ids.iter().any(|x| x == applies_to) {
            return Err(verr(
                "ontology_ref_unresolved",
                format!("action_type '{aid}' applies_to '{applies_to}' does not resolve to a declared object_type"),
            ));
        }
        if kind != "function" && applies_to.is_empty() {
            return Err(verr(
                "ontology_action_target_required",
                format!("action_type '{aid}' of kind '{kind}' requires an applies_to object_type"),
            ));
        }
    }

    // Readiness projection — honest: draft/incomplete allowed, `ready` only when the required
    // semantic pieces exist (≥1 typed object with properties + a title, and ≥1 relation or action).
    let (n_obj, n_link, n_act) = (object_types.len(), link_types.len(), action_types.len());
    let status = if n_obj == 0 {
        gaps.insert(
            0,
            "no object_types declared — the model is an empty draft".into(),
        );
        "empty"
    } else {
        if n_link == 0 && n_act == 0 {
            gaps.push(
                "no link_types or action_types — the model declares no relations or behaviors"
                    .into(),
            );
        }
        if gaps.is_empty() {
            "ready"
        } else {
            "incomplete"
        }
    };
    let legacy = |k: &str| {
        com.get(k)
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    };
    let legacy_untyped = legacy("objects")
        + legacy("actions")
        + legacy("events")
        + legacy("states")
        + legacy("roles");

    Ok(json!({
        "status": status,
        "counts": {
            "value_types": value_types.len(),
            "object_types": n_obj,
            "link_types": n_link,
            "action_types": n_act
        },
        "gaps": gaps,
        "object_instances": 0,
        "object_data_note": OBJECT_DATA_NOTE,
        "legacy_untyped_names": legacy_untyped
    }))
}

/// Build an ontology receipt (PURE — nothing persists here; #62 proof discipline). The receipt
/// carries only record-derived fields + the op/summary + the RESOLVED acting principal (INV-37:
/// every mutation receipt names who acted) — never raw request material.
fn build_ontology_receipt(
    ontology_ref: &str,
    op: &str,
    summary: &str,
    now: &str,
    acting_principal_ref: &str,
) -> (String, Value) {
    let id = format!("ontr_{:x}", nanos());
    let receipt_ref = format!("agentgres://odk-ontology-receipt/{id}");
    let rec = json!({
        "schema_version": "ioi.hypervisor.odk.ontology-receipt.v1",
        "receipt_id": id,
        "receipt_ref": receipt_ref,
        "ontology_ref": ontology_ref,
        "op": op,
        "outcome": "ok",
        "summary": summary,
        "acting_principal_ref": acting_principal_ref,
        "at": now
    });
    (id, rec)
}

/// Atomic-with-rollback finalization (#62 discipline): the ONTOLOGY record persists first (a
/// receipt must never describe an unpersisted state); the receipt follows; if the receipt write
/// fails, `prev` is RESTORED (patch) or the record REMOVED (create) with checked operations so a
/// persisted accepted edit never lacks its receipt. Every failure reports; no partial success.
fn finalize_ontology_persist(
    data_dir: &str,
    id: &str,
    prev: Option<&Value>,
    record: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), String> {
    persist_record(data_dir, KIND_ONT, id, record)
        .map_err(|e| format!("ontology record persist failed ({e}) — nothing changed"))?;
    match persist_record(data_dir, KIND_ONT_RECEIPT, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => match prev {
            Some(p) => match persist_record(data_dir, KIND_ONT, id, p) {
                Ok(()) => Err(format!("ontology receipt persist failed ({e}); the prior record state was restored — nothing changed")),
                Err(e2) => Err(format!("ontology receipt persist failed ({e}) AND the record restore failed ({e2}) — manual repair required for ontology '{id}'")),
            },
            None => {
                if remove_record(data_dir, KIND_ONT, id) {
                    Err(format!("ontology receipt persist failed ({e}); the created record was rolled back — nothing changed"))
                } else {
                    Err(format!("ontology receipt persist failed ({e}) AND the created record rollback failed — manual repair required for ontology '{id}'"))
                }
            }
        },
    }
}

/// Editable top-level fields (operational wave #63): present-but-wrong-type or oversized values
/// are REJECTED with typed codes, never silently defaulted.
fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.chars().count() > max {
                return Err(verr(
                    "odk_field_too_long",
                    format!("`{key}` exceeds the bounded length ({max} chars)"),
                ));
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(verr(
            "odk_field_type_invalid",
            format!("`{key}` must be a string when present"),
        )),
    }
}

/// Optimistic concurrency (#63): when `expected_revision` is supplied it must be an integer that
/// exactly matches the persisted revision. Malformed → typed invalid refusal; mismatch → typed
/// conflict. Either refusal changes NOTHING. Legacy callers that omit it are preserved.
pub(crate) fn check_expected_revision(
    body: &Value,
    current: u64,
) -> Result<(), (StatusCode, String, String)> {
    match body.get("expected_revision") {
        None | Some(Value::Null) => Ok(()),
        Some(v) => match v.as_u64() {
            None => Err((StatusCode::BAD_REQUEST, "odk_expected_revision_invalid".into(), "expected_revision must be an integer".into())),
            Some(er) if er != current => Err((StatusCode::CONFLICT, "odk_revision_conflict".into(), format!("expected_revision {er} does not match the persisted revision {current} — reload and re-apply your edit"))),
            Some(_) => Ok(()),
        },
    }
}

// ================================ DOMAIN ONTOLOGY ================================================

/// PROSE ABOUT THE PLANE IS PROJECTED ON READ, NEVER SERVED FROM THE RECORD.
///
/// `health.object_data_note` describes what this ESTATE can do, and it is computed at write time and
/// persisted into the record — so every ontology written before a capability lands keeps the old
/// sentence for ever, and a review found exactly that: three user-facing pages still telling readers
/// no object-instance plane is bound, months after one was, with no backfill anywhere in the stack.
/// A stored note is a snapshot of what was true when the record was written; a reader wants what is
/// true now. So the note is REPROJECTED on every read. The counts and gaps beside it stay stored
/// truth — they are facts about the model, which is what the record is for.
fn reproject_object_data_note(record: &mut Value) {
    if let Some(health) = record.get_mut("health").and_then(Value::as_object_mut) {
        if health.contains_key("object_data_note") {
            health.insert("object_data_note".to_string(), json!(OBJECT_DATA_NOTE));
        }
    }
}

pub(crate) async fn handle_odk_ontology_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_ONT);
    if let Some(domain) = q.get("domain").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|o| o.get("domain").and_then(|v| v.as_str()) == Some(domain));
    }
    sort_by_updated(&mut items);
    for item in items.iter_mut() {
        reproject_object_data_note(item);
    }
    Json(json!({ "ok": true, "ontologies": items }))
}

/// POST /v1/hypervisor/odk/domain-ontologies — create a DomainOntology DRAFT. The semantic root: it
/// embeds a typed CanonicalObjectModel (value/object/link/action types), validated fail-closed, and
/// carries revision 1 + a create receipt + a readiness health projection.
pub(crate) async fn handle_odk_ontology_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // W1.1/G-2 finding closed — identity FIRST (rule E): an anonymous caller is owed the typed
    // refusal before any validation runs, so no field-shape probe exists for unauthenticated
    // callers. An ontology write is an authored mutation, not an anonymous append.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    // TRIM TO JUDGE, PERSIST WHAT THE CALLER SENT. `apply_ontology_change` stores `domain`
    // VERBATIM; this route stored it TRIMMED, so create and patch disagreed on the same field —
    // one field's worth of exactly the divergence this module's own comment claims to have ended,
    // and silent normalization of persisted data is a defect this run has already paid for once.
    // The emptiness judgement still uses the trimmed value, which is what the shared validator does.
    let domain_raw = body.get("domain").and_then(|v| v.as_str());
    let domain = domain_raw.filter(|s| !s.trim().is_empty());
    let Some(domain) = domain else {
        return bad(
            "odk_domain_required",
            "A DomainOntology must declare a non-empty domain.",
        );
    };
    let com = body.get("canonical_object_model").cloned().unwrap_or_else(
        || json!({ "value_types": [], "object_types": [], "link_types": [], "action_types": [] }),
    );
    if domain.chars().count() > 120 {
        return bad(
            "odk_field_too_long",
            "`domain` exceeds the bounded length (120 chars)",
        );
    }
    // Hardened (#63): present-but-wrong-type or oversized editable fields are rejected typed.
    let version = match str_opt_bounded(&body, "version", 60) {
        Ok(v) => v.unwrap_or_else(|| "0.1.0".to_string()),
        Err((code, msg)) => return bad(&code, &msg),
    };
    let description = match str_opt_bounded(&body, "description", 2000) {
        Ok(v) => v.unwrap_or_default(),
        Err((code, msg)) => return bad(&code, &msg),
    };
    let health = match validate_object_model(&com) {
        Ok(h) => h,
        Err((code, msg)) => return bad(&code, &msg),
    };
    let id = format!("ont_{:x}", nanos());
    let now = iso_now();
    let oref = format!("ontology://{id}");
    // #62 proof discipline: build record + receipt PURE, then finalize atomically-with-rollback.
    let (receipt_id, receipt) = build_ontology_receipt(
        &oref,
        "created",
        "DomainOntology draft created",
        &now,
        &identity.principal_ref,
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let record = json!({
        "schema_version": "ioi.hypervisor.odk.domain-ontology.v1",
        "object": "ioi.hypervisor.odk.domain_ontology",
        "id": id,
        "ref": oref,
        "domain": domain,
        "version": version,
        "description": description,
        "status": "draft",
        // Typed CanonicalObjectModel embedded + validated; health is the readiness projection.
        "canonical_object_model": com,
        "health": health,
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "DomainOntology draft created", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    if let Err(m) =
        finalize_ontology_persist(&st.data_dir, &id, None, &record, &receipt_id, &receipt)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": { "code": "odk_persist_failed", "message": m } })),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "ontology": record, "ontology_receipt": receipt })),
    )
}

pub(crate) async fn handle_odk_ontology_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let mut out = json_get(&st.data_dir, KIND_ONT, "ontology", &id);
    if let Some(record) = out.0.get_mut("ontology") {
        reproject_object_data_note(record);
    }
    out
}

/// PATCH — fail-closed on a malformed model (revision is NOT bumped on rejection); optimistic
/// concurrency via `expected_revision` (#63 — integer, must match exactly, refusal changes
/// NOTHING; legacy callers that omit it are preserved); on success bumps the revision exactly
/// once, recomputes health, appends bounded history, and persists record + patch receipt
/// atomically-with-restore (#62 discipline). Returns the ontology AND the durable receipt.
pub(crate) async fn handle_odk_ontology_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // W1.1/G-2 finding closed — identity FIRST (rule E): the refusal is owed BEFORE the record
    // load, so an unauthenticated caller can never use the 404 as an existence oracle.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    apply_ontology_change(&st.data_dir, &identity, &id, &body)
}

/// THE ONE VALIDATOR FOR AN ONTOLOGY CHANGE SET, shared by the edit path and the proposal plane.
///
/// A review demonstrated that proposal-time checking was strictly weaker than apply-time: an empty
/// `domain`, an over-length field, and a duplicate object-type id were all ACCEPTED as proposals and
/// then refused on apply, leaving permanently unappliable "open" proposals accumulating. That
/// contradicts the reason a proposal is validated at all — a proposal that could never apply is a
/// note. Both paths now run this, so "the same rules an ordinary edit obeys" is a shared function
/// rather than a claim.
pub(crate) fn validate_ontology_change(body: &Value) -> Result<(), (StatusCode, Value)> {
    for (key, max) in [("domain", 120usize), ("version", 60), ("description", 2000)] {
        match str_opt_bounded(body, key, max) {
            Ok(Some(value)) if key == "domain" && value.trim().is_empty() => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    json!({ "code": "odk_domain_required", "message": "`domain` must stay non-empty" }),
                ))
            }
            Ok(_) => {}
            Err((code, message)) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    json!({ "code": code, "message": message }),
                ))
            }
        }
    }
    // A NULL OBJECT MODEL IS PRESENT AND INVALID, and it stays that way.
    //
    // An earlier revision made it "absent" to match how `str_opt_bounded` reads the string fields,
    // citing a propose/patch divergence. THERE WAS NO DIVERGENCE: both planes already refused it
    // with `odk_field_type_invalid`. What existed was an inconsistency INSIDE this validator, and
    // it got resolved by relaxing the STRICTER side — turning a typed refusal on a shipped route
    // into an accepted no-op that bumped the revision and minted a receipt for nothing. Fail-closed
    // to fail-open, undeclared. The internal inconsistency is real and is left standing
    // deliberately: a missing string field and a missing model are different shapes, and between
    // two ways to make them agree the honest one admits less.
    if let Some(model) = body.get("canonical_object_model") {
        if !model.is_object() {
            return Err((
                StatusCode::BAD_REQUEST,
                json!({ "code": "odk_field_type_invalid", "message": "`canonical_object_model` must be an object" }),
            ));
        }
        if let Err((code, message)) = validate_object_model(model) {
            return Err((
                StatusCode::BAD_REQUEST,
                json!({ "code": code, "message": message }),
            ));
        }
    }
    Ok(())
}

/// THE ONE WRITER FOR AN ONTOLOGY EDIT.
///
/// Extracted from the PATCH handler so the ontology-proposal plane can APPLY a proposal through the
/// exact path an ordinary edit takes. A proposal apply that re-implemented validation, revision
/// bumping, health recomputation, receipting or history would be a SECOND ADMISSION PATH for one act
/// — with its own answer to `expected_revision`, its own idea of what a valid model is, and its own
/// receipt shape. The estate's standing law is that no surface mints a second spine beside a kernel
/// owner; this keeps proposals composing over the owner rather than beside it.
///
/// Identity is resolved by the CALLER, before this is reached, because rule E owes a 401 before the
/// record read below is allowed to reveal existence.
pub(crate) fn apply_ontology_change(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    id: &str,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    let st_data_dir = data_dir;
    let Some(prev) = load(st_data_dir, KIND_ONT, id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "ontology not found", "error": { "code": "odk_ontology_not_found", "message": "ontology not found" } }),
            ),
        );
    };
    let current_rev = prev.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    if let Err((status, code, msg)) = check_expected_revision(body, current_rev) {
        return (
            status,
            Json(
                json!({ "ok": false, "error": { "code": code, "message": msg, "current_revision": current_rev } }),
            ),
        );
    }
    // THE SHARED VALIDATOR, not a second copy of these rules. A review found this path carrying an
    // inline duplicate of `validate_ontology_change` while the proposal plane called the function —
    // two copies nothing held in agreement, and one had already diverged (an explicit `null` domain
    // was accepted here and refused there). One caller, one validator, or "the same rules an
    // ordinary edit obeys" is a sentence rather than a property.
    if let Err((_status, error)) = validate_ontology_change(body) {
        return (StatusCode::OK, Json(json!({ "ok": false, "error": error })));
    }
    let mut o = prev.clone();
    let mut changed: Vec<String> = Vec::new();
    for key in ["domain", "version", "description"] {
        // Validated above by the shared validator; only PRESENT string fields are applied, so an
        // absent field and an explicit null both leave the record untouched exactly as before.
        //
        // AND THE VALUE IS STORED VERBATIM. An earlier revision of this extraction wrote
        // `value.trim()`, which is an UNDECLARED REWRITE OF CALLER DATA on a shipped write path:
        // `create` stored `"  9.9.9  "` while `patch` of the same string stored `"9.9.9"`, a
        // proposal's reviewed text stopped being the text that got written, and the length bound
        // still measured the raw string while storage was trimmed. Trimming belongs to the
        // emptiness CHECK in the validator, never to what is persisted.
        if let Some(value) = body.get(key).and_then(Value::as_str) {
            o[key] = json!(value);
            changed.push(key.to_string());
        }
    }
    if let Some(new_com) = body.get("canonical_object_model") {
        o["canonical_object_model"] = new_com.clone();
        changed.push("canonical_object_model".to_string());
    }
    // Recompute health from the resulting model (guaranteed valid — checked above or unchanged).
    let com = o
        .get("canonical_object_model")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Ok(health) = validate_object_model(&com) {
        o["health"] = health;
    }
    let rev = current_rev + 1;
    o["revision"] = json!(rev);
    let now = iso_now();
    o["updated_at"] = json!(now.clone());
    let summary = format!(
        "patched: {}",
        if changed.is_empty() {
            "no-op".to_string()
        } else {
            changed.join(", ")
        }
    );
    let oref = o
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let (receipt_id, receipt) =
        build_ontology_receipt(&oref, "patched", &summary, &now, &identity.principal_ref);
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    // Append a bounded history entry + carry the receipt ref.
    let mut hist = o
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": "patched", "at": now, "summary": summary, "receipt_ref": receipt_ref.clone() }));
    let len = hist.len();
    if len > 20 {
        hist = hist[len - 20..].to_vec();
    }
    o["history"] = json!(hist);
    let mut refs = o
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.push(receipt_ref);
    o["receipt_refs"] = json!(refs);
    if let Err(m) =
        finalize_ontology_persist(st_data_dir, id, Some(&prev), &o, &receipt_id, &receipt)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": { "code": "odk_persist_failed", "message": m } })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "ontology": o, "ontology_receipt": receipt })),
    )
}

/// DELETE /v1/hypervisor/odk/domain-ontologies/:id — receipted deletion.
///
/// Deletion is an effectful mutation of an ontology, so it emits a `deleted` receipt exactly like
/// create and patch. It follows the same #62 discipline in reverse: the record is removed FIRST (a
/// receipt must never describe an unpersisted state), then the receipt is written; if the receipt
/// write fails the record is RESTORED, so a deleted ontology never lacks its receipt. A missing
/// ontology is reported honestly and emits nothing — there was no mutation to attest.
pub(crate) async fn handle_odk_ontology_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    // W1.1/G-2 finding closed — identity FIRST (rule E): the refusal is owed BEFORE the record
    // load inside the receipted delete, so an anonymous caller gets no existence oracle. All
    // authenticated outcomes keep their 200 body shapes exactly.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    (
        StatusCode::OK,
        Json(delete_ontology_receipted(
            &st.data_dir,
            &id,
            &identity.principal_ref,
        )),
    )
}

/// The receipted-delete body, separated from the axum handler so the rollback discipline is
/// directly testable (same shape as `finalize_ontology_persist`'s test).
fn delete_ontology_receipted(data_dir: &str, id: &str, acting_principal_ref: &str) -> Value {
    let Some(prev) = load(data_dir, KIND_ONT, id) else {
        return json!({ "ok": false, "removed": false, "id": id, "reason": "ontology not found" });
    };
    let oref = prev.get("ref").and_then(|v| v.as_str()).unwrap_or("");
    let (receipt_id, receipt) = build_ontology_receipt(
        oref,
        "deleted",
        "DomainOntology deleted",
        &iso_now(),
        acting_principal_ref,
    );
    if !remove_record(data_dir, KIND_ONT, id) {
        return json!({
            "ok": false, "removed": false, "id": id,
            "reason": "ontology record removal failed — nothing changed"
        });
    }
    if let Err(e) = persist_record(data_dir, KIND_ONT_RECEIPT, &receipt_id, &receipt) {
        let reason = if persist_record(data_dir, KIND_ONT, id, &prev).is_ok() {
            format!(
                "ontology receipt persist failed ({e}); the record was restored — nothing changed"
            )
        } else {
            format!("ontology receipt persist failed ({e}) AND the record restore failed — manual repair required for ontology '{id}'")
        };
        return json!({ "ok": false, "removed": false, "id": id, "reason": reason });
    }
    json!({ "ok": true, "removed": true, "id": id, "ontology_receipt": receipt })
}

/// GET /v1/hypervisor/odk/domain-ontologies/:id/health — the readiness projection (over ODK).
pub(crate) async fn handle_odk_ontology_health(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load(&st.data_dir, KIND_ONT, &id) {
        Some(o) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "ontology_ref": o.get("ref").cloned().unwrap_or(Value::Null),
                "revision": o.get("revision").cloned().unwrap_or(json!(1)),
                "health": o.get("health").cloned().unwrap_or_else(|| json!({ "status": "empty" }))
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "ontology not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/domain-ontologies/:id/history — embedded history + persisted receipts.
pub(crate) async fn handle_odk_ontology_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(o) = load(&st.data_dir, KIND_ONT, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "ontology not found" })),
        );
    };
    let oref = o
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut receipts = read_record_dir(&st.data_dir, KIND_ONT_RECEIPT);
    receipts.retain(|r| r.get("ontology_ref").and_then(|v| v.as_str()) == Some(oref.as_str()));
    receipts.sort_by(|a, b| {
        b.get("at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "ontology_ref": oref,
            "revision": o.get("revision").cloned().unwrap_or(json!(1)),
            "history": o.get("history").cloned().unwrap_or_else(|| json!([])),
            "receipts": receipts
        })),
    )
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
    headers: HeaderMap,
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
    let id = odk_derived_id(
        "recipe",
        body.get("owner_ref").and_then(|v| v.as_str()).unwrap_or(""),
        body.get("idempotency_key")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
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
    if let Err(response) = manifest_registered_valid(&record) {
        return response;
    }
    odk_admit(
        &st.data_dir,
        &headers,
        &body,
        OdkAdmission {
            family: KIND_RECIPE,
            scope_kind: "hypervisor-odk-data-recipe",
            ref_prefix: "data-recipe://",
            op_kind: "event_stream.hypervisor_odk_data_recipe_admitted",
            reply_key: "data_recipe",
            persist_error: "odk_data_recipe_persistence_failed",
            projection: OdkProjection::InlineTimestamps,
        },
        &id,
        record,
        None,
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
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut r) = load(&st.data_dir, KIND_RECIPE, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "error": { "code": "odk_data_recipe_not_found", "message": "data_recipe not found" } }),
            ),
        );
    };
    if let Some(ok) = body.get("output_kind").and_then(|v| v.as_str()) {
        if !RECIPE_OUTPUT_KINDS.contains(&ok) {
            return bad(
                "odk_output_kind_invalid",
                &format!("output_kind must be one of {RECIPE_OUTPUT_KINDS:?}"),
            );
        }
    }
    if let Some(oref) = body.get("ontology_ref").and_then(|v| v.as_str()) {
        if let Err((c, m)) = require_local_ref(&st.data_dir, oref, "ontology", "ontology_ref") {
            return bad(&c, &m);
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
                return bad(&c, &m);
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
    let previous = load(&st.data_dir, KIND_RECIPE, &id).unwrap_or_else(|| json!({}));
    odk_admit(
        &st.data_dir,
        &headers,
        &body,
        OdkAdmission {
            family: KIND_RECIPE,
            scope_kind: "hypervisor-odk-data-recipe",
            ref_prefix: "data-recipe://",
            op_kind: "event_stream.hypervisor_odk_data_recipe_revised",
            reply_key: "data_recipe",
            persist_error: "odk_data_recipe_persistence_failed",
            projection: OdkProjection::InlineTimestamps,
        },
        &id,
        r,
        Some(&previous),
    )
}

pub(crate) async fn handle_odk_recipe_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_RECIPE, &id)
}

// ============================ ODK MANIFEST (builder/conformance) ================================

pub(crate) async fn handle_odk_manifest_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_MANIFEST);
    sort_by_updated(&mut items);
    Json(json!({ "ok": true, "manifests": items }))
}

// ==================== M05.6 · THE ODK MANIFEST FAMILY, UNDER A REGISTERED CONTRACT ===============
//
// G-4 forbids a surface, client or projection from claiming an object family until that family's
// wire contract is registered. `ioi.hypervisor.odk.manifest.v1` was a local Rust string with no
// `_meta/schemas/` entry behind it, so every ODK manifest claim rested on a constant. The contract
// is now registered — as the record this lane ACTUALLY mints, divergences and all — and this route
// validates what it writes against it before admitting.
//
// TWO THINGS THAT DID NOT HAPPEN HERE, DELIBERATELY. The canonical successor
// `ioi.ontology-development-kit-manifest.v2` is registered beside v1, with canon's sixteen member
// lists under canon's own names; this build does not yet AUTHOR it, because the split of v1's folded
// members — `recipe_refs` into `data_recipe_refs`, `eval_refs` into dataset and benchmark refs,
// `mcp_operator_contracts` into operator and MCP refs — cannot be performed by a migration: a v1
// record does not record which member is which, so only the author can say. And v1's wire contract
// is not narrowed by stealth: the two passthrough fields keep their names and their meaning. What
// changes is that a record this route cannot project is REFUSED at authoring instead of admitted and
// then unreadable, and the refusal names the failing field.
const ODK_MANIFEST_V1_SCHEMA_VERSION: &str = "ioi.hypervisor.odk.manifest.v1";
const ODK_MANIFEST_V2_SCHEMA_VERSION: &str = "ioi.ontology-development-kit-manifest.v2";
const ODK_MANIFEST_V1_CONTRACT_ID: &str =
    "schema://ioi/foundations/objects/ontology-development-kit-manifest/v1";

/// Refuse an authoring request naming any manifest contract this build does not write.
fn require_manifest_authored_version(body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    match body.get("schema_version") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(declared)) if declared == ODK_MANIFEST_V1_SCHEMA_VERSION => Ok(()),
        Some(Value::String(declared)) if declared == ODK_MANIFEST_V2_SCHEMA_VERSION => Err(bad(
            "odk_manifest_successor_not_authored_here",
            &format!(
                "'{ODK_MANIFEST_V2_SCHEMA_VERSION}' is registered canon but this build does not author it: v1 folds three pairs of canonical members into single lists and no migration can say which member is which. Authoring a successor is an explicit act by the author who knows"
            ),
        )),
        Some(declared) => Err(bad(
            "odk_manifest_contract_unsupported",
            &format!(
                "this build authors {ODK_MANIFEST_V1_SCHEMA_VERSION} only; {declared} is refused rather than downgraded"
            ),
        )),
    }
}

/// Validate one assembled manifest against its REGISTERED contract before it can be admitted.
fn manifest_registered_valid(record: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        ODK_MANIFEST_V1_CONTRACT_ID,
        record,
    )
    .map_err(|reason| {
        bad(
            "odk_manifest_not_registered_valid",
            &format!(
                "the manifest this request builds is not valid against {ODK_MANIFEST_V1_CONTRACT_ID}: {reason}"
            ),
        )
    })
}

/// POST /v1/hypervisor/odk/manifests — create an OntologyDevelopmentKitManifest DRAFT bundling
/// ontology refs (required, ≥1) + recipe + surface-descriptor refs + named contract refs.
pub(crate) async fn handle_odk_manifest_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(response) = require_manifest_authored_version(&body) {
        return response;
    }
    let ontology_refs = str_refs(&body, "ontology_refs");
    if let Err((c, m)) = require_local_ref_list(
        &st.data_dir,
        &ontology_refs,
        "ontology",
        "ontology_ref",
        true,
    ) {
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
    let id = odk_derived_id(
        "odk",
        body.get("owner_ref").and_then(|v| v.as_str()).unwrap_or(""),
        body.get("idempotency_key")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
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
    odk_admit(
        &st.data_dir,
        &headers,
        &body,
        OdkAdmission {
            family: KIND_MANIFEST,
            scope_kind: "hypervisor-odk-manifest",
            ref_prefix: "odk-manifest://",
            op_kind: "event_stream.hypervisor_odk_manifest_admitted",
            reply_key: "manifest",
            persist_error: "odk_manifest_persistence_failed",
            projection: OdkProjection::InlineTimestamps,
        },
        &id,
        record,
        None,
    )
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
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(response) = require_manifest_authored_version(&body) {
        return response;
    }
    let Some(mut man) = load(&st.data_dir, KIND_MANIFEST, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "error": { "code": "odk_manifest_not_found", "message": "manifest not found" } }),
            ),
        );
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
            return bad(&c, &m);
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
            return bad(&c, &m);
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
            return bad(&c, &m);
        }
    }
    for key in ["eval_refs", "worker_plan_refs", "mcp_operator_contracts"] {
        if body.get(key).is_some() {
            if let Err((c, m)) = check_named_refs(&st.data_dir, &str_refs(&body, key)) {
                return bad(&c, &m);
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
    if let Err(response) = manifest_registered_valid(&man) {
        return response;
    }
    let previous = load(&st.data_dir, KIND_MANIFEST, &id).unwrap_or_else(|| json!({}));
    odk_admit(
        &st.data_dir,
        &headers,
        &body,
        OdkAdmission {
            family: KIND_MANIFEST,
            scope_kind: "hypervisor-odk-manifest",
            ref_prefix: "odk-manifest://",
            op_kind: "event_stream.hypervisor_odk_manifest_revised",
            reply_key: "manifest",
            persist_error: "odk_manifest_persistence_failed",
            projection: OdkProjection::InlineTimestamps,
        },
        &id,
        man,
        Some(&previous),
    )
}

pub(crate) async fn handle_odk_manifest_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_MANIFEST, &id)
}

// ---------------------------------------------------------------------------------------------
// W1.2 / MEF-GAP-004 — owner-scoped, idempotent, CAS-checked, Agentgres-admitted, receipted
// descriptor mutation. The descriptor plane previously wrote straight to the record directory
// with a nanos() id: no authenticated owner, no caller idempotency, no expected-head compare,
// no admission, no receipt. This reuses the same foundation the package registry closed
// MEF-CLOSED-003 with, so the two planes cannot drift.
// ---------------------------------------------------------------------------------------------
const ODK_NAMESPACE: &str = "hypervisor-odk";
const ODK_DESCRIPTOR_SCOPE_KIND: &str = "hypervisor-odk-surface-descriptor";

pub(crate) fn odk_scope_refusal(
    error: super::substrate_store::RequestScopeRefusal,
) -> (StatusCode, Json<Value>) {
    use super::substrate_store::RequestScopeRefusal;
    let status = match error {
        RequestScopeRefusal::AuthenticationRequired
        | RequestScopeRefusal::PrincipalIdentityInvalid => StatusCode::UNAUTHORIZED,
        RequestScopeRefusal::TenantAuthorityRequired
        | RequestScopeRefusal::ResourceScopeRequired
        | RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
        RequestScopeRefusal::SubstrateUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
    )
}

fn odk_mutation_refusal(
    error: super::mutation_event_foundation::MutationRefusal,
) -> (StatusCode, Json<Value>) {
    use super::mutation_event_foundation::MutationRefusal;
    match error {
        MutationRefusal::Scope(error) => odk_scope_refusal(error),
        MutationRefusal::Admission(error) => (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "code": error.code(), "message": error.to_string() })),
        ),
        error @ MutationRefusal::RequestFingerprintFailed(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
        ),
        error => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
        ),
    }
}

/// Timestamps come from the ADMISSION, never from request-time wall-clock: a payload that
/// carries `iso_now()` can never be byte-identical across a retry, which is what makes an
/// idempotency key meaningless.
fn admitted_stamp_ms(recorded_at_ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    let ms = recorded_at_ms as i128;
    time::OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(iso_now)
}

fn odk_hash_tail(prefix: &str, identity: &str) -> String {
    {
        use sha2::Digest;
        format!("{prefix}.{:x}", sha2::Sha256::digest(identity.as_bytes()))
    }
}

/// One owner-scoped admission path for every ODK family. The caller validates its own shape and
/// hands over a finished record; this does identity, owner binding, caller idempotency, CAS,
/// Agentgres admission, and the read-model projection. Six handlers share it so descriptors,
/// recipes and manifests cannot drift into three different mutation contracts.
///
/// `previous` is None for a genesis create and Some(existing) for a successor patch.
struct OdkAdmission<'a> {
    family: &'a str,
    scope_kind: &'a str,
    ref_prefix: &'a str,
    op_kind: &'a str,
    reply_key: &'a str,
    persist_error: &'a str,
    /// How the admitted payload is projected for storage and reply.
    projection: OdkProjection,
}

/// Where runtime timestamps go relative to the admitted record.
///
/// THE LEGACY FAMILIES INLINE THEM AND THE v2 DESCRIPTOR CANNOT. `odk_admit` used to stamp
/// `created_at`/`updated_at` onto a copy of the admitted payload for every family. That is harmless
/// for an open record shape and WRONG for a registered one: the v2 descriptor contract closes its
/// object with `additionalProperties: false`, so a projection carrying two extra keys is not
/// registered-valid — the admitted CHAIN bytes were clean, but the row on disk and the record handed
/// back to the caller were not. Widening the contract to admit two storage fields would be letting
/// local storage edit canon, so the record stays exactly as admitted and the runtime metadata sits
/// beside it in an envelope.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OdkProjection {
    /// Stamp `created_at`/`updated_at` onto the record itself (the four legacy ODK families).
    InlineTimestamps,
    /// A DESCRIPTOR row, written by the repair path itself from the admitted history.
    ///
    /// THE WRITE PATH AND THE REPAIR PATH ARE NOW ONE FUNCTION, which is the only way "the row is a
    /// projection of the chain" can be true rather than asserted. Two implementations that agree
    /// today drift tomorrow: this one hard-coded the v2 envelope for EVERY descriptor write, so
    /// withdrawing a stored v1 wrote a row announcing `descriptor_contract_id: …/v2` over a v1
    /// record, while `rebuild_descriptor_row` reconstructed the same descriptor in the legacy lane's
    /// inline shape. The row a write left behind and the row a repair produced were different bytes
    /// for the same admitted state, and only one of them could be right.
    DescriptorFromHistory,
}

/// The projection envelope schema for a v2 descriptor row and reply.
const DESCRIPTOR_PROJECTION_SCHEMA: &str = "ioi.hypervisor.odk.surface-descriptor-projection.v2";

/// The read-model row for one admitted descriptor, in the shape ITS OWN registered version stores.
///
/// VERSION-CORRECT, AND AN UNKNOWN VERSION FAILS CLOSED. A v2 row is an envelope that carries the
/// closed registered record byte-exact with runtime metadata beside it; a stored v1 row IS the
/// record with those two keys inlined, exactly as the legacy lane wrote it. There is no third shape
/// and no default arm: writing an unrecognised record into whichever shape happened to be last in
/// the match is how a projection starts claiming a contract its contents were never admitted under.
///
/// `created_at`/`updated_at` are supplied by the caller and are DERIVED FROM THE ADMITTED HISTORY,
/// never copied from the row being replaced — see `resolve_admitted_surface_descriptor`.
fn descriptor_row(
    record: &Value,
    created_at: &str,
    updated_at: &str,
) -> Result<Value, (StatusCode, Json<Value>)> {
    match record.get("schema_version").and_then(Value::as_str) {
        Some(DESCRIPTOR_V2_SCHEMA_VERSION) => Ok(json!({
            "schema_version": DESCRIPTOR_PROJECTION_SCHEMA,
            "descriptor_contract_id": DESCRIPTOR_V2_CONTRACT_ID,
            "descriptor": record,
            "created_at": created_at,
            "updated_at": updated_at,
        })),
        Some(DESCRIPTOR_V1_SCHEMA_VERSION) => {
            let mut inlined = record.clone();
            inlined["created_at"] = json!(created_at);
            inlined["updated_at"] = json!(updated_at);
            Ok(inlined)
        }
        unknown => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "odk_descriptor_projection_failed",
                    "message": format!(
                        "a descriptor admitted as '{}' has no projection shape in this build; it is refused rather than stored under a contract it was never admitted under",
                        unknown.unwrap_or("(no schema_version)")
                    )
                }
            })),
        )),
    }
}

fn odk_admit(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
    spec: OdkAdmission<'_>,
    id: &str,
    record: Value,
    previous: Option<&Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    odk_admit_with_identity(data_dir, &identity, body, spec, id, record, previous)
}

/// The admission itself, over an ALREADY-RESOLVED identity.
///
/// Split from the transport wrapper so the historical-upgrade proof can seed a stored v1 through the
/// EXACT foundation the legacy lane used — same scope binding, same caller idempotency, same
/// compare-and-swap, same Agentgres admission, same projection — without a public v1 authoring
/// bypass, which this build refuses by design and must keep refusing.
#[allow(clippy::too_many_arguments)]
fn odk_admit_with_identity(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    body: &Value,
    spec: OdkAdmission<'_>,
    id: &str,
    mut record: Value,
    previous: Option<&Value>,
) -> (StatusCode, Json<Value>) {
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if idempotency_key.is_empty() {
        return bad(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried write cannot apply twice",
        );
    }
    // A patch may not move a resource between owners, so on a successor the owner comes from the
    // admitted record rather than the request body.
    let owner_ref = match previous {
        Some(existing) => existing["owner_ref"].as_str().unwrap_or("").to_string(),
        None => body
            .get("owner_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
    };
    if owner_ref.is_empty() {
        return bad(
            "odk_owner_ref_required",
            "owner_ref is required: this record is owned by exactly one org:// or project://",
        );
    }
    let expected_head = body
        .get("expected_head")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if previous.is_some() && expected_head.is_none() {
        return bad(
            "mutation_successor_expected_head_required",
            "expected_head is required: a patch compare-and-swaps against the exact admitted head",
        );
    }

    // Wall-clock never enters the admitted payload: a retry could never be byte-identical, and the
    // substrate would refuse the replay as same-key-different-bytes, making the key meaningless.
    let created_at = previous.map(|existing| existing["created_at"].clone());
    if let Some(object) = record.as_object_mut() {
        object.remove("created_at");
        object.remove("updated_at");
        object.insert("owner_ref".into(), json!(owner_ref));
    }

    let resource_ref = format!("{}{id}", spec.ref_prefix);
    let scope = match super::substrate_store::bind_request_resource_scope(
        data_dir,
        &identity,
        spec.scope_kind,
        &resource_ref,
        &owner_ref,
        &owner_ref,
        idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return odk_scope_refusal(error),
    };
    let tail = odk_hash_tail(spec.scope_kind, &resource_ref);
    match super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        previous.is_none(),
        super::mutation_event_foundation::ScopedMutation {
            identity: &identity,
            scope: &scope,
            resource_kind: spec.scope_kind,
            resource_ref: &resource_ref,
            owner_namespace: ODK_NAMESPACE,
            stream_tail: &tail,
            op_kind: spec.op_kind,
            expected_head,
            payload: &record,
            idempotency_key,
            recorded_at_ms: 0,
        },
    ) {
        Ok(commit) => {
            let stamp = admitted_stamp_ms(commit.projection.operation.recorded_at_ms);
            let record = commit.projection.operation.payload.clone();
            // THE ROW AND THE REPLY ANSWER TWO DIFFERENT QUESTIONS, and returning one object for both
            // put two shapes under one key name. The envelope exists so local storage can carry
            // runtime metadata without editing a closed registered record; it is not what a caller
            // asked for. Returning it meant `POST` answered with
            // `{schema_version: "…surface-descriptor-projection.v2", descriptor: {…}}` while `GET` on
            // the same resource answered with the bare record — under the SAME `surface_descriptor`
            // key. A consumer validating the create reply against the registered contract saw an
            // object with two unknown fields and none of the known ones, so every field it wanted read
            // as ABSENT rather than as an error. The row keeps the envelope; the reply is the
            // canonical record, which is what is registered-valid and what every read already returns.
            let reply_body = match spec.projection {
                OdkProjection::InlineTimestamps => {
                    let created = created_at.unwrap_or_else(|| json!(stamp.clone()));
                    let mut inlined = record;
                    inlined["created_at"] = created;
                    inlined["updated_at"] = json!(stamp);
                    if let Err(response) =
                        persist_required(data_dir, spec.family, id, &inlined, spec.persist_error)
                    {
                        return response;
                    }
                    inlined
                }
                // THE ROW IS NOT WRITTEN HERE AT ALL; it is REBUILT, by the same function
                // `POST …/rebuild-index` runs, from the history this commit just extended. Composing
                // the row here from `previous["created_at"]` was wrong twice over. A v2 record does
                // not CARRY `created_at` — the envelope does — so `previous["created_at"]` read as
                // JSON null, and every patch and every withdrawal wrote a row whose creation time was
                // null. And it produced bytes by a second route that the repair path had to
                // re-derive, so "a rebuilt row is what the write path would have produced" was two
                // implementations agreeing rather than one function running twice.
                OdkProjection::DescriptorFromHistory => {
                    if let Err(response) = rebuild_descriptor_row(data_dir, identity, &resource_ref)
                    {
                        return response;
                    }
                    record
                }
            };
            (
                if previous.is_some() {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                Json(json!({
                    "ok": true,
                    spec.reply_key: reply_body,
                    "replayed": commit.replayed,
                    "receipt_ref": commit.receipt_ref,
                    "operation_ref": commit.operation_ref
                })),
            )
        }
        Err(error) => odk_mutation_refusal(error),
    }
}

/// Derive a resource id from owner + caller key so a retried create resolves the SAME resource.
/// A wall-clock id can never be idempotent.
fn odk_derived_id(prefix: &str, owner_ref: &str, idempotency_key: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("{owner_ref}\u{0}{idempotency_key}").as_bytes());
    format!("{prefix}_{digest:x}")[..(prefix.len() + 17)].to_string()
}

// ============================ ONTOLOGY SURFACE DESCRIPTOR =======================================

/// GET /v1/hypervisor/odk/surface-descriptors — this CALLER'S descriptors, resolved from the chain.
///
/// THREE THINGS WERE WRONG WITH THE SWEEP THIS REPLACES, and they compounded.
///
/// It took NO IDENTITY AT ALL. Every stored descriptor in the process, for every owner and every
/// tenant, was returned to any caller who asked — including `owner_ref`, every binding, every
/// `surface_ref` and every ontology revision each one names. A route whose sibling `GET /:id` is
/// owner-scoped, handing the whole corpus to an anonymous caller, is not a weaker read; it is the
/// same disclosure with the fence removed.
///
/// It answered from the READ-MODEL ROWS, so an operator who deleted a row removed a descriptor from
/// its owner's own inventory, and a corrupted row was listed as whatever the corruption said.
///
/// And it could not say what it had NOT seen. A short list and an empty corpus were the same answer.
///
/// So this authorizes first, enumerates the caller's descriptor scopes from the request-scope
/// namespace, and resolves EACH ONE through the owner reader that projects the Agentgres chain. The
/// row is compared and never consulted.
///
/// THE CENSUS IS SCOPED TO THE CALLER, AND THAT IS A CORRECTION. It briefly carried the global
/// descriptor-stream total, the count this caller was NOT authorized for, and the process-wide
/// read-model row count — so that a caller could tell "there are none" from "there are none I may
/// see". Every one of those three is a fact about OTHER TENANTS, answered to anyone authenticated:
/// poll the endpoint and the global total tells you when a competitor created a descriptor, and the
/// difference tells you how many they hold. Replacing a corpus-wide read with a cross-tenant
/// COUNTING oracle is not a fence, it is the same disclosure at lower resolution. A complete
/// inventory is genuine evidence, but it belongs to offline and administrative evidence paths that
/// are entitled to the whole substrate — not to an ordinary tenant-scoped list. What remains here is
/// exactly what this caller already owns: how many of ITS descriptors resolved, how many were
/// withdrawn, which were unreadable, and what ITS rows said.
pub(crate) async fn handle_odk_descriptor_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    let authorized = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        ODK_DESCRIPTOR_SCOPE_KIND,
    ) {
        Ok(refs) => refs,
        Err(error) => return odk_scope_refusal(error),
    };

    let mut items: Vec<Value> = Vec::new();
    let mut withdrawn = 0usize;
    let mut unreadable: Vec<Value> = Vec::new();
    let mut index_agreed = 0usize;
    let mut index_rebuilt_from_absent = 0usize;
    let mut index_rebuilt_from_stale = 0usize;
    // A BTreeSet iterates in sorted order, so the list, the census and every count below are a
    // function of the admitted corpus alone and not of directory iteration order.
    for descriptor_ref in &authorized {
        match resolve_admitted_surface_descriptor(&st.data_dir, &identity, descriptor_ref) {
            Ok(resolved) => {
                match resolved.index_state {
                    "agreed_with_agentgres" => index_agreed += 1,
                    "absent_rebuilt_from_agentgres" => index_rebuilt_from_absent += 1,
                    _ => index_rebuilt_from_stale += 1,
                }
                // Surviving tombstones are the durable record of a withdrawal, not a live
                // descriptor. They are COUNTED rather than silently dropped, so a caller can tell a
                // corpus of three that never grew from one that was withdrawn down to it.
                if matches!(resolved.status.as_str(), "revoked" | "deleted") {
                    withdrawn += 1;
                    continue;
                }
                items.push(resolved.record);
            }
            // A stream this caller holds a scope for but cannot project is NAMED. Dropping it would
            // make an unreadable descriptor indistinguishable from an absent one.
            Err((status, Json(payload))) => unreadable.push(json!({
                "surface_descriptor_ref": descriptor_ref,
                "status": status.as_u16(),
                "code": payload.pointer("/error/code").cloned().unwrap_or(Value::Null),
            })),
        }
    }
    let resolved_count = items.len();

    if let Some(cp) = q
        .get("composition_pattern")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|d| d.get("composition_pattern").and_then(|v| v.as_str()) == Some(cp));
    }
    // CANONICAL NAME ON THE QUERY TOO. v2 binds `ontology_refs`; a stored v1 has the singular
    // `ontology_ref`. One parameter matches either, because the caller is asking about a binding
    // rather than about which contract version happens to hold it.
    if let Some(oref) = q
        .get("ontology_refs")
        .or_else(|| q.get("ontology_ref"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|d| {
            d.get("ontology_ref").and_then(|v| v.as_str()) == Some(oref)
                || d.get("ontology_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(oref)))
        });
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "surface_descriptors": items,
            // Answered from the owner chain, not from the rebuildable projection, so destroying the
            // index cannot shorten this list.
            "projection_source": "agentgres_owner_chain",
            // EVERY NUMBER HERE IS A FACT ABOUT THIS CALLER'S OWN DESCRIPTORS. Nothing is derived
            // from the substrate at large, so no count moves when another tenant writes.
            "census": {
                "census_scope": "this_caller_only",
                "authorized_for_this_caller": authorized.len(),
                "resolved_from_chain": resolved_count,
                "withdrawn_and_hidden": withdrawn,
                "unreadable": unreadable,
                "index_agreed_with_chain": index_agreed,
                "index_absent_answered_from_chain": index_rebuilt_from_absent,
                "index_stale_answered_from_chain": index_rebuilt_from_stale,
            },
            "authority_nonclaim": DESCRIPTOR_AUTHORITY_NONCLAIM,
            "truth_nonclaim": DESCRIPTOR_TRUTH_NONCLAIM,
        })),
    )
}

/// POST /v1/hypervisor/odk/surface-descriptors — create an OntologySurfaceDescriptor DRAFT bound to
/// an ontology (+ optional recipe refs). `composition_pattern` must be one of the canonical patterns.
/// `domain_app` is allowed as a pattern, but NO DomainApp object is created here.
// ======================= M05.5 · THE INVARIANT-11 BINDING SET AND FIELD CONVERGENCE ==============
//
// WHAT WAS ABSENT AND WHY IT MATTERED. Non-negotiable 11 requires every ODK-generated surface to
// declare owning ontology refs, object-model refs, data-recipe refs where applicable, policy-bound
// data view refs, authority requirements, daemon/API dependencies, receipt obligations and
// conformance expectations BEFORE it becomes durable product inventory. The v1 record carried none
// of the eight. It also named its ontology binding `ontology_ref` (singular) and its recipes
// `recipe_refs` — the unqualified name the term-boundary ruling forbids — so a stored descriptor
// could not be checked against invariant 11 even in principle, and the field names diverged from the
// canonical envelope in `objects/semantic-plane.md`.
//
// FIVE PROPERTIES ARE STRUCTURAL RATHER THAN DOCUMENTARY:
//
// 1. THE BINDING SET IS CARRIED, NOT DESCRIBED. All eight members are required fields of the
//    registered v2 contract, and the record declares the set it satisfies, so a relying party with
//    only the bytes can check invariant 11 without asking this daemon anything.
//
// 2. LEGACY NAMES ARE REFUSED, NOT TRANSLATED. `ontology_ref` and `recipe_refs` on an authoring
//    request are a typed refusal. Silently mapping them onto the canonical names would make the
//    convergence invisible and leave two spellings alive for the same fact.
//
// 3. ONTOLOGY REFS ARE OWNER-RESOLVED AND EXACT. Each is an admitted revision resolved through
//    `ontology_version_routes::resolve_admitted_revision`, and that owner's committed hash is bound
//    verbatim. A family head — `ontology://ns/name` — is refused: durable product inventory may not
//    silently re-mean itself when the family advances.
//
// 4. AUTHORING IS AN ORDINARY GOVERNED MUTATION. It crosses `odk_admit` — authenticated owner scope,
//    caller idempotency, compare-and-swap, Agentgres admission, receipt — and NOT a CapabilityLease
//    or an AuthorityGrant. The stale wording that said otherwise was withdrawn by ruling and the
//    record carries `capability_lease_crossing` as an explicit nonclaim so it cannot creep back.
//
// 5. v1 IS READABLE, NEVER REINTERPRETED. A stored v1 record keeps its own `schema_version` and is
//    served as itself; nothing here reads one AS a v2. Converging one is an explicit act that names
//    the predecessor and the exact bytes it came from.

/// The eight canonical members of the invariant-11 binding set, in canon's own order.
const INVARIANT_11_BINDING_SET: &[&str] = &[
    "ontology_refs",
    "canonical_object_model_refs",
    "data_recipe_refs",
    "policy_bound_data_view_refs",
    "authority_requirement_refs",
    "daemon_api_refs",
    "receipt_obligations",
    "conformance_profile_refs",
];

/// The legacy names v1 used for two of those members. Refused on authoring, never translated.
const LEGACY_DESCRIPTOR_FIELDS: &[(&str, &str)] = &[
    ("ontology_ref", "ontology_refs"),
    ("recipe_refs", "data_recipe_refs"),
];

const DESCRIPTOR_V2_SCHEMA_VERSION: &str = "ioi.ontology-surface-descriptor.v2";
const DESCRIPTOR_V1_SCHEMA_VERSION: &str = "ioi.hypervisor.odk.surface-descriptor.v1";
const DESCRIPTOR_V2_CONTRACT_ID: &str =
    "schema://ioi/foundations/objects/ontology-surface-descriptor/v2";
/// The registered predecessor: DEPRECATED and READ-ONLY. It exists so a convergence can name its
/// source contract exactly and hash that source under its own material list, and so "v1 carries none
/// of the invariant-11 binding set" is a checked expectation rather than a claim in prose.
const DESCRIPTOR_V1_CONTRACT_ID: &str =
    "schema://ioi/foundations/objects/ontology-surface-descriptor/v1";
const DESCRIPTOR_AUTHORITY_NONCLAIM: &str = "ontology_surface_descriptor_grants_no_authority";
const DESCRIPTOR_TRUTH_NONCLAIM: &str =
    "ontology_surface_descriptor_is_not_runtime_or_semantic_truth";
/// NN 10 as a runtime refusal as well as a schema shape.
const DESCRIPTOR_REQUIRED_NONCLAIMS: &[&str] = &[
    "authority",
    "capability_lease_crossing",
    "runtime_truth",
    "semantic_truth",
    "permission_truth",
    "marketplace_truth",
];

fn descriptor_refuse(code: &str, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

/// A required non-empty ref set whose every member carries one of `schemes`.
fn descriptor_ref_set(
    body: &Value,
    key: &str,
    schemes: &[&str],
    min: usize,
) -> Result<Value, (StatusCode, Json<Value>)> {
    let Some(entries) = body.get(key) else {
        return Err(descriptor_refuse(
            "odk_descriptor_binding_member_absent",
            format!(
                "'{key}' is a member of the invariant-11 binding set and must be present; an absent member and a declared empty one are different findings, and a surface that declares neither cannot be checked against invariant 11"
            ),
        ));
    };
    let Some(entries) = entries.as_array() else {
        return Err(descriptor_refuse(
            "odk_descriptor_binding_member_malformed",
            format!("'{key}' must be an array of refs"),
        ));
    };
    if entries.len() < min {
        return Err(descriptor_refuse(
            "odk_descriptor_binding_member_empty",
            format!("'{key}' needs at least {min} ref(s)"),
        ));
    }
    let mut seen: Vec<String> = Vec::new();
    for entry in entries {
        let value = entry.as_str().unwrap_or("").trim().to_string();
        if !schemes.iter().any(|scheme| value.starts_with(scheme)) {
            return Err(descriptor_refuse(
                "odk_descriptor_binding_ref_not_canonical",
                format!("'{key}' carries '{value}', which is not one of {schemes:?}"),
            ));
        }
        if seen.contains(&value) {
            return Err(descriptor_refuse(
                "odk_descriptor_binding_ref_duplicated",
                format!("'{key}' declares '{value}' twice"),
            ));
        }
        seen.push(value);
    }
    Ok(json!(seen))
}

/// Build one admitted v2 descriptor record, or refuse.
fn build_descriptor_v2(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    body: &Value,
    id: &str,
    owner_ref: &str,
    pattern: &str,
) -> Result<Value, (StatusCode, Json<Value>)> {
    // THE VERSION GATE IS FIRST AND IT REFUSES RATHER THAN DOWNGRADING.
    match body.get("schema_version") {
        Some(Value::String(declared)) if declared == DESCRIPTOR_V2_SCHEMA_VERSION => {}
        Some(Value::String(declared)) if declared == DESCRIPTOR_V1_SCHEMA_VERSION => {
            return Err(descriptor_refuse(
                "odk_descriptor_version_superseded",
                format!(
                    "'{DESCRIPTOR_V1_SCHEMA_VERSION}' carries none of the invariant-11 binding set and is no longer authorable; new descriptors are authored at '{DESCRIPTOR_V2_SCHEMA_VERSION}'. Stored v1 records remain readable and are never reinterpreted as v2"
                ),
            ))
        }
        Some(declared) => {
            return Err(descriptor_refuse(
                "odk_descriptor_version_unsupported",
                format!(
                    "this build authors {DESCRIPTOR_V2_SCHEMA_VERSION} only; '{declared}' is refused rather than downgraded"
                ),
            ))
        }
        None => {
            return Err(descriptor_refuse(
                "odk_descriptor_version_required",
                format!(
                    "schema_version is required and must be '{DESCRIPTOR_V2_SCHEMA_VERSION}'; an unversioned authoring request used to mint a descriptor with no binding set at all"
                ),
            ))
        }
    }

    // LEGACY NAMES ARE REFUSED, NOT TRANSLATED. Mapping them silently would leave two live spellings
    // for one fact and make the convergence invisible to everyone downstream.
    for (legacy, canonical) in LEGACY_DESCRIPTOR_FIELDS {
        if body.get(*legacy).is_some() {
            return Err(descriptor_refuse(
                "odk_descriptor_legacy_field_name",
                format!(
                    "'{legacy}' is the v1 name for '{canonical}'; it is refused rather than translated, because silently accepting it would keep two spellings alive for one canonical field"
                ),
            ));
        }
    }

    let display_name = body
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if display_name.is_empty() || display_name.len() > 160 {
        return Err(descriptor_refuse(
            "odk_descriptor_display_name_required",
            "display_name is required and is 1..160 characters",
        ));
    }
    let surface_ref = body
        .get("surface_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if !surface_ref.starts_with("surface://") || surface_ref.len() > 250 {
        return Err(descriptor_refuse(
            "odk_descriptor_surface_ref_not_canonical",
            "surface_ref must be a 'surface://' ref",
        ));
    }

    // THE EIGHT MEMBERS. `data_recipe_refs` may be empty — canon says 'where applicable' — but it
    // must be PRESENT, because an absent member and a declared 'this surface binds none' are
    // different findings and only one of them is checkable.
    let ontology_refs = descriptor_ref_set(body, "ontology_refs", &["ontology://"], 1)?;
    let object_models =
        descriptor_ref_set(body, "canonical_object_model_refs", &["object-model://"], 1)?;
    let data_recipes = descriptor_ref_set(body, "data_recipe_refs", &["data-recipe://"], 0)?;
    let policy_views = descriptor_ref_set(body, "policy_bound_data_view_refs", &["view://"], 1)?;
    let authority_requirements = descriptor_ref_set(
        body,
        "authority_requirement_refs",
        &["policy://", "grant://", "scope:"],
        1,
    )?;
    let daemon_apis = descriptor_ref_set(body, "daemon_api_refs", &["api://"], 1)?;
    let receipt_obligations = descriptor_ref_set(body, "receipt_obligations", &["receipt://"], 1)?;
    let conformance_profiles =
        descriptor_ref_set(body, "conformance_profile_refs", &["profile://"], 1)?;

    // The remaining canonical envelope members. Optional in cardinality, required in presence.
    let connector_mappings =
        descriptor_ref_set(body, "connector_mapping_refs", &["mapping://"], 0)?;
    let projections = descriptor_ref_set(body, "ontology_projection_refs", &["projection://"], 0)?;
    let allowed_actions = descriptor_ref_set(
        body,
        "allowed_action_refs",
        &["action://", "ontology-action://"],
        0,
    )?;
    let operator_contracts =
        descriptor_ref_set(body, "operator_contract_refs", &["contract://"], 0)?;
    let mcp_contracts = descriptor_ref_set(body, "mcp_contract_refs", &["mcp-profile://"], 0)?;
    let generated_artifacts =
        descriptor_ref_set(body, "generated_artifact_refs", &["artifact://"], 0)?;

    // OWNER RESOLUTION, NOT A PREFIX CHECK. Each ontology ref is resolved by the family's own
    // published reader, which also decides authorization, and that owner's committed hash is bound
    // verbatim. A caller with no scope on a family cannot bind it, and a family head is refused by
    // the resolver's own identity parser before anything else happens.
    let mut bound = Vec::new();
    for entry in ontology_refs.as_array().into_iter().flatten() {
        let reference = entry.as_str().unwrap_or_default();
        let resolved = super::ontology_version_routes::resolve_admitted_revision(
            data_dir, identity, reference,
        )
        .map_err(|(status, Json(payload))| {
            (
                status,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "odk_descriptor_ontology_ref_unresolved",
                        "message": format!(
                            "'{reference}' is not an exact admitted ontology revision this caller may bind; a surface descriptor binds owner-resolved revisions, never a family head and never a ref it merely spells correctly"
                        ),
                        "owner_refusal": payload,
                    }
                })),
            )
        })?;
        bound.push(json!({
            "ontology_revision_ref": resolved.ontology_id,
            "ontology_content_hash": resolved.content_hash,
        }));
    }

    // THE NONCLAIM SET IS READ STRICTLY, BECAUSE FILTERING IT SILENTLY REWROTE THE CALLER'S CLAIM.
    //
    // `filter_map(Value::as_str)` DROPS every member that is not a string, and `.and_then(as_array)`
    // turned a non-array into an empty list. So `does_not_assert: {"authority": true}` and
    // `does_not_assert: [1, 2, 3]` both became `[]` — refused, but for "incomplete" rather than for
    // being unreadable — while `["authority", 7, "runtime_truth", …]` silently DISCARDED the 7 and
    // admitted a record whose nonclaim set was not the one the caller sent. A nonclaim is the record
    // saying what it does not confer; quietly editing it is the one edit that must never be silent.
    // Duplicates are refused for the same reason: the schema's `uniqueItems` would fail the record
    // later with a shape complaint, and the caller's actual mistake — saying the same thing twice —
    // is a fact this route can name.
    let declared_nonclaims: Vec<String> = match body.get("does_not_assert") {
        Some(Value::Array(entries)) => {
            let mut tokens: Vec<String> = Vec::with_capacity(entries.len());
            for entry in entries {
                let Some(token) = entry.as_str() else {
                    return Err(descriptor_refuse(
                        "odk_descriptor_nonclaim_not_canonical",
                        "every member of does_not_assert is one of the closed vocabulary's string tokens; a non-string member is refused rather than filtered out, because dropping it would admit a nonclaim set the caller did not send",
                    ));
                };
                if tokens.iter().any(|seen| seen == token) {
                    return Err(descriptor_refuse(
                        "odk_descriptor_nonclaim_duplicated",
                        format!("does_not_assert declares '{token}' twice; the set is a set"),
                    ));
                }
                tokens.push(token.to_string());
            }
            tokens
        }
        _ => {
            return Err(descriptor_refuse(
                "odk_descriptor_nonclaim_not_canonical",
                "does_not_assert is required and must be an array of the closed vocabulary's string tokens",
            ))
        }
    };
    if let Some(missing) = DESCRIPTOR_REQUIRED_NONCLAIMS
        .iter()
        .find(|required| !declared_nonclaims.iter().any(|token| token == *required))
    {
        return Err(descriptor_refuse(
            "odk_descriptor_nonclaim_incomplete",
            format!(
                "a descriptor must explicitly disclaim '{missing}': a descriptor that does not say so is read as claiming it by omission, and `capability_lease_crossing` in particular is the wording a withdrawn ruling once made true"
            ),
        ));
    }

    let migration = descriptor_migration_block(data_dir, identity, body, id, owner_ref)?;

    let record = assemble_descriptor_v2(
        id,
        surface_ref,
        display_name,
        owner_ref,
        pattern,
        ontology_refs,
        bound,
        [
            object_models,
            data_recipes,
            connector_mappings,
            policy_views,
            projections,
            allowed_actions,
            daemon_apis,
            operator_contracts,
            mcp_contracts,
            authority_requirements,
            receipt_obligations,
            conformance_profiles,
            generated_artifacts,
        ],
        migration,
        declared_nonclaims,
    );
    finish_descriptor_v2(record, body)
}
/// Derive one descriptor's migration block, or refuse.
///
/// MIGRATION IS EXPLICIT, OWNER-RESOLVED, AND SAME-OWNER. A descriptor converged from a stored v1
/// names that predecessor and the exact bytes it came from; one authored fresh names none. A v1
/// record is never read AS a v2.
///
/// THE SOURCE COMES FROM THE CHAIN, NOT THE ROW. Loading the local record directory made a
/// rebuildable projection load-bearing for a durable commitment: delete the row and a convergence
/// refuses over a predecessor its owner still holds; corrupt it and the descriptor commits the hash
/// of the corruption. It also skipped authorization entirely, so a caller could converge from
/// ANOTHER TENANT'S descriptor and, because the commitment is carried in the successor, learn that
/// tenant's exact record bytes. The owner reader applies this family's own scope, and the explicit
/// owner comparison below closes the remaining case where one principal holds scope on both.
///
/// It is a NAMED SEAM rather than an inline block because it is the whole of the historical-upgrade
/// contract, and the upgrade path is the one path a fresh deployment can never reach through the
/// public API: this build refuses to author the v1 a convergence needs, by design. So
/// `the_historical_v1_upgrade_converges_restarts_and_replays` seeds a real v1 through the same
/// owner-scoped admission foundation the legacy lane used and drives THIS function — the production
/// derivation, not a copy of it — for the success case and for every refusal.
fn descriptor_migration_block(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    body: &Value,
    id: &str,
    owner_ref: &str,
) -> Result<Value, (StatusCode, Json<Value>)> {
    Ok(
        match body
            .get(DESCRIPTOR_MIGRATION_SOURCE_KEY)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            None => json!({
                "from_schema_version": Value::Null,
                "from_descriptor_ref": Value::Null,
                "from_content_hash": Value::Null,
                "compatibility": "initial",
                "reinterprets_predecessor": false,
            }),
            Some(predecessor_ref) => {
                if !matches!(split_ref(predecessor_ref), Some(("surface-descriptor", _))) {
                    return Err(descriptor_refuse(
                        "odk_descriptor_migration_source_not_canonical",
                        "migrated_from_descriptor_ref must be a 'surface-descriptor://' ref",
                    ));
                }
                if predecessor_ref == format!("surface-descriptor://{id}") {
                    return Err(descriptor_refuse(
                    "odk_descriptor_migration_source_is_itself",
                    "a descriptor is never converged from itself: a convergence mints a new record from a predecessor's bytes, and a record naming itself has a cycle rather than a provenance",
                ));
                }
                let predecessor =
                resolve_admitted_surface_descriptor(data_dir, identity, predecessor_ref).map_err(
                    |(_, Json(payload))| {
                        descriptor_refuse(
                            "odk_descriptor_migration_source_unresolved",
                            format!(
                                "'{predecessor_ref}' does not resolve to an admitted descriptor this caller may converge from: {}",
                                payload
                                    .pointer("/error/message")
                                    .and_then(Value::as_str)
                                    .unwrap_or("refused by its owner")
                            ),
                        )
                    },
                )?;
                // A CONVERGENCE DOES NOT CROSS AN OWNERSHIP BOUNDARY. The successor is owned by this
                // request's owner, so a predecessor owned by anyone else would move a record between
                // owners under the name of a migration.
                if predecessor.record.get("owner_ref").and_then(Value::as_str) != Some(owner_ref) {
                    return Err(descriptor_refuse(
                    "odk_descriptor_migration_source_owner_mismatch",
                    "a convergence names a predecessor owned by the SAME owner as the successor; a migration is not a way to move a descriptor between owners",
                ));
                }
                // DOWNGRADE AND SIDEWAYS-MIGRATION BOTH FAIL CLOSED. Only the registered, deprecated v1
                // is a legitimate source: a v2 is never converged from another v2, and an unknown stored
                // version is refused rather than hashed under a contract it was not admitted under.
                if predecessor.schema_version != DESCRIPTOR_V1_SCHEMA_VERSION {
                    return Err(descriptor_refuse(
                    "odk_descriptor_migration_source_not_v1",
                    format!(
                        "a convergence names a stored '{DESCRIPTOR_V1_SCHEMA_VERSION}' predecessor; '{}' is refused rather than converged, because a record is only ever hashed under the contract it was admitted under",
                        predecessor.schema_version
                    ),
                ));
                }
                // The predecessor is checked against its OWN registered contract before its bytes become
                // a durable commitment: a source this build cannot project is a refusal here, not a hash
                // of something nobody can name.
                if let Err(reason) =
                ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                    DESCRIPTOR_V1_CONTRACT_ID,
                    &predecessor.record,
                )
            {
                return Err(descriptor_refuse(
                    "odk_descriptor_migration_source_not_registered_valid",
                    format!("the v1 predecessor is not valid against its own registered contract: {reason}"),
                ));
            }
                let from_content_hash = descriptor_v1_content_hash(&predecessor.record);
                // A CALLER MAY PIN THE SOURCE BYTES, AND A CHANGED SOURCE THEN REFUSES. Without this a
                // convergence silently commits whatever the predecessor says at the instant it runs, so
                // a caller that read a v1, decided to converge it, and raced a change to it would freeze
                // bytes it never saw.
                if let Asserted::Present(asserted) =
                    descriptor_asserted_str(body, "expected_migration_source_content_hash")
                {
                    if asserted != from_content_hash {
                        return Err(descriptor_refuse(
                        "odk_descriptor_migration_source_substituted",
                        "expected_migration_source_content_hash does not match the predecessor's current admitted bytes; the source changed after it was read, and a convergence commits bytes the caller actually saw",
                    ));
                    }
                }
                json!({
                    "from_schema_version": DESCRIPTOR_V1_SCHEMA_VERSION,
                    "from_descriptor_ref": predecessor_ref,
                    "from_content_hash": from_content_hash,
                    "compatibility": "converged_from_v1",
                    "reinterprets_predecessor": false,
                })
            }
        },
    )
}

/// Assemble one admitted v2 descriptor from its already-validated parts.
///
/// Separated from `build_descriptor_v2` so the record shape has ONE producer: the authoring route
/// and the historical-upgrade proof assemble the same bytes through the same function, and a field
/// added here reaches both without either being edited.
#[allow(clippy::too_many_arguments)]
fn assemble_descriptor_v2(
    id: &str,
    surface_ref: &str,
    display_name: &str,
    owner_ref: &str,
    pattern: &str,
    ontology_refs: Value,
    bound: Vec<Value>,
    members: [Value; 13],
    migration: Value,
    declared_nonclaims: Vec<String>,
) -> Value {
    let [object_models, data_recipes, connector_mappings, policy_views, projections, allowed_actions, daemon_apis, operator_contracts, mcp_contracts, authority_requirements, receipt_obligations, conformance_profiles, generated_artifacts] =
        members;
    let mut record = json!({
        "schema_version": DESCRIPTOR_V2_SCHEMA_VERSION,
        "surface_descriptor_id": format!("surface-descriptor://{id}"),
        "descriptor_record_profile": "ontology_surface_descriptor",
        "surface_ref": surface_ref,
        "display_name": display_name,
        "owner_ref": owner_ref,
        "composition_pattern": pattern,
        "ontology_refs": ontology_refs,
        "bound_ontology_revisions": bound,
        "bound_ontology_revision_count": bound.len(),
        "ontology_resolved_by": "ontology_version_routes::resolve_admitted_revision",
        "canonical_object_model_refs": object_models,
        "data_recipe_refs": data_recipes,
        "connector_mapping_refs": connector_mappings,
        "policy_bound_data_view_refs": policy_views,
        "ontology_projection_refs": projections,
        "allowed_action_refs": allowed_actions,
        "daemon_api_refs": daemon_apis,
        "operator_contract_refs": operator_contracts,
        "mcp_contract_refs": mcp_contracts,
        "authority_requirement_refs": authority_requirements,
        "receipt_obligations": receipt_obligations,
        "conformance_profile_refs": conformance_profiles,
        "generated_artifact_refs": generated_artifacts,
        "invariant_11_binding_set": INVARIANT_11_BINDING_SET,
        "invariant_11_member_count": INVARIANT_11_BINDING_SET.len(),
        "migration": migration,
        "constants": {
            "member_ontology_refs": "ontology_refs",
            "member_canonical_object_model_refs": "canonical_object_model_refs",
            "member_data_recipe_refs": "data_recipe_refs",
            "member_policy_bound_data_view_refs": "policy_bound_data_view_refs",
            "member_authority_requirement_refs": "authority_requirement_refs",
            "member_daemon_api_refs": "daemon_api_refs",
            "member_receipt_obligations": "receipt_obligations",
            "member_conformance_profile_refs": "conformance_profile_refs",
            "nonclaim_authority_token": "authority",
        },
        "authority_nonclaim": DESCRIPTOR_AUTHORITY_NONCLAIM,
        "truth_nonclaim": DESCRIPTOR_TRUTH_NONCLAIM,
        "does_not_assert": declared_nonclaims,
        "status": "draft",
    });
    record["content_hash"] = json!(descriptor_content_hash(&record));
    record
}

/// Validate one assembled record against the REGISTERED contract before it can be admitted.
fn descriptor_registered_valid(record: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        DESCRIPTOR_V2_CONTRACT_ID,
        record,
    )
    .map_err(|reason| {
        descriptor_refuse(
            "odk_descriptor_not_registered_valid",
            format!("the descriptor this request builds is not registered-valid: {reason}"),
        )
    })
}

fn finish_descriptor_v2(record: Value, body: &Value) -> Result<Value, (StatusCode, Json<Value>)> {
    // The projected record is validated against the REGISTERED contract before it can be admitted,
    // so an unprojectable descriptor is a refusal here rather than permanently durable bytes that
    // the read path can only answer 502 about.
    descriptor_registered_valid(&record)?;

    // The caller's remaining assertions are answered against the record this request actually built,
    // which is where those facts now exist. The same checker answers them on the replay path against
    // the stored record, so a claim is examined whether the command is fresh or a duplicate — and
    // both paths refuse by the same cause, so a caller cannot tell them apart by the shape of a
    // refusal.
    if let Some(response) = descriptor_assertion_divergence(&record, body) {
        return Err(response);
    }
    Ok(record)
}

// ------------------------------------------------- the published descriptor resolution seam

/// One admitted descriptor, resolved from the Agentgres chain rather than from the read model.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedSurfaceDescriptor {
    pub(crate) descriptor_ref: String,
    pub(crate) schema_version: String,
    pub(crate) composition_pattern: String,
    pub(crate) status: String,
    /// The canonical admitted record, byte-exact as the chain holds it.
    pub(crate) record: Value,
    pub(crate) admitted_head: String,
    pub(crate) revision_count: usize,
    /// Whether the local row agreed with the chain, was rebuilt, or was absent entirely.
    pub(crate) index_state: &'static str,
    /// The row's runtime metadata, DERIVED FROM THE ADMITTED HISTORY: the admission stamp of this
    /// descriptor's genesis operation and of its latest one. They are a function of the chain, so
    /// they survive the row being deleted and are unaffected by the row being corrupted.
    pub(crate) projected_created_at: String,
    pub(crate) projected_updated_at: String,
}

/// Resolve one descriptor for a caller entitled to see it, FROM THE CHAIN.
///
/// THIS EXISTS BECAUSE THE ROW WAS THE ANSWER AND SHOULD NEVER HAVE BEEN. Every descriptor read —
/// list, get, patch, delete, and both consumer routes — used to load the local record directory. That
/// makes the rebuildable projection load-bearing: delete the row and the descriptor is gone, corrupt
/// it and the descriptor is whatever the corruption says, even though the Agentgres owner chain still
/// holds the admitted truth. A projection whose loss changes the answer is not a projection.
///
/// So this reads the owner-scoped operation history, takes the last admitted payload as the record,
/// and reports what the row DID say — it is never consulted for the answer. Authorization is the same
/// owner seam the writes cross, so a caller with no scope on this descriptor learns nothing about
/// whether it exists.
///
/// GRANTS NOTHING. It returns a record, a head and a status. Reading a descriptor is not permission
/// to mount, serve, register or act on the surface it describes.
pub(crate) fn resolve_admitted_surface_descriptor(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    descriptor_ref: &str,
) -> Result<ResolvedSurfaceDescriptor, (StatusCode, Json<Value>)> {
    let Some(("surface-descriptor", id)) = split_ref(descriptor_ref) else {
        return Err(descriptor_refuse(
            "odk_descriptor_ref_not_canonical",
            "a descriptor is addressed as 'surface-descriptor://<id>'",
        ));
    };
    let scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        ODK_DESCRIPTOR_SCOPE_KIND,
        descriptor_ref,
        None,
    )
    .map_err(odk_scope_refusal)?;
    let tail = odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, descriptor_ref);
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        data_dir,
        identity,
        &scope,
        ODK_DESCRIPTOR_SCOPE_KIND,
        descriptor_ref,
        ODK_NAMESPACE,
        &tail,
    )
    .map_err(odk_mutation_refusal)?;
    let Some(latest) = history.last() else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "odk_surface_descriptor_not_found",
                    "message": "this descriptor has no admitted history — an absent descriptor is a typed absence, never an empty success"
                }
            })),
        ));
    };
    let record = latest.operation.payload.clone();
    let schema_version = record
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // EVERY VERSION IS VALIDATED, AND AN UNKNOWN ONE FAILS CLOSED.
    //
    // Only v2 was checked here, so the other two cases fell through to `Ok`: a stored v1 was served
    // unvalidated, and a record carrying ANY other `schema_version` — including none at all — was
    // served as though this build understood it. That is the exact shape of the defect this module
    // keeps finding: the unknown case taking the success path because nobody wrote an arm for it.
    // Both consumers then read that record's fields, and a field this build cannot interpret reads as
    // ABSENT rather than as an error.
    //
    // v1 has been a registered contract since this unit landed, so there is no longer any reason for
    // it to be the unchecked half. It is validated against its OWN contract — never against v2's,
    // which would be reinterpreting it — and anything else is a typed refusal.
    let contract_id = match schema_version.as_str() {
        DESCRIPTOR_V2_SCHEMA_VERSION => DESCRIPTOR_V2_CONTRACT_ID,
        DESCRIPTOR_V1_SCHEMA_VERSION => DESCRIPTOR_V1_CONTRACT_ID,
        unknown => {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "odk_descriptor_version_unsupported",
                        "message": format!(
                            "the chain holds a descriptor admitted as '{unknown}', which this build neither authors nor projects; an unrecognised stored version is refused rather than served as though it were understood"
                        )
                    }
                })),
            ))
        }
    };
    if let Err(reason) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            contract_id,
            &record,
        )
    {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "odk_descriptor_projection_failed",
                    "message": format!("the chain holds a descriptor this build cannot project against {contract_id}: {reason}")
                }
            })),
        ));
    }

    // THE ROW'S RUNTIME METADATA IS DERIVED HERE, FROM THE HISTORY THIS FUNCTION ALREADY READ.
    //
    // It used to be recovered from the row itself, which made it the one part of a "rebuildable"
    // projection that was not rebuildable: repairing a DELETED row wrote `created_at: null` and
    // `updated_at: null`, and repairing a CORRUPTED one copied whatever the corruption said straight
    // back out — the exact bytes a repair exists to discard. The chain records when each operation
    // was admitted, so both stamps are a function of the admitted history: creation is the genesis
    // operation's admission stamp and last-update is the latest one's. `first()` is safe because
    // `last()` above already established the history is non-empty.
    let projected_created_at = history
        .first()
        .map(|entry| admitted_stamp_ms(entry.operation.recorded_at_ms))
        .unwrap_or_default();
    let projected_updated_at = admitted_stamp_ms(latest.operation.recorded_at_ms);

    // THE ROW IS COMPARED, NEVER CONSULTED. Reporting agreement positively is what lets a verifier
    // prove the rebuild happened rather than infer it from an unchanged answer. The comparison is
    // against the WHOLE row a rebuild would write, not just the record inside it, so
    // `agreed_with_agentgres` means byte-identical-to-the-repair rather than merely
    // carrying-the-right-record — a row whose metadata drifted is stale and gets repaired.
    let expected = descriptor_row(&record, &projected_created_at, &projected_updated_at)?;
    let row = load(data_dir, KIND_SD, id);
    let index_state = match row.as_ref() {
        None => "absent_rebuilt_from_agentgres",
        Some(row) if *row == expected => "agreed_with_agentgres",
        Some(_) => "stale_rebuilt_from_agentgres",
    };

    Ok(ResolvedSurfaceDescriptor {
        descriptor_ref: descriptor_ref.to_string(),
        composition_pattern: record
            .get("composition_pattern")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        status: record
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        schema_version,
        record,
        admitted_head: latest.head.clone(),
        revision_count: history.len(),
        index_state,
        projected_created_at,
        projected_updated_at,
    })
}

/// Rebuild the local read-model row for one descriptor from the chain, and report what changed.
///
/// A PURE FUNCTION OF THE ADMITTED HISTORY. Nothing about the row being replaced is read: not its
/// bytes, not its shape, and — since this cut — not its timestamps either. That is what makes the
/// repair deterministic and idempotent, and it is the whole point: a repair that copies anything out
/// of the thing it is repairing carries the damage forward. It used to carry exactly that. The
/// runtime metadata was recovered FROM the existing row, so repairing a deleted row wrote
/// `created_at: null` / `updated_at: null` and repairing a corrupted one preserved the corrupted
/// stamps verbatim — the two cases this function exists for were the two it could not fix. Both are
/// now derived by `resolve_admitted_surface_descriptor` from the operation history.
///
/// BOTH REGISTERED VERSIONS ARE REBUILT. This repaired only v2 and returned `Ok` for everything
/// else, so `POST …/rebuild-index` on a stored v1 answered `200` with the resolved record and wrote
/// NOTHING — a silent no-op that reads exactly like a successful repair. An operator who deleted a
/// v1 row and then ran the documented recovery would be told the recovery succeeded and still have
/// no row. The two versions store differently, and that difference is why the no-op was easy to miss:
/// a v2 row is a projection envelope wrapping the record, while a v1 row IS the record with its
/// runtime timestamps inlined, exactly as the legacy lane wrote it. `descriptor_row` owns that
/// dispatch for the write path and this one alike, so a rebuilt row is byte-identical to what the
/// write path produced BECAUSE IT IS THE SAME CALL — `odk_admit_with_identity` finishes a descriptor
/// admission by running this function. `resolve_admitted_surface_descriptor` has already refused any
/// unknown version, and `descriptor_row` refuses it a second time rather than defaulting.
pub(crate) fn rebuild_descriptor_row(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    descriptor_ref: &str,
) -> Result<ResolvedSurfaceDescriptor, (StatusCode, Json<Value>)> {
    let resolved = resolve_admitted_surface_descriptor(data_dir, identity, descriptor_ref)?;
    let Some(("surface-descriptor", id)) = split_ref(descriptor_ref) else {
        return Err(descriptor_refuse(
            "odk_descriptor_ref_not_canonical",
            "a descriptor is addressed as 'surface-descriptor://<id>'",
        ));
    };
    let row = descriptor_row(
        &resolved.record,
        &resolved.projected_created_at,
        &resolved.projected_updated_at,
    )?;
    persist_required(
        data_dir,
        KIND_SD,
        id,
        &row,
        "odk_surface_descriptor_persistence_failed",
    )?;
    Ok(resolved)
}

/// SHA-256 over the JCS bytes of a descriptor minus its own hash field.
/// The exact material the registered invariant
/// `ontology_surface_descriptor.content_hash.commits_the_whole_descriptor` commits: every field of
/// the contract except the hash itself, under a domain separator.
///
/// FLAT AND ENUMERATED, BECAUSE THAT IS WHAT THE INVARIANT LANGUAGE CAN CHECK. The first cut hashed
/// a nested `{domain, record}` preimage, which no supported operator can reproduce — so the
/// commitment was computed by this module and verified by NOTHING. A hash only this code can check
/// is not a commitment; it is a number the record carries. `material_fields` builds a flat map, so
/// the producer builds the same flat map, and the two agree by construction rather than by hope.
const DESCRIPTOR_CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "surface_descriptor_id",
    "descriptor_record_profile",
    "surface_ref",
    "display_name",
    "owner_ref",
    "composition_pattern",
    "ontology_refs",
    "bound_ontology_revisions",
    "bound_ontology_revision_count",
    "ontology_resolved_by",
    "canonical_object_model_refs",
    "data_recipe_refs",
    "policy_bound_data_view_refs",
    "authority_requirement_refs",
    "daemon_api_refs",
    "receipt_obligations",
    "conformance_profile_refs",
    "connector_mapping_refs",
    "ontology_projection_refs",
    "allowed_action_refs",
    "operator_contract_refs",
    "mcp_contract_refs",
    "generated_artifact_refs",
    "invariant_11_binding_set",
    "invariant_11_member_count",
    "migration",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "does_not_assert",
    "status",
];

const DESCRIPTOR_CONTENT_COMMITMENT_DOMAIN: &str =
    "ioi.ontology-surface-descriptor-content-commitment-jcs-sha256.v2";

fn descriptor_content_hash(record: &Value) -> String {
    domain_separated_hash(
        record,
        DESCRIPTOR_CONTENT_COMMITMENT_DOMAIN,
        DESCRIPTOR_CONTENT_MATERIAL_FIELDS,
    )
}

/// M05.6 — THE COMMITMENT A CONSUMER BINDS, DISPATCHED BY THE VERSION IT WAS ADMITTED UNDER.
///
/// A DomainApp's derived snapshot is a projection of one descriptor's bytes, so the app records
/// WHICH bytes. That number has to come from the descriptor owner, because only this module knows
/// that a v1 record is hashed over the v1 contract's four material fields under the v1 domain
/// separator and a v2 over the v2 contract's thirty-two under its own. A consumer computing it
/// itself would be a second producer of the same commitment, and the two would drift the first time
/// either contract gained a field.
///
/// Returns `None` for a record this build does not recognise. There is no default arm: a snapshot
/// bound to a hash produced by guessing which contract a record satisfies is worse than no binding,
/// because it reads exactly like a real one.
pub(crate) fn descriptor_content_commitment(record: &Value) -> Option<String> {
    match record.get("schema_version").and_then(Value::as_str) {
        Some(DESCRIPTOR_V2_SCHEMA_VERSION) => Some(descriptor_content_hash(record)),
        Some(DESCRIPTOR_V1_SCHEMA_VERSION) => Some(descriptor_v1_content_hash(record)),
        _ => None,
    }
}

/// THE PREDECESSOR IS HASHED UNDER ITS OWN CONTRACT, NOT UNDER ITS SUCCESSOR'S.
///
/// A convergence commits the exact bytes it came from, and `descriptor_content_hash` cannot produce
/// that number for a v1 record: its material list is the v2 contract's thirty-two fields, of which a
/// v1 record carries four. Hashing a v1 through it reads twenty-eight fields as absent, so every v1
/// descriptor sharing an owner, a pattern and a status commits to the SAME hash — and
/// `migration.from_content_hash` stops identifying one predecessor. A source that changed after a
/// convergence would then be indistinguishable from one that did not, which is the single thing the
/// field exists to make decidable.
///
/// The field list is the registered v1 contract's own `required` array, in its own order, and a
/// focused test asserts that — so a field added to the v1 schema and forgotten here fails there
/// rather than at the first convergence nobody can check.
const DESCRIPTOR_V1_CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "object",
    "id",
    "ref",
    "name",
    "description",
    "status",
    "composition_pattern",
    "ontology_ref",
    "recipe_refs",
    "owner_ref",
    "view_config",
];

const DESCRIPTOR_V1_CONTENT_COMMITMENT_DOMAIN: &str =
    "ioi.ontology-surface-descriptor-content-commitment-jcs-sha256.v1";

fn descriptor_v1_content_hash(record: &Value) -> String {
    domain_separated_hash(
        record,
        DESCRIPTOR_V1_CONTENT_COMMITMENT_DOMAIN,
        DESCRIPTOR_V1_CONTENT_MATERIAL_FIELDS,
    )
}

/// SHA-256 over the JCS bytes of a flat, domain-separated material map.
///
/// Flat and enumerated because that is what the portable invariant language can reproduce: a nested
/// preimage is a number only its producer can recompute, which is not a commitment.
///
/// M05.6 — SHARED WITH THE DOMAIN-APP FAMILIES RATHER THAN COPIED. The DomainApp, DomainAppRuntime
/// and DomainAppMountReceipt contracts commit themselves the same way, and a second implementation
/// of a commitment is a second answer waiting to disagree with the first.
pub(crate) fn domain_separated_hash(record: &Value, domain: &str, fields: &[&str]) -> String {
    use sha2::Digest;
    let mut material = serde_json::Map::new();
    material.insert("domain".into(), json!(domain));
    for field in fields {
        material.insert(
            (*field).to_string(),
            record.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    let bytes = serde_jcs::to_vec(&Value::Object(material)).unwrap_or_default();
    format!("sha256:{:x}", sha2::Sha256::digest(&bytes))
}

// ------------------------------------------------------------- history-stable replay, before anything
//
// WHY REPLAY MUST BE RESOLVED FIRST, AND FROM HISTORY. Agentgres normalises `expected_head`,
// `expected_absent` and `recorded_at_ms` out of its duplicate test, so a retry that observes a newer
// head is still a duplicate. What it CANNOT normalise away is the payload — and every descriptor
// handler rebuilt its payload out of live state before submitting it:
//
//   * `patch` applied the caller's fields onto the CURRENT row. Retry patch A after patch B landed
//     and the bytes are B-plus-A, not the A that key admitted: `SameKeyDifferentBytes`, a refusal
//     where a replay was owed, for a caller doing exactly what an ambiguous response requires.
//   * `delete` built its tombstone from the CURRENT record, with the same consequence.
//   * `create` re-derived `migration.from_content_hash` from the migration SOURCE. A source that
//     advanced between the first attempt and the retry changed the bytes of an already-admitted
//     command, so the convergence could never be retried again.
//
// So each handler now resolves its key against the admitted history BEFORE it reads dependencies,
// the local row, the migration source, or the head. When the key already admitted, the caller's full
// intent is compared against the stored record, its `expected_*` assertions are answered against that
// record, and the ORIGINAL admitted fact is returned. The world moving is not a reason to refuse a
// retry; the caller asking a different question is.

/// One descriptor's admitted history, as this caller is entitled to see it.
///
/// PURE READ, mirroring `mutation_event_foundation::admitted_history_for_caller` for a family whose
/// stream tail is hand-derived rather than the generic one. It reads the request scope instead of
/// binding it, so asking "did I already do this?" is not itself a mutation, and an authorization
/// mismatch answers EMPTY rather than a status: the question is "what have I already done here?",
/// "nothing" is the safe answer, and a refusal would be a fresh existence oracle for another
/// principal's id. Only a substrate failure surfaces as a typed refusal.
fn descriptor_admitted_history(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    expected_owner_ref: Option<&str>,
    descriptor_ref: &str,
) -> Result<Vec<agentgres::mux::ExactProjection>, (StatusCode, Json<Value>)> {
    use super::substrate_store::RequestScopeRefusal;
    let scope = match super::substrate_store::read_request_scope(
        data_dir,
        ODK_DESCRIPTOR_SCOPE_KIND,
        descriptor_ref,
    ) {
        Ok(Some(scope)) => scope,
        // No scope was ever reserved for this ref, so nothing was ever admitted under it.
        Ok(None) => return Ok(Vec::new()),
        Err(error @ RequestScopeRefusal::SubstrateUnavailable(_)) => {
            return Err(odk_scope_refusal(error))
        }
        Err(_) => return Ok(Vec::new()),
    };
    if scope.principal_ref != identity.principal_ref
        || !identity.authorizes_tenant(&scope.tenant_ref)
        || scope.tenant_ref != scope.owner_ref
        || expected_owner_ref.is_some_and(|owner_ref| owner_ref != scope.owner_ref)
    {
        return Ok(Vec::new());
    }
    super::mutation_event_foundation::read_owner_scoped_history(
        data_dir,
        identity,
        &scope,
        ODK_DESCRIPTOR_SCOPE_KIND,
        descriptor_ref,
        ODK_NAMESPACE,
        &odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, descriptor_ref),
    )
    .map_err(odk_mutation_refusal)
}

/// The exact admitted fact one key already recorded, returned as its own original reply.
///
/// The refs are rebuilt from the STORED projection with the same `agentgres::refs` calls the
/// admission path uses, so a replay hands back byte-identical coordinates rather than a
/// reconstruction that merely resembles them.
fn descriptor_replay_reply(
    descriptor_ref: &str,
    prior: &agentgres::mux::ExactProjection,
) -> (StatusCode, Json<Value>) {
    let tail = odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, descriptor_ref);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "surface_descriptor": prior.operation.payload,
            "replayed": true,
            "receipt_ref": agentgres::refs::event_stream_receipt_ref(
                ODK_NAMESPACE, &tail, prior.admission_batch_seq, &prior.admission_root),
            "operation_ref": agentgres::refs::event_stream_operation_ref(
                ODK_NAMESPACE, &tail, prior.seq, &prior.head),
            "authority_nonclaim": DESCRIPTOR_AUTHORITY_NONCLAIM,
            "truth_nonclaim": DESCRIPTOR_TRUTH_NONCLAIM,
        })),
    )
}

/// The contract fields a CALLER authors. A replay compares every one of them.
///
/// A LIST THAT MUST BE REMEMBERED IS NOT A FENCE, so this one does not stand alone: it is one half of
/// an exact partition of the contract's own material fields, and
/// `every_contract_field_is_either_caller_intent_or_server_authored` fails the moment a field is in
/// neither half or in both. Adding a field to the contract therefore forces a decision about whether
/// a caller authors it, rather than letting it default into the gap where it can be changed under an
/// already-admitted key and receive the original record back as though the request had been recorded.
const DESCRIPTOR_CALLER_INTENT_FIELDS: &[&str] = &[
    "schema_version",
    "surface_ref",
    "display_name",
    "owner_ref",
    "composition_pattern",
    "ontology_refs",
    "canonical_object_model_refs",
    "data_recipe_refs",
    "policy_bound_data_view_refs",
    "authority_requirement_refs",
    "daemon_api_refs",
    "receipt_obligations",
    "conformance_profile_refs",
    "connector_mapping_refs",
    "ontology_projection_refs",
    "allowed_action_refs",
    "operator_contract_refs",
    "mcp_contract_refs",
    "generated_artifact_refs",
    "does_not_assert",
];

/// The fields this server derives. A caller never authors them, so they are not part of the intent a
/// replay compares — comparing them would make a canonically-identical retry read as a changed one.
///
/// `migration` is here because the BLOCK is server-authored: the caller chooses only a predecessor
/// ref, and the contract, the compatibility label and the source hash are all derived from it. That
/// one caller choice is compared explicitly beside this list, under its request name.
const DESCRIPTOR_SERVER_AUTHORED_FIELDS: &[&str] = &[
    "surface_descriptor_id",
    "descriptor_record_profile",
    "bound_ontology_revisions",
    "bound_ontology_revision_count",
    "ontology_resolved_by",
    "invariant_11_binding_set",
    "invariant_11_member_count",
    "migration",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "status",
];

/// The caller's request name for the one migration input it chooses.
const DESCRIPTOR_MIGRATION_SOURCE_KEY: &str = "migrated_from_descriptor_ref";

/// The mutation-control inputs neither route derives: the caller's key and its head assertion.
const DESCRIPTOR_CONTROL_FIELDS: &[&str] = &["idempotency_key", "expected_head"];

/// The `expected_*` assertions these routes answer, named exactly.
const DESCRIPTOR_ASSERTION_FIELDS: &[&str] = &[
    "expected_descriptor_ref",
    "expected_content_hash",
    "expected_migration_source_content_hash",
    "expected_status",
    "expected_bound_ontology_content_hashes",
];

/// Every field a CREATE request may carry.
///
/// AN UNRECOGNISED FIELD IS A REFUSAL, NOT A SHRUG. Both routes read the fields they wanted and
/// ignored the rest, so a request could carry anything at all and be admitted as though it had not.
/// Three consequences, in rising order of seriousness. A caller that MISSPELLED a binding member —
/// `receipt_obligation`, `daemon_api_ref` — was told the correctly-spelled one was absent, which
/// points at the wrong field. A caller that sent a field this contract does not have got `201` and
/// read the reply as confirmation it had been stored. And a caller that sent an
/// AUTHORITY-LOOKING field — `authority_grant_ref`, `capability_lease_ref`, `granted_scopes`,
/// `authority_nonclaim: "…grants_authority"` — was ALSO told `201`, with a record that of course
/// contains no such thing. Nothing was granted, but the response is indistinguishable from one where
/// something was, and "the server accepted my grant field" is precisely the misreading a descriptor's
/// whole nonclaim vocabulary exists to prevent. Naming the closed set turns all three into one typed
/// refusal that says which field it did not recognise.
///
/// This list is checked against the contract by
/// `the_create_allowlist_is_exactly_caller_intent_plus_control_and_assertions`, so a member added to
/// the caller-intent half of the contract partition cannot be left unauthorable here.
const DESCRIPTOR_CREATE_REQUEST_FIELDS: &[&str] = &[
    // The caller-authored contract fields, minus `owner_ref` which is read separately below.
    "schema_version",
    "surface_ref",
    "display_name",
    "owner_ref",
    "composition_pattern",
    "ontology_refs",
    "canonical_object_model_refs",
    "data_recipe_refs",
    "policy_bound_data_view_refs",
    "authority_requirement_refs",
    "daemon_api_refs",
    "receipt_obligations",
    "conformance_profile_refs",
    "connector_mapping_refs",
    "ontology_projection_refs",
    "allowed_action_refs",
    "operator_contract_refs",
    "mcp_contract_refs",
    "generated_artifact_refs",
    "does_not_assert",
    // The one migration input a caller chooses.
    DESCRIPTOR_MIGRATION_SOURCE_KEY,
    // Mutation control and caller assertions.
    "idempotency_key",
    "expected_head",
    "expected_descriptor_ref",
    "expected_content_hash",
    "expected_migration_source_content_hash",
    "expected_status",
    "expected_bound_ontology_content_hashes",
];

/// Every field a PATCH request may carry.
///
/// `owner_ref` is DELIBERATELY ABSENT. A successor takes its owner from the admitted record, so a
/// body `owner_ref` was read by nothing and changed nothing — and a caller sending one was answered
/// `200` with a record still owned by someone else. Refusing it says the true thing: moving a
/// descriptor between owners is not an ordinary governed patch.
const DESCRIPTOR_PATCH_REQUEST_FIELDS: &[&str] = &[
    "display_name",
    "composition_pattern",
    "status",
    "idempotency_key",
    "expected_head",
    "expected_descriptor_ref",
    "expected_content_hash",
    "expected_migration_source_content_hash",
    "expected_status",
    "expected_bound_ontology_content_hashes",
];

/// Refuse any request field outside a route's closed set — by its MOST SPECIFIC cause.
///
/// THE ORDER OF THESE THREE ARMS IS THE POINT. A closed allowlist placed in front of two existing,
/// more informative refusals shadows both: `ontology_ref` on a create stops being "the v1 name for
/// `ontology_refs`, refused rather than translated" and becomes a generic "unknown field", and
/// `ontology_refs` on a patch stops being "a binding is not patchable — author a new descriptor" and
/// becomes that same generic thing. Both callers then receive a refusal that is true and useless,
/// and the two properties this unit spent its whole design establishing become invisible at the one
/// moment a caller would learn them. A field this route KNOWS about is answered by the rule that
/// knows why.
fn refuse_unknown_request_fields(
    body: &Value,
    allowed: &[&str],
    route: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(fields) = body.as_object() else {
        return Err(descriptor_refuse(
            "odk_descriptor_request_not_an_object",
            "a descriptor request is a JSON object",
        ));
    };
    for name in fields.keys() {
        let name = name.as_str();
        if allowed.contains(&name) {
            continue;
        }
        // A LEGACY SPELLING, refused rather than translated — on either route.
        if let Some((legacy, canonical)) = LEGACY_DESCRIPTOR_FIELDS
            .iter()
            .find(|(legacy, _)| *legacy == name)
        {
            return Err(descriptor_refuse(
                "odk_descriptor_legacy_field_name",
                format!(
                    "'{legacy}' is the v1 name for '{canonical}'; it is refused rather than translated, because silently accepting it would keep two spellings alive for one canonical field"
                ),
            ));
        }
        // A REAL v2 FIELD this route will not let the caller set: the mistake is about governance,
        // not spelling, and the refusal says which — and says it differently on the two routes,
        // because they are two different mistakes. On a patch the field EXISTS on the record and the
        // caller may not move it; on a create the caller is trying to author a value this server
        // derives, and telling it "not patchable" would name the wrong reason.
        //
        // The contract's fields are the commitment material PLUS the commitment itself, which is
        // absent from that list by construction — a hash cannot commit itself. Without the second
        // clause, a caller offering its own `content_hash` — the one field whose forgery the whole
        // commitment exists to prevent — would be told it had sent an "unknown field".
        if DESCRIPTOR_CONTENT_MATERIAL_FIELDS.contains(&name) || name == "content_hash" {
            return Err(if route == "patch" {
                descriptor_refuse(
                    "odk_descriptor_field_not_patchable",
                    format!(
                        "'{name}' is not an ordinary governed patch of a '{DESCRIPTOR_V2_SCHEMA_VERSION}'; this route moves {DESCRIPTOR_PATCHABLE_FIELDS:?} and an explicit status transition. A binding names an EXACT admitted revision, so moving one does not amend this descriptor — it describes a different surface, and the honest act is to author one"
                    ),
                )
            } else {
                descriptor_refuse(
                    "odk_descriptor_field_not_caller_authored",
                    format!(
                        "'{name}' is a field of this contract that the SERVER derives; a caller does not author it. Accepting it and overwriting it would answer 201 to a request whose value was discarded, and accepting it and KEEPING it would let a caller write its own nonclaims, its own commitment or its own binding provenance"
                    ),
                )
            });
        }
        return Err(descriptor_refuse(
            "odk_descriptor_request_field_unknown",
            format!(
                "'{name}' is not a field of a descriptor {route} request; it is refused rather than ignored, because a request accepted with an unrecognised field reads as one where that field was stored. This route accepts exactly {allowed:?}"
            ),
        ));
    }
    Ok(())
}

/// Read one caller-authored field from a request with the SAME normalisation the builder applies.
///
/// Comparing the raw request text instead would make a canonically-identical retry — one extra
/// space, one re-serialised array — read as a changed intent and refuse a legitimate duplicate.
fn descriptor_request_field(body: &Value, name: &str) -> Value {
    match body.get(name) {
        None => Value::Null,
        Some(Value::String(value)) => json!(value.trim()),
        Some(Value::Array(entries)) => json!(entries
            .iter()
            .map(|entry| json!(entry.as_str().unwrap_or_default().trim()))
            .collect::<Vec<Value>>()),
        Some(other) => other.clone(),
    }
}

/// The exact caller-authored field on which this request diverges from the one this key admitted.
///
/// REPLAY ONLY AN IDENTICAL COMMAND. Answering from the admitted record without first comparing what
/// is being asked would turn the idempotency key into a way to receive one descriptor in answer to a
/// different one: the same key with a widened binding set, a different ontology revision or a shorter
/// nonclaim list would receive the original back, and that reads as "your request was recorded".
fn descriptor_replay_intent_divergence(record: &Value, body: &Value) -> Option<&'static str> {
    for name in DESCRIPTOR_CALLER_INTENT_FIELDS {
        if descriptor_request_field(body, name) != record.get(*name).cloned().unwrap_or(Value::Null)
        {
            return Some(name);
        }
    }
    // The one caller-chosen migration input, under its request name. A retry that dropped or moved
    // its predecessor is asking for a different descriptor, not repeating this one.
    let claimed = descriptor_request_field(body, DESCRIPTOR_MIGRATION_SOURCE_KEY);
    let admitted = record
        .pointer("/migration/from_descriptor_ref")
        .cloned()
        .unwrap_or(Value::Null);
    if claimed != admitted {
        return Some(DESCRIPTOR_MIGRATION_SOURCE_KEY);
    }
    None
}

fn descriptor_replay_intent_refusal(field: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "ok": false,
            "error": {
                "code": "odk_descriptor_replay_intent_changed",
                "message": format!(
                    "this idempotency key already admitted a descriptor whose '{field}' differs from this request; a key replays one exact command and is never a way to receive a stored descriptor in answer to a changed one"
                ),
            }
        })),
    )
}

/// One caller-supplied `expected_*` assertion, read WITHOUT letting a wrong type become an absence.
///
/// `Value::as_str` answers `None` for two different situations — the field is absent, and the field
/// is present but is a number, an object or a bool — so reading an assertion through
/// `.get(key).and_then(Value::as_str)` SILENTLY SKIPS it whenever the caller sends the wrong type.
/// A claim this route cannot read is not a claim it may ignore.
enum Asserted<T> {
    Absent,
    Malformed,
    Present(T),
}

fn descriptor_asserted_str<'a>(body: &'a Value, key: &str) -> Asserted<&'a str> {
    match body.get(key) {
        None | Some(Value::Null) => Asserted::Absent,
        Some(Value::String(value)) => Asserted::Present(value.as_str()),
        Some(_) => Asserted::Malformed,
    }
}

fn descriptor_assertion_not_canonical(key: &str, required: &str) -> (StatusCode, Json<Value>) {
    descriptor_refuse(
        "odk_descriptor_assertion_not_canonical",
        format!("'{key}' must be {required}; an assertion this route cannot read is not one it may skip"),
    )
}

/// Every `expected_*` name this route answers, so an unreadable one is refused as itself.
///
/// SHAPE BEFORE STATE, AND THAT ORDER IS THE POINT. Each assertion is compared where its fact
/// exists, which for the content hash is after the record is built. A malformed assertion sent to a
/// descriptor that already has revisions would otherwise be answered with a head or replay refusal —
/// a refusal about a different thing, with the unreadable claim still unexamined.
const DESCRIPTOR_STRING_ASSERTIONS: &[(&str, &str)] = &[
    (
        "expected_descriptor_ref",
        "a 'surface-descriptor://' string",
    ),
    ("expected_content_hash", "a 'sha256:<64 hex>' string"),
    (
        "expected_migration_source_content_hash",
        "a 'sha256:<64 hex>' string",
    ),
    ("expected_status", "one of the four canonical status names"),
];

fn validate_descriptor_assertion_shapes(body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    for (key, required) in DESCRIPTOR_STRING_ASSERTIONS {
        if matches!(descriptor_asserted_str(body, key), Asserted::Malformed) {
            return Err(descriptor_assertion_not_canonical(key, required));
        }
    }
    match body.get("expected_bound_ontology_content_hashes") {
        None | Some(Value::Null) => {}
        Some(Value::Array(entries)) if entries.iter().all(Value::is_string) => {}
        Some(_) => {
            return Err(descriptor_assertion_not_canonical(
                "expected_bound_ontology_content_hashes",
                "an array of 'sha256:<64 hex>' strings, positionally aligned with ontology_refs",
            ))
        }
    }
    Ok(())
}

/// The caller's assertions, answered against ONE exact descriptor record.
///
/// WHY THE REPLAY PATH NEEDS ITS OWN CHECKER. `expected_*` is the caller saying what it believes a
/// server-derived fact to be, and a disagreement is a refusal rather than an accepted substitution.
/// The replay path returns before most of those facts are derived, so without this a caller reusing
/// an admitted key could assert a false content hash, a false owner-committed ontology hash or a
/// false migration source and receive `200 replayed: true` — the claim silently skipped rather than
/// answered. Reusing a key is not a way to have a claim about the record go unexamined.
fn descriptor_assertion_divergence(
    record: &Value,
    body: &Value,
) -> Option<(StatusCode, Json<Value>)> {
    let mismatch = |code: &str, what: &str| {
        Some(descriptor_refuse(
            code,
            format!("{what}; a caller assertion about a server-derived fact is answered, never accepted as a substitution"),
        ))
    };
    if let Asserted::Present(asserted) = descriptor_asserted_str(body, "expected_descriptor_ref") {
        if Some(asserted) != record.get("surface_descriptor_id").and_then(Value::as_str) {
            return mismatch(
                "odk_descriptor_ref_substituted",
                "expected_descriptor_ref does not name this descriptor",
            );
        }
    }
    if let Asserted::Present(asserted) = descriptor_asserted_str(body, "expected_content_hash") {
        if Some(asserted) != record.get("content_hash").and_then(Value::as_str) {
            return mismatch(
                "odk_descriptor_content_hash_substituted",
                "expected_content_hash does not match this descriptor's committed bytes",
            );
        }
    }
    if let Asserted::Present(asserted) = descriptor_asserted_str(body, "expected_status") {
        if Some(asserted) != record.get("status").and_then(Value::as_str) {
            return mismatch(
                "odk_descriptor_status_substituted",
                "expected_status does not match this descriptor's admitted status",
            );
        }
    }
    // THE MIGRATION SOURCE IS ASSERTED AGAINST THE FROZEN COMMITMENT, NEVER AGAINST TODAY'S SOURCE.
    // A convergence committed the predecessor's bytes as they were; that is the fact the caller is
    // making a claim about, and re-reading the source here would make an honest retry fail whenever
    // the world moved underneath an already-admitted record.
    if let Asserted::Present(asserted) =
        descriptor_asserted_str(body, "expected_migration_source_content_hash")
    {
        if Some(asserted)
            != record
                .pointer("/migration/from_content_hash")
                .and_then(Value::as_str)
        {
            return mismatch(
                "odk_descriptor_migration_source_substituted",
                "expected_migration_source_content_hash does not match the predecessor bytes this descriptor committed",
            );
        }
    }
    if let Some(Value::Array(asserted)) = body.get("expected_bound_ontology_content_hashes") {
        let bound: Vec<&str> = record
            .get("bound_ontology_revisions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|row| row.get("ontology_content_hash").and_then(Value::as_str))
            .collect();
        let claimed: Vec<&str> = asserted.iter().filter_map(Value::as_str).collect();
        if claimed != bound {
            return mismatch(
                "odk_descriptor_ontology_hash_substituted",
                "expected_bound_ontology_content_hashes does not match the hashes the ontology owner committed for this descriptor's revisions",
            );
        }
    }
    None
}

pub(crate) async fn handle_odk_descriptor_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // W1.2 / MEF-GAP-004 — identity first. A descriptor write is an owner-scoped mutation, not
    // an anonymous record-directory append.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    let owner_ref = body
        .get("owner_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if owner_ref.is_empty() {
        return bad(
            "odk_owner_ref_required",
            "owner_ref is required: a descriptor is owned by exactly one org:// or project://",
        );
    }
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if idempotency_key.is_empty() {
        return bad(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried descriptor create cannot mint a second record",
        );
    }
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
    // Identity is derived from the owner + caller key, never from wall-clock nanos: a replayed
    // request must resolve to the SAME resource, which a timestamp id can never do.
    let id = odk_derived_id("sd", owner_ref, idempotency_key);
    let descriptor_ref = format!("surface-descriptor://{id}");

    // The closed request set, then assertion SHAPE — both before anything is read — so an
    // unrecognised or unreadable field is answered as itself rather than surfacing as a refusal
    // about a completely different thing.
    if let Err(response) =
        refuse_unknown_request_fields(&body, DESCRIPTOR_CREATE_REQUEST_FIELDS, "create")
    {
        return response;
    }
    if let Err(response) = validate_descriptor_assertion_shapes(&body) {
        return response;
    }

    // REPLAY BEFORE DEPENDENCIES. A convergence re-derives its source hash from the predecessor, so a
    // source that advanced between the first attempt and the retry changed the bytes of an
    // already-admitted command and the substrate answered `same key, different bytes` — a refusal for
    // a caller doing exactly what an ambiguous response requires. Resolving the key against the
    // admitted history first means the retry finds its own admitted fact and returns it, with the
    // predecessor bytes it originally froze.
    match descriptor_admitted_history(&st.data_dir, &identity, Some(owner_ref), &descriptor_ref) {
        Ok(history) => {
            if let Some(prior) = history
                .iter()
                .find(|entry| entry.operation.idem_key == idempotency_key)
            {
                if let Some(field) =
                    descriptor_replay_intent_divergence(&prior.operation.payload, &body)
                {
                    return descriptor_replay_intent_refusal(field);
                }
                if let Some(response) =
                    descriptor_assertion_divergence(&prior.operation.payload, &body)
                {
                    return response;
                }
                return descriptor_replay_reply(&descriptor_ref, prior);
            }
        }
        Err(response) => return response,
    }

    // M05.5 — NEW AUTHORING USES THE SUCCESSOR, AND THE LEGACY SHAPE IS REFUSED RATHER THAN ACCEPTED.
    //
    // A descriptor authored today without the invariant-11 binding set becomes durable product
    // inventory that no reader can check against invariant 11 — which is exactly the state this unit
    // exists to end. Stored v1 records stay READABLE on the query path under explicit compatibility
    // rules and are never reinterpreted as v2; what is closed here is authoring NEW ones.
    let record = match build_descriptor_v2(&st.data_dir, &identity, &body, &id, owner_ref, pattern)
    {
        Ok(record) => record,
        Err(response) => return response,
    };

    odk_admit(
        &st.data_dir,
        &headers,
        &body,
        OdkAdmission {
            family: KIND_SD,
            scope_kind: ODK_DESCRIPTOR_SCOPE_KIND,
            ref_prefix: "surface-descriptor://",
            op_kind: "event_stream.hypervisor_odk_surface_descriptor_admitted",
            reply_key: "surface_descriptor",
            persist_error: "odk_surface_descriptor_persistence_failed",
            projection: OdkProjection::DescriptorFromHistory,
        },
        &id,
        record,
        None,
    )
}

/// GET /v1/hypervisor/odk/surface-descriptors/:id — the descriptor as its OWNER holds it.
///
/// Answered from the Agentgres chain through the published resolver, not from the read-model row, so
/// deleting or corrupting that row cannot hide or alter an admitted descriptor. `index_state` reports
/// what the row DID say, which is how a verifier proves the rebuild happened rather than inferring it
/// from an unchanged answer. Identity is required: reading a descriptor is scoped to its owner.
pub(crate) async fn handle_odk_descriptor_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    let descriptor_ref = format!("surface-descriptor://{id}");
    match resolve_admitted_surface_descriptor(&st.data_dir, &identity, &descriptor_ref) {
        Ok(resolved) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "surface_descriptor": resolved.record,
                "admitted_head": resolved.admitted_head,
                "revision_count": resolved.revision_count,
                "index_state": resolved.index_state,
                "authority_nonclaim": DESCRIPTOR_AUTHORITY_NONCLAIM,
                "truth_nonclaim": DESCRIPTOR_TRUTH_NONCLAIM,
            })),
        ),
        Err(response) => response,
    }
}

/// POST /v1/hypervisor/odk/surface-descriptors/:id/rebuild-index — repair the read-model row.
///
/// The row is a function of the admitted history, so this is deterministic and idempotent: it
/// restores exactly the bytes the chain implies. It exists to make "the index can be destroyed and
/// rebuilt without altering truth" an operation a verifier can PERFORM, rather than a property the
/// module asserts about itself.
pub(crate) async fn handle_odk_descriptor_rebuild_index(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    let descriptor_ref = format!("surface-descriptor://{id}");
    match rebuild_descriptor_row(&st.data_dir, &identity, &descriptor_ref) {
        Ok(resolved) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "surface_descriptor": resolved.record,
                "admitted_head": resolved.admitted_head,
                "revision_count": resolved.revision_count,
                // What the row said BEFORE the repair, so a caller can tell a no-op from a recovery.
                "index_state_before_rebuild": resolved.index_state,
                "authority_nonclaim": DESCRIPTOR_AUTHORITY_NONCLAIM,
            })),
        ),
        Err(response) => response,
    }
}

/// The v2 fields an ordinary governed patch may move, and nothing else.
///
/// THE ALLOWLIST IS THE v2 CONTRACT'S, NOT v1'S. It was inherited verbatim from the v1 lane —
/// `display_name`, `description`, `composition_pattern`, `view_config` — of which `description` and
/// `view_config` are not v2 fields at all. Writing either onto a v2 record produced an object the
/// registered contract refuses under `additionalProperties: false`, so the patch failed closed at
/// revalidation with a message about registered validity rather than about the field the caller
/// actually sent. A closed vocabulary that names fields the object does not have is not a fence; it
/// is a way to be refused for the wrong reason.
///
/// WHAT IS DELIBERATELY NOT HERE. The bindings — every member of the invariant-11 set, the resolved
/// revisions, the migration block, the constants and the nonclaims — are not patchable. A descriptor
/// binds EXACT admitted revisions, so moving a binding does not amend this descriptor, it describes a
/// different surface; the honest act is to author one, which is a create with its own owner
/// resolution and its own commitment. `status` is patchable only through the explicit transitions
/// below, and identity and the commitment are never caller-writable.
const DESCRIPTOR_PATCHABLE_FIELDS: &[&str] = &["display_name", "composition_pattern"];

/// The status moves canon's four-member vocabulary allows, as an explicit closed set.
///
/// A withdrawal is terminal and there is no resurrection: a `revoked` descriptor that could be
/// returned to `active` would make the withdrawal a suggestion. Nothing moves backwards, because a
/// deprecated or active descriptor returning to `draft` would let durable product inventory
/// re-enter authoring while consumers still hold it.
const DESCRIPTOR_STATUS_TRANSITIONS: &[(&str, &str)] = &[
    ("draft", "active"),
    ("draft", "revoked"),
    ("active", "deprecated"),
    ("active", "revoked"),
    ("deprecated", "revoked"),
];

/// Apply one governed patch to an admitted v2 record, or refuse.
fn apply_descriptor_patch(
    record: &mut Value,
    body: &Value,
) -> Result<(), (StatusCode, Json<Value>)> {
    // THE LEGACY NAMES CANNOT COME BACK THROUGH PATCH. Refusing them at create and accepting them
    // here would leave the convergence one request away from being undone.
    for (legacy, canonical) in LEGACY_DESCRIPTOR_FIELDS {
        if body.get(*legacy).is_some() {
            return Err(descriptor_refuse(
                "odk_descriptor_legacy_field_name",
                format!(
                    "'{legacy}' is the v1 name for '{canonical}' and is refused on patch as it is on create; a converged descriptor does not acquire the legacy spelling back one request later"
                ),
            ));
        }
    }
    // Legacy spellings, unknown fields and un-patchable contract fields are all refused by
    // `refuse_unknown_request_fields` before this runs, each by its own cause.
    if let Some(pattern) = body.get("composition_pattern") {
        let Some(pattern) = pattern
            .as_str()
            .filter(|p| COMPOSITION_PATTERNS.contains(p))
        else {
            return Err(descriptor_refuse(
                "odk_composition_pattern_invalid",
                format!("composition_pattern must be one of {COMPOSITION_PATTERNS:?}"),
            ));
        };
        record["composition_pattern"] = json!(pattern);
    }
    if let Some(display_name) = body.get("display_name") {
        let Some(display_name) = display_name
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 160)
        else {
            return Err(descriptor_refuse(
                "odk_descriptor_display_name_required",
                "display_name is 1..160 characters",
            ));
        };
        record["display_name"] = json!(display_name);
    }
    if let Some(requested) = body.get("status") {
        let current = record
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(requested) = requested.as_str() else {
            return Err(descriptor_refuse(
                "odk_descriptor_status_transition_refused",
                "status must be one of canon's four names",
            ));
        };
        if requested != current && !DESCRIPTOR_STATUS_TRANSITIONS.contains(&(current, requested)) {
            return Err(descriptor_refuse(
                "odk_descriptor_status_transition_refused",
                format!(
                    "'{current}' -> '{requested}' is not one of the declared transitions {DESCRIPTOR_STATUS_TRANSITIONS:?}; a withdrawal is terminal and nothing moves backwards, because durable product inventory consumers already hold may not re-enter authoring"
                ),
            ));
        }
        record["status"] = json!(requested);
    }
    Ok(())
}

/// The governed field on which this patch request diverges from the one this key admitted.
///
/// It compares every governed field the request NAMES against the record that key admitted. That is
/// what it claims and no more: it decides "this key already produced a record that says what you are
/// asking for", which is the question a retry after an ambiguous response is really asking. It does
/// not attempt to distinguish a record that reached those values through this patch from one that
/// reached them another way, because on this stream, under this key, there is exactly one such
/// record.
fn descriptor_patch_intent_divergence(record: &Value, body: &Value) -> Option<&'static str> {
    for name in DESCRIPTOR_PATCHABLE_FIELDS.iter().chain(["status"].iter()) {
        if body.get(*name).is_some()
            && descriptor_request_field(body, name)
                != record.get(*name).cloned().unwrap_or(Value::Null)
        {
            return Some(name);
        }
    }
    None
}

pub(crate) async fn handle_odk_descriptor_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    if let Err(response) =
        refuse_unknown_request_fields(&body, DESCRIPTOR_PATCH_REQUEST_FIELDS, "patch")
    {
        return response;
    }
    if let Err(response) = validate_descriptor_assertion_shapes(&body) {
        return response;
    }
    let descriptor_ref = format!("surface-descriptor://{id}");
    // THE CHAIN IS THE PRECONDITION, NOT THE ROW. Reading the local record directory made the
    // rebuildable projection load-bearing for a mutation: delete the row and an admitted descriptor
    // could no longer be patched by its own owner, and corrupt it and the patch applied to whatever
    // the corruption said.
    let history = match descriptor_admitted_history(&st.data_dir, &identity, None, &descriptor_ref)
    {
        Ok(history) => history,
        Err(response) => return response,
    };
    let Some(latest) = history.last() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "odk_surface_descriptor_not_found",
                    "message": "this descriptor has no admitted history — an absent descriptor is a typed absence, never an empty success"
                }
            })),
        );
    };
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");

    // REPLAY BEFORE PRECONDITIONS, AND BEFORE THE PATCH IS APPLIED TO ANYTHING. Retrying patch A
    // after patch B landed used to rebuild A's payload on top of B's record, so the bytes were
    // B-plus-A rather than the A this key admitted, and the substrate answered `same key, different
    // bytes`. Resolving the key against history first returns A's own admitted fact.
    if !idempotency_key.is_empty() {
        if let Some(prior) = history
            .iter()
            .find(|entry| entry.operation.idem_key == idempotency_key)
        {
            if let Some(field) = descriptor_patch_intent_divergence(&prior.operation.payload, &body)
            {
                return descriptor_replay_intent_refusal(field);
            }
            if let Some(response) = descriptor_assertion_divergence(&prior.operation.payload, &body)
            {
                return response;
            }
            return descriptor_replay_reply(&descriptor_ref, prior);
        }
    }

    let previous = latest.operation.payload.clone();
    let stored_version = previous
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // A STORED v1 IS READABLE, NOT EDITABLE INTO A v2, and an unknown version fails closed rather
    // than being patched under a contract it was never admitted under.
    match stored_version {
        DESCRIPTOR_V2_SCHEMA_VERSION => {}
        DESCRIPTOR_V1_SCHEMA_VERSION => {
            return descriptor_refuse(
                "odk_descriptor_v1_is_readable_not_patchable",
                format!(
                    "this descriptor is a stored '{DESCRIPTOR_V1_SCHEMA_VERSION}' record; it remains readable exactly as admitted and is never edited into a '{DESCRIPTOR_V2_SCHEMA_VERSION}'. Converge it explicitly by authoring a successor that names it in {DESCRIPTOR_MIGRATION_SOURCE_KEY}"
                ),
            )
        }
        unknown => {
            return descriptor_refuse(
                "odk_descriptor_version_unsupported",
                format!(
                    "this descriptor was admitted as '{unknown}', which this build neither authors nor patches; an unrecognised stored version is refused rather than edited under a contract it was never admitted under"
                ),
            )
        }
    }

    let mut record = previous.clone();
    if let Err(response) = apply_descriptor_patch(&mut record, &body) {
        return response;
    }

    // THE COMMITMENT FOLLOWS THE BYTES. Leaving the predecessor's `content_hash` on a changed record
    // would make every later reader verify a commitment over bytes that no longer exist. The record
    // is then re-validated against the registered contract, so a patch cannot walk a descriptor out
    // of invariant-11 conformance.
    record["content_hash"] = json!(descriptor_content_hash(&record));
    if let Err(reason) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            DESCRIPTOR_V2_CONTRACT_ID,
            &record,
        )
    {
        return descriptor_refuse(
            "odk_descriptor_not_registered_valid",
            format!("this patch would leave the descriptor not registered-valid: {reason}"),
        );
    }
    if let Some(response) = descriptor_assertion_divergence(&record, &body) {
        return response;
    }

    odk_admit(
        &st.data_dir,
        &headers,
        &body,
        OdkAdmission {
            family: KIND_SD,
            scope_kind: ODK_DESCRIPTOR_SCOPE_KIND,
            ref_prefix: "surface-descriptor://",
            op_kind: "event_stream.hypervisor_odk_surface_descriptor_revised",
            reply_key: "surface_descriptor",
            persist_error: "odk_surface_descriptor_persistence_failed",
            projection: OdkProjection::DescriptorFromHistory,
        },
        &id,
        record,
        Some(&previous),
    )
}

pub(crate) async fn handle_odk_descriptor_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return odk_scope_refusal(error),
    };
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or("")
    };
    withdraw_descriptor_with_identity(
        &st.data_dir,
        &identity,
        &id,
        header("x-ioi-idempotency-key"),
        header("x-ioi-expected-head"),
    )
}

/// The withdrawal itself, over an ALREADY-RESOLVED identity.
///
/// Split from the transport wrapper for the same reason `odk_admit_with_identity` is: a stored v1 is
/// unreachable through the public API — this build refuses to author one, by design — so the only
/// way to prove that WITHDRAWING one behaves is to drive this exact function over a seeded v1. A
/// copy of the delete logic written inside a test would prove the copy.
fn withdraw_descriptor_with_identity(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    id: &str,
    idempotency_key: &str,
    expected_head: &str,
) -> (StatusCode, Json<Value>) {
    // W1.2 / MEF-GAP-004 — a delete is the most consequential mutation in the family and was the
    // only one that took no identity at all: any caller could erase any descriptor. It is a
    // successor mutation like any other, so it carries the same owner scope, caller idempotency
    // and compare-and-swap, and it is RECORDED rather than silently dropping the row.
    // THE CHAIN IS THE PRECONDITION, NOT THE ROW. Reading the local row here made deletion
    // self-erasing: the first delete removed the only row, so an exact retry — the ordinary
    // consequence of an ambiguous response — answered 404 for a descriptor whose withdrawal was
    // already admitted and durable. Resolving from the owner history instead means the retry finds
    // the same admitted state and replays it, and a caller who deleted the row by hand cannot make
    // the descriptor disappear from its own owner.
    let descriptor_ref = format!("surface-descriptor://{id}");
    // REPLAY BEFORE THE TOMBSTONE IS BUILT. The withdrawal record is derived from the CURRENT record,
    // so a delete retried after any other successor landed produced different bytes under the same
    // key and was refused as `same key, different bytes` — for a caller doing exactly what an
    // ambiguous response requires. The key is resolved against the admitted history first, so the
    // retry finds its own withdrawal and replays it.
    let history = match descriptor_admitted_history(data_dir, identity, None, &descriptor_ref) {
        Ok(history) => history,
        Err(response) => return response,
    };
    if !idempotency_key.is_empty() {
        if let Some(prior) = history
            .iter()
            .find(|entry| entry.operation.idem_key == idempotency_key)
        {
            return descriptor_replay_reply(&descriptor_ref, prior);
        }
    }
    let resolved = match resolve_admitted_surface_descriptor(data_dir, identity, &descriptor_ref) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let previous = resolved.record.clone();
    let mut tombstone = previous.clone();
    // CANON'S OWN WITHDRAWAL STATE. The v1 lane wrote `deleted`, which is a fifth status the
    // canonical envelope does not define; v2 converges onto `revoked`. The hash follows the bytes and
    // the tombstone is re-validated, so a withdrawal is a registered-valid successor rather than an
    // out-of-contract record that only the delete path knows how to read.
    if resolved.schema_version == DESCRIPTOR_V2_SCHEMA_VERSION {
        tombstone["status"] = json!("revoked");
        tombstone["content_hash"] = json!(descriptor_content_hash(&tombstone));
        if let Err(reason) =
            ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                DESCRIPTOR_V2_CONTRACT_ID,
                &tombstone,
            )
        {
            return descriptor_refuse(
                "odk_descriptor_not_registered_valid",
                format!("the withdrawal this request builds is not registered-valid: {reason}"),
            );
        }
    } else {
        tombstone["status"] = json!("deleted");
    }
    let body = json!({
        "idempotency_key": idempotency_key,
        "expected_head": expected_head,
    });
    // THE WITHDRAWN ROW IS KEPT, AS THE WITHDRAWAL, AND IN THE WITHDRAWN RECORD'S OWN VERSION.
    // Removing it left the chain holding an admitted tombstone that no local read could see, so the
    // projection and the owner disagreed about a descriptor's existence — and the disagreement
    // resolved in favour of the projection, which is the wrong way round. The row now carries the
    // withdrawn record, the list view still hides it, and an exact retry replays the same admitted
    // successor instead of failing to find its own subject.
    //
    // The projection is `DescriptorFromHistory` rather than the v2 envelope this path used to
    // hard-code. A v1 withdrawal builds a valid v1 tombstone above — `status: "deleted"`, the
    // predecessor's own bytes, never reinterpreted — and then persisted it through an envelope
    // announcing `descriptor_contract_id: …/v2` over it. The row claimed a contract its contents
    // were never admitted under, and it was a shape no other path wrote for a v1, so the documented
    // repair produced different bytes than the withdrawal had. `descriptor_row` dispatches on the
    // record's own version instead, and the repair IS the write.
    odk_admit_with_identity(
        data_dir,
        identity,
        &body,
        OdkAdmission {
            family: KIND_SD,
            scope_kind: ODK_DESCRIPTOR_SCOPE_KIND,
            ref_prefix: "surface-descriptor://",
            op_kind: "event_stream.hypervisor_odk_surface_descriptor_deleted",
            reply_key: "surface_descriptor",
            persist_error: "odk_surface_descriptor_persistence_failed",
            projection: OdkProjection::DescriptorFromHistory,
        },
        id,
        tombstone,
        Some(&previous),
    )
}

#[cfg(test)]
mod descriptor_v2_contract_tests {
    use super::*;

    const FIXTURES: &[(&str, &str)] = &[
        (
            "positive-authored-at-v2",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/positive-authored-at-v2.json"),
        ),
        (
            "positive-converged-from-v1",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/positive-converged-from-v1.json"),
        ),
        (
            "negative-legacy-ontology-ref-field-name",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-legacy-ontology-ref-field-name.json"),
        ),
        (
            "negative-legacy-recipe-refs-field-name",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-legacy-recipe-refs-field-name.json"),
        ),
        (
            "negative-mutable-latest-ontology-binding",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-mutable-latest-ontology-binding.json"),
        ),
        (
            "negative-binding-set-member-missing",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-binding-set-member-missing.json"),
        ),
        (
            "negative-binding-set-member-substituted",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-binding-set-member-substituted.json"),
        ),
        (
            "negative-capability-lease-nonclaim-omitted",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-capability-lease-nonclaim-omitted.json"),
        ),
        (
            "negative-v1-schema-version-on-v2",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-v1-schema-version-on-v2.json"),
        ),
        (
            "negative-binding-set-count-narrowed",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-binding-set-count-narrowed.json"),
        ),
        (
            "negative-stale-content-hash",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-stale-content-hash.json"),
        ),
        (
            "negative-named-revision-without-owner-hash",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-named-revision-without-owner-hash.json"),
        ),
        (
            "negative-revision-bound-twice",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-revision-bound-twice.json"),
        ),
        (
            "negative-binding-set-equal-count-substitution",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-binding-set-equal-count-substitution.json"),
        ),
        (
            "negative-migration-partial-tuple",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-migration-partial-tuple.json"),
        ),
        (
            "negative-migration-mixed-tuple",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v2/negative-migration-mixed-tuple.json"),
        ),
    ];

    /// The registered v1 corpus. v1 is DEPRECATED AND READ-ONLY, and these prove what it could never
    /// carry — which is what makes "v1 could not be checked against invariant 11" a checked
    /// expectation rather than a claim in a commit message.
    const V1_FIXTURES: &[(&str, &str)] = &[
        (
            "positive-stored-v1-record",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v1/positive-stored-v1-record.json"),
        ),
        (
            "negative-binding-set-member-on-v1",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v1/negative-binding-set-member-on-v1.json"),
        ),
        (
            "negative-canonical-status-on-v1",
            include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-surface-descriptor-v1/negative-canonical-status-on-v1.json"),
        ),
    ];

    const V1_SCHEMA: &str = include_str!(
        "../../../../../docs/architecture/_meta/schemas/ontology-surface-descriptor.v1.schema.json"
    );

    fn fixture(name: &str) -> Value {
        let (_, body) = FIXTURES
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .unwrap_or_else(|| panic!("no fixture named {name}"));
        serde_json::from_str(body).expect("fixture is JSON")
    }

    fn registered(document: &Value) -> Result<(), String> {
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            DESCRIPTOR_V2_CONTRACT_ID,
            document,
        )
    }

    /// The registered v2 corpus, run against the SAME validator the admission path uses.
    ///
    /// WHY THIS FAMILY CHECKS ITSELF. The shared golden-fixture test iterates every registered
    /// contract and aborts on the FIRST failure; it currently aborts on an
    /// `assurance-transition-receipt` positive failing `$.admission: failed oneOf`, a defect that
    /// predates this branch at `ea40cfde2` and belongs to another owner. Letting a neighbour's broken
    /// fixture mean this contract's corpus is never executed would be exactly the "green because
    /// nothing ran" failure this program keeps finding.
    #[test]
    fn the_registered_v2_corpus_passes_and_fails_exactly_where_it_claims_to() {
        for (name, body) in FIXTURES {
            let document: Value = serde_json::from_str(body).expect("fixture is JSON");
            let result = registered(&document);
            if name.starts_with("positive-") {
                result.unwrap_or_else(|reason| {
                    panic!("{name} must pass the registered contract: {reason}")
                });
                // THE PRODUCER IS THE ORACLE: the commitment is recomputed by the same function the
                // admission path uses, so a fixture cannot agree with a hash nothing produces.
                assert_eq!(
                    json!(descriptor_content_hash(&document)),
                    document["content_hash"],
                    "{name} content hash"
                );
            } else {
                assert!(
                    result.is_err(),
                    "{name} must be refused by the registered contract"
                );
            }
        }
    }

    /// The stale-hash negative differs from a valid record in EXACTLY its hash.
    ///
    /// Repairing only the hash must make it valid; otherwise the fixture carries a second, unnamed
    /// defect and would be evidence for the wrong rule.
    #[test]
    fn the_stale_hash_negative_has_exactly_one_defect() {
        let stale = fixture("negative-stale-content-hash");
        assert!(registered(&stale).is_err());
        assert_ne!(
            json!(descriptor_content_hash(&stale)),
            stale["content_hash"],
            "the stale-hash negative must actually carry a stale hash"
        );
        let mut repaired = stale.clone();
        repaired["content_hash"] = json!(descriptor_content_hash(&stale));
        assert!(
            registered(&repaired).is_ok(),
            "repairing ONLY the hash must make it valid, proving the hash was its single defect"
        );
    }

    /// THE EQUAL-COUNT SUBSTITUTION IS THE CASE EVERY OTHER RULE MISSES, so it is proved to fail on
    /// the rule it is registered against and on NOTHING ELSE.
    ///
    /// A fixture that failed for a second, unnamed reason would be evidence for the wrong rule: it
    /// would keep passing if the set-equality rule were deleted. So this asserts the shape checks and
    /// both arithmetic fences accept it — the counts DO agree, the entries ARE unique, the hash IS
    /// current — and that repairing only the substituted identity makes it valid.
    #[test]
    fn the_equal_count_substitution_fails_only_on_exact_set_equality() {
        const RULE: &str =
            "ontology_surface_descriptor.ontology_binding.the_bound_set_is_exactly_the_owning_set";
        let substituted = fixture("negative-binding-set-equal-count-substitution");
        let reason = registered(&substituted).expect_err("the substitution must be refused");
        assert!(reason.contains(RULE), "must fail on {RULE}, got: {reason}");

        // Every fence that is NOT this rule accepts it, which is precisely the problem it exists for.
        let refs = substituted["ontology_refs"].as_array().unwrap().len();
        let bound = substituted["bound_ontology_revisions"].as_array().unwrap();
        assert_eq!(refs, bound.len());
        assert_eq!(json!(refs), substituted["bound_ontology_revision_count"]);
        let identities: std::collections::BTreeSet<&str> = bound
            .iter()
            .map(|row| row["ontology_revision_ref"].as_str().unwrap())
            .collect();
        assert_eq!(identities.len(), bound.len(), "the entries are unique");
        assert_eq!(
            json!(descriptor_content_hash(&substituted)),
            substituted["content_hash"],
            "the commitment is current, so the stale-hash rule is not what refuses this"
        );

        // Repairing ONLY the substituted identity makes it valid, proving that was its one defect.
        let mut repaired = substituted.clone();
        repaired["bound_ontology_revisions"][1]["ontology_revision_ref"] =
            repaired["ontology_refs"][1].clone();
        repaired["content_hash"] = json!(descriptor_content_hash(&repaired));
        assert!(
            registered(&repaired).is_ok(),
            "repairing only the identity must make it valid: {:?}",
            registered(&repaired)
        );
    }

    /// The two migration negatives fail at the SCHEMA, which is what the registry declares.
    ///
    /// Both are the shapes the flat five-field block admitted and the conditional pair now refuses:
    /// a `converged_from_v1` naming no source bytes, and a provenance carried under `initial`.
    #[test]
    fn the_partial_and_mixed_migration_tuples_are_refused_and_the_two_legitimate_ones_are_not() {
        // `validate_architecture_contract` runs the schema first and short-circuits, so a message
        // with no `invariant:` in it is proof the SCHEMA refused — which is what the registry
        // declares for both, and what makes the conditional pair load-bearing rather than decorative.
        for name in [
            "negative-migration-partial-tuple",
            "negative-migration-mixed-tuple",
        ] {
            let reason = registered(&fixture(name)).expect_err("{name} must be refused");
            assert!(
                !reason.contains("invariant:"),
                "{name} must be refused by the SCHEMA, not merely by an invariant: {reason}"
            );
            assert!(
                reason.contains("migration"),
                "{name} must be refused at the migration block: {reason}"
            );
        }
        // And the two tuples canon DOES define are accepted, so the conditional pair narrowed the
        // shape without closing a legitimate path.
        for name in ["positive-authored-at-v2", "positive-converged-from-v1"] {
            registered(&fixture(name))
                .unwrap_or_else(|reason| panic!("{name} must remain valid: {reason}"));
        }
    }

    /// The producer's commitment material IS the registered rule's, field for field.
    ///
    /// A hash both sides compute from separately-maintained lists agrees until someone edits one of
    /// them. This makes a field added to the contract and forgotten in the producer fail here, rather
    /// than at the first admitted record nobody can verify.
    #[test]
    fn the_content_commitment_material_is_the_registered_material() {
        const PROFILE: &str = include_str!(
            "../../../../../docs/architecture/_meta/schemas/invariants/ontology-surface-descriptor.v2.invariants.json"
        );
        let profile: Value = serde_json::from_str(PROFILE).expect("profile is JSON");
        let rule = profile["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .find(|rule| {
                rule["rule_id"]
                    == "ontology_surface_descriptor.content_hash.commits_the_whole_descriptor"
            })
            .expect("the registered profile declares a content commitment rule");
        let mut registered_fields: Vec<String> = rule["expression"]["material_fields"]
            .as_object()
            .expect("material fields")
            .keys()
            .filter(|key| *key != "domain")
            .cloned()
            .collect();
        registered_fields.sort();
        let mut produced: Vec<String> = DESCRIPTOR_CONTENT_MATERIAL_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect();
        produced.sort();
        assert_eq!(registered_fields, produced);
        assert_eq!(
            rule["expression"]["material_fields"]["domain"]["value"],
            json!(DESCRIPTOR_CONTENT_COMMITMENT_DOMAIN)
        );
    }

    /// The binding set the module emits is canon's eight, and the legacy names it refuses are the
    /// two v1 spellings those members replaced.
    #[test]
    fn the_binding_set_and_the_refused_legacy_names_are_canonical() {
        assert_eq!(
            INVARIANT_11_BINDING_SET,
            &[
                "ontology_refs",
                "canonical_object_model_refs",
                "data_recipe_refs",
                "policy_bound_data_view_refs",
                "authority_requirement_refs",
                "daemon_api_refs",
                "receipt_obligations",
                "conformance_profile_refs",
            ]
        );
        assert_eq!(
            LEGACY_DESCRIPTOR_FIELDS,
            &[
                ("ontology_ref", "ontology_refs"),
                ("recipe_refs", "data_recipe_refs"),
            ]
        );
        // Each legacy name's canonical successor is itself a binding-set member, so the convergence
        // lands ON the set invariant 11 requires rather than beside it.
        for (_, canonical) in LEGACY_DESCRIPTOR_FIELDS {
            assert!(INVARIANT_11_BINDING_SET.contains(canonical));
        }
    }

    /// The registered v1 corpus, run against the same validator the convergence path uses.
    #[test]
    fn the_registered_v1_corpus_passes_and_fails_exactly_where_it_claims_to() {
        for (name, body) in V1_FIXTURES {
            let document: Value = serde_json::from_str(body).expect("fixture is JSON");
            let result =
                ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                    DESCRIPTOR_V1_CONTRACT_ID,
                    &document,
                );
            if name.starts_with("positive-") {
                result
                    .unwrap_or_else(|reason| panic!("{name} must pass the v1 contract: {reason}"));
            } else {
                assert!(result.is_err(), "{name} must be refused by the v1 contract");
            }
        }
    }

    /// v1 IS THE PREDECESSOR THIS UNIT EXISTS BECAUSE OF, so its incapacity is asserted rather than
    /// described: the registered v1 contract carries NONE of the eight members invariant 11 requires,
    /// and it carries both legacy spellings the convergence refuses.
    #[test]
    fn the_v1_contract_carries_none_of_the_invariant_11_binding_set() {
        let schema: Value = serde_json::from_str(V1_SCHEMA).expect("v1 schema is JSON");
        let properties = schema["properties"].as_object().expect("v1 properties");
        for member in INVARIANT_11_BINDING_SET {
            assert!(
                !properties.contains_key(*member),
                "v1 must not carry the invariant-11 member {member}"
            );
        }
        for (legacy, _) in LEGACY_DESCRIPTOR_FIELDS {
            assert!(
                properties.contains_key(*legacy),
                "v1 is the contract the legacy name {legacy} came from"
            );
        }
        // The predecessor is closed, so a v1 record cannot acquire a binding set by carrying extra
        // keys — which is what makes the negative fixture above fail at the schema layer.
        assert_eq!(schema["additionalProperties"], json!(false));
    }

    /// The v1 commitment material IS the registered v1 contract's own required field list.
    ///
    /// A convergence freezes the predecessor's bytes under this list. If the two drift, the frozen
    /// number stops identifying the record it came from, and a changed source becomes
    /// indistinguishable from an unchanged one — silently, at every later read.
    #[test]
    fn the_v1_commitment_material_is_the_registered_v1_required_set() {
        let schema: Value = serde_json::from_str(V1_SCHEMA).expect("v1 schema is JSON");
        let required: Vec<String> = schema["required"]
            .as_array()
            .expect("v1 required")
            .iter()
            .map(|value| value.as_str().expect("field name").to_string())
            .collect();
        let produced: Vec<String> = DESCRIPTOR_V1_CONTENT_MATERIAL_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect();
        assert_eq!(required, produced);
        // The two domains are distinct, so the same bytes never hash to the same commitment under
        // both contracts and a v1 hash can never be mistaken for a v2 one.
        assert_ne!(
            DESCRIPTOR_V1_CONTENT_COMMITMENT_DOMAIN,
            DESCRIPTOR_CONTENT_COMMITMENT_DOMAIN
        );
    }

    /// Hashing a v1 record with the v2 material list COLLAPSES distinct predecessors onto one
    /// commitment. This is the defect the separate v1 domain and field list exist to prevent, and it
    /// is asserted rather than argued.
    #[test]
    fn the_v2_material_list_cannot_distinguish_two_v1_records_and_the_v1_list_can() {
        let one: Value = serde_json::from_str(V1_FIXTURES[0].1).expect("fixture is JSON");
        let mut two = one.clone();
        two["id"] = json!("sd_00000000000000000");
        two["ref"] = json!("surface-descriptor://sd_00000000000000000");
        two["name"] = json!("A completely different descriptor");
        two["ontology_ref"] = json!("ontology://acme-clinic/billing-codes");
        two["recipe_refs"] = json!([]);
        two["view_config"] = json!({});

        assert_eq!(
            descriptor_content_hash(&one),
            descriptor_content_hash(&two),
            "the v2 material list reads twenty-eight of its fields as absent on a v1, so two unrelated v1 records commit to the SAME hash — which is exactly why a convergence may not use it"
        );
        assert_ne!(
            descriptor_v1_content_hash(&one),
            descriptor_v1_content_hash(&two),
            "the v1 material list distinguishes them, so `migration.from_content_hash` identifies ONE predecessor"
        );
    }

    /// Every field of the contract is either caller intent or server-authored — never neither.
    ///
    /// THIS IS THE FENCE, NOT THE LIST. A replay compares the caller-intent half; a field that fell
    /// into the gap could be changed under an already-admitted key and receive the original record
    /// back with `replayed: true`, which reads as "your request was recorded". Adding a field to the
    /// contract therefore forces a decision here rather than defaulting into that gap.
    #[test]
    fn every_contract_field_is_either_caller_intent_or_server_authored() {
        let mut partition: Vec<&str> = DESCRIPTOR_CALLER_INTENT_FIELDS
            .iter()
            .chain(DESCRIPTOR_SERVER_AUTHORED_FIELDS.iter())
            .copied()
            .collect();
        let total = partition.len();
        partition.sort_unstable();
        partition.dedup();
        assert_eq!(total, partition.len(), "the two halves must be disjoint");

        let mut material: Vec<&str> = DESCRIPTOR_CONTENT_MATERIAL_FIELDS.to_vec();
        material.sort_unstable();
        assert_eq!(
            partition, material,
            "the two halves must cover the contract's commitment material exactly"
        );
        // `content_hash` is in neither half by construction: it commits the others and is derived
        // last, so it is not in the material list either.
        assert!(!material.contains(&"content_hash"));
    }

    /// The status ladder is canon's four names and the moves between them are one-way.
    #[test]
    fn the_status_ladder_is_terminal_at_revoked_and_never_moves_backwards() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/ontology-surface-descriptor.v2.schema.json"
        ))
        .expect("v2 schema is JSON");
        let canonical: Vec<&str> = schema["properties"]["status"]["enum"]
            .as_array()
            .expect("status enum")
            .iter()
            .map(|value| value.as_str().expect("status name"))
            .collect();
        assert_eq!(canonical, ["draft", "active", "deprecated", "revoked"]);
        for (from, to) in DESCRIPTOR_STATUS_TRANSITIONS {
            assert!(canonical.contains(from) && canonical.contains(to));
            // Terminal: nothing leaves `revoked`, so a withdrawal is not a suggestion.
            assert_ne!(*from, "revoked");
            // One-way: `draft` is only ever left, never returned to.
            assert_ne!(*to, "draft");
        }
    }

    // ===================================================================== THE HISTORICAL UPGRADE
    //
    // THE ONE PATH A FRESH DEPLOYMENT CAN NEVER REACH THROUGH THE PUBLIC API. A convergence needs a
    // stored v1 predecessor, and this build refuses to author one — that refusal IS the unit. So the
    // success case cannot be driven by the live gate at all, and for one commit it was carried as a
    // nonclaim: "the successful convergence path is not driven live, and cannot be." That is a real
    // gap dressed as a disclosure. A migration that has never been executed is not a migration; it is
    // a plan, and the first operator to run it would be its first test.
    //
    // This drives it, without inventing a bypass. It seeds the v1 through
    // `odk_admit_with_identity` — the SAME owner-scoped foundation the legacy lane used, with the
    // same scope binding, caller idempotency, compare-and-swap, admission and projection — then
    // closes and reopens the substrate handle, resolves and rebuilds through the production readers,
    // derives the migration block through the PRODUCTION `descriptor_migration_block`, assembles the
    // successor through the PRODUCTION `assemble_descriptor_v2`, admits it through the same
    // foundation, restarts again, and retries the convergence key after the source has moved.
    //
    // THE ONTOLOGY PREREQUISITE IS REAL, NOT SUPPLIED. An earlier cut of this test handed
    // `assemble_descriptor_v2` literal `bound_ontology_revisions` rows and called the split with the
    // live gate "each proves what it can legitimately reach". That was wrong, and it was wrong in the
    // specific way this module keeps finding: the one seam the convergence depends on — owner
    // resolution of an exact admitted revision — was the one seam the proof skipped, so the test
    // could not have failed if `build_descriptor_v2` stopped resolving at all. A proof that routes
    // around the thing it is proving is not a weaker proof; it is evidence for a different claim.
    //
    // So the prerequisite is seeded through M05.1's OWN admission helper, which derives the record,
    // the content commitment and the projection with that owner's own code. The convergence then
    // passes a COMPLETE authoring request into the production `build_descriptor_v2`, so
    // `resolve_admitted_revision` and every request validation actually run, and the bound rows are
    // whatever that owner committed.

    fn upgrade_identity(principal: &str) -> super::super::substrate_store::RequestIdentity {
        super::super::substrate_store::request_identity_for_test(
            principal,
            ["org://acme-clinic".to_string()],
        )
    }

    /// THE LEGACY ID WIDTH IS A BOUNDED, RECORDED GAP — asserted here rather than described.
    ///
    /// `odk_derived_id` truncates to `prefix.len() + 17`, which for the `sd` prefix is nineteen
    /// characters TOTAL — three of prefix and SIXTEEN hex digits. The registered v1 contract requires
    /// seventeen. So a descriptor minted by the historical v1 producer does not satisfy the contract
    /// this milestone registered for it.
    ///
    /// v1 IS NOT ALTERED TO MATCH. Widening the registered pattern to accommodate the old producer
    /// would be reinterpreting a predecessor to fit its implementation, which is the exact move this
    /// unit exists to refuse — and it would silently redefine what a "valid v1" is for every reader.
    /// The contract states the canonical v1 envelope; the producer that fell short of it is gone, and
    /// no path in this build mints a v1 at all.
    ///
    /// THE BOUNDED CONSEQUENCE, stated exactly: a genuine legacy row whose id carries sixteen hex
    /// digits will FAIL `resolve_admitted_surface_descriptor`'s registered-v1 validation with
    /// `odk_descriptor_projection_failed`, and can therefore be neither read through the owner seam
    /// nor converged. It fails CLOSED — it is never reinterpreted, never half-converged, and never
    /// silently repaired — and the refusal names the contract and the failing path. Repairing that
    /// population needs a versioned successor to v1 with the real width, which is a migration this
    /// unit does not own and does not perform. Until that lands, this is an open gap, and this test
    /// is what keeps it from being forgotten.
    #[test]
    fn the_legacy_id_width_does_not_satisfy_the_registered_v1_contract() {
        let minted = odk_derived_id("sd", "org://acme-clinic", "legacy-create-1");
        assert_eq!(minted.len(), 19, "three of prefix and sixteen hex digits");
        let hex = minted.trim_start_matches("sd_");
        assert_eq!(hex.len(), 16);

        let mut legacy: Value = serde_json::from_str(V1_FIXTURES[0].1).expect("fixture is JSON");
        legacy["id"] = json!(minted);
        legacy["ref"] = json!(format!("surface-descriptor://{minted}"));
        let reason =
            ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                DESCRIPTOR_V1_CONTRACT_ID,
                &legacy,
            )
            .expect_err("the historical producer's id width is refused by the registered contract");
        assert!(
            reason.contains("$.id"),
            "the refusal names the failing field: {reason}"
        );
        // And the contract's own width is what a contract-valid v1 carries.
        let canonical: Value = serde_json::from_str(V1_FIXTURES[0].1).expect("fixture is JSON");
        assert_eq!(
            canonical["id"]
                .as_str()
                .unwrap()
                .trim_start_matches("sd_")
                .len(),
            17
        );
    }

    /// The exact record the v1 lane minted, admitted through the shared foundation.
    ///
    /// The id is an explicit, contract-valid seventeen-hex literal rather than `odk_derived_id`'s
    /// sixteen: this seeds the CANONICAL v1 the registered contract describes, and the width gap
    /// above is recorded as its own bounded finding rather than smuggled in here.
    fn seed_v1(
        data_dir: &str,
        identity: &super::super::substrate_store::RequestIdentity,
        owner_ref: &str,
        id: &str,
        key: &str,
        name: &str,
    ) -> (String, StatusCode) {
        let record = json!({
            "schema_version": DESCRIPTOR_V1_SCHEMA_VERSION,
            "object": "ioi.hypervisor.odk.surface_descriptor",
            "id": id,
            "ref": format!("surface-descriptor://{id}"),
            "name": name,
            "description": "the legacy descriptor record, exactly as the v1 lane minted it",
            "status": "draft",
            "composition_pattern": "monitoring_console",
            "ontology_ref": "ontology://ont_2b7f4c8a9e1d05f36",
            "recipe_refs": [],
            "owner_ref": owner_ref,
            "view_config": {},
        });
        let (status, _) = odk_admit_with_identity(
            data_dir,
            identity,
            &json!({ "idempotency_key": key, "owner_ref": owner_ref }),
            OdkAdmission {
                family: KIND_SD,
                scope_kind: ODK_DESCRIPTOR_SCOPE_KIND,
                ref_prefix: "surface-descriptor://",
                op_kind: "event_stream.hypervisor_odk_surface_descriptor_admitted",
                reply_key: "surface_descriptor",
                persist_error: "odk_surface_descriptor_persistence_failed",
                // THE DESCRIPTOR FAMILY'S OWN PROJECTION, which dispatches on the record's version:
                // a v1 lands in the legacy lane's shape — the record IS the row — because that is
                // what `descriptor_row` writes for a v1, not because this seed asked for it.
                projection: OdkProjection::DescriptorFromHistory,
            },
            &id,
            record,
            None,
        );
        (format!("surface-descriptor://{id}"), status)
    }

    /// A COMPLETE v2 authoring request, exactly as the route accepts one.
    ///
    /// Passed whole into `build_descriptor_v2`, so every member check, the closed nonclaim
    /// vocabulary, the owner resolution of the ontology binding and the migration derivation all run.
    fn upgrade_request(owner_ref: &str, key: &str, revision_ref: &str) -> Value {
        json!({
            "owner_ref": owner_ref,
            "idempotency_key": key,
            "schema_version": DESCRIPTOR_V2_SCHEMA_VERSION,
            "display_name": "Intake console (converged from v1)",
            "surface_ref": "surface://acme-clinic/intake-console",
            "composition_pattern": "monitoring_console",
            "ontology_refs": [revision_ref],
            "canonical_object_model_refs": ["object-model://acme-clinic/patient-intake/appointment"],
            "data_recipe_refs": [],
            "policy_bound_data_view_refs": ["view://acme-clinic/intake/reviewer"],
            "authority_requirement_refs": ["scope:intake.review"],
            "daemon_api_refs": ["api://v1/hypervisor/ontology-versions"],
            "receipt_obligations": ["receipt://acme-clinic/intake/review-decision"],
            "conformance_profile_refs": ["profile://acme-clinic/intake/review-inbox/v1"],
            "connector_mapping_refs": [],
            "ontology_projection_refs": [],
            "allowed_action_refs": [],
            "operator_contract_refs": [],
            "mcp_contract_refs": [],
            "generated_artifact_refs": [],
            "does_not_assert": DESCRIPTOR_REQUIRED_NONCLAIMS,
        })
    }

    /// Seed the smallest contract-valid M05.1 revision through THAT OWNER'S own admission helper.
    fn seed_ontology_revision(data_dir: &str, owner_ref: &str) -> String {
        let caller = super::super::mutation_event_foundation::WriteCaller {
            identity: upgrade_identity("user://one"),
            owner_ref: owner_ref.to_string(),
            idempotency_key: "upgrade-ontology-1".to_string(),
        };
        let proposal = json!({
            "owner_ref": owner_ref,
            "idempotency_key": "upgrade-ontology-1",
            "namespace": "acme-clinic",
            "name": "patient-intake",
            "governing_scope_ref": "domain://acme-clinic/intake",
            "policy_hash": format!("sha256:{}", "1a".repeat(32)),
            "entity_types": [{
                "term_id": "ontology://acme-clinic/patient-intake/term/patient",
                "label": "patient",
            }],
            "valid_time": { "starts_at": "2026-01-01T00:00:00Z", "ends_at": null },
        });
        let (document, _) = super::super::ontology_version_routes::admit_revision_for_test(
            data_dir, &caller, &proposal, None,
        )
        .expect("the ontology owner admits its own prerequisite revision");
        document["ontology_id"]
            .as_str()
            .expect("the admitted revision names itself")
            .to_string()
    }

    #[test]
    fn the_historical_v1_upgrade_converges_restarts_and_replays() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = upgrade_identity("user://one");
        const OWNER: &str = "org://acme-clinic";
        const V1_ID: &str = "sd_1a2b3c4d5e6f70819";

        // --------------------------------- the REAL M05.1 prerequisite, through its owner's own code
        let revision_ref = seed_ontology_revision(data_dir, OWNER);
        assert_eq!(
            revision_ref, "ontology://acme-clinic/patient-intake/revision/1",
            "the prerequisite is an EXACT admitted revision, not a family head"
        );

        // ---------------------------------------------------------------- a REAL stored v1 exists
        let (v1_ref, status) = seed_v1(
            data_dir,
            &identity,
            OWNER,
            V1_ID,
            "legacy-create-1",
            "Intake console",
        );
        assert_eq!(status, StatusCode::CREATED, "the v1 seed is admitted");

        // ------------------------------------------------ state closes and reopens, then resolves
        super::super::substrate_store::reset_handle_for_test();
        let stored = resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
            .expect("a stored v1 resolves after the handle is reopened");
        assert_eq!(stored.schema_version, DESCRIPTOR_V1_SCHEMA_VERSION);
        // FINDING 2: v1 is validated against its OWN registered contract on the read path. It used
        // to be the unchecked half — only v2 was validated, so a stored v1 was served unexamined.
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            DESCRIPTOR_V1_CONTRACT_ID,
            &stored.record,
        )
        .expect("the seeded v1 is valid against the registered v1 contract");

        // FINDING 3: destroying the v1 row and rebuilding restores a v1-SHAPED row, rather than
        // answering 200 and writing nothing.
        let row_id = v1_ref.trim_start_matches("surface-descriptor://");
        let row_as_written = load(data_dir, KIND_SD, row_id).expect("the seed wrote a row");
        remove_record(data_dir, KIND_SD, row_id);
        assert!(load(data_dir, KIND_SD, row_id).is_none(), "the row is gone");
        let rebuilt = rebuild_descriptor_row(data_dir, &identity, &v1_ref)
            .expect("a stored v1 row rebuilds from the chain");
        assert_eq!(rebuilt.index_state, "absent_rebuilt_from_agentgres");
        let restored_row = load(data_dir, KIND_SD, row_id).expect("the v1 row is written back");
        // THE REPAIR IS BYTE-IDENTICAL TO THE WRITE, which is the whole claim a rebuildable
        // projection makes. It could not have been while the timestamps were recovered FROM the row:
        // repairing a deleted row wrote `created_at: null` / `updated_at: null`, so the restored row
        // and the written one differed in exactly the two fields the repair was least able to check.
        assert_eq!(
            restored_row, row_as_written,
            "a rebuilt v1 row is byte-identical to the row the write path produced"
        );
        // The legacy lane INLINES its runtime timestamps into the row, so a rebuilt v1 row is the
        // admitted record plus those two keys — that shape is the point, and it is what a silent
        // no-op would not have produced.
        let mut without_stamps = restored_row.clone();
        let row_object = without_stamps
            .as_object_mut()
            .expect("the row is an object");
        assert_eq!(
            row_object.remove("created_at"),
            Some(json!(rebuilt.projected_created_at)),
            "creation time is DERIVED from the genesis admission, not copied from the row"
        );
        assert_eq!(
            row_object.remove("updated_at"),
            Some(json!(rebuilt.projected_updated_at)),
            "last-update time is DERIVED from the latest admission, not copied from the row"
        );
        assert!(
            rebuilt.projected_created_at.ends_with('Z') && !rebuilt.projected_created_at.is_empty(),
            "the derived stamp is a real admission time: {}",
            rebuilt.projected_created_at
        );
        assert_eq!(
            without_stamps, stored.record,
            "a rebuilt v1 row carries the admitted record in the legacy lane's own shape"
        );
        // AND IT IS IDEMPOTENT. A second repair over an already-agreeing row changes nothing and says
        // so, which is how an operator tells a no-op apart from a recovery.
        let again = rebuild_descriptor_row(data_dir, &identity, &v1_ref)
            .expect("a healthy v1 row rebuilds again");
        assert_eq!(again.index_state, "agreed_with_agentgres");
        assert_eq!(load(data_dir, KIND_SD, row_id), Some(restored_row.clone()));

        // ------------------------------------------------------- the convergence, production code
        //
        // THE WHOLE BUILDER RUNS. `build_descriptor_v2` validates the version gate, refuses the
        // legacy names, checks all eight members, resolves the ontology binding through M05.1's own
        // seam, enforces the closed nonclaim vocabulary, derives the migration block, assembles the
        // record, commits it and validates it against the registered contract — none of which is
        // skipped or supplied here.
        let convergence_key = "converge-1";
        let converged_id = odk_derived_id("sd", OWNER, convergence_key);
        let mut request = upgrade_request(OWNER, convergence_key, &revision_ref);
        request[DESCRIPTOR_MIGRATION_SOURCE_KEY] = json!(v1_ref);
        let frozen = descriptor_v1_content_hash(&stored.record);

        let converged = build_descriptor_v2(
            data_dir,
            &identity,
            &request,
            &converged_id,
            OWNER,
            "monitoring_console",
        )
        .expect("the production builder converges a same-owner stored v1");
        assert_eq!(
            converged["migration"]["compatibility"],
            json!("converged_from_v1")
        );
        assert_eq!(
            converged["migration"]["from_schema_version"],
            json!(DESCRIPTOR_V1_SCHEMA_VERSION)
        );
        assert_eq!(converged["migration"]["from_descriptor_ref"], json!(v1_ref));
        assert_eq!(
            converged["migration"]["reinterprets_predecessor"],
            json!(false)
        );
        // The frozen bytes are the predecessor's OWN commitment, under the v1 domain separator.
        assert_eq!(converged["migration"]["from_content_hash"], json!(frozen));
        // THE BINDING IS THE ONTOLOGY OWNER'S, RESOLVED — not a row this test supplied.
        assert_eq!(converged["ontology_refs"], json!([revision_ref]));
        assert_eq!(
            converged["bound_ontology_revisions"][0]["ontology_revision_ref"],
            json!(revision_ref)
        );
        let owner_hash = converged["bound_ontology_revisions"][0]["ontology_content_hash"]
            .as_str()
            .expect("the owner committed a hash")
            .to_string();
        assert!(owner_hash.starts_with("sha256:") && owner_hash.len() == 71);
        assert_eq!(converged["bound_ontology_revision_count"], json!(1));
        assert_eq!(
            converged["ontology_resolved_by"],
            json!("ontology_version_routes::resolve_admitted_revision"),
            "the successor pins the real owner seam"
        );
        let (status, Json(reply)) = odk_admit_with_identity(
            data_dir,
            &identity,
            &request,
            OdkAdmission {
                family: KIND_SD,
                scope_kind: ODK_DESCRIPTOR_SCOPE_KIND,
                ref_prefix: "surface-descriptor://",
                op_kind: "event_stream.hypervisor_odk_surface_descriptor_admitted",
                reply_key: "surface_descriptor",
                persist_error: "odk_surface_descriptor_persistence_failed",
                projection: OdkProjection::DescriptorFromHistory,
            },
            &converged_id,
            converged.clone(),
            None,
        );
        assert_eq!(status, StatusCode::CREATED, "the convergence is admitted");
        // FINDING 8: the reply is the BARE REGISTERED RECORD, byte-identical to what was assembled —
        // not the storage envelope, which is what every other read returns.
        assert_eq!(reply["surface_descriptor"], converged);

        // ------------------------------------------------------------------ restart, then resolve
        super::super::substrate_store::reset_handle_for_test();
        let converged_ref = format!("surface-descriptor://{converged_id}");
        let after_restart =
            resolve_admitted_surface_descriptor(data_dir, &identity, &converged_ref)
                .expect("the converged successor resolves after a restart");
        assert_eq!(
            after_restart.record, converged,
            "the converged record projects byte-identically across a restart"
        );
        // The predecessor is UNREINTERPRETED: it is still itself, still v1, still its own bytes.
        let predecessor_after = resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
            .expect("the v1 predecessor is still readable after its successor exists");
        assert_eq!(predecessor_after.record, stored.record);
        assert_eq!(
            predecessor_after.schema_version,
            DESCRIPTOR_V1_SCHEMA_VERSION
        );

        // --------------------------------- THE SOURCE MOVES, AND THE CONVERGENCE KEY STILL REPLAYS
        //
        // This is the case that made the whole replay-first ordering necessary: a convergence
        // re-derives its source hash from the predecessor, so a source that advanced between the
        // first attempt and the retry changed the bytes of an already-admitted command and the
        // substrate answered `same key, different bytes`.
        let head = super::super::substrate_store::read_event_stream_operation(
            data_dir,
            ODK_NAMESPACE,
            &odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, &v1_ref),
        )
        .expect("the v1 stream reads")
        .expect("the v1 stream has a head")
        .head;
        let mut moved = stored.record.clone();
        moved["name"] = json!("Intake console, renamed after the convergence");
        let (status, _) = odk_admit_with_identity(
            data_dir,
            &identity,
            &json!({ "idempotency_key": "legacy-patch-2", "expected_head": head }),
            OdkAdmission {
                family: KIND_SD,
                scope_kind: ODK_DESCRIPTOR_SCOPE_KIND,
                ref_prefix: "surface-descriptor://",
                op_kind: "event_stream.hypervisor_odk_surface_descriptor_revised",
                reply_key: "surface_descriptor",
                persist_error: "odk_surface_descriptor_persistence_failed",
                projection: OdkProjection::DescriptorFromHistory,
            },
            row_id,
            moved,
            Some(&stored.record),
        );
        assert_eq!(status, StatusCode::OK, "the v1 source advances");
        let moved_hash = descriptor_v1_content_hash(
            &resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
                .expect("the moved v1 resolves")
                .record,
        );
        assert_ne!(moved_hash, frozen, "the source really did change");

        // The retry finds its own admitted fact, with the bytes it originally FROZE.
        let history = descriptor_admitted_history(data_dir, &identity, Some(OWNER), &converged_ref)
            .expect("the converged history reads");
        let prior = history
            .iter()
            .find(|entry| entry.operation.idem_key == convergence_key)
            .expect("the convergence key is in its own history");
        assert!(
            descriptor_replay_intent_divergence(&prior.operation.payload, &request).is_none(),
            "the retry is the same command"
        );
        let (status, Json(replay)) = descriptor_replay_reply(&converged_ref, prior);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["replayed"], json!(true));
        // FINDING 8 again: a replay returns the same bare registered record, byte-for-byte.
        assert_eq!(replay["surface_descriptor"], converged);
        assert_eq!(
            replay["surface_descriptor"]["migration"]["from_content_hash"],
            json!(frozen),
            "the replay carries the bytes the convergence froze, not the source's current bytes"
        );

        // ------------------------------------------------------------------ and the refusals
        //
        // Every one goes through the WHOLE production builder, not the migration seam alone, so each
        // is proven reachable on the real authoring path with the ontology binding already resolved.
        let target = "sd_fedcba98765432100";
        let converge_from = |source: &str, extra: Option<(&str, &str)>| {
            let mut body = upgrade_request(OWNER, "refusal-probe", &revision_ref);
            body[DESCRIPTOR_MIGRATION_SOURCE_KEY] = json!(source);
            if let Some((key, value)) = extra {
                body[key] = json!(value);
            }
            body
        };

        // CHANGED SOURCE, ASSERTED: a caller pinning the bytes it read is refused once they move.
        let (status, Json(refusal)) = build_descriptor_v2(
            data_dir,
            &identity,
            &converge_from(
                &v1_ref,
                Some(("expected_migration_source_content_hash", &frozen)),
            ),
            target,
            OWNER,
            "monitoring_console",
        )
        .expect_err("a pinned source that has moved is refused");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            refusal["error"]["code"],
            json!("odk_descriptor_migration_source_substituted")
        );

        // DOWNGRADE / SIDEWAYS: a v2 is never a convergence source.
        let (_, Json(refusal)) = build_descriptor_v2(
            data_dir,
            &identity,
            &converge_from(&converged_ref, None),
            target,
            OWNER,
            "monitoring_console",
        )
        .expect_err("a v2 source is refused");
        assert_eq!(
            refusal["error"]["code"],
            json!("odk_descriptor_migration_source_not_v1")
        );

        // SELF-SOURCE: a record naming itself has a cycle, not a provenance.
        let (_, Json(refusal)) = build_descriptor_v2(
            data_dir,
            &identity,
            &converge_from(&v1_ref, None),
            V1_ID,
            OWNER,
            "monitoring_console",
        )
        .expect_err("a self-naming source is refused");
        assert_eq!(
            refusal["error"]["code"],
            json!("odk_descriptor_migration_source_is_itself")
        );

        // CROSS-OWNER: another principal's descriptor is not a convergence source, and the refusal
        // comes from the owner seam rather than from a comparison this module makes on borrowed
        // bytes — a caller with no scope learns nothing about whether the source exists. It refuses
        // at the ONTOLOGY binding first, because that owner scopes its family the same way: a
        // stranger cannot reach either resource, which is the property being asserted.
        let stranger = upgrade_identity("user://two");
        let (_, Json(refusal)) = build_descriptor_v2(
            data_dir,
            &stranger,
            &converge_from(&v1_ref, None),
            target,
            OWNER,
            "monitoring_console",
        )
        .expect_err("another principal cannot converge from this descriptor");
        assert!(
            matches!(
                refusal["error"]["code"].as_str(),
                Some("odk_descriptor_migration_source_unresolved")
                    | Some("odk_descriptor_ontology_ref_unresolved")
            ),
            "a stranger is refused by an owner seam, not by a comparison on borrowed bytes: {refusal}"
        );
        // And the migration seam refuses it on its own, with no ontology step in the way.
        let (_, Json(refusal)) = descriptor_migration_block(
            data_dir,
            &stranger,
            &json!({ DESCRIPTOR_MIGRATION_SOURCE_KEY: v1_ref }),
            target,
            OWNER,
        )
        .expect_err("the migration seam refuses a stranger's convergence source");
        assert_eq!(
            refusal["error"]["code"],
            json!("odk_descriptor_migration_source_unresolved")
        );
    }

    /// WITHDRAWING A STORED v1: the version-correct projection, the retry, the restart, the repair.
    ///
    /// THE PATH NO HTTP REQUEST CAN REACH. Authoring a v1 is closed by design, so a stored v1 only
    /// ever exists from before this build — and the one mutation an operator is most likely to run
    /// against such a record is a withdrawal. That path built a correct v1 tombstone and then wrote
    /// it through an envelope hard-coded to the v2 contract, so the row on disk announced
    /// `descriptor_contract_id: schema://…/ontology-surface-descriptor/v2` over a record admitted as
    /// v1. Nothing failed. The chain was right, the answer was right, and the projection carried a
    /// contract claim about bytes that were never admitted under it — while the documented repair,
    /// `POST …/rebuild-index`, wrote the SAME descriptor in a different shape. Two shapes for one
    /// admitted state, and the disagreement was invisible because every read answers from the chain.
    ///
    /// This drives `withdraw_descriptor_with_identity` — the production withdrawal, not a copy — over
    /// a seeded v1, then retries it, restarts the substrate, destroys the row and repairs it.
    #[test]
    fn a_stored_v1_withdrawal_is_version_correct_and_repairs_to_the_same_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = upgrade_identity("user://one");
        const OWNER: &str = "org://acme-clinic";
        const V1_ID: &str = "sd_0f1e2d3c4b5a69788";

        let (v1_ref, status) = seed_v1(
            data_dir,
            &identity,
            OWNER,
            V1_ID,
            "legacy-create-1",
            "Intake console",
        );
        assert_eq!(status, StatusCode::CREATED, "the v1 seed is admitted");
        let head = super::super::substrate_store::read_event_stream_operation(
            data_dir,
            ODK_NAMESPACE,
            &odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, &v1_ref),
        )
        .expect("the v1 stream reads")
        .expect("the v1 stream has a head")
        .head;

        // ------------------------------------------------------------------------ the withdrawal
        let (status, Json(reply)) = withdraw_descriptor_with_identity(
            data_dir,
            &identity,
            V1_ID,
            "legacy-withdraw-1",
            &head,
        );
        assert_eq!(status, StatusCode::OK, "the v1 withdrawal is admitted");
        // v1 IS NOT REINTERPRETED ON THE WAY OUT. Its tombstone is its own record with its own
        // withdrawal state, under its own `schema_version` — not converged onto v2's `revoked`.
        assert_eq!(
            reply["surface_descriptor"]["schema_version"],
            json!(DESCRIPTOR_V1_SCHEMA_VERSION)
        );
        assert_eq!(reply["surface_descriptor"]["status"], json!("deleted"));

        // ------------------------------------------- THE ROW IS THE WITHDRAWN RECORD'S OWN SHAPE
        let withdrawn_row = load(data_dir, KIND_SD, V1_ID).expect("the withdrawn row is kept");
        assert_eq!(
            withdrawn_row["schema_version"],
            json!(DESCRIPTOR_V1_SCHEMA_VERSION),
            "a v1 withdrawal is stored in the legacy lane's inline shape"
        );
        assert!(
            withdrawn_row.get("descriptor_contract_id").is_none()
                && withdrawn_row.get("descriptor").is_none(),
            "the row claims no v2 contract over a v1 record: {withdrawn_row}"
        );
        assert_eq!(withdrawn_row["status"], json!("deleted"));
        // The runtime metadata is DERIVED: creation did not move when the withdrawal landed, and the
        // last-update did. Before this cut both were carried over from `previous["created_at"]`,
        // which a v2 record does not have and a v1 row held only by accident of shape.
        let resolved = resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
            .expect("the withdrawn v1 still resolves");
        assert_eq!(resolved.revision_count, 2, "genesis plus withdrawal");
        assert_eq!(resolved.index_state, "agreed_with_agentgres");
        assert_eq!(
            withdrawn_row["created_at"],
            json!(resolved.projected_created_at)
        );
        assert_eq!(
            withdrawn_row["updated_at"],
            json!(resolved.projected_updated_at)
        );
        assert!(
            !resolved.projected_created_at.is_empty() && !resolved.projected_updated_at.is_empty(),
            "neither derived stamp is null after a withdrawal"
        );

        // -------------------------------------------------------- an exact retry replays, not 404
        let (status, Json(retry)) = withdraw_descriptor_with_identity(
            data_dir,
            &identity,
            V1_ID,
            "legacy-withdraw-1",
            &head,
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retry["replayed"], json!(true));
        assert_eq!(
            retry["surface_descriptor"], reply["surface_descriptor"],
            "the retry replays its own admitted withdrawal byte-for-byte"
        );
        assert_eq!(
            resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
                .expect("the withdrawn v1 resolves after the retry")
                .revision_count,
            2,
            "the retry appended nothing"
        );

        // ------------------------------------------- restart, then destroy the row and repair it
        super::super::substrate_store::reset_handle_for_test();
        let after_restart = resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
            .expect("the withdrawn v1 resolves after the handle is reopened");
        assert_eq!(after_restart.record, resolved.record);
        assert_eq!(after_restart.index_state, "agreed_with_agentgres");

        remove_record(data_dir, KIND_SD, V1_ID);
        let repaired = rebuild_descriptor_row(data_dir, &identity, &v1_ref)
            .expect("a withdrawn v1 row rebuilds from the chain");
        assert_eq!(repaired.index_state, "absent_rebuilt_from_agentgres");
        assert_eq!(
            load(data_dir, KIND_SD, V1_ID),
            Some(withdrawn_row.clone()),
            "the repair restores exactly the bytes the withdrawal wrote — same shape, same stamps"
        );

        // A CORRUPTED ROW IS NEITHER TRUSTED NOR PRESERVED, including its metadata. Corrupting only
        // the timestamps is the case the old repair could not fix: it copied them straight back.
        let mut corrupt = withdrawn_row.clone();
        corrupt["created_at"] = json!("1999-01-01T00:00:00Z");
        corrupt["status"] = json!("draft");
        persist_required(data_dir, KIND_SD, V1_ID, &corrupt, "unreachable")
            .expect("the corrupt row is planted");
        let over_corruption = resolve_admitted_surface_descriptor(data_dir, &identity, &v1_ref)
            .expect("a corrupted row does not stop the chain answering");
        assert_eq!(over_corruption.index_state, "stale_rebuilt_from_agentgres");
        assert_eq!(
            over_corruption.record, resolved.record,
            "the corruption never reaches the answer"
        );
        rebuild_descriptor_row(data_dir, &identity, &v1_ref).expect("the corrupt row is repaired");
        assert_eq!(
            load(data_dir, KIND_SD, V1_ID),
            Some(withdrawn_row),
            "the repair discards the corrupted stamps rather than carrying them forward"
        );
    }

    /// The create allowlist is exactly the caller-authored half of the contract plus the control and
    /// assertion inputs — so a member added to the contract cannot be left unauthorable.
    #[test]
    fn the_create_allowlist_is_exactly_caller_intent_plus_control_and_assertions() {
        let mut expected: Vec<&str> = DESCRIPTOR_CALLER_INTENT_FIELDS
            .iter()
            .copied()
            .chain(std::iter::once(DESCRIPTOR_MIGRATION_SOURCE_KEY))
            .chain(DESCRIPTOR_CONTROL_FIELDS.iter().copied())
            .chain(DESCRIPTOR_ASSERTION_FIELDS.iter().copied())
            .collect();
        expected.sort_unstable();
        let mut actual: Vec<&str> = DESCRIPTOR_CREATE_REQUEST_FIELDS.to_vec();
        actual.sort_unstable();
        assert_eq!(actual, expected);

        // The patch set is the governed fields plus the same control and assertion inputs, and
        // `owner_ref` is deliberately NOT among them: a successor takes its owner from the admitted
        // record, so a body `owner_ref` changed nothing and was answered 200.
        let mut patch: Vec<&str> = DESCRIPTOR_PATCHABLE_FIELDS
            .iter()
            .copied()
            .chain(std::iter::once("status"))
            .chain(DESCRIPTOR_CONTROL_FIELDS.iter().copied())
            .chain(DESCRIPTOR_ASSERTION_FIELDS.iter().copied())
            .collect();
        patch.sort_unstable();
        let mut actual_patch: Vec<&str> = DESCRIPTOR_PATCH_REQUEST_FIELDS.to_vec();
        actual_patch.sort_unstable();
        assert_eq!(actual_patch, patch);
        assert!(!DESCRIPTOR_PATCH_REQUEST_FIELDS.contains(&"owner_ref"));

        // An authority-looking substitution is outside both closed sets, so it is refused BY NAME
        // rather than accepted and ignored — and the refusal names the RIGHT reason. A field this
        // contract does not have is unknown; a field it HAS but the server derives is refused as
        // not-caller-authored, because telling a caller `authority_nonclaim` is "unknown" would be
        // false, and accepting it would let a caller write its own nonclaims.
        for (forged, expected) in [
            (
                "authority_grant_ref",
                "odk_descriptor_request_field_unknown",
            ),
            (
                "capability_lease_ref",
                "odk_descriptor_request_field_unknown",
            ),
            ("granted_scopes", "odk_descriptor_request_field_unknown"),
            (
                "authority_nonclaim",
                "odk_descriptor_field_not_caller_authored",
            ),
            ("content_hash", "odk_descriptor_field_not_caller_authored"),
            (
                "bound_ontology_revisions",
                "odk_descriptor_field_not_caller_authored",
            ),
        ] {
            assert!(!DESCRIPTOR_CREATE_REQUEST_FIELDS.contains(&forged));
            assert!(!DESCRIPTOR_PATCH_REQUEST_FIELDS.contains(&forged));
            let refused = refuse_unknown_request_fields(
                &json!({ forged: "anything" }),
                DESCRIPTOR_CREATE_REQUEST_FIELDS,
                "create",
            );
            let (status, Json(payload)) = refused.expect_err("a forged field is refused");
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(payload["error"]["code"], json!(expected), "for '{forged}'");
        }
        // And on the patch route the same contract field is refused as NOT PATCHABLE, which is the
        // governance answer that route owes.
        let (_, Json(payload)) = refuse_unknown_request_fields(
            &json!({ "ontology_refs": [] }),
            DESCRIPTOR_PATCH_REQUEST_FIELDS,
            "patch",
        )
        .expect_err("a binding is refused on patch");
        assert_eq!(
            payload["error"]["code"],
            json!("odk_descriptor_field_not_patchable")
        );
        // A legacy spelling keeps its own, more informative refusal on BOTH routes rather than being
        // shadowed by the allowlist.
        for allowed in [
            DESCRIPTOR_CREATE_REQUEST_FIELDS,
            DESCRIPTOR_PATCH_REQUEST_FIELDS,
        ] {
            let (_, Json(payload)) =
                refuse_unknown_request_fields(&json!({ "ontology_ref": "x" }), allowed, "create")
                    .expect_err("a legacy spelling is refused");
            assert_eq!(
                payload["error"]["code"],
                json!("odk_descriptor_legacy_field_name")
            );
        }
    }

    /// The patch allowlist names only fields the v2 contract actually has.
    ///
    /// The list it replaces was inherited from v1 and named `description` and `view_config`, which
    /// are not v2 fields — so a caller patching either was refused for being "not registered-valid"
    /// rather than for naming a field this object does not have.
    #[test]
    fn every_patchable_field_is_a_field_of_the_v2_contract() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/ontology-surface-descriptor.v2.schema.json"
        ))
        .expect("v2 schema is JSON");
        let properties = schema["properties"].as_object().expect("v2 properties");
        for field in DESCRIPTOR_PATCHABLE_FIELDS {
            assert!(properties.contains_key(*field), "{field} is not a v2 field");
        }
        // No binding is patchable: a descriptor binds EXACT admitted revisions, so moving one
        // describes a different surface rather than amending this one.
        for member in INVARIANT_11_BINDING_SET {
            assert!(!DESCRIPTOR_PATCHABLE_FIELDS.contains(member));
        }
        for reserved in ["content_hash", "migration", "constants", "owner_ref"] {
            assert!(!DESCRIPTOR_PATCHABLE_FIELDS.contains(&reserved));
        }
    }
}

#[cfg(test)]
mod odk_tests {
    use super::*;

    /// W1.2 / MEF-GAP-004 — a descriptor create is an owner-scoped mutation. The five properties
    /// the coverage declaration named, asserted at the unit that enforces them: authenticated
    /// owner scope, caller idempotency, genesis CAS, admission, and a receipt.
    #[test]
    fn descriptor_identity_is_derived_from_owner_and_caller_key_not_wall_clock() {
        // The whole point of dropping nanos(): the same owner + key must resolve to the same
        // resource, so a retried create cannot mint a second descriptor.
        let derive = |owner: &str, key: &str| odk_derived_id("sd", owner, key);
        let a_id = |owner: &str, key: &str| odk_derived_id("sd", owner, key);
        assert_eq!(
            a_id("org://acme", "k"),
            odk_derived_id("sd", "org://acme", "k")
        );
        let a = derive("org://acme", "form-submit-1");
        assert_eq!(
            a,
            derive("org://acme", "form-submit-1"),
            "a retry is the same resource"
        );
        assert_ne!(
            a,
            derive("org://acme", "form-submit-2"),
            "a different key is a different resource"
        );
        assert_ne!(
            a,
            derive("org://other", "form-submit-1"),
            "owner is part of identity"
        );
        assert!(a.starts_with("sd_") && a.len() == 19);
    }

    /// The scope kind and stream tail must be stable and owner-namespaced, or two descriptors
    /// would share an Agentgres stream and CAS would compare the wrong heads.
    #[test]
    fn descriptor_stream_tail_is_stable_and_resource_bound() {
        // Reader and writer MUST derive the tail from the same constant. They once did not:
        // the GET used a literal while the writer used the scope kind, so `admitted_head` read
        // an empty stream and every compare-and-swap patch refused.
        let one = odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, "surface-descriptor://sd_aaa");
        let two = odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, "surface-descriptor://sd_bbb");
        assert_eq!(
            one,
            odk_hash_tail(ODK_DESCRIPTOR_SCOPE_KIND, "surface-descriptor://sd_aaa")
        );
        assert_ne!(
            one, two,
            "distinct descriptors must not share a stream tail"
        );
        assert!(one.starts_with(&format!("{ODK_DESCRIPTOR_SCOPE_KIND}.")));
        assert_eq!(ODK_NAMESPACE, "hypervisor-odk");
        assert_eq!(
            ODK_DESCRIPTOR_SCOPE_KIND,
            "hypervisor-odk-surface-descriptor"
        );
    }

    /// A refusal must carry the status its class implies. An unauthenticated write answering 200,
    /// or a CAS conflict answering 400, is the failure mode this whole packet exists to remove.
    #[test]
    fn descriptor_refusals_carry_their_class_status() {
        use super::super::substrate_store::RequestScopeRefusal;
        assert_eq!(
            odk_scope_refusal(RequestScopeRefusal::AuthenticationRequired).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            odk_scope_refusal(RequestScopeRefusal::ResourceOwnerMismatch).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            odk_mutation_refusal(
                super::super::mutation_event_foundation::MutationRefusal::IdempotencyKeyInvalid
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            odk_mutation_refusal(
                super::super::mutation_event_foundation::MutationRefusal::GenesisExpectedHeadPresent
            )
            .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn expected_revision_matches_mismatches_and_malformed() {
        // Legacy callers omitting it are preserved.
        assert!(check_expected_revision(&json!({}), 3).is_ok());
        assert!(check_expected_revision(&json!({ "expected_revision": null }), 3).is_ok());
        assert!(check_expected_revision(&json!({ "expected_revision": 3 }), 3).is_ok());
        // Mismatch → typed conflict with the CONFLICT status.
        let (st, code, _m) =
            check_expected_revision(&json!({ "expected_revision": 2 }), 3).unwrap_err();
        assert_eq!(st, StatusCode::CONFLICT);
        assert_eq!(code, "odk_revision_conflict");
        // Malformed (string / float / negative) → typed invalid with BAD_REQUEST.
        for bad in [json!("3"), json!(3.5), json!(-1)] {
            let (st2, code2, _m2) =
                check_expected_revision(&json!({ "expected_revision": bad }), 3).unwrap_err();
            assert_eq!(st2, StatusCode::BAD_REQUEST);
            assert_eq!(code2, "odk_expected_revision_invalid");
        }
    }

    #[test]
    fn hardened_fields_reject_wrong_types_and_oversize() {
        assert_eq!(str_opt_bounded(&json!({}), "version", 60).unwrap(), None);
        assert_eq!(
            str_opt_bounded(&json!({ "version": "1.0" }), "version", 60).unwrap(),
            Some("1.0".into())
        );
        assert_eq!(
            str_opt_bounded(&json!({ "version": 7 }), "version", 60)
                .unwrap_err()
                .0,
            "odk_field_type_invalid"
        );
        assert_eq!(
            str_opt_bounded(&json!({ "version": "x".repeat(61) }), "version", 60)
                .unwrap_err()
                .0,
            "odk_field_too_long"
        );
    }

    #[test]
    fn validator_rejects_untyped_entries_bad_enums_and_bad_required() {
        // Non-object entry.
        assert_eq!(
            validate_object_model(&json!({ "object_types": ["loan"] }))
                .unwrap_err()
                .0,
            "ontology_entry_invalid"
        );
        // enum_values wrong type / non-string members.
        assert_eq!(validate_object_model(&json!({ "value_types": [{ "id": "e", "name": "E", "base": "enum", "enum_values": "a,b" }] })).unwrap_err().0, "ontology_field_type_invalid");
        assert_eq!(validate_object_model(&json!({ "value_types": [{ "id": "e", "name": "E", "base": "enum", "enum_values": [1, 2] }] })).unwrap_err().0, "ontology_field_type_invalid");
        // required must be boolean when present.
        assert_eq!(validate_object_model(&json!({ "object_types": [{ "id": "a", "name": "A", "properties": [{ "id": "t", "name": "T", "value_type": "string", "required": "yes" }] }] })).unwrap_err().0, "ontology_field_type_invalid");
        // title_property must be a string when present.
        assert_eq!(validate_object_model(&json!({ "object_types": [{ "id": "a", "name": "A", "title_property": 4, "properties": [{ "id": "t", "name": "T", "value_type": "string" }] }] })).unwrap_err().0, "ontology_field_type_invalid");
        // Oversized collection.
        let big: Vec<Value> = (0..COM_COLLECTION_MAX + 1)
            .map(|i| json!({ "id": format!("v{i}"), "name": format!("V{i}") }))
            .collect();
        assert_eq!(
            validate_object_model(&json!({ "value_types": big }))
                .unwrap_err()
                .0,
            "ontology_collection_bounds"
        );
        // Legacy untyped string-array builders stay tolerated (untyped/empty health, never typed).
        let h = validate_object_model(&json!({ "objects": ["a", "b"] })).unwrap();
        assert_eq!(h["legacy_untyped_names"], json!(2));
    }

    #[test]
    fn ontology_finalize_rolls_back_create_and_restores_patch_on_receipt_failure() {
        let dir = std::env::temp_dir().join(format!("ioi-ont-final-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();
        let now = "2026-01-01T00:00:00Z";
        let (rid, receipt) =
            build_ontology_receipt("ontology://ont_x", "created", "s", now, "user://tester");
        // INV-37: the receipt names the resolved acting principal.
        assert_eq!(receipt["acting_principal_ref"], json!("user://tester"));
        let record =
            json!({ "id": "ont_x", "ref": "ontology://ont_x", "revision": 1, "status": "draft" });
        // Block the receipts dir with a plain file → receipt persist fails.
        std::fs::write(dir.join(KIND_ONT_RECEIPT), b"blocker").unwrap();
        // CREATE lane: the created record must be ROLLED BACK (removed).
        let err = finalize_ontology_persist(data_dir, "ont_x", None, &record, &rid, &receipt)
            .unwrap_err();
        assert!(err.contains("rolled back"), "{err}");
        assert!(
            load(data_dir, KIND_ONT, "ont_x").is_none(),
            "no unproven ontology survives"
        );
        // PATCH lane: the PRIOR record must be RESTORED.
        persist_record(data_dir, KIND_ONT, "ont_x", &record).unwrap();
        let updated =
            json!({ "id": "ont_x", "ref": "ontology://ont_x", "revision": 2, "status": "draft" });
        let err2 =
            finalize_ontology_persist(data_dir, "ont_x", Some(&record), &updated, &rid, &receipt)
                .unwrap_err();
        assert!(err2.contains("restored"), "{err2}");
        assert_eq!(
            load(data_dir, KIND_ONT, "ont_x").unwrap()["revision"],
            json!(1),
            "the stale patch did not survive"
        );
        // Happy path once unblocked: record + receipt both persist.
        std::fs::remove_file(dir.join(KIND_ONT_RECEIPT)).unwrap();
        finalize_ontology_persist(data_dir, "ont_x", Some(&record), &updated, &rid, &receipt)
            .unwrap();
        assert_eq!(
            load(data_dir, KIND_ONT, "ont_x").unwrap()["revision"],
            json!(2)
        );
        assert_eq!(
            load(data_dir, KIND_ONT_RECEIPT, &rid).unwrap()["op"],
            json!("created")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ontology_delete_emits_a_receipt_and_restores_the_record_when_the_receipt_cannot_persist() {
        let dir = std::env::temp_dir().join(format!("ioi-ont-del-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();
        let record =
            json!({ "id": "ont_d", "ref": "ontology://ont_d", "revision": 1, "status": "draft" });

        // A missing ontology reports honestly and attests nothing — there was no mutation.
        let missing = delete_ontology_receipted(data_dir, "ont_absent", "user://tester");
        assert_eq!(missing["ok"], json!(false));
        assert_eq!(missing["removed"], json!(false));
        assert!(read_record_dir(data_dir, KIND_ONT_RECEIPT).is_empty());

        // Receipt persist blocked → the record must be RESTORED; no unreceipted deletion survives.
        persist_record(data_dir, KIND_ONT, "ont_d", &record).unwrap();
        std::fs::write(dir.join(KIND_ONT_RECEIPT), b"blocker").unwrap();
        let blocked = delete_ontology_receipted(data_dir, "ont_d", "user://tester");
        assert_eq!(blocked["ok"], json!(false));
        assert_eq!(blocked["removed"], json!(false));
        assert!(
            blocked["reason"].as_str().unwrap().contains("restored"),
            "{blocked}"
        );
        assert!(
            load(data_dir, KIND_ONT, "ont_d").is_some(),
            "an unreceipted deletion must not survive"
        );

        // Happy path: the record is gone AND a `deleted` receipt exists naming the ontology.
        std::fs::remove_file(dir.join(KIND_ONT_RECEIPT)).unwrap();
        let ok = delete_ontology_receipted(data_dir, "ont_d", "user://tester");
        assert_eq!(ok["ok"], json!(true));
        assert_eq!(ok["removed"], json!(true));
        assert!(load(data_dir, KIND_ONT, "ont_d").is_none());
        let receipts = read_record_dir(data_dir, KIND_ONT_RECEIPT);
        assert_eq!(receipts.len(), 1, "exactly one delete receipt");
        assert_eq!(receipts[0]["op"], json!("deleted"));
        assert_eq!(receipts[0]["ontology_ref"], json!("ontology://ont_d"));
        assert_eq!(receipts[0]["acting_principal_ref"], json!("user://tester"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn split_ref_parses_scheme_and_rest() {
        assert_eq!(split_ref("ontology://ont_1"), Some(("ontology", "ont_1")));
        assert_eq!(
            split_ref("surface-descriptor://sd_9"),
            Some(("surface-descriptor", "sd_9"))
        );
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
        let err = require_local_ref("/nonexistent", "recipe://r1", "ontology", "ontology_ref")
            .unwrap_err();
        assert_eq!(err.0, "odk_ref_prefix_invalid");
        // right scheme but unresolvable (empty data dir) -> unresolved
        let err = require_local_ref(
            "/nonexistent",
            "ontology://ont_x",
            "ontology",
            "ontology_ref",
        )
        .unwrap_err();
        assert_eq!(err.0, "odk_ref_unresolved");
    }

    #[test]
    fn check_named_refs_ignores_external_but_flags_local_missing() {
        // external named refs (non-ODK scheme or no scheme) are always allowed
        assert!(check_named_refs(
            "/nonexistent",
            &["s3://bucket/x".into(), "trace-123".into()]
        )
        .is_ok());
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

    #[test]
    fn required_persistence_refuses_success_when_record_directory_is_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(KIND_SD), b"not-a-directory").unwrap();
        let error = persist_required(
            dir.path().to_str().unwrap(),
            KIND_SD,
            "sd_failure",
            &json!({"id":"sd_failure"}),
            "odk_surface_descriptor_persistence_failed",
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.1 .0["error"]["code"],
            json!("odk_surface_descriptor_persistence_failed")
        );
    }

    // ---- Ontology-manager contract validation.

    #[test]
    fn type_id_shape_is_enforced() {
        assert!(valid_type_id("loan"));
        assert!(valid_type_id("loan_v2"));
        assert!(!valid_type_id("Loan")); // uppercase-first
        assert!(!valid_type_id("2loan")); // digit-first
        assert!(!valid_type_id("loan type")); // space
        assert!(!valid_type_id("")); // empty
    }

    /// A well-formed model with a typed object (property → base value_type), a relation and an action.
    fn ready_model() -> Value {
        json!({
            "value_types": [{ "id": "money", "name": "Money", "base": "double" }],
            "object_types": [
                { "id": "loan", "name": "Loan", "title_property": "title",
                  "properties": [
                    { "id": "title", "name": "Title", "value_type": "string" },
                    { "id": "amount", "name": "Amount", "value_type": "money" }
                  ] },
                { "id": "borrower", "name": "Borrower", "title_property": "name",
                  "properties": [ { "id": "name", "name": "Name", "value_type": "string" } ] }
            ],
            "link_types": [{ "id": "held_by", "name": "Held by", "from": "loan", "to": "borrower", "cardinality": "one_to_many" }],
            "action_types": [{ "id": "approve", "name": "Approve", "kind": "modify_object", "applies_to": "loan" }]
        })
    }

    #[test]
    fn ready_model_projects_ready_health() {
        let h = validate_object_model(&ready_model()).expect("valid");
        assert_eq!(h["status"], "ready");
        assert_eq!(h["counts"]["object_types"], 2);
        assert_eq!(h["object_instances"], 0);
        assert_eq!(h["gaps"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn empty_model_is_allowed_but_empty_health() {
        let h = validate_object_model(&json!({})).expect("empty is allowed as a draft");
        assert_eq!(h["status"], "empty");
    }

    #[test]
    fn legacy_string_array_model_is_tolerated_as_empty() {
        // Back-compat: the pre-hardening shape (string arrays) must still validate (health empty).
        let legacy = json!({ "objects": ["Loan", "Borrower"], "actions": ["approve"], "states": ["draft"], "roles": [], "events": [] });
        let h = validate_object_model(&legacy).expect("legacy shape must not be rejected");
        assert_eq!(h["status"], "empty");
        assert_eq!(h["legacy_untyped_names"], 4);
    }

    #[test]
    fn object_without_relation_or_action_is_incomplete() {
        let m = json!({
            "object_types": [{ "id": "loan", "name": "Loan", "title_property": "title",
                "properties": [{ "id": "title", "name": "Title", "value_type": "string" }] }]
        });
        let h = validate_object_model(&m).expect("valid but incomplete");
        assert_eq!(h["status"], "incomplete");
        assert!(h["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g.as_str().unwrap().contains("relations or behaviors")));
    }

    #[test]
    fn invalid_type_id_is_rejected() {
        let mut m = ready_model();
        m["object_types"][0]["id"] = json!("Loan Type!");
        assert_eq!(
            validate_object_model(&m).unwrap_err().0,
            "ontology_type_id_invalid"
        );
    }

    #[test]
    fn duplicate_object_name_is_rejected() {
        let mut m = ready_model();
        m["object_types"][1]["name"] = json!("loan"); // dup of "Loan" (case-insensitive)
        assert_eq!(
            validate_object_model(&m).unwrap_err().0,
            "ontology_duplicate_name"
        );
    }

    #[test]
    fn unresolved_link_end_is_rejected() {
        let mut m = ready_model();
        m["link_types"][0]["to"] = json!("nonexistent");
        assert_eq!(
            validate_object_model(&m).unwrap_err().0,
            "ontology_ref_unresolved"
        );
    }

    #[test]
    fn unresolved_property_value_type_is_rejected() {
        let mut m = ready_model();
        m["object_types"][0]["properties"][1]["value_type"] = json!("currency"); // not a base nor declared
        assert_eq!(
            validate_object_model(&m).unwrap_err().0,
            "ontology_ref_unresolved"
        );
    }

    #[test]
    fn bad_cardinality_and_action_kind_are_rejected() {
        let mut m = ready_model();
        m["link_types"][0]["cardinality"] = json!("some_to_many");
        assert_eq!(
            validate_object_model(&m).unwrap_err().0,
            "ontology_cardinality_invalid"
        );
        let mut m2 = ready_model();
        m2["action_types"][0]["kind"] = json!("teleport");
        assert_eq!(
            validate_object_model(&m2).unwrap_err().0,
            "ontology_action_kind_invalid"
        );
    }

    #[test]
    fn enum_value_type_requires_values() {
        let m = json!({ "value_types": [{ "id": "grade", "name": "Grade", "base": "enum" }] });
        assert_eq!(
            validate_object_model(&m).unwrap_err().0,
            "ontology_enum_values_required"
        );
    }
}
