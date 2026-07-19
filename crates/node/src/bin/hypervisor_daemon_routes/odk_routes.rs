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

pub(crate) const KIND_ONT: &str = "odk-domain-ontologies";
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
const KIND_ONT_RECEIPT: &str = "odk-ontology-receipts";

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
        "object_data_note": "schema only — no object-instance/projection plane is bound; explorer rows require a real ontology-bound object plane (not built here)",
        "legacy_untyped_names": legacy_untyped
    }))
}

/// Build an ontology receipt (PURE — nothing persists here; #62 proof discipline). The receipt
/// carries only record-derived fields + the op/summary — never request material.
fn build_ontology_receipt(
    ontology_ref: &str,
    op: &str,
    summary: &str,
    now: &str,
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
fn check_expected_revision(body: &Value, current: u64) -> Result<(), (StatusCode, String, String)> {
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

/// POST /v1/hypervisor/odk/domain-ontologies — create a DomainOntology DRAFT. The semantic root: it
/// embeds a typed CanonicalObjectModel (value/object/link/action types), validated fail-closed, and
/// carries revision 1 + a create receipt + a readiness health projection.
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
    let (receipt_id, receipt) =
        build_ontology_receipt(&oref, "created", "DomainOntology draft created", &now);
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
    json_get(&st.data_dir, KIND_ONT, "ontology", &id)
}

/// PATCH — fail-closed on a malformed model (revision is NOT bumped on rejection); optimistic
/// concurrency via `expected_revision` (#63 — integer, must match exactly, refusal changes
/// NOTHING; legacy callers that omit it are preserved); on success bumps the revision exactly
/// once, recomputes health, appends bounded history, and persists record + patch receipt
/// atomically-with-restore (#62 discipline). Returns the ontology AND the durable receipt.
pub(crate) async fn handle_odk_ontology_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(prev) = load(&st.data_dir, KIND_ONT, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "ontology not found", "error": { "code": "odk_ontology_not_found", "message": "ontology not found" } }),
            ),
        );
    };
    let current_rev = prev.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    if let Err((status, code, msg)) = check_expected_revision(&body, current_rev) {
        return (
            status,
            Json(
                json!({ "ok": false, "error": { "code": code, "message": msg, "current_revision": current_rev } }),
            ),
        );
    }
    // Hardened (#63): editable fields present-but-wrong-type/oversized are rejected typed.
    let mut typed_fields: Vec<(&str, Value)> = Vec::new();
    for (key, max) in [("domain", 120usize), ("version", 60), ("description", 2000)] {
        match str_opt_bounded(&body, key, max) {
            Ok(Some(v)) => {
                if key == "domain" && v.trim().is_empty() {
                    return (
                        StatusCode::OK,
                        Json(
                            json!({ "ok": false, "error": { "code": "odk_domain_required", "message": "`domain` must stay non-empty" } }),
                        ),
                    );
                }
                typed_fields.push((key, json!(v)));
            }
            Ok(None) => {}
            Err((code, msg)) => {
                return (
                    StatusCode::OK,
                    Json(json!({ "ok": false, "error": { "code": code, "message": msg } })),
                )
            }
        }
    }
    if let Some(new_com) = body.get("canonical_object_model") {
        if !new_com.is_object() {
            return (
                StatusCode::OK,
                Json(
                    json!({ "ok": false, "error": { "code": "odk_field_type_invalid", "message": "`canonical_object_model` must be an object" } }),
                ),
            );
        }
        // Validate the replacement model BEFORE mutating anything — a bad patch changes nothing.
        if let Err((code, msg)) = validate_object_model(new_com) {
            return (
                StatusCode::OK,
                Json(json!({ "ok": false, "error": { "code": code, "message": msg } })),
            );
        }
    }
    let mut o = prev.clone();
    let mut changed: Vec<String> = Vec::new();
    for (key, v) in typed_fields {
        o[key] = v;
        changed.push(key.to_string());
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
    let (receipt_id, receipt) = build_ontology_receipt(&oref, "patched", &summary, &now);
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
        finalize_ontology_persist(&st.data_dir, &id, Some(&prev), &o, &receipt_id, &receipt)
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

pub(crate) async fn handle_odk_ontology_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    json_del(&st.data_dir, KIND_ONT, &id)
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
            return Json(
                json!({ "ok": false, "error": { "code": "odk_output_kind_invalid", "message": format!("output_kind must be one of {RECIPE_OUTPUT_KINDS:?}") } }),
            );
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

pub(crate) async fn handle_odk_manifest_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
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
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "manifest": record })),
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
            return Json(
                json!({ "ok": false, "error": { "code": "odk_composition_pattern_invalid", "message": format!("composition_pattern must be one of {COMPOSITION_PATTERNS:?}") } }),
            );
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
        let (rid, receipt) = build_ontology_receipt("ontology://ont_x", "created", "s", now);
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
