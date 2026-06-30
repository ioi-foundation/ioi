//! Foundry object plane — FOUNDATION cut (daemon-first, draft-only).
//!
//! Hypervisor Foundry is the persistent capability factory that unifies what borrowed tools split
//! across Model Catalog / Model Studio / Evals / Training / Inference / Ontology. This cut builds
//! the PLANE, not a dashboard: real durable objects (`FoundrySpec`, `FoundryRunPlan`) plus a read
//! projection (`overview`) bound to EXISTING real substrate — model-mount routes/providers/backends/
//! endpoints, model-mount receipts, agent transcripts, and the Work Ledger.
//!
//! It is deliberately inert:
//!   * no training execution, no eval execution, no inference serving;
//!   * no promotion mutation, no registry/alias mutation;
//!   * no authority crossing — a spec/plan only NAMES policy/evidence refs; it never enforces or
//!     bypasses authority.
//! Specs and plans are always `status: "draft"`. The Foundry UI card is intentionally NOT flipped
//! live in this cut: the plane exists first, the surface comes next (so it opens onto real objects
//! instead of an empty temple).

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const SPEC_KIND: &str = "foundry-specs";
const RUN_PLAN_KIND: &str = "foundry-run-plans";
const SPEC_SCHEMA: &str = "ioi.hypervisor.foundry-spec.v1";
const RUN_PLAN_SCHEMA: &str = "ioi.hypervisor.foundry-run-plan.v1";
/// The capability families a FoundrySpec can declare. They are LABELS for draft specs — none of
/// them executes in this foundation.
const SPEC_KINDS: &[&str] = &[
    "model_tune",
    "model_eval",
    "tool_build",
    "inference_endpoint",
    "ontology",
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

/// GET the daemon's own loopback API — counts/validates against the REAL substrate the rest of the
/// platform serves (no duplicated catalogs). Returns parsed JSON or Null on any failure.
async fn get_json(base: &str, path: &str) -> Value {
    let url = format!("{base}{path}");
    match reqwest::Client::new().get(&url).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    }
}

/// Pull a JSON list out of a daemon response that is either a top-level array or `{<key>: [...]}`.
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

/// Collect identifier strings from a list of records, checking each of `keys` per record.
fn collect_ids(list: &[Value], keys: &[&str]) -> HashSet<String> {
    let mut out = HashSet::new();
    for item in list {
        for k in keys {
            if let Some(s) = item.get(*k).and_then(|v| v.as_str()) {
                if !s.is_empty() {
                    out.insert(s.to_string());
                }
            }
        }
    }
    out
}

/// Read declared string refs from a body field (array of strings).
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

/// The real model-mount catalog ids a spec/plan may bind to.
struct Catalog {
    routes: HashSet<String>,
    providers: HashSet<String>,
    backends: HashSet<String>,
    endpoints: HashSet<String>,
}
async fn fetch_catalog(base: &str) -> Catalog {
    Catalog {
        routes: collect_ids(
            &as_list(&get_json(base, "/v1/model-mount/routes").await),
            &["id"],
        ),
        providers: collect_ids(
            &as_list(&get_json(base, "/v1/model-mount/providers").await),
            &["id", "provider_ref"],
        ),
        backends: collect_ids(
            &as_list(&get_json(base, "/v1/model-mount/backends").await),
            &["backend_id", "id"],
        ),
        endpoints: collect_ids(
            &as_list(&get_json(base, "/v1/model-mount/endpoints").await),
            &["endpoint_id", "id"],
        ),
    }
}

/// Validate a spec's bindings against the live catalog. Enforces: at least one real route OR
/// provider ref, and every declared catalog ref must resolve. Returns Err((code, message)).
fn validate_bindings(
    cat: &Catalog,
    route_refs: &[String],
    provider_refs: &[String],
    backend_refs: &[String],
    endpoint_refs: &[String],
) -> Result<(), (String, String)> {
    if route_refs.is_empty() && provider_refs.is_empty() {
        return Err((
            "foundry_binding_required".into(),
            "A FoundrySpec must bind to at least one real model route or provider (model_route_refs / provider_refs)."
                .into(),
        ));
    }
    let unknown =
        |refs: &[String], set: &HashSet<String>, label: &str| -> Option<(String, String)> {
            for r in refs {
                if !set.contains(r) {
                    return Some((
                        "foundry_ref_unresolved".into(),
                        format!("{label} ref '{r}' does not resolve to real substrate."),
                    ));
                }
            }
            None
        };
    if let Some(e) = unknown(route_refs, &cat.routes, "model_route") {
        return Err(e);
    }
    if let Some(e) = unknown(provider_refs, &cat.providers, "provider") {
        return Err(e);
    }
    if let Some(e) = unknown(backend_refs, &cat.backends, "backend") {
        return Err(e);
    }
    if let Some(e) = unknown(endpoint_refs, &cat.endpoints, "endpoint") {
        return Err(e);
    }
    Ok(())
}

/// GET /v1/hypervisor/foundry/overview — real substrate counts + Foundry object counts + recents.
/// A read projection: nothing is executed or promoted; it situates the (draft) Foundry plane
/// against the real model-mount catalog, receipts, transcripts and Work Ledger.
pub(crate) async fn handle_foundry_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let base = st.base_url.clone();
    let routes = as_list(&get_json(&base, "/v1/model-mount/routes").await);
    let providers = as_list(&get_json(&base, "/v1/model-mount/providers").await);
    let endpoints = as_list(&get_json(&base, "/v1/model-mount/endpoints").await);
    let backends = as_list(&get_json(&base, "/v1/model-mount/backends").await);
    let receipts = as_list(&get_json(&base, "/v1/model-mount/receipts").await);
    let transcripts = as_list(&get_json(&base, "/v1/hypervisor/agent-run-transcripts").await);
    let ledger = as_list(&get_json(&base, "/v1/hypervisor/work-ledger").await);

    let specs = read_record_dir(&st.data_dir, SPEC_KIND);
    let run_plans = read_record_dir(&st.data_dir, RUN_PLAN_KIND);

    let slim_spec = |s: &Value| {
        json!({
            "id": s.get("id").cloned().unwrap_or(Value::Null),
            "name": s.get("name").cloned().unwrap_or(Value::Null),
            "kind": s.get("kind").cloned().unwrap_or(Value::Null),
            "status": s.get("status").cloned().unwrap_or(Value::Null),
            "updated_at": s.get("updated_at").cloned().unwrap_or(Value::Null),
        })
    };
    let slim_plan = |p: &Value| {
        json!({
            "id": p.get("id").cloned().unwrap_or(Value::Null),
            "name": p.get("name").cloned().unwrap_or(Value::Null),
            "spec_ref": p.get("spec_ref").cloned().unwrap_or(Value::Null),
            "status": p.get("status").cloned().unwrap_or(Value::Null),
            "updated_at": p.get("updated_at").cloned().unwrap_or(Value::Null),
        })
    };
    let by_updated = |a: &Value, b: &Value| {
        b["updated_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["updated_at"].as_str().unwrap_or(""))
    };
    let mut recent_specs: Vec<Value> = specs.iter().map(slim_spec).collect();
    let mut recent_plans: Vec<Value> = run_plans.iter().map(slim_plan).collect();
    recent_specs.sort_by(by_updated);
    recent_plans.sort_by(by_updated);
    recent_specs.truncate(8);
    recent_plans.truncate(8);

    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.foundry-overview.v1",
        "status_note": "Foundry foundation: specs and run-plans are drafts. No training/eval execution, no promotion or registry mutation in this plane.",
        "substrate": {
            "model_routes": routes.len(),
            "providers": providers.len(),
            "endpoints": endpoints.len(),
            "backends": backends.len(),
            "model_mount_receipts": receipts.len(),
            "agent_transcripts": transcripts.len(),
            "work_ledger_entries": ledger.len()
        },
        "foundry": {
            "specs": specs.len(),
            "run_plans": run_plans.len()
        },
        "recent_specs": recent_specs,
        "recent_run_plans": recent_plans
    }))
}

/// GET /v1/hypervisor/foundry/specs[?kind=…] — list FoundrySpec drafts (newest first).
pub(crate) async fn handle_foundry_specs_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut specs = read_record_dir(&st.data_dir, SPEC_KIND);
    if let Some(kind) = q.get("kind").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        specs.retain(|s| s.get("kind").and_then(|v| v.as_str()) == Some(kind));
    }
    specs.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "specs": specs }))
}

/// POST /v1/hypervisor/foundry/specs — create a FoundrySpec DRAFT bound to real substrate.
/// Requires at least one resolving model route OR provider ref; every declared catalog ref must
/// resolve. The spec is never executed; `status` is always "draft".
pub(crate) async fn handle_foundry_spec_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let kind = body
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("model_eval")
        .to_string();
    if !SPEC_KINDS.contains(&kind.as_str()) {
        return bad(
            "foundry_kind_invalid",
            &format!("kind must be one of {SPEC_KINDS:?}"),
        );
    }
    let route_refs = str_refs(&body, "model_route_refs");
    let provider_refs = str_refs(&body, "provider_refs");
    let backend_refs = str_refs(&body, "backend_refs");
    let endpoint_refs = str_refs(&body, "endpoint_refs");
    let cat = fetch_catalog(&st.base_url).await;
    if let Err((code, message)) =
        validate_bindings(&cat, &route_refs, &provider_refs, &backend_refs, &endpoint_refs)
    {
        return bad(&code, &message);
    }
    let id = format!("fspec_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": SPEC_SCHEMA,
        "object": "ioi.hypervisor.foundry_spec",
        "id": id,
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("foundry-spec"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "kind": kind,
        "status": "draft",
        "model_route_refs": route_refs,
        "provider_refs": provider_refs,
        "backend_refs": backend_refs,
        "endpoint_refs": endpoint_refs,
        // Opaque provenance pointers (transcripts / receipts / ledger entries). Declared, not executed.
        "evidence_refs": str_refs(&body, "evidence_refs"),
        // Free-form spec inputs (base model, datasets, eval suite, objective). Never executed here.
        "inputs": body.get("inputs").cloned().unwrap_or_else(|| json!({})),
        // Names a policy ref for later enforcement; this plane neither enforces nor bypasses authority.
        "authority_policy_ref": body.get("authority_policy_ref").cloned().unwrap_or(Value::Null),
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, SPEC_KIND, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "spec": record })))
}

/// GET /v1/hypervisor/foundry/specs/:id — fetch one FoundrySpec.
pub(crate) async fn handle_foundry_spec_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, SPEC_KIND, &id) {
        Some(s) => Json(json!({ "ok": true, "spec": s })),
        None => Json(json!({ "ok": false, "reason": "foundry spec not found" })),
    }
}

/// PATCH /v1/hypervisor/foundry/specs/:id — update mutable fields. id / schema_version / status /
/// created_at are immutable here (status stays "draft" — no promotion in this plane). Re-validates
/// bindings against real substrate if any binding field changes.
pub(crate) async fn handle_foundry_spec_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut s) = load(&st.data_dir, SPEC_KIND, &id) else {
        return Json(json!({ "ok": false, "reason": "foundry spec not found" }));
    };
    if let Some(kind) = body.get("kind").and_then(|v| v.as_str()) {
        if !SPEC_KINDS.contains(&kind) {
            return Json(json!({ "ok": false, "error": {
                "code": "foundry_kind_invalid",
                "message": format!("kind must be one of {SPEC_KINDS:?}")
            } }));
        }
    }
    let touches_binding = [
        "model_route_refs",
        "provider_refs",
        "backend_refs",
        "endpoint_refs",
    ]
    .iter()
    .any(|k| body.get(*k).is_some());
    for key in [
        "name",
        "description",
        "kind",
        "model_route_refs",
        "provider_refs",
        "backend_refs",
        "endpoint_refs",
        "evidence_refs",
        "inputs",
        "authority_policy_ref",
    ] {
        if let Some(v) = body.get(key) {
            s[key] = v.clone();
        }
    }
    if touches_binding {
        let cat = fetch_catalog(&st.base_url).await;
        if let Err((code, message)) = validate_bindings(
            &cat,
            &str_refs(&s, "model_route_refs"),
            &str_refs(&s, "provider_refs"),
            &str_refs(&s, "backend_refs"),
            &str_refs(&s, "endpoint_refs"),
        ) {
            return Json(json!({ "ok": false, "error": { "code": code, "message": message } }));
        }
    }
    s["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, SPEC_KIND, &id, &s);
    Json(json!({ "ok": true, "spec": s }))
}

/// GET /v1/hypervisor/foundry/run-plans[?spec_ref=…] — list FoundryRunPlan drafts (newest first).
pub(crate) async fn handle_foundry_run_plans_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut plans = read_record_dir(&st.data_dir, RUN_PLAN_KIND);
    if let Some(sref) = q.get("spec_ref").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        plans.retain(|p| p.get("spec_ref").and_then(|v| v.as_str()) == Some(sref));
    }
    plans.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "run_plans": plans }))
}

/// POST /v1/hypervisor/foundry/run-plans — draft a FoundryRunPlan from an existing FoundrySpec.
/// Requires `spec_ref` that resolves. The plan is a DRAFT: it records planned steps + a target
/// route/provider (validated against real substrate) + a PROMOTION PREVIEW that is computed and
/// never applied. Nothing is dispatched.
pub(crate) async fn handle_foundry_run_plan_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let spec_ref = body
        .get("spec_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(spec_ref) = spec_ref else {
        return bad(
            "foundry_spec_ref_required",
            "A FoundryRunPlan must declare a spec_ref (an existing FoundrySpec).",
        );
    };
    let Some(spec) = load(&st.data_dir, SPEC_KIND, spec_ref) else {
        return bad(
            "foundry_spec_not_found",
            &format!("spec_ref '{spec_ref}' does not resolve to a FoundrySpec."),
        );
    };
    // Target route/provider: explicit on the body, else inherited from the spec's first binding.
    let first_ref = |v: &Value, key: &str| -> Option<String> {
        v.get(key)
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
            .map(str::to_string)
    };
    let target_route = body
        .get("target_route_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| first_ref(&spec, "model_route_refs"));
    let target_provider = body
        .get("target_provider_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| first_ref(&spec, "provider_refs"));
    if target_route.is_none() && target_provider.is_none() {
        return bad(
            "foundry_target_required",
            "A run plan needs a target_route_ref or target_provider_ref (none on the body or the spec).",
        );
    }
    let cat = fetch_catalog(&st.base_url).await;
    if let Some(r) = &target_route {
        if !cat.routes.contains(r) {
            return bad(
                "foundry_ref_unresolved",
                &format!("target_route_ref '{r}' does not resolve to real substrate."),
            );
        }
    }
    if let Some(p) = &target_provider {
        if !cat.providers.contains(p) {
            return bad(
                "foundry_ref_unresolved",
                &format!("target_provider_ref '{p}' does not resolve to real substrate."),
            );
        }
    }
    let id = format!("frun_{:x}", nanos());
    let now = iso_now();
    let promotion_preview = json!({
        "would_promote": false,
        "note": "preview only — this foundation performs no promotion, registry alias, or model mutation",
        "target_route_ref": target_route,
        "target_provider_ref": target_provider,
        "from_spec_kind": spec.get("kind").cloned().unwrap_or(Value::Null)
    });
    let record = json!({
        "schema_version": RUN_PLAN_SCHEMA,
        "object": "ioi.hypervisor.foundry_run_plan",
        "id": id,
        "spec_ref": spec_ref,
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("foundry-run-plan"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        "target_route_ref": target_route,
        "target_provider_ref": target_provider,
        // Planned phases (opaque). Nothing here is dispatched; it is a plan, not a run.
        "steps": body.get("steps").cloned().unwrap_or_else(|| json!([])),
        "inputs": body.get("inputs").cloned().unwrap_or_else(|| json!({})),
        "evidence_refs": str_refs(&body, "evidence_refs"),
        "promotion_preview": promotion_preview,
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, RUN_PLAN_KIND, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "run_plan": record })),
    )
}

/// GET /v1/hypervisor/foundry/run-plans/:id — fetch one FoundryRunPlan.
pub(crate) async fn handle_foundry_run_plan_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, RUN_PLAN_KIND, &id) {
        Some(p) => Json(json!({ "ok": true, "run_plan": p })),
        None => Json(json!({ "ok": false, "reason": "foundry run plan not found" })),
    }
}

/// DELETE /v1/hypervisor/foundry/specs/:id — remove a DRAFT spec. Everything in this plane is a
/// draft; there is no promoted/immutable state to protect, so a draft delete is honest (not a
/// promotion/registry mutation). Returns {ok, removed} so a no-op delete is honest.
pub(crate) async fn handle_foundry_spec_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, SPEC_KIND, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

/// DELETE /v1/hypervisor/foundry/run-plans/:id — remove a DRAFT run plan.
pub(crate) async fn handle_foundry_run_plan_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, RUN_PLAN_KIND, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod foundry_tests {
    use super::*;

    fn cat() -> Catalog {
        let mk = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<HashSet<String>>();
        Catalog {
            routes: mk(&["route.local-first"]),
            providers: mk(&["provider.hypervisor.local"]),
            backends: mk(&["backend.hypervisor.native-local.fixture"]),
            endpoints: mk(&["endpoint.e2e.native-local"]),
        }
    }

    #[test]
    fn binding_requires_at_least_one_route_or_provider() {
        let err = validate_bindings(&cat(), &[], &[], &[], &[]).unwrap_err();
        assert_eq!(err.0, "foundry_binding_required");
    }

    #[test]
    fn binding_accepts_a_real_route_and_rejects_an_unknown_ref() {
        // A real route alone is valid.
        assert!(validate_bindings(&cat(), &["route.local-first".into()], &[], &[], &[]).is_ok());
        // A real provider alone is valid.
        assert!(
            validate_bindings(&cat(), &[], &["provider.hypervisor.local".into()], &[], &[]).is_ok()
        );
        // An unknown route ref is rejected with the unresolved code.
        let err = validate_bindings(&cat(), &["route.does-not-exist".into()], &[], &[], &[])
            .unwrap_err();
        assert_eq!(err.0, "foundry_ref_unresolved");
        // An unknown backend ref (alongside a valid route) is also rejected.
        let err = validate_bindings(
            &cat(),
            &["route.local-first".into()],
            &[],
            &["backend.nope".into()],
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, "foundry_ref_unresolved");
    }

    #[test]
    fn as_list_handles_array_and_wrapped_shapes() {
        // top-level array
        assert_eq!(as_list(&json!([{"id":"a"},{"id":"b"}])).len(), 2);
        // {runs:[...]} wrapper (agent-run-transcripts shape)
        assert_eq!(as_list(&json!({"ok":true,"runs":[{"run_id":"r1"}]})).len(), 1);
        // null / non-list → empty
        assert_eq!(as_list(&Value::Null).len(), 0);
    }

    #[test]
    fn collect_ids_reads_multiple_keys() {
        let list = vec![
            json!({"id": "provider.x", "provider_ref": "provider.x"}),
            json!({"id": "provider.y"}),
            json!({"provider_ref": "provider.z"}),
        ];
        let ids = collect_ids(&list, &["id", "provider_ref"]);
        assert!(ids.contains("provider.x"));
        assert!(ids.contains("provider.y"));
        assert!(ids.contains("provider.z"));
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn str_refs_filters_non_strings_and_empties() {
        let body = json!({ "refs": ["a", "", 7, "b", null] });
        assert_eq!(str_refs(&body, "refs"), vec!["a".to_string(), "b".to_string()]);
        assert!(str_refs(&body, "missing").is_empty());
    }
}
