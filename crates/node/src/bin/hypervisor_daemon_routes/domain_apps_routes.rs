//! Domain Apps object plane — FOUNDATION cut (daemon-first, draft-only).
//!
//! A DomainApp is a real generated-app CANDIDATE over an ODK surface descriptor. This cut builds the
//! object plane, not a runtime: a durable draft `DomainApp` that MUST reference a real
//! `surface-descriptor://…` whose `composition_pattern == domain_app` (the app-shape contract), with
//! an optional `odk_manifest_ref` for packaging provenance.
//!
//! Deliberately inert — it does NOT pretend the runtime exists:
//!   * no generated/mounted app runtime, no app iframe/route mounting, no widget execution;
//!   * no form submission, no domain-action execution;
//!   * no marketplace publish; no authority crossing.
//! `runtime_posture` is always {mounted:false, route:null}. `status` is always "draft". No
//! `/__ioi/domain-apps` UI card in this cut. `/v1/hypervisor/blueprints` stays 404.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, DaemonState};

const KIND_DAPP: &str = "domain-apps";
const KIND_SD: &str = "odk-surface-descriptors";
const KIND_MANIFEST: &str = "odk-manifests";
/// Visibility of a draft DomainApp (marketplace_candidate is a flag, not a publish).
const VISIBILITIES: &[&str] = &["private", "org", "marketplace_candidate"];

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
fn split_ref(r: &str) -> Option<(&str, &str)> {
    r.split_once("://")
        .filter(|(s, rest)| !s.is_empty() && !rest.is_empty())
}
fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
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
fn arr_strs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn push_unique(v: &mut Vec<String>, s: &str) {
    if !s.is_empty() && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// Resolve `surface_descriptor_ref` and enforce the app-shape contract: it must be a
/// `surface-descriptor://` ref that resolves AND whose composition_pattern is `domain_app`.
fn resolve_domain_app_descriptor(data_dir: &str, sd_ref: &str) -> Result<Value, (String, String)> {
    match split_ref(sd_ref) {
        Some(("surface-descriptor", id)) => match load(data_dir, KIND_SD, id) {
            Some(d) => {
                if d.get("composition_pattern").and_then(|v| v.as_str()) == Some("domain_app") {
                    Ok(d)
                } else {
                    Err((
                        "domain_app_descriptor_pattern_mismatch".into(),
                        "surface_descriptor_ref must reference a descriptor whose composition_pattern == domain_app".into(),
                    ))
                }
            }
            None => Err((
                "domain_app_descriptor_unresolved".into(),
                format!(
                    "surface_descriptor_ref '{sd_ref}' does not resolve to a surface descriptor"
                ),
            )),
        },
        _ => Err((
            "domain_app_ref_prefix_invalid".into(),
            "surface_descriptor_ref must be a 'surface-descriptor://' ref".into(),
        )),
    }
}

/// Resolve an optional `odk_manifest_ref`: must be an `odk://` ref that resolves AND whose
/// surface_descriptor_refs include `sd_ref`.
fn resolve_manifest_including(
    data_dir: &str,
    man_ref: &str,
    sd_ref: &str,
) -> Result<Value, (String, String)> {
    match split_ref(man_ref) {
        Some(("odk", id)) => match load(data_dir, KIND_MANIFEST, id) {
            Some(m) => {
                if manifest_includes_descriptor(&m, sd_ref) {
                    Ok(m)
                } else {
                    Err((
                        "domain_app_manifest_missing_descriptor".into(),
                        "odk_manifest_ref does not include surface_descriptor_ref in its surface_descriptor_refs".into(),
                    ))
                }
            }
            None => Err((
                "domain_app_manifest_unresolved".into(),
                format!("odk_manifest_ref '{man_ref}' does not resolve to an ODK manifest"),
            )),
        },
        _ => Err((
            "domain_app_ref_prefix_invalid".into(),
            "odk_manifest_ref must be an 'odk://' ref".into(),
        )),
    }
}
fn manifest_includes_descriptor(manifest: &Value, sd_ref: &str) -> bool {
    arr_strs(manifest, "surface_descriptor_refs")
        .iter()
        .any(|r| r == sd_ref)
}

/// A snapshot of provenance refs derived from the bound descriptor (+ manifest, if any).
struct Derived {
    ontology_refs: Vec<String>,
    data_recipe_refs: Vec<String>,
    mcp_contract_refs: Vec<String>,
}
fn derive_snapshot(descriptor: &Value, manifest: Option<&Value>, body: &Value) -> Derived {
    let mut ontology_refs = Vec::new();
    let mut data_recipe_refs = Vec::new();
    let mut mcp_contract_refs = Vec::new();
    // From the descriptor: single ontology_ref + recipe_refs.
    if let Some(o) = descriptor.get("ontology_ref").and_then(|v| v.as_str()) {
        push_unique(&mut ontology_refs, o);
    }
    for r in arr_strs(descriptor, "recipe_refs") {
        push_unique(&mut data_recipe_refs, &r);
    }
    // From the manifest (if bound): ontology_refs, recipe_refs, mcp_operator_contracts.
    if let Some(m) = manifest {
        for r in arr_strs(m, "ontology_refs") {
            push_unique(&mut ontology_refs, &r);
        }
        for r in arr_strs(m, "recipe_refs") {
            push_unique(&mut data_recipe_refs, &r);
        }
        for r in arr_strs(m, "mcp_operator_contracts") {
            push_unique(&mut mcp_contract_refs, &r);
        }
    }
    // Plus any author-supplied named mcp_contract_refs.
    for r in str_refs(body, "mcp_contract_refs") {
        push_unique(&mut mcp_contract_refs, &r);
    }
    Derived {
        ontology_refs,
        data_recipe_refs,
        mcp_contract_refs,
    }
}

/// GET /v1/hypervisor/domain-apps/overview — real substrate counts (ODK descriptors, incl. the
/// domain_app-pattern candidates, ontologies, recipes, manifests) + DomainApp counts by visibility.
pub(crate) async fn handle_domain_apps_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let descriptors = read_record_dir(&st.data_dir, KIND_SD);
    let domain_app_descriptors = descriptors
        .iter()
        .filter(|d| d.get("composition_pattern").and_then(|v| v.as_str()) == Some("domain_app"))
        .count();
    let apps = read_record_dir(&st.data_dir, KIND_DAPP);
    let mut by_visibility: HashMap<String, i64> = HashMap::new();
    for a in &apps {
        let v = a
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("private")
            .to_string();
        *by_visibility.entry(v).or_insert(0) += 1;
    }
    let mut recent: Vec<Value> = apps
        .iter()
        .map(|a| {
            json!({
                "domain_app_id": a.get("domain_app_id").cloned().unwrap_or(Value::Null),
                "domain_app_ref": a.get("domain_app_ref").cloned().unwrap_or(Value::Null),
                "name": a.get("name").cloned().unwrap_or(Value::Null),
                "status": a.get("status").cloned().unwrap_or(Value::Null),
                "visibility": a.get("visibility").cloned().unwrap_or(Value::Null),
                "surface_descriptor_ref": a.get("surface_descriptor_ref").cloned().unwrap_or(Value::Null),
                "updated_at": a.get("updated_at").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    recent.sort_by(|a, b| {
        b["updated_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["updated_at"].as_str().unwrap_or(""))
    });
    recent.truncate(8);

    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.domain-apps-overview.v1",
        "status_note": "Domain Apps foundation: DomainApp objects are drafts — candidates over an ODK domain_app descriptor. No generated/mounted runtime, no domain-action execution, no marketplace publish in this plane.",
        "substrate": {
            "odk_surface_descriptors": descriptors.len(),
            "odk_domain_app_descriptors": domain_app_descriptors,
            "odk_domain_ontologies": read_record_dir(&st.data_dir, "odk-domain-ontologies").len(),
            "odk_data_recipes": read_record_dir(&st.data_dir, "odk-data-recipes").len(),
            "odk_manifests": read_record_dir(&st.data_dir, KIND_MANIFEST).len()
        },
        "domain_apps": {
            "total": apps.len(),
            "by_visibility": serde_json::to_value(&by_visibility).unwrap_or_else(|_| json!({}))
        },
        "visibilities": VISIBILITIES,
        "recent_domain_apps": recent
    }))
}

/// GET /v1/hypervisor/domain-apps[?visibility=…&surface_descriptor_ref=…] — list DomainApp drafts.
pub(crate) async fn handle_domain_apps_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_DAPP);
    if let Some(vis) = q
        .get("visibility")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|a| a.get("visibility").and_then(|v| v.as_str()) == Some(vis));
    }
    if let Some(sd) = q
        .get("surface_descriptor_ref")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|a| a.get("surface_descriptor_ref").and_then(|v| v.as_str()) == Some(sd));
    }
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "domain_apps": items }))
}

/// POST /v1/hypervisor/domain-apps — create a DomainApp DRAFT candidate over an ODK domain_app
/// descriptor. surface_descriptor_ref is required (must resolve + be composition_pattern domain_app);
/// odk_manifest_ref is optional (if present, must resolve AND include the descriptor).
pub(crate) async fn handle_domain_apps_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let sd_ref = str_field(&body, "surface_descriptor_ref");
    if sd_ref.is_empty() {
        return bad(
            "domain_app_descriptor_required",
            "A DomainApp must declare a surface_descriptor_ref (the app-shape contract).",
        );
    }
    let descriptor = match resolve_domain_app_descriptor(&st.data_dir, sd_ref) {
        Ok(d) => d,
        Err((c, m)) => return bad(&c, &m),
    };
    let man_ref = str_field(&body, "odk_manifest_ref");
    let manifest = if man_ref.is_empty() {
        None
    } else {
        match resolve_manifest_including(&st.data_dir, man_ref, sd_ref) {
            Ok(m) => Some(m),
            Err((c, m)) => return bad(&c, &m),
        }
    };
    let visibility = {
        let v = body
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("private");
        if !VISIBILITIES.contains(&v) {
            return bad(
                "domain_app_visibility_invalid",
                &format!("visibility must be one of {VISIBILITIES:?}"),
            );
        }
        v.to_string()
    };
    let derived = derive_snapshot(&descriptor, manifest.as_ref(), &body);
    let id = format!("dapp_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.domain-app.v1",
        "object": "ioi.hypervisor.domain_app",
        "domain_app_id": id,
        "domain_app_ref": format!("domain-app://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("domain-app"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        "surface_descriptor_ref": sd_ref,
        "odk_manifest_ref": if man_ref.is_empty() { Value::Null } else { json!(man_ref) },
        "project_ref": body.get("project_ref").cloned().unwrap_or(Value::Null),
        "owner_ref": body.get("owner_ref").cloned().unwrap_or(Value::Null),
        "visibility": visibility,
        // Derived provenance snapshot from the descriptor (+ manifest, if bound).
        "ontology_refs": derived.ontology_refs,
        "data_recipe_refs": derived.data_recipe_refs,
        "mcp_contract_refs": derived.mcp_contract_refs,
        // Author-supplied named refs (not resolved here).
        "authority_requirement_refs": str_refs(&body, "authority_requirement_refs"),
        "operator_contract_refs": str_refs(&body, "operator_contract_refs"),
        "receipt_obligations": str_refs(&body, "receipt_obligations"),
        "generated_artifact_refs": str_refs(&body, "generated_artifact_refs"),
        // No runtime is mounted by this plane.
        "runtime_posture": {
            "mounted": false,
            "route": Value::Null,
            "note": "draft object only; no generated runtime mounted"
        },
        "created_at": now,
        "updated_at": now
    });
    if let Err(response) = persist_required(
        &st.data_dir,
        KIND_DAPP,
        &id,
        &record,
        "domain_app_persistence_failed",
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "domain_app": record })),
    )
}

pub(crate) async fn handle_domain_apps_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_DAPP, &id) {
        Some(a) => Json(json!({ "ok": true, "domain_app": a })),
        None => Json(json!({ "ok": false, "reason": "domain_app not found" })),
    }
}

/// PATCH /v1/hypervisor/domain-apps/:id — update mutable fields. If the descriptor or manifest ref
/// changes, re-validate the contract and re-derive the provenance snapshot. id / schema_version /
/// status / created_at are immutable (status stays draft; runtime_posture stays unmounted).
pub(crate) async fn handle_domain_apps_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut a) = load(&st.data_dir, KIND_DAPP, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "error": { "code": "domain_app_not_found", "message": "domain_app not found" } }),
            ),
        );
    };
    if let Some(v) = body.get("visibility").and_then(|v| v.as_str()) {
        if !VISIBILITIES.contains(&v) {
            return bad(
                "domain_app_visibility_invalid",
                &format!("visibility must be one of {VISIBILITIES:?}"),
            );
        }
    }
    // Resolve the effective descriptor + manifest refs (post-patch) and re-validate if either moves.
    let touches_refs =
        body.get("surface_descriptor_ref").is_some() || body.get("odk_manifest_ref").is_some();
    let sd_ref = body
        .get("surface_descriptor_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            a.get("surface_descriptor_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    // odk_manifest_ref: an explicit empty string clears it; absent keeps the current value.
    let man_ref = if body.get("odk_manifest_ref").is_some() {
        str_field(&body, "odk_manifest_ref").to_string()
    } else {
        a.get("odk_manifest_ref")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    if touches_refs {
        let descriptor = match resolve_domain_app_descriptor(&st.data_dir, &sd_ref) {
            Ok(d) => d,
            Err((c, m)) => return bad(&c, &m),
        };
        let manifest = if man_ref.is_empty() {
            None
        } else {
            match resolve_manifest_including(&st.data_dir, &man_ref, &sd_ref) {
                Ok(m) => Some(m),
                Err((c, m)) => return bad(&c, &m),
            }
        };
        let derived = derive_snapshot(&descriptor, manifest.as_ref(), &body);
        a["surface_descriptor_ref"] = json!(sd_ref);
        a["odk_manifest_ref"] = if man_ref.is_empty() {
            Value::Null
        } else {
            json!(man_ref)
        };
        a["ontology_refs"] = json!(derived.ontology_refs);
        a["data_recipe_refs"] = json!(derived.data_recipe_refs);
        a["mcp_contract_refs"] = json!(derived.mcp_contract_refs);
    }
    for key in [
        "name",
        "description",
        "visibility",
        "project_ref",
        "owner_ref",
        "authority_requirement_refs",
        "operator_contract_refs",
        "receipt_obligations",
        "generated_artifact_refs",
    ] {
        if let Some(v) = body.get(key) {
            a[key] = v.clone();
        }
    }
    a["updated_at"] = json!(iso_now());
    if let Err(response) = persist_required(
        &st.data_dir,
        KIND_DAPP,
        &id,
        &a,
        "domain_app_persistence_failed",
    ) {
        return response;
    }
    (StatusCode::OK, Json(json!({ "ok": true, "domain_app": a })))
}

pub(crate) async fn handle_domain_apps_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_DAPP, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

// ============================ DOMAIN-APP RUNTIME MOUNT (effectful cut A) =========================
//
// A GOVERNED mount admission — effectful but NOT serving. Mount requires a real domain-app plus an
// APPROVED ApprovalRequest and an OPEN ReleaseControl that both target this domain app; on success the
// daemon admits the mount, writes a durable DomainAppRuntime record (mounted:true), emits an admission
// receipt (hashed state_root), backlinks the DomainApp runtime_posture, and stores the governance +
// authority refs that permitted it. It does NOT start a process, expose a URL, create ingress, publish,
// run connectors, or generate app code — that is the later serving cut. Unmount is a governed, receipted
// state transition.

const KIND_RUNTIME: &str = "domain-app-runtimes";
const KIND_MOUNT_RECEIPT: &str = "domain-app-mount-receipts";
const KIND_APPROVAL: &str = "governance-approval-requests";
const KIND_RELEASE: &str = "governance-release-controls";

/// The ApprovalRequest must be `approved` AND target this domain app (subject_ref == domain_app_ref).
fn approval_admits(approval: &Value, domain_app_ref: &str) -> Result<(), (String, String)> {
    if approval.get("status").and_then(|v| v.as_str()) != Some("approved") {
        return Err((
            "mount_approval_not_approved".into(),
            "approval_request_ref must reference an ApprovalRequest with status 'approved'".into(),
        ));
    }
    if approval.get("subject_ref").and_then(|v| v.as_str()) != Some(domain_app_ref) {
        return Err((
            "mount_control_wrong_subject".into(),
            "approval_request.subject_ref must target this domain app".into(),
        ));
    }
    Ok(())
}
/// The ReleaseControl must be `open` AND target this domain app (release_target_ref == domain_app_ref).
fn release_admits(release: &Value, domain_app_ref: &str) -> Result<(), (String, String)> {
    if release.get("state").and_then(|v| v.as_str()) != Some("open") {
        return Err((
            "mount_release_not_open".into(),
            "release_control_ref must reference a ReleaseControl with state 'open'".into(),
        ));
    }
    if release.get("release_target_ref").and_then(|v| v.as_str()) != Some(domain_app_ref) {
        return Err((
            "mount_control_wrong_subject".into(),
            "release_control.release_target_ref must target this domain app".into(),
        ));
    }
    Ok(())
}
/// Load a scheme-prefixed local ref (`scheme://id`) from `kind`, requiring the given scheme.
fn load_scheme(data_dir: &str, r: &str, scheme: &str, kind: &str) -> Option<Value> {
    match split_ref(r) {
        Some((s, id)) if s == scheme => load(data_dir, kind, id),
        _ => None,
    }
}
fn current_runtime(data_dir: &str, domain_app_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, KIND_RUNTIME)
        .into_iter()
        .find(|rt| {
            rt.get("domain_app_ref").and_then(|v| v.as_str()) == Some(domain_app_ref)
                && rt.get("mounted").and_then(|v| v.as_bool()) == Some(true)
        })
}
struct PendingMountReceipt {
    id: String,
    reference: String,
    value: Value,
}

fn build_mount_receipt(
    kind_action: &str,
    domain_app_ref: &str,
    approval_ref: &str,
    release_ref: &str,
) -> PendingMountReceipt {
    let id = format!("mrcpt_{:x}", nanos());
    let reference = format!("mount-receipt://{id}");
    let now = iso_now();
    let state_root = sha256_hex_str(&format!(
        "{kind_action}|{domain_app_ref}|{approval_ref}|{release_ref}|{now}"
    ));
    let receipt = json!({
        "schema_version": "ioi.hypervisor.domain-app-mount-receipt.v1",
        "object": "ioi.hypervisor.domain_app_mount_receipt",
        "id": id, "ref": reference,
        "action": kind_action,
        "domain_app_ref": domain_app_ref,
        "approval_request_ref": approval_ref,
        "release_control_ref": release_ref,
        "state_root": format!("sha256:{state_root}"),
        "at": now
    });
    PendingMountReceipt {
        id,
        reference,
        value: receipt,
    }
}

fn rollback_record(data_dir: &str, kind: &str, id: &str, prior: Option<&Value>) -> bool {
    match prior {
        Some(record) => persist_record(data_dir, kind, id, record).is_ok(),
        None => load(data_dir, kind, id).is_none() || remove_record(data_dir, kind, id),
    }
}

fn transition_persist_failure(
    code: &str,
    stage: &str,
    rollback_succeeded: bool,
) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "ok": false,
            "error": {
                "code": code,
                "message": if rollback_succeeded {
                    format!("the {stage} durable write failed; prior Domain App state was restored")
                } else {
                    format!("the {stage} durable write failed and rollback was incomplete; manual repair is required")
                },
                "rollback_succeeded": rollback_succeeded
            }
        })),
    )
}

/// Commit one runtime transition as runtime + DomainApp backlink + receipt set. Receipts are
/// persisted last so none can attest to state that failed to commit. Any later-stage failure
/// restores both prior records and removes receipts written by this attempt.
fn finalize_domain_app_transition(
    data_dir: &str,
    runtime_id: &str,
    prior_runtime: Option<&Value>,
    next_runtime: &Value,
    domain_app_id: &str,
    prior_domain_app: &Value,
    next_domain_app: &Value,
    receipts: &[PendingMountReceipt],
) -> Result<(), (StatusCode, Json<Value>)> {
    if persist_record(data_dir, KIND_RUNTIME, runtime_id, next_runtime).is_err() {
        return Err(transition_persist_failure(
            "domain_app_runtime_persistence_failed",
            "runtime",
            true,
        ));
    }
    if persist_record(data_dir, KIND_DAPP, domain_app_id, next_domain_app).is_err() {
        return Err(transition_persist_failure(
            "domain_app_backlink_persistence_failed",
            "Domain App backlink",
            rollback_record(data_dir, KIND_RUNTIME, runtime_id, prior_runtime),
        ));
    }
    let mut written_receipts: Vec<&str> = Vec::new();
    for receipt in receipts {
        if persist_record(data_dir, KIND_MOUNT_RECEIPT, &receipt.id, &receipt.value).is_err() {
            let mut rollback_succeeded = true;
            for id in written_receipts {
                rollback_succeeded &= load(data_dir, KIND_MOUNT_RECEIPT, id).is_none()
                    || remove_record(data_dir, KIND_MOUNT_RECEIPT, id);
            }
            rollback_succeeded &= load(data_dir, KIND_MOUNT_RECEIPT, &receipt.id).is_none()
                || remove_record(data_dir, KIND_MOUNT_RECEIPT, &receipt.id);
            rollback_succeeded &=
                rollback_record(data_dir, KIND_DAPP, domain_app_id, Some(prior_domain_app));
            rollback_succeeded &=
                rollback_record(data_dir, KIND_RUNTIME, runtime_id, prior_runtime);
            return Err(transition_persist_failure(
                "domain_app_receipt_persistence_failed",
                "receipt",
                rollback_succeeded,
            ));
        }
        written_receipts.push(&receipt.id);
    }
    Ok(())
}

/// POST /v1/hypervisor/domain-apps/:id/mount — governed mount admission (effectful, not serving).
pub(crate) async fn handle_domain_app_mount(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(prior_dapp) = load(&st.data_dir, KIND_DAPP, &id) else {
        return bad("domain_app_not_found", "domain app not found");
    };
    let domain_app_ref = prior_dapp
        .get("domain_app_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if prior_dapp
        .get("runtime_posture")
        .and_then(|p| p.get("mounted"))
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return bad(
            "domain_app_already_mounted",
            "this domain app already has a mounted runtime; unmount first",
        );
    }
    let approval_ref = str_field(&body, "approval_request_ref");
    let release_ref = str_field(&body, "release_control_ref");
    let Some(approval) = load_scheme(
        &st.data_dir,
        approval_ref,
        "approval-request",
        KIND_APPROVAL,
    ) else {
        return bad(
            "mount_approval_unresolved",
            "approval_request_ref must be an 'approval-request://' ref that resolves",
        );
    };
    let Some(release) = load_scheme(&st.data_dir, release_ref, "release-control", KIND_RELEASE)
    else {
        return bad(
            "mount_release_unresolved",
            "release_control_ref must be a 'release-control://' ref that resolves",
        );
    };
    if let Err((c, m)) = approval_admits(&approval, &domain_app_ref) {
        return bad(&c, &m);
    }
    if let Err((c, m)) = release_admits(&release, &domain_app_ref) {
        return bad(&c, &m);
    }
    // Admission granted by the control plane. Emit a receipt + durable runtime record (mounted:true).
    let receipt = build_mount_receipt(
        "domain_app.mount",
        &domain_app_ref,
        approval_ref,
        release_ref,
    );
    let authority_refs = approval
        .get("required_authority_refs")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let rid = format!("dartm_{:x}", nanos());
    let now = iso_now();
    let runtime = json!({
        "schema_version": "ioi.hypervisor.domain-app-runtime.v1",
        "object": "ioi.hypervisor.domain_app_runtime",
        "id": rid, "ref": format!("domain-app-runtime://{rid}"),
        "domain_app_ref": domain_app_ref,
        "mounted": true,
        "state": "mounted",
        "serving": false,
        "route": Value::Null,
        "approval_request_ref": approval_ref,
        "release_control_ref": release_ref,
        "authority_refs": authority_refs,
        "receipt_refs": [receipt.reference.clone()],
        "rollback": { "unmountable": true, "note": "governed unmount available; no process/ingress to tear down (not serving)" },
        "note": "governed mount admission; effectful but NOT serving — no process, URL, ingress, publish, or connector action",
        "mounted_at": now,
        "unmounted_at": Value::Null,
        "created_at": now, "updated_at": now
    });
    // Backlink the DomainApp runtime_posture to the mounted runtime.
    let mut next_dapp = prior_dapp.clone();
    next_dapp["runtime_posture"] = json!({
        "mounted": true, "route": Value::Null, "serving": false,
        "mount_ref": format!("domain-app-runtime://{rid}"),
        "approval_request_ref": approval_ref, "release_control_ref": release_ref,
        "note": "governed mount admission; not serving"
    });
    next_dapp["updated_at"] = json!(iso_now());
    if let Err(response) = finalize_domain_app_transition(
        &st.data_dir,
        &rid,
        None,
        &runtime,
        &id,
        &prior_dapp,
        &next_dapp,
        std::slice::from_ref(&receipt),
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "runtime": runtime, "receipt": receipt.value })),
    )
}

/// POST /v1/hypervisor/domain-apps/:id/unmount — governed, receipted unmount state transition.
pub(crate) async fn handle_domain_app_unmount(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(prior_dapp) = load(&st.data_dir, KIND_DAPP, &id) else {
        return bad("domain_app_not_found", "domain app not found");
    };
    let domain_app_ref = prior_dapp
        .get("domain_app_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let Some(prior_runtime) = current_runtime(&st.data_dir, &domain_app_ref) else {
        return bad(
            "domain_app_not_mounted",
            "no mounted runtime for this domain app",
        );
    };
    let rid = prior_runtime
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let approval_ref = prior_runtime
        .get("approval_request_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let release_ref = prior_runtime
        .get("release_control_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt = build_mount_receipt(
        "domain_app.unmount",
        &domain_app_ref,
        &approval_ref,
        &release_ref,
    );
    let mut refs: Vec<Value> = prior_runtime
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.push(json!(receipt.reference.clone()));
    let mut next_runtime = prior_runtime.clone();
    next_runtime["mounted"] = json!(false);
    next_runtime["state"] = json!("unmounted");
    next_runtime["unmounted_at"] = json!(iso_now());
    next_runtime["unmount_reason"] =
        json!(body.get("reason").and_then(|v| v.as_str()).unwrap_or(""));
    next_runtime["receipt_refs"] = json!(refs);
    next_runtime["updated_at"] = json!(iso_now());
    let mut next_dapp = prior_dapp.clone();
    next_dapp["runtime_posture"] = json!({ "mounted": false, "route": Value::Null, "serving": false, "note": "unmounted (governed)" });
    next_dapp["updated_at"] = json!(iso_now());
    if let Err(response) = finalize_domain_app_transition(
        &st.data_dir,
        &rid,
        Some(&prior_runtime),
        &next_runtime,
        &id,
        &prior_dapp,
        &next_dapp,
        std::slice::from_ref(&receipt),
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "runtime": next_runtime, "receipt": receipt.value })),
    )
}

/// GET /v1/hypervisor/domain-app-runtimes[?domain_app_ref=…] — the mounted-runtime resource list.
pub(crate) async fn handle_domain_app_runtime_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_RUNTIME);
    if let Some(dref) = q
        .get("domain_app_ref")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|r| r.get("domain_app_ref").and_then(|v| v.as_str()) == Some(dref));
    }
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "runtimes": items }))
}
pub(crate) async fn handle_domain_app_runtime_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_RUNTIME, &id) {
        Some(r) => Json(json!({ "ok": true, "runtime": r })),
        None => Json(json!({ "ok": false, "reason": "domain app runtime not found" })),
    }
}

// ---- SERVING (internal, descriptor-driven; reuses the mount's governance) -----------------------
// serve is a sub-step of the same governed mount — it reuses the mount's approved ApprovalRequest and
// open ReleaseControl (re-validated live), assigns an INTERNAL route only, and emits serve receipts.
// Still no process, public ingress, publish, connector action, or object mutation.

/// Precheck the runtime for a serve transition (pure): must be mounted and not already serving.
fn serve_precheck(runtime: &Value) -> Result<(), (String, String)> {
    if runtime.get("mounted").and_then(|v| v.as_bool()) != Some(true) {
        return Err((
            "domain_app_not_mounted".into(),
            "runtime must be mounted before it can serve".into(),
        ));
    }
    if runtime.get("serving").and_then(|v| v.as_bool()) == Some(true) {
        return Err((
            "domain_app_already_serving".into(),
            "runtime is already serving".into(),
        ));
    }
    Ok(())
}

/// POST /v1/hypervisor/domain-apps/:id/serve — start internal, descriptor-driven serving.
pub(crate) async fn handle_domain_app_serve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(prior_dapp) = load(&st.data_dir, KIND_DAPP, &id) else {
        return bad("domain_app_not_found", "domain app not found");
    };
    let domain_app_ref = prior_dapp
        .get("domain_app_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let Some(prior_runtime) = current_runtime(&st.data_dir, &domain_app_ref) else {
        return bad(
            "domain_app_not_mounted",
            "no mounted runtime for this domain app",
        );
    };
    if let Err((c, m)) = serve_precheck(&prior_runtime) {
        return bad(&c, &m);
    }
    // Re-validate the mount's governance is STILL valid (approval approved, release open, right subject).
    let approval_ref = prior_runtime
        .get("approval_request_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let release_ref = prior_runtime
        .get("release_control_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let Some(approval) = load_scheme(
        &st.data_dir,
        &approval_ref,
        "approval-request",
        KIND_APPROVAL,
    ) else {
        return bad(
            "serve_approval_missing",
            "the mount's ApprovalRequest no longer resolves",
        );
    };
    let Some(release) = load_scheme(&st.data_dir, &release_ref, "release-control", KIND_RELEASE)
    else {
        return bad(
            "serve_release_missing",
            "the mount's ReleaseControl no longer resolves",
        );
    };
    if let Err((c, m)) = approval_admits(&approval, &domain_app_ref) {
        return bad(&c, &m);
    }
    if let Err((c, m)) = release_admits(&release, &domain_app_ref) {
        return bad(&c, &m);
    }
    let rid = prior_runtime
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt = build_mount_receipt(
        "domain_app.serve_start",
        &domain_app_ref,
        &approval_ref,
        &release_ref,
    );
    let route = format!("/__ioi/domain-app-runtime/{rid}");
    let mut refs: Vec<Value> = prior_runtime
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.push(json!(receipt.reference.clone()));
    let mut next_runtime = prior_runtime.clone();
    next_runtime["serving"] = json!(true);
    next_runtime["state"] = json!("serving");
    next_runtime["internal_route_ref"] = json!(route);
    next_runtime["serve_started_at"] = json!(iso_now());
    next_runtime["receipt_refs"] = json!(refs);
    next_runtime["updated_at"] = json!(iso_now());
    // Backlink: DomainApp runtime_posture now serving on the INTERNAL route (still no external ingress).
    let mut next_dapp = prior_dapp.clone();
    let mut posture = next_dapp
        .get("runtime_posture")
        .cloned()
        .unwrap_or_else(|| json!({}));
    posture["serving"] = json!(true);
    posture["route"] = json!(route);
    posture["note"] =
        json!("internally served (descriptor-driven, read-only); no external ingress");
    next_dapp["runtime_posture"] = posture;
    next_dapp["updated_at"] = json!(iso_now());
    if let Err(response) = finalize_domain_app_transition(
        &st.data_dir,
        &rid,
        Some(&prior_runtime),
        &next_runtime,
        &id,
        &prior_dapp,
        &next_dapp,
        std::slice::from_ref(&receipt),
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "runtime": next_runtime, "receipt": receipt.value })),
    )
}

/// POST /v1/hypervisor/domain-apps/:id/stop-serving — stop serving; return to mounted, receipted.
pub(crate) async fn handle_domain_app_stop_serving(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(prior_dapp) = load(&st.data_dir, KIND_DAPP, &id) else {
        return bad("domain_app_not_found", "domain app not found");
    };
    let domain_app_ref = prior_dapp
        .get("domain_app_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let Some(prior_runtime) = current_runtime(&st.data_dir, &domain_app_ref) else {
        return bad(
            "domain_app_not_mounted",
            "no mounted runtime for this domain app",
        );
    };
    if prior_runtime.get("serving").and_then(|v| v.as_bool()) != Some(true) {
        return bad("domain_app_not_serving", "runtime is not serving");
    }
    let rid = prior_runtime
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let approval_ref = prior_runtime
        .get("approval_request_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let release_ref = prior_runtime
        .get("release_control_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt = build_mount_receipt(
        "domain_app.serve_stop",
        &domain_app_ref,
        &approval_ref,
        &release_ref,
    );
    let mut refs: Vec<Value> = prior_runtime
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.push(json!(receipt.reference.clone()));
    let mut next_runtime = prior_runtime.clone();
    next_runtime["serving"] = json!(false);
    next_runtime["state"] = json!("mounted");
    next_runtime["internal_route_ref"] = Value::Null;
    next_runtime["serve_stopped_at"] = json!(iso_now());
    next_runtime["receipt_refs"] = json!(refs);
    next_runtime["updated_at"] = json!(iso_now());
    let mut next_dapp = prior_dapp.clone();
    let mut posture = next_dapp
        .get("runtime_posture")
        .cloned()
        .unwrap_or_else(|| json!({}));
    posture["serving"] = json!(false);
    posture["route"] = Value::Null;
    posture["note"] = json!("mounted (governed); serving stopped");
    next_dapp["runtime_posture"] = posture;
    next_dapp["updated_at"] = json!(iso_now());
    if let Err(response) = finalize_domain_app_transition(
        &st.data_dir,
        &rid,
        Some(&prior_runtime),
        &next_runtime,
        &id,
        &prior_dapp,
        &next_dapp,
        std::slice::from_ref(&receipt),
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "runtime": next_runtime, "receipt": receipt.value })),
    )
}

// ---- KillSwitch enforcement helpers (shared with governance_routes) ----------------------------
// These let the Governance KillSwitch enforce path stop/unmount Domain-App runtimes using the SAME
// receipt + state posture as the normal transitions, so enforcement is auditable and consistent.

/// Resolve the ACTIVE (mounted OR serving) runtimes a KillSwitch subject_ref targets. Supports
/// `domain-app-runtime://<id>` (one runtime) and `domain-app://<id>` (all active runtimes for the app).
pub(crate) fn runtimes_for_kill_target(data_dir: &str, subject_ref: &str) -> Vec<Value> {
    let active = |rt: &Value| {
        rt.get("mounted").and_then(|v| v.as_bool()) == Some(true)
            || rt.get("serving").and_then(|v| v.as_bool()) == Some(true)
    };
    match split_ref(subject_ref) {
        Some(("domain-app-runtime", id)) => load(data_dir, KIND_RUNTIME, id)
            .filter(active)
            .into_iter()
            .collect(),
        Some(("domain-app", _)) => read_record_dir(data_dir, KIND_RUNTIME)
            .into_iter()
            .filter(|rt| {
                rt.get("domain_app_ref").and_then(|v| v.as_str()) == Some(subject_ref) && active(rt)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Enforce a kill on ONE runtime: stop serving (if serving) + unmount (if mounted), forcing
/// serving:false and mounted:false, appending receipts (same kinds as the governed transitions plus
/// kill-specific actions), setting state "killed", and resetting the DomainApp backlink. Returns the
/// receipt refs emitted. Effectful — used only from the governance enforce path.
pub(crate) fn kill_enforce_runtime(
    data_dir: &str,
    runtime: &Value,
) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let mut next_runtime = runtime.clone();
    let rid = next_runtime
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let dref = next_runtime
        .get("domain_app_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let approval = next_runtime
        .get("approval_request_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let release = next_runtime
        .get("release_control_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let now = iso_now();
    let mut refs: Vec<Value> = next_runtime
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut emitted: Vec<String> = Vec::new();
    let mut receipts: Vec<PendingMountReceipt> = Vec::new();
    if next_runtime.get("serving").and_then(|v| v.as_bool()) == Some(true) {
        let receipt =
            build_mount_receipt("domain_app.kill_stop_serving", &dref, &approval, &release);
        refs.push(json!(receipt.reference.clone()));
        emitted.push(receipt.reference.clone());
        receipts.push(receipt);
        next_runtime["serving"] = json!(false);
        next_runtime["internal_route_ref"] = Value::Null;
        next_runtime["serve_stopped_at"] = json!(now);
    }
    if next_runtime.get("mounted").and_then(|v| v.as_bool()) == Some(true) {
        let receipt = build_mount_receipt("domain_app.kill_unmount", &dref, &approval, &release);
        refs.push(json!(receipt.reference.clone()));
        emitted.push(receipt.reference.clone());
        receipts.push(receipt);
        next_runtime["mounted"] = json!(false);
        next_runtime["unmounted_at"] = json!(now);
    }
    next_runtime["state"] = json!("killed");
    next_runtime["killed"] = json!(true);
    next_runtime["killed_at"] = json!(now);
    next_runtime["receipt_refs"] = json!(refs);
    next_runtime["updated_at"] = json!(now);
    let Some(("domain-app", dapp_id)) = split_ref(&dref) else {
        return Err(transition_persist_failure(
            "domain_app_backlink_invalid",
            "Domain App backlink resolution",
            true,
        ));
    };
    let Some(prior_dapp) = load(data_dir, KIND_DAPP, dapp_id) else {
        return Err(transition_persist_failure(
            "domain_app_backlink_missing",
            "Domain App backlink resolution",
            true,
        ));
    };
    let mut next_dapp = prior_dapp.clone();
    next_dapp["runtime_posture"] = json!({ "mounted": false, "serving": false, "route": Value::Null, "note": "killed by KillSwitch enforcement" });
    next_dapp["updated_at"] = json!(now);
    finalize_domain_app_transition(
        data_dir,
        &rid,
        Some(runtime),
        &next_runtime,
        dapp_id,
        &prior_dapp,
        &next_dapp,
        &receipts,
    )?;
    Ok(emitted)
}

#[cfg(test)]
mod domain_apps_tests {
    use super::*;

    #[test]
    fn mount_gating_requires_approved_and_open_and_right_subject() {
        let dref = "domain-app://dapp_1";
        // approved + targets subject -> ok
        assert!(
            approval_admits(&json!({ "status": "approved", "subject_ref": dref }), dref).is_ok()
        );
        // not approved -> err
        assert_eq!(
            approval_admits(&json!({ "status": "pending", "subject_ref": dref }), dref)
                .unwrap_err()
                .0,
            "mount_approval_not_approved"
        );
        // approved but wrong subject -> err
        assert_eq!(
            approval_admits(
                &json!({ "status": "approved", "subject_ref": "domain-app://other" }),
                dref
            )
            .unwrap_err()
            .0,
            "mount_control_wrong_subject"
        );
        // release open + targets subject -> ok
        assert!(release_admits(
            &json!({ "state": "open", "release_target_ref": dref }),
            dref
        )
        .is_ok());
        // release closed -> err
        assert_eq!(
            release_admits(
                &json!({ "state": "closed", "release_target_ref": dref }),
                dref
            )
            .unwrap_err()
            .0,
            "mount_release_not_open"
        );
        // release open but wrong target -> err
        assert_eq!(
            release_admits(
                &json!({ "state": "open", "release_target_ref": "domain-app://other" }),
                dref
            )
            .unwrap_err()
            .0,
            "mount_control_wrong_subject"
        );
    }

    #[test]
    fn serve_precheck_requires_mounted_not_already_serving() {
        assert!(serve_precheck(&json!({ "mounted": true, "serving": false })).is_ok());
        assert_eq!(
            serve_precheck(&json!({ "mounted": false, "serving": false }))
                .unwrap_err()
                .0,
            "domain_app_not_mounted"
        );
        assert_eq!(
            serve_precheck(&json!({ "mounted": true, "serving": true }))
                .unwrap_err()
                .0,
            "domain_app_already_serving"
        );
    }

    #[test]
    fn split_ref_and_prefixes() {
        assert_eq!(
            split_ref("surface-descriptor://sd_1"),
            Some(("surface-descriptor", "sd_1"))
        );
        assert_eq!(split_ref("odk://odk_1"), Some(("odk", "odk_1")));
        assert_eq!(split_ref("dapp_1"), None);
    }

    #[test]
    fn manifest_include_check() {
        let m = json!({ "surface_descriptor_refs": ["surface-descriptor://sd_1", "surface-descriptor://sd_2"] });
        assert!(manifest_includes_descriptor(
            &m,
            "surface-descriptor://sd_1"
        ));
        assert!(!manifest_includes_descriptor(
            &m,
            "surface-descriptor://sd_9"
        ));
        assert!(!manifest_includes_descriptor(
            &json!({}),
            "surface-descriptor://sd_1"
        ));
    }

    #[test]
    fn visibility_enum() {
        assert!(VISIBILITIES.contains(&"private"));
        assert!(VISIBILITIES.contains(&"marketplace_candidate"));
        assert!(!VISIBILITIES.contains(&"public"));
    }

    #[test]
    fn derive_snapshot_merges_descriptor_and_manifest_and_dedups() {
        let descriptor = json!({
            "ontology_ref": "ontology://ont_1",
            "recipe_refs": ["recipe://rec_1"]
        });
        let manifest = json!({
            "ontology_refs": ["ontology://ont_1", "ontology://ont_2"],
            "recipe_refs": ["recipe://rec_1", "recipe://rec_3"],
            "mcp_operator_contracts": ["mcp://c1"]
        });
        let body = json!({ "mcp_contract_refs": ["mcp://c2", "mcp://c1"] });
        let d = derive_snapshot(&descriptor, Some(&manifest), &body);
        // ontology: ont_1 (descriptor) + ont_2 (manifest), deduped
        assert_eq!(
            d.ontology_refs,
            vec![
                "ontology://ont_1".to_string(),
                "ontology://ont_2".to_string()
            ]
        );
        // recipes: rec_1 + rec_3, deduped
        assert_eq!(
            d.data_recipe_refs,
            vec!["recipe://rec_1".to_string(), "recipe://rec_3".to_string()]
        );
        // mcp: manifest c1 + body c2 (c1 not duplicated)
        assert_eq!(
            d.mcp_contract_refs,
            vec!["mcp://c1".to_string(), "mcp://c2".to_string()]
        );
    }

    #[test]
    fn derive_snapshot_without_manifest() {
        let descriptor = json!({ "ontology_ref": "ontology://ont_1", "recipe_refs": [] });
        let d = derive_snapshot(&descriptor, None, &json!({}));
        assert_eq!(d.ontology_refs, vec!["ontology://ont_1".to_string()]);
        assert!(d.data_recipe_refs.is_empty());
        assert!(d.mcp_contract_refs.is_empty());
    }

    #[test]
    fn required_persistence_refuses_success_when_record_directory_is_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(KIND_DAPP), b"not-a-directory").unwrap();
        let error = persist_required(
            dir.path().to_str().unwrap(),
            KIND_DAPP,
            "dapp_failure",
            &json!({"domain_app_id":"dapp_failure"}),
            "domain_app_persistence_failed",
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.1 .0["error"]["code"],
            json!("domain_app_persistence_failed")
        );
    }

    #[test]
    fn transition_restores_runtime_and_backlink_when_receipt_cannot_persist() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let prior_runtime = json!({
            "id":"runtime_1",
            "domain_app_ref":"domain-app://dapp_1",
            "mounted":true,
            "serving":false,
            "state":"mounted",
            "receipt_refs":[]
        });
        let prior_dapp = json!({
            "domain_app_id":"dapp_1",
            "domain_app_ref":"domain-app://dapp_1",
            "runtime_posture":{"mounted":true,"serving":false}
        });
        persist_record(data_dir, KIND_RUNTIME, "runtime_1", &prior_runtime).unwrap();
        persist_record(data_dir, KIND_DAPP, "dapp_1", &prior_dapp).unwrap();

        // A plain file at the receipt-directory coordinate forces the last-stage write to fail
        // after both state records commit, exercising the compensating restore path.
        std::fs::write(dir.path().join(KIND_MOUNT_RECEIPT), b"not-a-directory").unwrap();
        let mut next_runtime = prior_runtime.clone();
        next_runtime["serving"] = json!(true);
        next_runtime["state"] = json!("serving");
        let mut next_dapp = prior_dapp.clone();
        next_dapp["runtime_posture"]["serving"] = json!(true);
        let receipt = build_mount_receipt(
            "domain_app.serve_start",
            "domain-app://dapp_1",
            "approval-request://approval_1",
            "release-control://release_1",
        );

        let error = finalize_domain_app_transition(
            data_dir,
            "runtime_1",
            Some(&prior_runtime),
            &next_runtime,
            "dapp_1",
            &prior_dapp,
            &next_dapp,
            std::slice::from_ref(&receipt),
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.1 .0["error"]["code"],
            json!("domain_app_receipt_persistence_failed")
        );
        assert_eq!(error.1 .0["error"]["rollback_succeeded"], json!(true));
        assert_eq!(
            load(data_dir, KIND_RUNTIME, "runtime_1"),
            Some(prior_runtime)
        );
        assert_eq!(load(data_dir, KIND_DAPP, "dapp_1"), Some(prior_dapp));
    }
}
