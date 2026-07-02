//! Marketplace object plane (daemon-first). Draft listings/candidates/reviews/offers over REAL
//! agent / Domain App / ODK / Foundry substrate.
//!
//! PUBLISH INVARIANT (sharpened): the old absolute "nothing publishes" rule is retired and replaced
//! by a precise one — a `domain_app` listing publishes ONLY when it has an admitted
//! MarketplaceAdmissionReview, an OPEN ReleaseControl targeting the candidate/listing, AND a backing
//! DomainAppRuntime that is `mounted:true` and `serving:true`. Publishing sets read-only distribution
//! metadata (`public_state: published`) with runtime backing — it is NOT a commercial install/hire flow.
//!
//! Four durable objects: MarketplaceListingDraft · MarketplacePublishCandidate ·
//! MarketplaceAdmissionReview · ManagedInstanceOffer. Cross-references use canonical prefixed URIs.
//!
//! Hard boundaries (enforced, not decorative):
//!   * NO payments, settlement, routing marketplace, install/hire runtime, managed-instance
//!     instantiation, external ingress, or sas.xyz delivery loop.
//!   * `published` means read-only discoverable metadata WITH runtime backing — not a hire/install.
//!   * A ManagedInstanceOffer stays runtime_posture {instantiated:false} — no instance lifecycle.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, DaemonState};

const KIND_LISTING: &str = "marketplace-listings";
const KIND_CANDIDATE: &str = "marketplace-publish-candidates";
const KIND_REVIEW: &str = "marketplace-admission-reviews";
const KIND_OFFER: &str = "marketplace-instance-offers";
const KIND_PUBLISH_RECEIPT: &str = "marketplace-publish-receipts";
const KIND_DOMAIN_APP: &str = "domain-apps";
const KIND_RUNTIME: &str = "domain-app-runtimes";
const KIND_RELEASE: &str = "governance-release-controls";

/// What a listing may offer — each maps to a real substrate plane for subject resolution.
const LISTING_KINDS: &[&str] = &[
    "agent",
    "domain_app",
    "ontology_pack",
    "data_recipe",
    "foundry_capability",
];
/// A managed-instance offer may bind an agent or a domain app (both real today).
const OFFER_KINDS: &[&str] = &["agent", "domain_app"];
/// Admission review decisions. NOTE: `admitted` is NOT `published` — nothing publishes in this plane.
const ADMISSION_DECISIONS: &[&str] = &["pending", "needs_changes", "admitted", "rejected"];

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
        &std::fs::read(Path::new(data_dir).join(kind).join(format!("{}.json", safe(id)))).ok()?,
    )
    .ok()
}
fn bad(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}
fn split_ref(r: &str) -> Option<(&str, &str)> {
    r.split_once("://")
        .filter(|(s, rest)| !s.is_empty() && !rest.is_empty())
}
fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(|v| v.as_str()).map(str::trim).unwrap_or("")
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
fn histogram(items: &[Value], key: &str) -> HashMap<String, i64> {
    let mut h = HashMap::new();
    for it in items {
        let k = it.get(key).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        *h.entry(k).or_insert(0) += 1;
    }
    h
}
async fn get_json(base: &str, path: &str) -> Value {
    match reqwest::Client::new().get(format!("{base}{path}")).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    }
}

/// A ref that must carry `scheme://` AND resolve to a local record of `kind`.
fn resolve_scheme_ref(
    data_dir: &str,
    r: &str,
    scheme: &str,
    kind: &str,
    label: &str,
) -> Result<(), (String, String)> {
    match split_ref(r) {
        Some((s, rest)) if s == scheme => {
            if load(data_dir, kind, rest).is_some() {
                Ok(())
            } else {
                Err((
                    "marketplace_ref_unresolved".into(),
                    format!("{label} '{r}' does not resolve to a local {scheme} record"),
                ))
            }
        }
        _ => Err((
            "marketplace_ref_prefix_invalid".into(),
            format!("{label} must be a '{scheme}://' ref"),
        )),
    }
}

/// Validate a listing's subject_ref against the REAL substrate plane for its listing_kind.
async fn resolve_listing_subject(
    data_dir: &str,
    base: &str,
    listing_kind: &str,
    subject_ref: &str,
) -> Result<(), (String, String)> {
    match listing_kind {
        // Agent: subject_ref is a real /v1/agents id (no scheme).
        "agent" => {
            let agents = get_json(base, "/v1/agents").await;
            let ok = agents
                .as_array()
                .map(|a| a.iter().any(|x| x.get("id").and_then(|v| v.as_str()) == Some(subject_ref)))
                .unwrap_or(false);
            if ok {
                Ok(())
            } else {
                Err((
                    "marketplace_subject_unresolved".into(),
                    format!("agent listing subject_ref '{subject_ref}' is not a real agent id"),
                ))
            }
        }
        "domain_app" => resolve_scheme_ref(data_dir, subject_ref, "domain-app", "domain-apps", "domain_app subject_ref"),
        "ontology_pack" => resolve_scheme_ref(data_dir, subject_ref, "odk", "odk-manifests", "ontology_pack subject_ref"),
        "data_recipe" => resolve_scheme_ref(data_dir, subject_ref, "recipe", "odk-data-recipes", "data_recipe subject_ref"),
        // Foundry capability: subject_ref is a Foundry spec or run-plan id (no scheme).
        "foundry_capability" => {
            if load(data_dir, "foundry-specs", subject_ref).is_some()
                || load(data_dir, "foundry-run-plans", subject_ref).is_some()
            {
                Ok(())
            } else {
                Err((
                    "marketplace_subject_unresolved".into(),
                    format!("foundry_capability subject_ref '{subject_ref}' is not a real Foundry spec/run-plan id"),
                ))
            }
        }
        _ => Err((
            "marketplace_listing_kind_invalid".into(),
            format!("listing_kind must be one of {LISTING_KINDS:?}"),
        )),
    }
}

/// Evidence refs may be named; those using a known local scheme must resolve.
fn check_evidence_refs(data_dir: &str, refs: &[String]) -> Result<(), (String, String)> {
    for r in refs {
        if let Some((scheme, rest)) = split_ref(r) {
            let kind = match scheme {
                "domain-app" => Some("domain-apps"),
                "odk" => Some("odk-manifests"),
                "recipe" => Some("odk-data-recipes"),
                "surface-descriptor" => Some("odk-surface-descriptors"),
                "ontology" => Some("odk-domain-ontologies"),
                "marketplace-listing" => Some(KIND_LISTING),
                "marketplace-publish" => Some(KIND_CANDIDATE),
                "marketplace-admission" => Some(KIND_REVIEW),
                _ => None, // work-ledger / receipt / state-root ids etc. are named, not resolved
            };
            if let Some(k) = kind {
                if load(data_dir, k, rest).is_none() {
                    return Err((
                        "marketplace_ref_unresolved".into(),
                        format!("evidence ref '{r}' does not resolve to a local {scheme} record"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Governance posture snapshot (evidence of gate state at candidacy/review time).
async fn governance_snapshot(base: &str) -> Value {
    let g = get_json(base, "/v1/hypervisor/governance/overview").await;
    let s = g.get("summary").cloned().unwrap_or(Value::Null);
    json!({
        "auth_enforced": s.get("auth_enforced").cloned().unwrap_or(Value::Null),
        "governance_gaps": s.get("governance_gaps").cloned().unwrap_or(Value::Null),
        "wallet_required_crossings": s.get("wallet_required_crossings").cloned().unwrap_or(Value::Null),
        "authority_grants_active": s.get("authority_grants_active").cloned().unwrap_or(Value::Null),
        "at": iso_now()
    })
}
/// Pure: the sharpened publish invariant — the reasons a candidate cannot publish, given resolved
/// facts. Empty => publishable. domain_app-only; requires admitted review + open release + serving
/// runtime.
fn publish_reasons(kind: &str, dapp_ok: bool, has_admitted: bool, has_open_release: bool, has_serving: bool) -> Vec<String> {
    let mut r = Vec::new();
    if kind != "domain_app" {
        r.push("listing_not_domain_app".to_string());
    }
    if !dapp_ok {
        r.push("domain_app_unresolved".to_string());
    }
    if !has_admitted {
        r.push("no_admitted_admission_review".to_string());
    }
    if !has_open_release {
        r.push("no_open_release_control".to_string());
    }
    if kind == "domain_app" && !has_serving {
        r.push("no_serving_runtime".to_string());
    }
    r
}
/// The resolved publish backing for a candidate (reasons + the refs that satisfied each gate).
#[derive(Default)]
struct PublishBacking {
    reasons: Vec<String>,
    listing_id: String,
    subject_ref: String,
    admission_review_ref: Option<String>,
    release_control_ref: Option<String>,
    runtime_ref: Option<String>,
    runtime_route: Option<String>,
}
/// Resolve the publish gates for a candidate against real substrate (listing kind, admitted review,
/// open ReleaseControl targeting candidate/listing, serving DomainAppRuntime for the subject).
fn publish_gates(data_dir: &str, candidate: &Value) -> PublishBacking {
    let mut b = PublishBacking::default();
    let cand_ref = candidate.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let listing_ref = candidate.get("listing_ref").and_then(|v| v.as_str()).unwrap_or("");
    let listing = match split_ref(listing_ref) {
        Some(("marketplace-listing", id)) => load(data_dir, KIND_LISTING, id),
        _ => None,
    };
    let Some(listing) = listing else {
        b.reasons.push("listing_unresolved".to_string());
        return b;
    };
    b.listing_id = listing.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let kind = listing.get("listing_kind").and_then(|v| v.as_str()).unwrap_or("");
    let subject = listing.get("subject_ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
    b.subject_ref = subject.clone();
    // domain app resolves?
    let dapp_ok = match split_ref(&subject) {
        Some(("domain-app", id)) => load(data_dir, KIND_DOMAIN_APP, id).is_some(),
        _ => false,
    };
    // admitted review for this candidate?
    if let Some(rv) = read_record_dir(data_dir, KIND_REVIEW).into_iter().find(|r| {
        r.get("candidate_ref").and_then(|v| v.as_str()) == Some(cand_ref.as_str())
            && r.get("decision").and_then(|v| v.as_str()) == Some("admitted")
    }) {
        b.admission_review_ref = rv.get("ref").and_then(|v| v.as_str()).map(str::to_string);
    }
    // open ReleaseControl targeting the candidate OR the listing?
    if let Some(rc) = read_record_dir(data_dir, KIND_RELEASE).into_iter().find(|r| {
        r.get("state").and_then(|v| v.as_str()) == Some("open")
            && matches!(r.get("release_target_ref").and_then(|v| v.as_str()), Some(t) if t == cand_ref || t == listing_ref)
    }) {
        b.release_control_ref = rc.get("ref").and_then(|v| v.as_str()).map(str::to_string);
    }
    // serving DomainAppRuntime for the subject?
    if let Some(rt) = read_record_dir(data_dir, KIND_RUNTIME).into_iter().find(|rt| {
        rt.get("domain_app_ref").and_then(|v| v.as_str()) == Some(subject.as_str())
            && rt.get("mounted").and_then(|v| v.as_bool()) == Some(true)
            && rt.get("serving").and_then(|v| v.as_bool()) == Some(true)
            && rt.get("internal_route_ref").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
    }) {
        b.runtime_route = rt.get("internal_route_ref").and_then(|v| v.as_str()).map(str::to_string);
        b.runtime_ref = rt.get("ref").and_then(|v| v.as_str()).map(str::to_string);
    }
    b.reasons = publish_reasons(kind, dapp_ok, b.admission_review_ref.is_some(), b.release_control_ref.is_some(), b.runtime_ref.is_some());
    b
}

// ===================================== OVERVIEW =================================================

/// GET /v1/hypervisor/marketplace/overview — real substrate candidates + marketplace object counts
/// + governance posture. Read projection; nothing is published, hired, or settled.
pub(crate) async fn handle_marketplace_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let base = st.base_url.clone();
    let agents = get_json(&base, "/v1/agents").await;
    let agents_len = agents.as_array().map(|a| a.len()).unwrap_or(0);
    let domain_apps = read_record_dir(&st.data_dir, "domain-apps");
    let dapp_candidates = domain_apps
        .iter()
        .filter(|d| d.get("visibility").and_then(|v| v.as_str()) == Some("marketplace_candidate"))
        .count();

    let listings = read_record_dir(&st.data_dir, KIND_LISTING);
    let candidates = read_record_dir(&st.data_dir, KIND_CANDIDATE);
    let reviews = read_record_dir(&st.data_dir, KIND_REVIEW);
    let offers = read_record_dir(&st.data_dir, KIND_OFFER);
    let gov = governance_snapshot(&base).await;

    let mut recent: Vec<Value> = listings
        .iter()
        .map(|l| {
            json!({
                "id": l.get("id").cloned().unwrap_or(Value::Null),
                "ref": l.get("ref").cloned().unwrap_or(Value::Null),
                "name": l.get("name").cloned().unwrap_or(Value::Null),
                "listing_kind": l.get("listing_kind").cloned().unwrap_or(Value::Null),
                "status": l.get("status").cloned().unwrap_or(Value::Null),
                "updated_at": l.get("updated_at").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    recent.sort_by(|a, b| b["updated_at"].as_str().unwrap_or("").cmp(a["updated_at"].as_str().unwrap_or("")));
    recent.truncate(8);

    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.marketplace-overview.v1",
        "status_note": "Marketplace: a domain_app listing publishes ONLY with an admitted review, an open ReleaseControl, and a mounted&serving DomainAppRuntime. Published = read-only, runtime-backed distribution metadata — never hired, instantiated, settled, or routed.",
        "substrate": {
            "agents": agents_len,
            "domain_apps_total": domain_apps.len(),
            "domain_apps_marketplace_candidates": dapp_candidates,
            "odk_manifests": read_record_dir(&st.data_dir, "odk-manifests").len(),
            "odk_data_recipes": read_record_dir(&st.data_dir, "odk-data-recipes").len(),
            "foundry_specs": read_record_dir(&st.data_dir, "foundry-specs").len(),
            "foundry_run_plans": read_record_dir(&st.data_dir, "foundry-run-plans").len()
        },
        "marketplace": {
            "listings": listings.len(),
            "listings_by_kind": serde_json::to_value(histogram(&listings, "listing_kind")).unwrap_or_else(|_| json!({})),
            "publish_candidates": candidates.len(),
            "admission_reviews": reviews.len(),
            "admission_reviews_by_decision": serde_json::to_value(histogram(&reviews, "decision")).unwrap_or_else(|_| json!({})),
            "managed_instance_offers": offers.len(),
            "published": listings.iter().filter(|l| l.get("public_state").and_then(|v| v.as_str()) == Some("published")).count()
        },
        "governance_posture": gov,
        "listing_kinds": LISTING_KINDS,
        "admission_decisions": ADMISSION_DECISIONS,
        "recent_listings": recent
    }))
}

// ================================ LISTING DRAFT ================================================

pub(crate) async fn handle_listing_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_LISTING);
    if let Some(k) = q.get("listing_kind").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|l| l.get("listing_kind").and_then(|v| v.as_str()) == Some(k));
    }
    items.sort_by(|a, b| b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "ok": true, "listings": items }))
}

/// POST /v1/hypervisor/marketplace/listings — draft a listing over REAL substrate.
pub(crate) async fn handle_listing_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let listing_kind = str_field(&body, "listing_kind");
    if !LISTING_KINDS.contains(&listing_kind) {
        return bad("marketplace_listing_kind_invalid", &format!("listing_kind must be one of {LISTING_KINDS:?}"));
    }
    let subject_ref = str_field(&body, "subject_ref");
    if subject_ref.is_empty() {
        return bad("marketplace_subject_required", "A listing must declare a subject_ref.");
    }
    if let Err((c, m)) = resolve_listing_subject(&st.data_dir, &st.base_url, listing_kind, subject_ref).await {
        return bad(&c, &m);
    }
    if let Err((c, m)) = check_evidence_refs(&st.data_dir, &str_refs(&body, "evidence_refs")) {
        return bad(&c, &m);
    }
    let id = format!("mlist_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.marketplace-listing.v1",
        "object": "ioi.hypervisor.marketplace_listing_draft",
        "id": id,
        "ref": format!("marketplace-listing://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("marketplace-listing"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        // A listing is NEVER publicly listed in this plane.
        "public_state": "unlisted",
        "listing_kind": listing_kind,
        "subject_ref": subject_ref,
        "evidence_refs": str_refs(&body, "evidence_refs"),
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_LISTING, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "listing": record })))
}

pub(crate) async fn handle_listing_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_LISTING, &id) {
        Some(l) => Json(json!({ "ok": true, "listing": l })),
        None => Json(json!({ "ok": false, "reason": "listing not found" })),
    }
}

pub(crate) async fn handle_listing_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut l) = load(&st.data_dir, KIND_LISTING, &id) else {
        return Json(json!({ "ok": false, "reason": "listing not found" }));
    };
    // If listing_kind or subject_ref changes, re-validate against real substrate.
    let new_kind = body
        .get("listing_kind")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| l.get("listing_kind").and_then(|v| v.as_str()).unwrap_or(""));
    if body.get("listing_kind").is_some() && !LISTING_KINDS.contains(&new_kind) {
        return Json(json!({ "ok": false, "error": { "code": "marketplace_listing_kind_invalid", "message": format!("listing_kind must be one of {LISTING_KINDS:?}") } }));
    }
    if body.get("listing_kind").is_some() || body.get("subject_ref").is_some() {
        let subj = body
            .get("subject_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or_else(|| l.get("subject_ref").and_then(|v| v.as_str()).unwrap_or(""));
        if let Err((c, m)) = resolve_listing_subject(&st.data_dir, &st.base_url, new_kind, subj).await {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    if body.get("evidence_refs").is_some() {
        if let Err((c, m)) = check_evidence_refs(&st.data_dir, &str_refs(&body, "evidence_refs")) {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    for key in ["name", "description", "listing_kind", "subject_ref", "evidence_refs"] {
        if let Some(v) = body.get(key) {
            l[key] = v.clone();
        }
    }
    l["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_LISTING, &id, &l);
    Json(json!({ "ok": true, "listing": l }))
}

pub(crate) async fn handle_listing_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_LISTING, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

// ============================ PUBLISH CANDIDATE ================================================

fn candidate_view(data_dir: &str, c: &Value) -> Value {
    let published = c.get("publish_state").and_then(|v| v.as_str()) == Some("published");
    let b = publish_gates(data_dir, c);
    let mut c = c.clone();
    c["blocked_reasons"] = if published { json!([]) } else { json!(b.reasons) };
    // Publishable only under the sharpened invariant (admitted review + open release + serving runtime).
    c["publishable"] = json!(!published && b.reasons.is_empty());
    c
}

pub(crate) async fn handle_candidate_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items: Vec<Value> = read_record_dir(&st.data_dir, KIND_CANDIDATE)
        .iter()
        .map(|c| candidate_view(&st.data_dir, c))
        .collect();
    items.sort_by(|a, b| b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "ok": true, "publish_candidates": items }))
}

/// POST /v1/hypervisor/marketplace/publish-candidates — nominate a listing (candidate, NOT publish).
pub(crate) async fn handle_candidate_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let listing_ref = str_field(&body, "listing_ref");
    if listing_ref.is_empty() {
        return bad("marketplace_listing_ref_required", "A publish candidate must declare a listing_ref.");
    }
    if let Err((c, m)) = resolve_scheme_ref(&st.data_dir, listing_ref, "marketplace-listing", KIND_LISTING, "listing_ref") {
        return bad(&c, &m);
    }
    let gov = governance_snapshot(&st.base_url).await;
    let id = format!("mpub_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.marketplace-publish-candidate.v1",
        "object": "ioi.hypervisor.marketplace_publish_candidate",
        "id": id,
        "ref": format!("marketplace-publish://{id}"),
        "listing_ref": listing_ref,
        "status": "draft",
        // Never leaves "candidate" — no publish path exists.
        "publish_state": "candidate",
        "admission_review_ref": Value::Null,
        "governance_posture_snapshot": gov,
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_CANDIDATE, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &record) })))
}

pub(crate) async fn handle_candidate_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_CANDIDATE, &id) {
        Some(c) => Json(json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &c) })),
        None => Json(json!({ "ok": false, "reason": "publish candidate not found" })),
    }
}

/// POST /v1/hypervisor/marketplace/publish-candidates/:id/publish — the ONE governed publish path.
/// Publishes a domain_app listing iff: admitted review + open ReleaseControl (targeting candidate or
/// listing) + a mounted&serving DomainAppRuntime backing the subject. Sets read-only published
/// distribution metadata (NOT a hire/install). Emits a publish receipt.
pub(crate) async fn handle_candidate_publish(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut candidate) = load(&st.data_dir, KIND_CANDIDATE, &id) else {
        return bad("marketplace_candidate_not_found", "publish candidate not found");
    };
    if candidate.get("publish_state").and_then(|v| v.as_str()) == Some("published") {
        return bad("marketplace_already_published", "this candidate is already published");
    }
    let b = publish_gates(&st.data_dir, &candidate);
    if !b.reasons.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": {
                "code": "marketplace_publish_blocked",
                "message": "publish requires: domain_app listing + admitted review + open ReleaseControl + mounted&serving runtime",
                "blocked_reasons": b.reasons
            } })),
        );
    }
    let now = iso_now();
    let admission_review_ref = b.admission_review_ref.clone().unwrap_or_default();
    let release_control_ref = b.release_control_ref.clone().unwrap_or_default();
    let published_runtime_ref = b.runtime_ref.clone().unwrap_or_default();
    let cand_ref = candidate.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Publish receipt (real proof: sha256 state_root over the backing tuple).
    let prid = format!("pubr_{:x}", nanos());
    let state_root = sha256_hex_str(&format!("publish|{cand_ref}|{admission_review_ref}|{release_control_ref}|{published_runtime_ref}|{now}"));
    let receipt = json!({
        "schema_version": "ioi.hypervisor.marketplace-publish-receipt.v1",
        "object": "ioi.hypervisor.marketplace_publish_receipt",
        "id": prid, "ref": format!("marketplace-publish-receipt://{prid}"),
        "candidate_ref": cand_ref,
        "listing_id": b.listing_id,
        "admission_review_ref": admission_review_ref,
        "release_control_ref": release_control_ref,
        "published_runtime_ref": published_runtime_ref,
        "state_root": format!("sha256:{state_root}"),
        "at": now
    });
    let _ = persist_record(&st.data_dir, KIND_PUBLISH_RECEIPT, &prid, &receipt);
    let receipt_ref = format!("marketplace-publish-receipt://{prid}");
    // Flip the candidate -> published (read-only distribution metadata, runtime-backed).
    candidate["publish_state"] = json!("published");
    candidate["published_at"] = json!(now);
    candidate["published_runtime_ref"] = json!(published_runtime_ref);
    candidate["release_control_ref"] = json!(release_control_ref);
    candidate["admission_review_ref"] = json!(admission_review_ref);
    candidate["publish_receipt_refs"] = json!([receipt_ref]);
    candidate["state_root"] = json!(format!("sha256:{state_root}"));
    candidate["updated_at"] = json!(now);
    let _ = persist_record(&st.data_dir, KIND_CANDIDATE, &id, &candidate);
    // Flip the listing public_state -> published.
    if let Some(mut listing) = load(&st.data_dir, KIND_LISTING, &b.listing_id) {
        listing["public_state"] = json!("published");
        listing["published_at"] = json!(now);
        listing["published_runtime_ref"] = json!(published_runtime_ref);
        listing["release_control_ref"] = json!(release_control_ref);
        listing["admission_review_ref"] = json!(admission_review_ref);
        listing["publish_receipt_refs"] = json!([receipt_ref.clone()]);
        listing["updated_at"] = json!(now);
        let _ = persist_record(&st.data_dir, KIND_LISTING, &b.listing_id, &listing);
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &candidate), "receipt": receipt })),
    )
}

pub(crate) async fn handle_candidate_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_CANDIDATE, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

// ============================ ADMISSION REVIEW ================================================

/// Link/unlink an admission review onto its candidate (transactional, best-effort).
fn link_candidate_review(data_dir: &str, candidate_ref: &str, review_ref: Option<&str>) {
    let Some((_, cid)) = split_ref(candidate_ref) else { return };
    let Some(mut c) = load(data_dir, KIND_CANDIDATE, cid) else { return };
    c["admission_review_ref"] = match review_ref {
        Some(r) => json!(r),
        None => Value::Null,
    };
    c["updated_at"] = json!(iso_now());
    let _ = persist_record(data_dir, KIND_CANDIDATE, cid, &c);
}

pub(crate) async fn handle_review_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_REVIEW);
    items.sort_by(|a, b| b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "ok": true, "admission_reviews": items }))
}

/// POST /v1/hypervisor/marketplace/admission-reviews — review a candidate. `admitted` != `published`.
pub(crate) async fn handle_review_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let candidate_ref = str_field(&body, "candidate_ref");
    if candidate_ref.is_empty() {
        return bad("marketplace_candidate_ref_required", "An admission review must declare a candidate_ref.");
    }
    if let Err((c, m)) = resolve_scheme_ref(&st.data_dir, candidate_ref, "marketplace-publish", KIND_CANDIDATE, "candidate_ref") {
        return bad(&c, &m);
    }
    let decision = {
        let d = body.get("decision").and_then(|v| v.as_str()).unwrap_or("pending");
        if !ADMISSION_DECISIONS.contains(&d) {
            return bad("marketplace_decision_invalid", &format!("decision must be one of {ADMISSION_DECISIONS:?}"));
        }
        d.to_string()
    };
    let gov = governance_snapshot(&st.base_url).await;
    let id = format!("madm_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.marketplace-admission-review.v1",
        "object": "ioi.hypervisor.marketplace_admission_review",
        "id": id,
        "ref": format!("marketplace-admission://{id}"),
        "candidate_ref": candidate_ref,
        "status": "draft",
        "decision": decision,
        // Explicit: admission is a gate review, not a publish. Nothing goes live from here.
        "admits_but_not_publishes": true,
        "reviewer_ref": body.get("reviewer_ref").cloned().unwrap_or(Value::Null),
        "findings": str_refs(&body, "findings"),
        "governance_posture_snapshot": gov,
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_REVIEW, &id, &record);
    // Link the review onto its candidate so blocked_reasons can reflect an admitted review.
    link_candidate_review(&st.data_dir, candidate_ref, Some(&format!("marketplace-admission://{id}")));
    (StatusCode::CREATED, Json(json!({ "ok": true, "admission_review": record })))
}

pub(crate) async fn handle_review_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_REVIEW, &id) {
        Some(r) => Json(json!({ "ok": true, "admission_review": r })),
        None => Json(json!({ "ok": false, "reason": "admission review not found" })),
    }
}

pub(crate) async fn handle_review_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut r) = load(&st.data_dir, KIND_REVIEW, &id) else {
        return Json(json!({ "ok": false, "reason": "admission review not found" }));
    };
    if let Some(d) = body.get("decision").and_then(|v| v.as_str()) {
        if !ADMISSION_DECISIONS.contains(&d) {
            return Json(json!({ "ok": false, "error": { "code": "marketplace_decision_invalid", "message": format!("decision must be one of {ADMISSION_DECISIONS:?}") } }));
        }
    }
    for key in ["decision", "reviewer_ref", "findings"] {
        if let Some(v) = body.get(key) {
            r[key] = v.clone();
        }
    }
    r["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_REVIEW, &id, &r);
    Json(json!({ "ok": true, "admission_review": r }))
}

pub(crate) async fn handle_review_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    // Unlink from the candidate first so blocked_reasons stays honest.
    if let Some(rev) = load(&st.data_dir, KIND_REVIEW, &id) {
        if let Some(cref) = rev.get("candidate_ref").and_then(|v| v.as_str()) {
            link_candidate_review(&st.data_dir, cref, None);
        }
    }
    let removed = remove_record(&st.data_dir, KIND_REVIEW, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

// ============================ MANAGED INSTANCE OFFER ==========================================

pub(crate) async fn handle_offer_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_OFFER);
    items.sort_by(|a, b| b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "ok": true, "managed_instance_offers": items }))
}

/// POST /v1/hypervisor/marketplace/instance-offers — a DRAFT offer over a real agent/domain-app.
/// It never instantiates: runtime_posture stays {instantiated:false}. No hire/install lifecycle.
pub(crate) async fn handle_offer_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let offer_kind = str_field(&body, "offer_kind");
    if !OFFER_KINDS.contains(&offer_kind) {
        return bad("marketplace_offer_kind_invalid", &format!("offer_kind must be one of {OFFER_KINDS:?}"));
    }
    let subject_ref = str_field(&body, "subject_ref");
    if subject_ref.is_empty() {
        return bad("marketplace_subject_required", "A managed instance offer must declare a subject_ref.");
    }
    // agent -> real /v1/agents id; domain_app -> real domain-app:// ref.
    if let Err((c, m)) = resolve_listing_subject(&st.data_dir, &st.base_url, offer_kind, subject_ref).await {
        return bad(&c, &m);
    }
    let listing_ref = str_field(&body, "listing_ref");
    if !listing_ref.is_empty() {
        if let Err((c, m)) = resolve_scheme_ref(&st.data_dir, listing_ref, "marketplace-listing", KIND_LISTING, "listing_ref") {
            return bad(&c, &m);
        }
    }
    let id = format!("moffer_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.managed-instance-offer.v1",
        "object": "ioi.hypervisor.managed_instance_offer",
        "id": id,
        "ref": format!("managed-instance-offer://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("managed-instance-offer"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "draft",
        "offer_kind": offer_kind,
        "subject_ref": subject_ref,
        "listing_ref": if listing_ref.is_empty() { Value::Null } else { json!(listing_ref) },
        // No instance lifecycle in this plane — the hard line.
        "runtime_posture": { "instantiated": false, "note": "draft offer only; no managed instance is hired, installed, or instantiated" },
        "created_at": now,
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_OFFER, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "managed_instance_offer": record })))
}

pub(crate) async fn handle_offer_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_OFFER, &id) {
        Some(o) => Json(json!({ "ok": true, "managed_instance_offer": o })),
        None => Json(json!({ "ok": false, "reason": "managed instance offer not found" })),
    }
}

pub(crate) async fn handle_offer_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut o) = load(&st.data_dir, KIND_OFFER, &id) else {
        return Json(json!({ "ok": false, "reason": "managed instance offer not found" }));
    };
    let new_kind = body
        .get("offer_kind")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| o.get("offer_kind").and_then(|v| v.as_str()).unwrap_or(""));
    if body.get("offer_kind").is_some() && !OFFER_KINDS.contains(&new_kind) {
        return Json(json!({ "ok": false, "error": { "code": "marketplace_offer_kind_invalid", "message": format!("offer_kind must be one of {OFFER_KINDS:?}") } }));
    }
    if body.get("offer_kind").is_some() || body.get("subject_ref").is_some() {
        let subj = body
            .get("subject_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or_else(|| o.get("subject_ref").and_then(|v| v.as_str()).unwrap_or(""));
        if let Err((c, m)) = resolve_listing_subject(&st.data_dir, &st.base_url, new_kind, subj).await {
            return Json(json!({ "ok": false, "error": { "code": c, "message": m } }));
        }
    }
    for key in ["name", "description", "offer_kind", "subject_ref", "listing_ref"] {
        if let Some(v) = body.get(key) {
            o[key] = v.clone();
        }
    }
    // runtime_posture is immutable here — never instantiated.
    o["runtime_posture"] = json!({ "instantiated": false, "note": "draft offer only; no managed instance is hired, installed, or instantiated" });
    o["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_OFFER, &id, &o);
    Json(json!({ "ok": true, "managed_instance_offer": o }))
}

pub(crate) async fn handle_offer_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_OFFER, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod marketplace_tests {
    use super::*;

    #[test]
    fn listing_and_offer_and_decision_enums() {
        assert!(LISTING_KINDS.contains(&"agent"));
        assert!(LISTING_KINDS.contains(&"foundry_capability"));
        assert!(!LISTING_KINDS.contains(&"widget"));
        assert!(OFFER_KINDS.contains(&"agent"));
        assert!(OFFER_KINDS.contains(&"domain_app"));
        assert!(!OFFER_KINDS.contains(&"ontology_pack"));
        assert!(ADMISSION_DECISIONS.contains(&"admitted"));
        assert!(!ADMISSION_DECISIONS.contains(&"published"));
    }

    #[test]
    fn publish_reasons_empty_only_when_all_gates_pass() {
        // domain_app + resolvable + admitted + open release + serving -> publishable (no reasons).
        assert!(publish_reasons("domain_app", true, true, true, true).is_empty());
    }

    #[test]
    fn publish_reasons_flag_each_missing_gate() {
        // non-domain_app is rejected up front.
        assert!(publish_reasons("agent", true, true, true, true).contains(&"listing_not_domain_app".to_string()));
        // each missing gate names itself.
        assert!(publish_reasons("domain_app", true, false, true, true).contains(&"no_admitted_admission_review".to_string()));
        assert!(publish_reasons("domain_app", true, true, false, true).contains(&"no_open_release_control".to_string()));
        assert!(publish_reasons("domain_app", true, true, true, false).contains(&"no_serving_runtime".to_string()));
        assert!(publish_reasons("domain_app", false, true, true, true).contains(&"domain_app_unresolved".to_string()));
        // all failing -> all reasons present.
        assert_eq!(publish_reasons("domain_app", false, false, false, false).len(), 4);
    }

    #[test]
    fn split_ref_parses_marketplace_schemes() {
        assert_eq!(split_ref("marketplace-listing://mlist_1"), Some(("marketplace-listing", "mlist_1")));
        assert_eq!(split_ref("marketplace-publish://mpub_1"), Some(("marketplace-publish", "mpub_1")));
        assert_eq!(split_ref("agent_2a9cc2ed"), None);
    }

    #[test]
    fn histogram_groups() {
        let items = vec![json!({"listing_kind": "agent"}), json!({"listing_kind": "agent"}), json!({"listing_kind": "domain_app"})];
        let h = histogram(&items, "listing_kind");
        assert_eq!(h.get("agent"), Some(&2));
        assert_eq!(h.get("domain_app"), Some(&1));
    }
}
