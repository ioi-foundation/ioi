//! Marketplace object plane — FOUNDATION cut (daemon-first, draft-only).
//!
//! The Marketplace substrate is `admission_only_until_runtime_backing`: it can draft listings,
//! nominate publish candidates, and record admission reviews over REAL agent / Domain App / ODK /
//! Foundry substrate — but nothing is ever published, hired, instantiated, settled, or routed here.
//!
//! Four durable DRAFT objects: MarketplaceListingDraft · MarketplacePublishCandidate ·
//! MarketplaceAdmissionReview · ManagedInstanceOffer. Cross-references use canonical prefixed URIs.
//!
//! Hard boundaries (enforced, not decorative):
//!   * NO payments, settlement, routing marketplace, install/hire runtime, managed-instance
//!     instantiation, or sas.xyz delivery loop.
//!   * NO "published" state — a candidate never leaves publish_state "candidate"; even an
//!     admission review that ADMITS does not publish (admission != published).
//!   * A ManagedInstanceOffer stays runtime_posture {instantiated:false} — no instance lifecycle.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const KIND_LISTING: &str = "marketplace-listings";
const KIND_CANDIDATE: &str = "marketplace-publish-candidates";
const KIND_REVIEW: &str = "marketplace-admission-reviews";
const KIND_OFFER: &str = "marketplace-instance-offers";

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
/// Why a candidate is not publishable — combining current governance + admission + the structural
/// `admission_only_until_runtime_backing` reason that always blocks publish in this plane.
fn derive_blocked_reasons(gov: &Value, has_admission_admitted: bool) -> Vec<String> {
    let mut r = Vec::new();
    if !has_admission_admitted {
        r.push("no_admitted_admission_review".to_string());
    }
    if gov.get("governance_gaps").and_then(|v| v.as_i64()).unwrap_or(1) > 0 {
        r.push("governance_gaps_present".to_string());
    }
    if !gov.get("auth_enforced").and_then(|v| v.as_bool()).unwrap_or(false) {
        r.push("auth_not_enforced".to_string());
    }
    // Structural: this plane has no runtime backing, so nothing publishes regardless.
    r.push("admission_only_until_runtime_backing".to_string());
    r
}
/// Does this candidate have a linked admission review that ADMITTED it? (drives blocked_reasons)
fn candidate_admitted(data_dir: &str, candidate: &Value) -> bool {
    let Some(rref) = candidate.get("admission_review_ref").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some((_, id)) = split_ref(rref) else { return false };
    load(data_dir, KIND_REVIEW, id)
        .and_then(|r| r.get("decision").and_then(|v| v.as_str()).map(str::to_string))
        .map(|d| d == "admitted")
        .unwrap_or(false)
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
        "status_note": "Marketplace foundation: admission_only_until_runtime_backing. Listings/candidates/reviews/offers are drafts. Nothing is published, hired, instantiated, settled, or routed.",
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
            "published": 0
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

fn candidate_view(data_dir: &str, gov: &Value, c: &Value) -> Value {
    let admitted = candidate_admitted(data_dir, c);
    let mut c = c.clone();
    c["blocked_reasons"] = json!(derive_blocked_reasons(gov, admitted));
    c["publishable"] = json!(false); // never publishable in this plane
    c
}

pub(crate) async fn handle_candidate_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let gov = governance_snapshot(&st.base_url).await;
    let mut items: Vec<Value> = read_record_dir(&st.data_dir, KIND_CANDIDATE)
        .iter()
        .map(|c| candidate_view(&st.data_dir, &gov, c))
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
    let gov_now = governance_snapshot(&st.base_url).await;
    (StatusCode::CREATED, Json(json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &gov_now, &record) })))
}

pub(crate) async fn handle_candidate_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_CANDIDATE, &id) {
        Some(c) => {
            let gov = governance_snapshot(&st.base_url).await;
            Json(json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &gov, &c) }))
        }
        None => Json(json!({ "ok": false, "reason": "publish candidate not found" })),
    }
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
    fn blocked_reasons_always_includes_runtime_backing_and_publish_is_impossible() {
        // Clean governance + admitted review: still blocked structurally.
        let gov = json!({ "governance_gaps": 0, "auth_enforced": true });
        let r = derive_blocked_reasons(&gov, true);
        assert!(r.contains(&"admission_only_until_runtime_backing".to_string()));
        assert!(!r.contains(&"no_admitted_admission_review".to_string()));
        assert!(!r.contains(&"governance_gaps_present".to_string()));
        assert!(!r.contains(&"auth_not_enforced".to_string()));
        // Even in the best case there is at least the structural reason -> never publishable.
        assert!(!r.is_empty());
    }

    #[test]
    fn blocked_reasons_accumulate_when_gates_fail() {
        let gov = json!({ "governance_gaps": 6, "auth_enforced": false });
        let r = derive_blocked_reasons(&gov, false);
        assert!(r.contains(&"no_admitted_admission_review".to_string()));
        assert!(r.contains(&"governance_gaps_present".to_string()));
        assert!(r.contains(&"auth_not_enforced".to_string()));
        assert!(r.contains(&"admission_only_until_runtime_backing".to_string()));
        assert_eq!(r.len(), 4);
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
