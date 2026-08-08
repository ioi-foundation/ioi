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

use agentgres::event_stream::AdmissionRefusal;

use super::mutation_event_foundation::{
    admit_owner_scoped_write, admitted_history_for_caller, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key, replay_stable_id, require_write_caller, MutationCommit,
    MutationRefusal, WriteCaller,
};
use super::{iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, DaemonState};

/// One owner namespace for the whole marketplace plane, so a listing, its candidate, its review and
/// its offer cannot be advanced from different tenants.
const MARKETPLACE_NAMESPACE: &str = "hypervisor-marketplace";

fn admitted_head_of(record: &Value) -> Option<String> {
    record
        .get("admitted_head")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// The head a successor must present. A record written before this plane bound identity has none,
/// and is refused rather than advanced blind — silently accepting would reintroduce the lost-update
/// this contract exists to stop.
fn require_head(record: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    admitted_head_of(record).ok_or_else(|| {
        bad(
            "marketplace_expected_head_required",
            "this record predates admitted mutation; it cannot be advanced without a head",
        )
    })
}

/// Strip the stream's own fact back out before admitting: leaving it in makes every successor
/// byte-different from its own replay, which defeats the idempotency key.
fn without_admitted_head(record: &Value) -> Value {
    let mut copy = record.clone();
    if let Some(map) = copy.as_object_mut() {
        map.remove("admitted_head");
    }
    copy
}

/// Strip wall-clock before admitting. A payload carrying `iso_now()` is byte-different on every
/// retry, so the same key admits different bytes and the retry is refused instead of replayed —
/// which makes the idempotency contract look present while doing nothing.
fn without_clock(record: &Value) -> Value {
    let mut copy = without_admitted_head(record);
    if let Some(map) = copy.as_object_mut() {
        map.remove("created_at");
        map.remove("updated_at");
    }
    copy
}

/// Stamp a created record from its own admission rather than the clock.
fn project_created(record: &mut Value, commit: &MutationCommit) {
    let stamp = admitted_stamp(commit.projection.operation.recorded_at_ms);
    record["created_at"] = json!(stamp);
    project_admission(record, commit);
}

fn project_admission(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(admitted_stamp(commit.projection.operation.recorded_at_ms));
}

/// Persist a projection whose transition is already admitted. A discarded write here is what let
/// this plane return success over state no later read would find.
fn project_or_fail(
    data_dir: &str,
    kind: &str,
    id: &str,
    record: &Value,
    code: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": { "code": code,
                "message": "the transition is admitted but its projection could not be written; replay to reconcile" } })),
        )
    })
}

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
fn histogram(items: &[Value], key: &str) -> HashMap<String, i64> {
    let mut h = HashMap::new();
    for it in items {
        let k = it
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *h.entry(k).or_insert(0) += 1;
    }
    h
}
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
                .map(|a| {
                    a.iter()
                        .any(|x| x.get("id").and_then(|v| v.as_str()) == Some(subject_ref))
                })
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
        "domain_app" => resolve_scheme_ref(
            data_dir,
            subject_ref,
            "domain-app",
            "domain-apps",
            "domain_app subject_ref",
        ),
        "ontology_pack" => resolve_scheme_ref(
            data_dir,
            subject_ref,
            "odk",
            "odk-manifests",
            "ontology_pack subject_ref",
        ),
        "data_recipe" => resolve_scheme_ref(
            data_dir,
            subject_ref,
            "recipe",
            "odk-data-recipes",
            "data_recipe subject_ref",
        ),
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
fn publish_reasons(
    kind: &str,
    dapp_ok: bool,
    has_admitted: bool,
    has_open_release: bool,
    has_serving: bool,
) -> Vec<String> {
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
    let cand_ref = candidate
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let listing_ref = candidate
        .get("listing_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let listing = match split_ref(listing_ref) {
        Some(("marketplace-listing", id)) => load(data_dir, KIND_LISTING, id),
        _ => None,
    };
    let Some(listing) = listing else {
        b.reasons.push("listing_unresolved".to_string());
        return b;
    };
    b.listing_id = listing
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let kind = listing
        .get("listing_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let subject = listing
        .get("subject_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    b.subject_ref = subject.clone();
    // domain app resolves?
    let dapp_ok = match split_ref(&subject) {
        Some(("domain-app", id)) => load(data_dir, KIND_DOMAIN_APP, id).is_some(),
        _ => false,
    };
    // admitted review for this candidate?
    if let Some(rv) = read_record_dir(data_dir, KIND_REVIEW)
        .into_iter()
        .find(|r| {
            r.get("candidate_ref").and_then(|v| v.as_str()) == Some(cand_ref.as_str())
                && r.get("decision").and_then(|v| v.as_str()) == Some("admitted")
        })
    {
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
    if let Some(rt) = read_record_dir(data_dir, KIND_RUNTIME)
        .into_iter()
        .find(|rt| {
            rt.get("domain_app_ref").and_then(|v| v.as_str()) == Some(subject.as_str())
                && rt.get("mounted").and_then(|v| v.as_bool()) == Some(true)
                && rt.get("serving").and_then(|v| v.as_bool()) == Some(true)
                && rt
                    .get("internal_route_ref")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
        })
    {
        b.runtime_route = rt
            .get("internal_route_ref")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        b.runtime_ref = rt.get("ref").and_then(|v| v.as_str()).map(str::to_string);
    }
    b.reasons = publish_reasons(
        kind,
        dapp_ok,
        b.admission_review_ref.is_some(),
        b.release_control_ref.is_some(),
        b.runtime_ref.is_some(),
    );
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
    recent.sort_by(|a, b| {
        b["updated_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["updated_at"].as_str().unwrap_or(""))
    });
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
    if let Some(k) = q
        .get("listing_kind")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|l| l.get("listing_kind").and_then(|v| v.as_str()) == Some(k));
    }
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "listings": items }))
}

/// POST /v1/hypervisor/marketplace/listings — draft a listing over REAL substrate.
pub(crate) async fn handle_listing_create(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity first, before any field of the body is read.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let listing_kind = str_field(&body, "listing_kind");
    if !LISTING_KINDS.contains(&listing_kind) {
        return bad(
            "marketplace_listing_kind_invalid",
            &format!("listing_kind must be one of {LISTING_KINDS:?}"),
        );
    }
    let subject_ref = str_field(&body, "subject_ref");
    if subject_ref.is_empty() {
        return bad(
            "marketplace_subject_required",
            "A listing must declare a subject_ref.",
        );
    }
    if let Err((c, m)) =
        resolve_listing_subject(&st.data_dir, &st.base_url, listing_kind, subject_ref).await
    {
        return bad(&c, &m);
    }
    if let Err((c, m)) = check_evidence_refs(&st.data_dir, &str_refs(&body, "evidence_refs")) {
        return bad(&c, &m);
    }
    // Content-derived, not clock-derived: a retried create must resolve to one resource.
    let id = replay_stable_id("mlist", &caller.owner_ref, &caller.idempotency_key);
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
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_LISTING,
        &format!("marketplace-listing://{id}"),
        "marketplace.listing.create",
        None,
        &without_clock(&record),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut record = record;
    project_created(&mut record, &commit);
    if let Err(response) = project_or_fail(
        &st.data_dir,
        KIND_LISTING,
        &id,
        &record,
        "marketplace_listing_persistence_failed",
    ) {
        return response;
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({ "ok": true, "replayed": commit.replayed, "listing": record })),
    )
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
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(mut l) = load(&st.data_dir, KIND_LISTING, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "listing not found" })),
        );
    };
    // If listing_kind or subject_ref changes, re-validate against real substrate.
    let new_kind = body
        .get("listing_kind")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| l.get("listing_kind").and_then(|v| v.as_str()).unwrap_or(""));
    if body.get("listing_kind").is_some() && !LISTING_KINDS.contains(&new_kind) {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "marketplace_listing_kind_invalid", "message": format!("listing_kind must be one of {LISTING_KINDS:?}") } }),
            ),
        );
    }
    if body.get("listing_kind").is_some() || body.get("subject_ref").is_some() {
        let subj = body
            .get("subject_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or_else(|| l.get("subject_ref").and_then(|v| v.as_str()).unwrap_or(""));
        if let Err((c, m)) =
            resolve_listing_subject(&st.data_dir, &st.base_url, new_kind, subj).await
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": { "code": c, "message": m } })),
            );
        }
    }
    if body.get("evidence_refs").is_some() {
        if let Err((c, m)) = check_evidence_refs(&st.data_dir, &str_refs(&body, "evidence_refs")) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": { "code": c, "message": m } })),
            );
        }
    }
    for key in [
        "name",
        "description",
        "listing_kind",
        "subject_ref",
        "evidence_refs",
    ] {
        if let Some(v) = body.get(key) {
            l[key] = v.clone();
        }
    }
    let expected_head = match require_head(&l) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_LISTING,
        &format!("marketplace-listing://{id}"),
        "marketplace.listing.patch",
        Some(&expected_head),
        &without_clock(&l),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    project_admission(&mut l, &commit);
    if let Err(response) = project_or_fail(
        &st.data_dir,
        KIND_LISTING,
        &id,
        &l,
        "marketplace_listing_persistence_failed",
    ) {
        return response;
    }
    (StatusCode::OK, Json(json!({ "ok": true, "listing": l })))
}

pub(crate) async fn handle_listing_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    // Optional so a DELETE with no body answers the typed refusal rather than a bare 415.
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(existing) = load(&st.data_dir, KIND_LISTING, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "error": { "code": "marketplace_listing_not_found", "message": "listing not found" } }),
            ),
        );
    };
    // Deletion is a transition. Dropping the projection without admitting a terminal event leaves
    // the stream asserting the record still exists.
    let expected_head = match require_head(&existing) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_LISTING,
        &format!("marketplace-listing://{id}"),
        "marketplace.listing.delete",
        Some(&expected_head),
        &json!({ "id": id, "deleted": true }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if !remove_record(&st.data_dir, KIND_LISTING, &id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "marketplace_listing_projection_removal_failed",
                "message": "the delete is admitted but its projection could not be removed; replay to reconcile"
            }, "admitted_head": commit.projection.head })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "removed": true, "replayed": commit.replayed, "id": id })),
    )
}

// ============================ PUBLISH CANDIDATE ================================================

fn candidate_view(data_dir: &str, c: &Value) -> Value {
    let published = c.get("publish_state").and_then(|v| v.as_str()) == Some("published");
    let b = publish_gates(data_dir, c);
    let mut c = c.clone();
    c["blocked_reasons"] = if published {
        json!([])
    } else {
        json!(b.reasons)
    };
    // Publishable only under the sharpened invariant (admitted review + open release + serving runtime).
    c["publishable"] = json!(!published && b.reasons.is_empty());
    c
}

pub(crate) async fn handle_candidate_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items: Vec<Value> = read_record_dir(&st.data_dir, KIND_CANDIDATE)
        .iter()
        .map(|c| candidate_view(&st.data_dir, c))
        .collect();
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "publish_candidates": items }))
}

/// POST /v1/hypervisor/marketplace/publish-candidates — nominate a listing (candidate, NOT publish).
pub(crate) async fn handle_candidate_create(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity first, before any field of the body is read.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let listing_ref = str_field(&body, "listing_ref");
    if listing_ref.is_empty() {
        return bad(
            "marketplace_listing_ref_required",
            "A publish candidate must declare a listing_ref.",
        );
    }
    if let Err((c, m)) = resolve_scheme_ref(
        &st.data_dir,
        listing_ref,
        "marketplace-listing",
        KIND_LISTING,
        "listing_ref",
    ) {
        return bad(&c, &m);
    }
    let gov = governance_snapshot(&st.base_url).await;
    // Content-derived, not clock-derived: a retried create must resolve to one resource.
    let id = replay_stable_id("mpub", &caller.owner_ref, &caller.idempotency_key);
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
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_CANDIDATE,
        &format!("marketplace-publish-candidate://{id}"),
        "marketplace.candidate.create",
        None,
        &without_clock(&record),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut record = record;
    project_created(&mut record, &commit);
    if let Err(response) = project_or_fail(
        &st.data_dir,
        KIND_CANDIDATE,
        &id,
        &record,
        "marketplace_candidate_persistence_failed",
    ) {
        return response;
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(
            json!({ "ok": true, "replayed": commit.replayed, "publish_candidate": candidate_view(&st.data_dir, &record) }),
        ),
    )
}

pub(crate) async fn handle_candidate_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, KIND_CANDIDATE, &id) {
        Some(c) => {
            Json(json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &c) }))
        }
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
    headers: axum::http::HeaderMap,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    // Publishing makes a listing publicly discoverable. It took no headers at all.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(mut candidate) = load(&st.data_dir, KIND_CANDIDATE, &id) else {
        return bad(
            "marketplace_candidate_not_found",
            "publish candidate not found",
        );
    };
    if candidate.get("publish_state").and_then(|v| v.as_str()) == Some("published") {
        return bad(
            "marketplace_already_published",
            "this candidate is already published",
        );
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
    let cand_ref = candidate
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // Publish receipt (real proof: sha256 state_root over the backing tuple).
    // Content-derived: a retried publish must reuse its receipt, not mint a second one for the
    // same admitted transition.
    let prid = replay_stable_id("pubr", &caller.owner_ref, &caller.idempotency_key);
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
    let receipt_ref = format!("marketplace-publish-receipt://{prid}");
    // The listing is not optional. This was `if let Some(listing)`, so a candidate whose listing had
    // been deleted still answered 201 with publish_state "published" while nothing was publicly
    // listed — the two halves of one publish disagreeing, with no error anywhere.
    let Some(mut listing) = load(&st.data_dir, KIND_LISTING, &b.listing_id) else {
        return bad(
            "marketplace_publish_listing_missing",
            "the candidate's listing no longer resolves; publish cannot flip a listing that is gone",
        );
    };
    candidate["publish_state"] = json!("published");
    candidate["published_runtime_ref"] = json!(published_runtime_ref);
    candidate["release_control_ref"] = json!(release_control_ref);
    candidate["admission_review_ref"] = json!(admission_review_ref);
    candidate["publish_receipt_refs"] = json!([receipt_ref]);
    candidate["state_root"] = json!(format!("sha256:{state_root}"));
    listing["public_state"] = json!("published");
    listing["published_runtime_ref"] = json!(published_runtime_ref);
    listing["release_control_ref"] = json!(release_control_ref);
    listing["admission_review_ref"] = json!(admission_review_ref);
    listing["publish_receipt_refs"] = json!([receipt_ref.clone()]);

    // Publish is ONE transition over three records. It was three discarded writes: a failed receipt
    // write still left the candidate claiming a receipt_ref no read could resolve, and a failed
    // candidate write still left the listing public. Admitting the whole tuple first makes the
    // published state recoverable rather than torn.
    let expected_head = match require_head(&candidate) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_CANDIDATE,
        &format!("marketplace-publish-candidate://{id}"),
        "marketplace.candidate.publish",
        Some(&expected_head),
        &json!({
            "receipt": receipt,
            "candidate": without_clock(&candidate),
            "listing": without_clock(&listing)
        }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let published_at = admitted_stamp(commit.projection.operation.recorded_at_ms);
    candidate["published_at"] = json!(published_at);
    listing["published_at"] = json!(published_at);
    project_admission(&mut candidate, &commit);
    project_admission(&mut listing, &commit);
    for (kind, key, record, code) in [
        (
            KIND_PUBLISH_RECEIPT,
            prid.as_str(),
            &receipt,
            "marketplace_publish_receipt_persistence_failed",
        ),
        (
            KIND_CANDIDATE,
            id.as_str(),
            &candidate,
            "marketplace_candidate_persistence_failed",
        ),
        (
            KIND_LISTING,
            b.listing_id.as_str(),
            &listing,
            "marketplace_listing_persistence_failed",
        ),
    ] {
        if let Err(response) = project_or_fail(&st.data_dir, kind, key, record, code) {
            return response;
        }
    }
    (
        StatusCode::CREATED,
        Json(
            json!({ "ok": true, "publish_candidate": candidate_view(&st.data_dir, &candidate), "receipt": receipt }),
        ),
    )
}

pub(crate) async fn handle_candidate_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    // Optional so a DELETE with no body answers the typed refusal rather than a bare 415.
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(existing) = load(&st.data_dir, KIND_CANDIDATE, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "error": { "code": "marketplace_candidate_not_found", "message": "candidate not found" } }),
            ),
        );
    };
    // Deletion is a transition. Dropping the projection without admitting a terminal event leaves
    // the stream asserting the record still exists.
    let expected_head = match require_head(&existing) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_CANDIDATE,
        &format!("marketplace-publish-candidate://{id}"),
        "marketplace.candidate.delete",
        Some(&expected_head),
        &json!({ "id": id, "deleted": true }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if !remove_record(&st.data_dir, KIND_CANDIDATE, &id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "marketplace_candidate_projection_removal_failed",
                "message": "the delete is admitted but its projection could not be removed; replay to reconcile"
            }, "admitted_head": commit.projection.head })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "removed": true, "replayed": commit.replayed, "id": id })),
    )
}

// ============================ ADMISSION REVIEW ================================================

/// Link/unlink an admission review onto its candidate (transactional, best-effort).
/// Link or unlink a candidate's admission review.
///
/// This swallowed every failure — malformed ref, missing candidate, failed write — and returned
/// unit. `publish_gates` reads `admission_review_ref`, so a silent failure here decides publish
/// eligibility from a backlink that was never written.
fn link_candidate_review(
    data_dir: &str,
    candidate_ref: &str,
    review_ref: Option<&str>,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some((_, cid)) = split_ref(candidate_ref) else {
        return Err(bad(
            "marketplace_candidate_ref_invalid",
            "candidate_ref is not a resolvable 'marketplace-publish-candidate://' ref",
        ));
    };
    let Some(mut c) = load(data_dir, KIND_CANDIDATE, cid) else {
        return Err(bad(
            "marketplace_candidate_not_found",
            "candidate_ref does not resolve to a candidate",
        ));
    };
    c["admission_review_ref"] = match review_ref {
        Some(r) => json!(r),
        None => Value::Null,
    };
    c["updated_at"] = json!(iso_now());
    project_or_fail(
        data_dir,
        KIND_CANDIDATE,
        cid,
        &c,
        "marketplace_candidate_backlink_persistence_failed",
    )
}

pub(crate) async fn handle_review_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_REVIEW);
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "admission_reviews": items }))
}

// ---- reviewer attribution (P-MKT-ATTR-1) -------------------------------------------------------
//
// An admission review's `reviewer_ref` is WHO REVIEWED, and an admitted review is a publish gate:
// `publish_reasons` reads it back as `no_admitted_admission_review`. Attribution a client chooses is
// not attribution at all. Canon (`identity-access-and-metering.md`) is flat about it — "Request
// bodies never select the acting principal, owner, role, or authority."
//
// Both handlers already resolve the acting principal (`require_write_caller`) and every admitted
// mutation is fingerprinted and scope-bound to it, so the record was the ONLY place a different name
// could survive: event truth said one principal, the projection a later read treats as proof said
// another. Two rules close that, both fail-closed:
//
//   1. A body carrying `reviewer_ref` is REFUSED, never ignored. Silently dropping it would let a
//      caller believe it had attributed the review while the record said otherwise, and any surface
//      sending one would go on lying instead of being fixed.
//   2. The reviewer written is `caller.identity.principal_ref`, set into the SAME bytes that are
//      admitted, so the event payload and the projection name one principal by construction.
//
// NONCLAIM: this packet closes ATTRIBUTION only. WHO MAY review an admission review still has no
// canonical role/authority owner, so nothing here decides that — any principal authorized for the
// owner tenant may still create and advance a review, exactly as before.

/// Refuse a body that names who reviewed. Refuses on the KEY BEING PRESENT, not on its value, so
/// `null`, `""`, and a value that happens to match the caller are refused alike: "accept it when it
/// matches" would make the gate depend on the very identity the request is trying to assert.
///
/// `reviewer_ref` is the only name checked, and deliberately so. It is the one attribution field
/// this plane writes; refusing invented spellings would refuse fields nothing here persists, and the
/// record is built key-by-key so no other body field can reach it. If this record ever gains a
/// second actor field, that field belongs in this gate on the same day.
fn reject_client_supplied_reviewer(body: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    if body.get("reviewer_ref").is_none() {
        return Ok(());
    }
    Err(bad(
        "marketplace_reviewer_ref_not_client_settable",
        "'reviewer_ref' is derived from the authenticated caller and cannot be supplied by the \
         request; remove it and re-send",
    ))
}

/// POST /v1/hypervisor/marketplace/admission-reviews — review a candidate. `admitted` != `published`.
pub(crate) async fn handle_review_create(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity first, before any field of the body is read.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // ORDER IS THE FIX. Everything decidable from the request is decided — and a retry is answered
    // from admitted truth — BEFORE the posture read below. `governance_snapshot` reads live gate
    // state and stamps its own wall clock, so a retry that re-derived it presented different bytes
    // under the same idempotency key and was refused 409 instead of replaying.
    match begin_admission_review_create(&st.data_dir, &caller, &body) {
        ReviewCreateStep::Answered(response) => response,
        ReviewCreateStep::Fresh(command) => {
            let gov = governance_snapshot(&st.base_url).await;
            finish_admission_review_create(&st.data_dir, &caller, &command, gov)
        }
    }
}

/// What a create still owes after everything decidable without the server's posture read.
enum ReviewCreateStep {
    /// Refused, or replayed from the fact this caller's key already admitted. Either way the
    /// posture read is not owed: it would only be discarded.
    Answered((StatusCode, Json<Value>)),
    /// A command with no prior admission. The caller supplies the posture and finishes it.
    Fresh(Value),
}

/// The stable half of an admission-review create: everything this command decides from the request
/// and its authenticated caller, and nothing a server derives on its behalf.
///
/// Two submissions are the SAME COMMAND exactly when this value is equal. The governance posture
/// snapshot and the two clocks are deliberately outside it: they are read from live state at create
/// time, so a retry cannot reproduce them, and treating them as identity made every retry a
/// different command. They are still written and still admitted — posture at review time is
/// evidence — they are simply not what makes a command itself.
fn admission_review_command(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    // A body may not name who reviewed. Refused here — before the candidate is resolved, before any
    // event is admitted, before any projection or candidate backlink is written, and before the
    // replay probe below can answer anything — so a forged create leaves nothing to reconcile and a
    // forged RETRY is refused rather than served from the original's success.
    reject_client_supplied_reviewer(body)?;
    let candidate_ref = str_field(body, "candidate_ref");
    if candidate_ref.is_empty() {
        return Err(bad(
            "marketplace_candidate_ref_required",
            "An admission review must declare a candidate_ref.",
        ));
    }
    if let Err((c, m)) = resolve_scheme_ref(
        data_dir,
        candidate_ref,
        "marketplace-publish",
        KIND_CANDIDATE,
        "candidate_ref",
    ) {
        return Err(bad(&c, &m));
    }
    let decision = body
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("pending");
    if !ADMISSION_DECISIONS.contains(&decision) {
        return Err(bad(
            "marketplace_decision_invalid",
            &format!("decision must be one of {ADMISSION_DECISIONS:?}"),
        ));
    }
    // Content-derived, not clock-derived: a retried create must resolve to one resource.
    let id = replay_stable_id("madm", &caller.owner_ref, &caller.idempotency_key);
    Ok(json!({
        "schema_version": "ioi.hypervisor.marketplace-admission-review.v1",
        "object": "ioi.hypervisor.marketplace_admission_review",
        "id": id,
        "ref": format!("marketplace-admission://{id}"),
        "candidate_ref": candidate_ref,
        "status": "draft",
        "decision": decision,
        // Explicit: admission is a gate review, not a publish. Nothing goes live from here.
        "admits_but_not_publishes": true,
        // THE reviewer: the server-resolved principal this write is admitted as. It rides the
        // command, so the admitted event and the projection carry one identical name.
        "reviewer_ref": caller.identity.principal_ref,
        "findings": str_refs(body, "findings")
    }))
}

/// The stable command an admitted create payload carries, with the server-derived posture removed.
/// One definition, used on both sides of the replay comparison, so what counts as "the same command"
/// cannot drift from what `admission_review_command` actually writes.
fn command_without_posture(payload: &Value) -> Value {
    let mut copy = payload.clone();
    if let Some(map) = copy.as_object_mut() {
        map.remove("governance_posture_snapshot");
    }
    copy
}

/// Decide a create as far as the request alone allows: refuse it, replay it from admitted truth, or
/// hand back the command that still needs a posture read.
fn begin_admission_review_create(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> ReviewCreateStep {
    let command = match admission_review_command(data_dir, caller, body) {
        Ok(command) => command,
        Err(response) => return ReviewCreateStep::Answered(response),
    };
    match replay_created_admission_review(data_dir, caller, &command) {
        Err(response) => ReviewCreateStep::Answered(response),
        Ok(Some(response)) => ReviewCreateStep::Answered(response),
        Ok(None) => ReviewCreateStep::Fresh(command),
    }
}

/// Answer a create from the fact this caller's key already admitted, if there is one.
///
/// `Ok(None)` means nothing was admitted under this key and the create proceeds unchanged.
fn replay_created_admission_review(
    data_dir: &str,
    caller: &WriteCaller,
    command: &Value,
) -> Result<Option<(StatusCode, Json<Value>)>, (StatusCode, Json<Value>)> {
    let id = str_field(command, "id").to_string();
    let history = admitted_history_for_caller(
        data_dir,
        caller,
        MARKETPLACE_NAMESPACE,
        KIND_REVIEW,
        &format!("marketplace-admission-review://{id}"),
    )?;
    let Some(prior) = history
        .iter()
        .find(|entry| entry.operation.idem_key == caller.idempotency_key)
    else {
        return Ok(None);
    };
    if prior.operation.op_kind != "marketplace.review.create" {
        // This key's prior fact is some other operation on this stream. Leave it to
        // `admit_owner_scoped_write`, which produces the substrate's own refusal exactly as today.
        return Ok(None);
    }
    if command_without_posture(&prior.operation.payload) != *command {
        // Same key, genuinely different command. Excluding the posture from replay identity must
        // not become permission to replay a stale success for a command the caller changed, so this
        // answers with the substrate's own refusal — same status, same code, same message.
        return Err(mutation_refusal_reply(MutationRefusal::Admission(
            AdmissionRefusal::SameKeyDifferentBytes {
                idem_key: caller.idempotency_key.clone(),
            },
        )));
    }
    // TERMINAL-TRUTH FENCE, and it runs before ANY write on this path.
    //
    // A delete admitted after this create is the stream's last word on whether the resource exists.
    // Replaying the create over it would rebuild the projection and re-link the candidate — an
    // admitted removal undone by a retry of the command that preceded it. The old moved-posture
    // 409 hid this: the retry never reached the substrate's replay, so the repair was unreachable.
    // Reading the history early makes it reachable, so the fence lands with it rather than after it.
    //
    // This is the same rule the delete path now applies from the other side: an admitted terminal
    // transition decides existence, and no earlier fact may be replayed over it. Refused rather than
    // answered 200 with the created record: that record is gone, and `removed:true` is what the
    // delete's own key already replays. A new review needs a new key, which mints a new resource.
    if let Some(terminal) = history.iter().find(|entry| {
        entry.seq > prior.seq && entry.operation.op_kind == "marketplace.review.delete"
    }) {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "error": {
                "code": "marketplace_review_removed",
                "message": "this idempotency key's review was admitted and has since been deleted; \
                            replaying the create would undo an admitted removal — use a new \
                            idempotency_key to review this candidate again"
            }, "admitted_head": terminal.head })),
        ));
    }
    // The CURRENT projection when there is one. This is the resource the command created, and
    // anything since is a later admitted fact — a patched decision above all. Re-projecting
    // create-time bytes here would silently undo that patch, which is precisely what a replay must
    // be incapable of.
    let record = match load(data_dir, KIND_REVIEW, &id) {
        Some(record) => record,
        None => {
            // Admitted with no projection: the original create's projection write failed, or the
            // read model was lost. Rebuild from the admitted payload and this operation's OWN stamp
            // — never a clock — and fail closed if the repair cannot be written.
            let mut repaired = prior.operation.payload.clone();
            let stamp = admitted_stamp(prior.operation.recorded_at_ms);
            repaired["created_at"] = json!(stamp);
            repaired["updated_at"] = json!(stamp);
            repaired["admitted_head"] = json!(prior.head);
            project_or_fail(
                data_dir,
                KIND_REVIEW,
                &id,
                &repaired,
                "marketplace_review_persistence_failed",
            )?;
            repaired
        }
    };
    // The candidate backlink is fail-closed here for the same reason it is on the first attempt:
    // publish gating reads `admission_review_ref`, so answering 200 over a backlink that was never
    // written would report a gate this review does not hold.
    link_candidate_review(
        data_dir,
        str_field(command, "candidate_ref"),
        Some(&format!("marketplace-admission://{id}")),
    )?;
    Ok(Some((
        StatusCode::OK,
        Json(json!({ "ok": true, "replayed": true, "admission_review": record })),
    )))
}

/// Admit and project a create whose command has no prior admission. The governance posture arrives
/// as a value because it is the handler's only await; the reviewer arrives only inside `caller`, so
/// there is no argument shape a request body could occupy.
fn finish_admission_review_create(
    data_dir: &str,
    caller: &WriteCaller,
    command: &Value,
    gov: Value,
) -> (StatusCode, Json<Value>) {
    let id = str_field(command, "id").to_string();
    let now = iso_now();
    let mut record = command.clone();
    record["governance_posture_snapshot"] = gov;
    record["created_at"] = json!(now);
    record["updated_at"] = json!(now);
    let commit = match admit_owner_scoped_write(
        data_dir,
        caller,
        MARKETPLACE_NAMESPACE,
        KIND_REVIEW,
        &format!("marketplace-admission-review://{id}"),
        "marketplace.review.create",
        None,
        &without_clock(&record),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    project_created(&mut record, &commit);
    if let Err(response) = project_or_fail(
        data_dir,
        KIND_REVIEW,
        &id,
        &record,
        "marketplace_review_persistence_failed",
    ) {
        return response;
    }
    // Link the review onto its candidate so blocked_reasons can reflect an admitted review. This
    // must not be best-effort: a review the candidate never learns about is a review that cannot
    // gate publish, and reporting 201 would say the opposite.
    if let Err(response) = link_candidate_review(
        data_dir,
        str_field(command, "candidate_ref"),
        Some(&format!("marketplace-admission://{id}")),
    ) {
        return response;
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({ "ok": true, "replayed": commit.replayed, "admission_review": record })),
    )
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
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    patch_admission_review(&st.data_dir, &id, &caller, &body)
}

/// Everything a patch decides once its caller is authenticated. Same split, and the same reason, as
/// `create_admission_review`.
fn patch_admission_review(
    data_dir: &str,
    id: &str,
    caller: &WriteCaller,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    // Before the record is even LOADED. A forged patch must be refused identically whether or not
    // the id exists: answering 400 for a real review and 404 for an invented one would turn this
    // refusal into an existence oracle for another tenant's records. A patch that names no reviewer
    // still reaches the load below and still answers the auth-before-load 404.
    if let Err(response) = reject_client_supplied_reviewer(body) {
        return response;
    }
    let Some(mut r) = load(data_dir, KIND_REVIEW, id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "admission review not found" })),
        );
    };
    if let Some(d) = body.get("decision").and_then(|v| v.as_str()) {
        if !ADMISSION_DECISIONS.contains(&d) {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": { "code": "marketplace_decision_invalid", "message": format!("decision must be one of {ADMISSION_DECISIONS:?}") } }),
                ),
            );
        }
    }
    for key in ["decision", "findings"] {
        if let Some(v) = body.get(key) {
            r[key] = v.clone();
        }
    }
    // Attribution is rewritten from the caller on EVERY admitted patch, not merged from the stored
    // record. Whoever advanced this review is its reviewer of record for the state that results, so
    // a stale name — including one a pre-cut body planted — is overwritten rather than inherited.
    // This lands BEFORE the payload is hashed below, so the event and the projection agree.
    r["reviewer_ref"] = json!(caller.identity.principal_ref);
    let expected_head = match require_head(&r) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        data_dir,
        caller,
        MARKETPLACE_NAMESPACE,
        KIND_REVIEW,
        &format!("marketplace-admission-review://{id}"),
        "marketplace.review.patch",
        Some(&expected_head),
        &without_clock(&r),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    project_admission(&mut r, &commit);
    if let Err(response) = project_or_fail(
        data_dir,
        KIND_REVIEW,
        id,
        &r,
        "marketplace_review_persistence_failed",
    ) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "admission_review": r })),
    )
}

pub(crate) async fn handle_review_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    // Optional so a DELETE with no body answers the typed refusal rather than a bare 415.
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    delete_admission_review(&st.data_dir, &id, &caller)
}

/// Everything a delete decides once its caller is authenticated. Split out of the handler, and
/// taking the already-resolved `caller`, for the same reason as create and patch: the replay
/// contract is exercised against THE code the route runs, not a re-stated copy of it.
fn delete_admission_review(
    data_dir: &str,
    id: &str,
    caller: &WriteCaller,
) -> (StatusCode, Json<Value>) {
    let Some(existing) = load(data_dir, KIND_REVIEW, id) else {
        // An absent projection is not proof this record never existed — the first attempt of THIS
        // command is what removed it. The substrate's replay scan would have matched, since the
        // delete payload carries no clock and `expected_head` is normalized out of replay identity,
        // but the old 404 returned before admission was ever reached, so the scan never ran. Ask the
        // admitted history first, and only then answer that there was nothing to delete.
        return match prior_admission_for_key(
            data_dir,
            caller,
            MARKETPLACE_NAMESPACE,
            KIND_REVIEW,
            &format!("marketplace-admission-review://{id}"),
        ) {
            Err(response) => response,
            Ok(Some(prior)) if prior.operation.op_kind == "marketplace.review.delete" => (
                StatusCode::OK,
                Json(json!({ "ok": true, "removed": true, "replayed": true, "id": id })),
            ),
            // Never existed, another principal's id, or a key whose prior fact was a create: each
            // answers exactly what it answered before, byte for byte.
            Ok(_) => (
                StatusCode::NOT_FOUND,
                Json(
                    json!({ "ok": false, "error": { "code": "marketplace_review_not_found", "message": "review not found" } }),
                ),
            ),
        };
    };
    // Deletion is a transition. Dropping the projection without admitting a terminal event leaves
    // the stream asserting the record still exists.
    let expected_head = match require_head(&existing) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        data_dir,
        caller,
        MARKETPLACE_NAMESPACE,
        KIND_REVIEW,
        &format!("marketplace-admission-review://{id}"),
        "marketplace.review.delete",
        Some(&expected_head),
        &json!({ "id": id, "deleted": true }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    // The candidate backlink is part of this transition, not a side effect: publish gating reads
    // admission_review_ref, so a swallowed unlink leaves a candidate pointing at a deleted review.
    if let Some(candidate_ref) = existing.get("candidate_ref").and_then(|v| v.as_str()) {
        if let Err(response) = link_candidate_review(data_dir, candidate_ref, None) {
            return response;
        }
    }
    if !remove_record(data_dir, KIND_REVIEW, id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "marketplace_review_projection_removal_failed",
                "message": "the delete is admitted but its projection could not be removed; replay to reconcile"
            }, "admitted_head": commit.projection.head })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "removed": true, "replayed": commit.replayed, "id": id })),
    )
}

// ============================ MANAGED INSTANCE OFFER ==========================================

pub(crate) async fn handle_offer_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_OFFER);
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "managed_instance_offers": items }))
}

/// POST /v1/hypervisor/marketplace/instance-offers — a DRAFT offer over a real agent/domain-app.
/// It never instantiates: runtime_posture stays {instantiated:false}. No hire/install lifecycle.
pub(crate) async fn handle_offer_create(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity first, before any field of the body is read.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let offer_kind = str_field(&body, "offer_kind");
    if !OFFER_KINDS.contains(&offer_kind) {
        return bad(
            "marketplace_offer_kind_invalid",
            &format!("offer_kind must be one of {OFFER_KINDS:?}"),
        );
    }
    let subject_ref = str_field(&body, "subject_ref");
    if subject_ref.is_empty() {
        return bad(
            "marketplace_subject_required",
            "A managed instance offer must declare a subject_ref.",
        );
    }
    // agent -> real /v1/agents id; domain_app -> real domain-app:// ref.
    if let Err((c, m)) =
        resolve_listing_subject(&st.data_dir, &st.base_url, offer_kind, subject_ref).await
    {
        return bad(&c, &m);
    }
    let listing_ref = str_field(&body, "listing_ref");
    if !listing_ref.is_empty() {
        if let Err((c, m)) = resolve_scheme_ref(
            &st.data_dir,
            listing_ref,
            "marketplace-listing",
            KIND_LISTING,
            "listing_ref",
        ) {
            return bad(&c, &m);
        }
    }
    // Content-derived, not clock-derived: a retried create must resolve to one resource.
    let id = replay_stable_id("moffer", &caller.owner_ref, &caller.idempotency_key);
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
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_OFFER,
        &format!("marketplace-instance-offer://{id}"),
        "marketplace.offer.create",
        None,
        &without_clock(&record),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut record = record;
    project_created(&mut record, &commit);
    if let Err(response) = project_or_fail(
        &st.data_dir,
        KIND_OFFER,
        &id,
        &record,
        "marketplace_offer_persistence_failed",
    ) {
        return response;
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({ "ok": true, "replayed": commit.replayed, "managed_instance_offer": record })),
    )
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
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(mut o) = load(&st.data_dir, KIND_OFFER, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "managed instance offer not found" })),
        );
    };
    let new_kind = body
        .get("offer_kind")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| o.get("offer_kind").and_then(|v| v.as_str()).unwrap_or(""));
    if body.get("offer_kind").is_some() && !OFFER_KINDS.contains(&new_kind) {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "marketplace_offer_kind_invalid", "message": format!("offer_kind must be one of {OFFER_KINDS:?}") } }),
            ),
        );
    }
    if body.get("offer_kind").is_some() || body.get("subject_ref").is_some() {
        let subj = body
            .get("subject_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or_else(|| o.get("subject_ref").and_then(|v| v.as_str()).unwrap_or(""));
        if let Err((c, m)) =
            resolve_listing_subject(&st.data_dir, &st.base_url, new_kind, subj).await
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": { "code": c, "message": m } })),
            );
        }
    }
    for key in [
        "name",
        "description",
        "offer_kind",
        "subject_ref",
        "listing_ref",
    ] {
        if let Some(v) = body.get(key) {
            o[key] = v.clone();
        }
    }
    // runtime_posture is immutable here — never instantiated.
    o["runtime_posture"] = json!({ "instantiated": false, "note": "draft offer only; no managed instance is hired, installed, or instantiated" });
    let expected_head = match require_head(&o) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_OFFER,
        &format!("marketplace-instance-offer://{id}"),
        "marketplace.offer.patch",
        Some(&expected_head),
        &without_clock(&o),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    project_admission(&mut o, &commit);
    if let Err(response) = project_or_fail(
        &st.data_dir,
        KIND_OFFER,
        &id,
        &o,
        "marketplace_offer_persistence_failed",
    ) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "managed_instance_offer": o })),
    )
}

pub(crate) async fn handle_offer_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    // Optional so a DELETE with no body answers the typed refusal rather than a bare 415.
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(existing) = load(&st.data_dir, KIND_OFFER, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "error": { "code": "marketplace_offer_not_found", "message": "offer not found" } }),
            ),
        );
    };
    // Deletion is a transition. Dropping the projection without admitting a terminal event leaves
    // the stream asserting the record still exists.
    let expected_head = match require_head(&existing) {
        Ok(head) => head,
        Err(response) => return response,
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        MARKETPLACE_NAMESPACE,
        KIND_OFFER,
        &format!("marketplace-instance-offer://{id}"),
        "marketplace.offer.delete",
        Some(&expected_head),
        &json!({ "id": id, "deleted": true }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if !remove_record(&st.data_dir, KIND_OFFER, &id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "marketplace_offer_projection_removal_failed",
                "message": "the delete is admitted but its projection could not be removed; replay to reconcile"
            }, "admitted_head": commit.projection.head })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "removed": true, "replayed": commit.replayed, "id": id })),
    )
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
        assert!(publish_reasons("agent", true, true, true, true)
            .contains(&"listing_not_domain_app".to_string()));
        // each missing gate names itself.
        assert!(publish_reasons("domain_app", true, false, true, true)
            .contains(&"no_admitted_admission_review".to_string()));
        assert!(publish_reasons("domain_app", true, true, false, true)
            .contains(&"no_open_release_control".to_string()));
        assert!(publish_reasons("domain_app", true, true, true, false)
            .contains(&"no_serving_runtime".to_string()));
        assert!(publish_reasons("domain_app", false, true, true, true)
            .contains(&"domain_app_unresolved".to_string()));
        // all failing -> all reasons present.
        assert_eq!(
            publish_reasons("domain_app", false, false, false, false).len(),
            4
        );
    }

    #[test]
    fn split_ref_parses_marketplace_schemes() {
        assert_eq!(
            split_ref("marketplace-listing://mlist_1"),
            Some(("marketplace-listing", "mlist_1"))
        );
        assert_eq!(
            split_ref("marketplace-publish://mpub_1"),
            Some(("marketplace-publish", "mpub_1"))
        );
        assert_eq!(split_ref("agent_2a9cc2ed"), None);
    }

    #[test]
    fn histogram_groups() {
        let items = vec![
            json!({"listing_kind": "agent"}),
            json!({"listing_kind": "agent"}),
            json!({"listing_kind": "domain_app"}),
        ];
        let h = histogram(&items, "listing_kind");
        assert_eq!(h.get("agent"), Some(&2));
        assert_eq!(h.get("domain_app"), Some(&1));
    }

    // ---- P-MKT-ATTR-1: the reviewer is the authenticated caller, resolved server-side -----------
    //
    // These drive `create_admission_review` / `patch_admission_review` — the exact functions the
    // routes call once identity is admitted — against a real tempdir and the real Agentgres
    // admission chain, so "the event and the projection agree" is read back from durable truth
    // rather than asserted about source order.

    use super::super::mutation_event_foundation::stream_tail;
    use super::super::substrate_store::{
        read_event_stream_history, read_event_stream_operation, request_identity_for_test,
        reset_handle_for_test,
    };

    /// The server-derived principal the identity seam would return; the ONLY admissible reviewer.
    /// Shaped like `resolve_request_identity`'s output (`user://<principal_id>`).
    const REVIEWER_PRINCIPAL: &str = "user://reviewer-real";
    /// A reviewer identity a request might try to assert. Never admissible.
    const FORGED_PRINCIPAL: &str = "user://attacker-chosen";
    const TEST_OWNER: &str = "org://local";

    fn test_caller(principal_ref: &str, idempotency_key: &str) -> WriteCaller {
        WriteCaller {
            identity: request_identity_for_test(principal_ref, [TEST_OWNER.to_string()]),
            owner_ref: TEST_OWNER.to_string(),
            idempotency_key: idempotency_key.to_string(),
        }
    }

    /// The handler derives this from the governance overview on every call. Pinning it here is what
    /// lets a replay present byte-identical material — see `governance_snapshot_carries_wall_clock`.
    fn pinned_governance_snapshot() -> Value {
        json!({
            "auth_enforced": true,
            "governance_gaps": 0,
            "wallet_required_crossings": 0,
            "authority_grants_active": 0,
            "at": "2026-01-01T00:00:00Z"
        })
    }

    fn seed_candidate(data_dir: &str, id: &str) -> String {
        persist_record(
            data_dir,
            KIND_CANDIDATE,
            id,
            &json!({ "id": id, "ref": format!("marketplace-publish://{id}") }),
        )
        .unwrap();
        format!("marketplace-publish://{id}")
    }

    fn review_tail(id: &str) -> String {
        stream_tail(KIND_REVIEW, &format!("marketplace-admission-review://{id}"))
    }

    /// The payload of the review's CURRENT admitted event, read back from the durable log. This is
    /// "event truth"; `load(.., KIND_REVIEW, id)` is "projection truth". The defect this packet
    /// closes was the two disagreeing about who reviewed.
    fn admitted_event_payload(data_dir: &str, id: &str) -> Option<Value> {
        read_event_stream_operation(data_dir, MARKETPLACE_NAMESPACE, &review_tail(id))
            .expect("the marketplace stream is readable")
            .map(|exact| exact.operation.payload)
    }

    fn admitted_event_count(data_dir: &str, id: &str) -> usize {
        read_event_stream_history(data_dir, MARKETPLACE_NAMESPACE, &review_tail(id))
            .expect("the marketplace stream is readable")
            .len()
    }

    /// Every shape a forged attribution can take. The KEY BEING PRESENT is the refusal — `null`,
    /// `""`, a non-string, and a value that happens to match the real caller are all refused, so no
    /// shape slips through and the gate never depends on the identity being asserted.
    fn forged_reviewer_values() -> Vec<Value> {
        vec![
            json!(FORGED_PRINCIPAL),
            json!(REVIEWER_PRINCIPAL),
            Value::Null,
            json!(""),
            json!({ "id": "x" }),
        ]
    }

    #[test]
    fn a_body_that_names_no_reviewer_passes_the_gate() {
        // The gate refuses forgery ONLY; it must not break any legitimate create or patch body.
        for admissible in [
            json!({ "candidate_ref": "marketplace-publish://mpub_1", "decision": "admitted" }),
            json!({ "decision": "needs_changes", "findings": ["finding://a"] }),
            json!({}),
            // A near-miss key is a different field and must not be refused as if it were this one.
            json!({ "reviewer_refs": ["user://a"] }),
        ] {
            assert!(
                reject_client_supplied_reviewer(&admissible).is_ok(),
                "must pass the gate: {admissible}"
            );
        }
        for forged in forged_reviewer_values() {
            let (status, Json(reply)) =
                reject_client_supplied_reviewer(&json!({ "reviewer_ref": forged.clone() }))
                    .expect_err(&format!(
                        "a body carrying reviewer_ref must be refused: {forged}"
                    ));
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                reply["error"]["code"],
                json!("marketplace_reviewer_ref_not_client_settable")
            );
            assert!(
                reply["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("authenticated caller"),
                "the refusal says WHY so a caller can fix the request: {reply}"
            );
        }
    }

    #[test]
    fn forged_reviewer_refuses_a_create_before_any_admission_or_projection() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_forged_create");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-forged-1");
        let id = replay_stable_id("madm", &caller.owner_ref, &caller.idempotency_key);

        for forged in forged_reviewer_values() {
            let body = json!({
                "candidate_ref": candidate_ref,
                "decision": "admitted",
                "reviewer_ref": forged.clone()
            });
            let (status, Json(reply)) =
                create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a create naming its own reviewer must be refused: {forged}"
            );
            assert_eq!(
                reply["error"]["code"],
                json!("marketplace_reviewer_ref_not_client_settable")
            );
            assert_eq!(reply["ok"], json!(false));
        }

        // Refused BEFORE anything durable happened: no admitted event, no projection, and no
        // candidate backlink — so a forged create leaves nothing for a later read to trust.
        assert_eq!(
            admitted_event_count(data_dir, &id),
            0,
            "a refused create admitted an event"
        );
        assert!(
            load(data_dir, KIND_REVIEW, &id).is_none(),
            "a refused create projected a review"
        );
        assert!(read_record_dir(data_dir, KIND_REVIEW).is_empty());
        assert!(
            load(data_dir, KIND_CANDIDATE, "mpub_forged_create")
                .unwrap()
                .get("admission_review_ref")
                .is_none(),
            "a refused create linked a review onto the candidate"
        );
    }

    #[test]
    fn create_projects_the_server_principal_the_admitted_event_binds() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_ok");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-ok-1");

        let (status, Json(reply)) = create_admission_review(
            data_dir,
            &caller,
            &json!({ "candidate_ref": candidate_ref, "decision": "admitted" }),
            pinned_governance_snapshot(),
        );
        assert_eq!(status, StatusCode::CREATED);
        let id = reply["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Response, projection, and the admitted event's own payload name ONE principal, and it is
        // the caller the write was admitted as — never a body field, which is the whole defect.
        let projected = load(data_dir, KIND_REVIEW, &id).expect("the review is projected");
        let event = admitted_event_payload(data_dir, &id).expect("the create admitted an event");
        for (label, value) in [
            ("response", &reply["admission_review"]["reviewer_ref"]),
            ("projection", &projected["reviewer_ref"]),
            ("admitted event", &event["reviewer_ref"]),
        ] {
            assert_eq!(
                value,
                &json!(REVIEWER_PRINCIPAL),
                "{label} does not name the server-resolved principal"
            );
        }
        assert_eq!(
            projected["reviewer_ref"], event["reviewer_ref"],
            "projection truth and event truth disagree about who reviewed"
        );
        // The rest of the create is unchanged: the review still gates publish through its candidate.
        assert_eq!(projected["decision"], json!("admitted"));
        assert_eq!(
            load(data_dir, KIND_CANDIDATE, "mpub_ok").unwrap()["admission_review_ref"],
            json!(format!("marketplace-admission://{id}"))
        );
    }

    #[test]
    fn create_replay_is_one_resource_and_keeps_the_same_reviewer() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_replay");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-replay-1");
        let body = json!({ "candidate_ref": candidate_ref, "decision": "pending" });

        let (first_status, Json(first)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        let (second_status, Json(second)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());

        assert_eq!(first_status, StatusCode::CREATED);
        assert_eq!(first["replayed"], json!(false));
        assert_eq!(
            second_status,
            StatusCode::OK,
            "a retried create must replay, not mint a second resource"
        );
        assert_eq!(second["replayed"], json!(true));
        assert_eq!(first["admission_review"], second["admission_review"]);
        assert_eq!(
            second["admission_review"]["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL),
            "a replay must not weaken attribution"
        );
        // One resource, one admitted event: the retry appended nothing.
        assert_eq!(read_record_dir(data_dir, KIND_REVIEW).len(), 1);
        let id = first["admission_review"]["id"].as_str().unwrap();
        assert_eq!(admitted_event_count(data_dir, id), 1);
        assert_eq!(
            admitted_event_payload(data_dir, id).unwrap()["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL)
        );
    }

    #[test]
    fn forged_reviewer_refuses_a_patch_before_any_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_forged_patch");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-for-patch-1");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &caller,
            &json!({ "candidate_ref": candidate_ref, "decision": "pending" }),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let before = load(data_dir, KIND_REVIEW, &id).unwrap();
        let events_before = admitted_event_count(data_dir, &id);

        for forged in forged_reviewer_values() {
            let (status, Json(reply)) = patch_admission_review(
                data_dir,
                &id,
                &test_caller(REVIEWER_PRINCIPAL, "patch-forged-1"),
                &json!({ "decision": "rejected", "reviewer_ref": forged.clone() }),
            );
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a patch naming its own reviewer must be refused: {forged}"
            );
            assert_eq!(
                reply["error"]["code"],
                json!("marketplace_reviewer_ref_not_client_settable")
            );
        }

        // Nothing moved: same bytes on disk, same head, no new event. The decision did not advance
        // and no reviewer was installed.
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap(),
            before,
            "a refused patch changed the projection"
        );
        assert_eq!(
            admitted_event_count(data_dir, &id),
            events_before,
            "a refused patch admitted an event"
        );

        // The refusal cannot be used as an existence oracle: a forged patch to an id that does not
        // exist answers the SAME 400, while a patch that names no reviewer keeps the 404.
        let (absent_forged, Json(absent_reply)) = patch_admission_review(
            data_dir,
            "madm_does_not_exist",
            &test_caller(REVIEWER_PRINCIPAL, "patch-forged-absent"),
            &json!({ "decision": "rejected", "reviewer_ref": FORGED_PRINCIPAL }),
        );
        assert_eq!(absent_forged, StatusCode::BAD_REQUEST);
        assert_eq!(
            absent_reply["error"]["code"],
            json!("marketplace_reviewer_ref_not_client_settable")
        );
        let (absent_clean, _) = patch_admission_review(
            data_dir,
            "madm_does_not_exist",
            &test_caller(REVIEWER_PRINCIPAL, "patch-clean-absent"),
            &json!({ "decision": "rejected" }),
        );
        assert_eq!(
            absent_clean,
            StatusCode::NOT_FOUND,
            "the auth-before-load 404 must survive for a body that forges nothing"
        );
    }

    #[test]
    fn patch_binds_the_acting_principal_and_never_inherits_a_stored_reviewer() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_patch");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-for-attr-1");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &caller,
            &json!({ "candidate_ref": candidate_ref, "decision": "pending" }),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        // POISON the projection the way a pre-cut body could: a reviewer nobody authenticated,
        // sitting in the record the patch is about to read.
        let mut poisoned = load(data_dir, KIND_REVIEW, &id).unwrap();
        poisoned["reviewer_ref"] = json!(FORGED_PRINCIPAL);
        persist_record(data_dir, KIND_REVIEW, &id, &poisoned).unwrap();

        let (status, Json(reply)) = patch_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "patch-attr-1"),
            &json!({ "decision": "admitted" }),
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply["admission_review"]["decision"], json!("admitted"));

        let projected = load(data_dir, KIND_REVIEW, &id).unwrap();
        let event = admitted_event_payload(data_dir, &id).expect("the patch admitted an event");
        for (label, value) in [
            ("response", &reply["admission_review"]["reviewer_ref"]),
            ("projection", &projected["reviewer_ref"]),
            ("admitted event", &event["reviewer_ref"]),
        ] {
            assert_eq!(
                value,
                &json!(REVIEWER_PRINCIPAL),
                "{label} does not name the acting principal"
            );
        }
        for (label, document) in [("projection", &projected), ("admitted event", &event)] {
            assert!(
                !serde_json::to_string(document)
                    .unwrap()
                    .contains(FORGED_PRINCIPAL),
                "{label} still carries the pre-cut reviewer"
            );
        }

        // A patch that changes nothing else STILL re-attributes: re-poison, patch with an empty
        // body, and the acting principal is back. Attribution is never merged from stored bytes.
        let mut repoisoned = load(data_dir, KIND_REVIEW, &id).unwrap();
        repoisoned["reviewer_ref"] = json!(FORGED_PRINCIPAL);
        persist_record(data_dir, KIND_REVIEW, &id, &repoisoned).unwrap();
        let (status, Json(reply)) = patch_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "patch-attr-2"),
            &json!({}),
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            reply["admission_review"]["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL)
        );
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap()["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL)
        );

        // The decision vocabulary is untouched by this cut, and a refused transition attributes
        // nothing: the projection keeps the reviewer and decision it already had.
        let admitted_state = load(data_dir, KIND_REVIEW, &id).unwrap();
        let (status, Json(reply)) = patch_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "patch-bad-vocab"),
            &json!({ "decision": "published" }),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply["error"]["code"],
            json!("marketplace_decision_invalid")
        );
        assert_eq!(load(data_dir, KIND_REVIEW, &id).unwrap(), admitted_state);
    }

    #[test]
    fn a_second_principal_cannot_take_over_the_attribution() {
        // Attribution cannot be handed off by patching as someone else: the resource scope was
        // bound to the creating principal, so a different caller is refused at the scope seam and
        // the recorded reviewer never changes.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_intruder");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &test_caller(REVIEWER_PRINCIPAL, "create-for-intruder-1"),
            &json!({ "candidate_ref": candidate_ref, "decision": "pending" }),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, _) = patch_admission_review(
            data_dir,
            &id,
            &test_caller("user://intruder", "patch-intruder-1"),
            &json!({ "decision": "admitted" }),
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap()["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL)
        );
        assert_eq!(
            admitted_event_payload(data_dir, &id).unwrap()["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL)
        );
    }

    #[test]
    fn the_governance_posture_is_evidence_in_the_payload_and_not_replay_identity() {
        // Replaces the test that PINNED this packet's defect. The nested `at: iso_now()` and the
        // live gate counts still survive `without_clock` into the admitted payload — deliberately,
        // because posture at review time is evidence and stripping it would delete the evidence to
        // fix the retry. What changed is what "the same command" means: the posture is excluded from
        // BOTH sides of the replay comparison, so two creates a second apart are one command with
        // one piece of evidence attached, not two different commands.
        let mut record = json!({
            "id": "madm_x",
            "decision": "admitted",
            "governance_posture_snapshot": { "governance_gaps": 0, "at": "2026-01-01T00:00:00Z" },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "admitted_head": "sha256:0"
        });
        let stripped = without_clock(&record);
        assert!(stripped.get("created_at").is_none());
        assert!(stripped.get("updated_at").is_none());
        assert!(stripped.get("admitted_head").is_none());
        assert_eq!(
            stripped["governance_posture_snapshot"]["at"],
            json!("2026-01-01T00:00:00Z"),
            "the posture must remain in the admitted payload as evidence"
        );

        // The payload still differs a second later — that is exactly why the substrate alone cannot
        // decide this — but the COMMAND does not.
        let first_command = command_without_posture(&stripped);
        record["governance_posture_snapshot"]["at"] = json!("2026-01-01T00:00:01Z");
        record["governance_posture_snapshot"]["governance_gaps"] = json!(3);
        let drifted = without_clock(&record);
        assert_ne!(drifted, stripped, "the posture drifts between submissions");
        assert_eq!(
            command_without_posture(&drifted),
            first_command,
            "posture drift must not make a retry a different command"
        );
        assert!(
            first_command.get("governance_posture_snapshot").is_none(),
            "the posture must not be part of replay identity"
        );
        assert_eq!(first_command["decision"], json!("admitted"));
    }

    // ---- P-MKT-REPLAY-1: exact replay for admission-review create and delete -------------------
    //
    // Every test below drives the production functions the routes call — `handle_review_create` is
    // `begin_admission_review_create` + the posture read + `finish_admission_review_create`, and
    // `handle_review_delete` is `delete_admission_review` — against a real tempdir and the real
    // Agentgres chain, so a replay is read back from durable truth rather than asserted about
    // source order.

    /// `handle_review_create`'s own body with its ONE await replaced by a supplied posture, so a
    /// test can control the value the handler reads from live governance state. Nothing else about
    /// the sequence is restated: both branches call the production functions the route calls.
    fn create_admission_review(
        data_dir: &str,
        caller: &WriteCaller,
        body: &Value,
        gov: Value,
    ) -> (StatusCode, Json<Value>) {
        match begin_admission_review_create(data_dir, caller, body) {
            ReviewCreateStep::Answered(response) => response,
            ReviewCreateStep::Fresh(command) => {
                finish_admission_review_create(data_dir, caller, &command, gov)
            }
        }
    }

    /// A posture that has MOVED since the previous submission — a later clock and different live
    /// gate counts. This is what `governance_snapshot` actually does between two HTTP retries, and
    /// what made the retry byte-different under one key.
    fn moved_governance_snapshot() -> Value {
        json!({
            "auth_enforced": true,
            "governance_gaps": 4,
            "wallet_required_crossings": 2,
            "authority_grants_active": 7,
            "at": "2026-06-15T12:34:56Z"
        })
    }

    /// The request-scope stream tails currently bound. A probe must never add one: asking "did I
    /// already do this?" is a read, and a read that reserves a scope is a write wearing a question.
    fn bound_scope_tails(data_dir: &str) -> Vec<String> {
        super::super::substrate_store::list_event_stream_tails(data_dir, "request-resource-scopes")
            .unwrap_or_default()
    }

    fn create_body(candidate_ref: &str, decision: &str) -> Value {
        json!({ "candidate_ref": candidate_ref, "decision": decision })
    }

    #[test]
    fn create_retry_over_a_moving_governance_snapshot_replays_one_review() {
        // THE test that fails before this packet. Two submissions of one command, with a posture
        // that moved in between: 201 then 200, one resource, one admitted event, identical bytes.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_moving");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-moving-1");
        let body = create_body(&candidate_ref, "admitted");

        let (first_status, Json(first)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        let (second_status, Json(second)) =
            create_admission_review(data_dir, &caller, &body, moved_governance_snapshot());

        assert_eq!(first_status, StatusCode::CREATED);
        assert_eq!(first["replayed"], json!(false));
        assert_eq!(
            second_status,
            StatusCode::OK,
            "a retry over a moved posture must replay, not conflict: {second}"
        );
        assert_eq!(second["replayed"], json!(true));
        assert_eq!(
            first["admission_review"], second["admission_review"],
            "the replay returned different bytes than the admitted original"
        );
        // The posture the review carries is the one admitted with it, not the one the retry read.
        assert_eq!(
            second["admission_review"]["governance_posture_snapshot"],
            pinned_governance_snapshot()
        );

        let id = first["admission_review"]["id"].as_str().unwrap();
        assert_eq!(read_record_dir(data_dir, KIND_REVIEW).len(), 1);
        assert_eq!(
            admitted_event_count(data_dir, id),
            1,
            "the retry appended a second event"
        );
        assert_eq!(
            load(data_dir, KIND_REVIEW, id).unwrap(),
            first["admission_review"],
            "the retry rewrote the projection"
        );
        reset_handle_for_test();
    }

    #[test]
    fn create_retry_under_a_changed_command_still_refuses_by_name() {
        // Excluding the posture from replay identity must not let a genuinely different command
        // borrow an admitted key's success. The refusal keeps its own name and its own status.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let first_candidate = seed_candidate(data_dir, "mpub_changed_a");
        let second_candidate = seed_candidate(data_dir, "mpub_changed_b");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-changed-1");

        let (status, Json(created)) = create_admission_review(
            data_dir,
            &caller,
            &create_body(&first_candidate, "pending"),
            pinned_governance_snapshot(),
        );
        assert_eq!(status, StatusCode::CREATED);
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let before = load(data_dir, KIND_REVIEW, &id).unwrap();

        for changed in [
            create_body(&second_candidate, "pending"),
            create_body(&first_candidate, "rejected"),
            json!({ "candidate_ref": first_candidate, "decision": "pending", "findings": ["finding://a"] }),
        ] {
            let (status, Json(reply)) =
                create_admission_review(data_dir, &caller, &changed, moved_governance_snapshot());
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "a changed command under an admitted key must refuse: {changed}"
            );
            assert_eq!(
                reply["code"],
                json!("event_stream_same_key_different_bytes"),
                "the refusal must keep the substrate's own name: {reply}"
            );
            assert_eq!(reply["ok"], json!(false));
        }
        assert_eq!(admitted_event_count(data_dir, &id), 1);
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap(),
            before,
            "a refused retry changed the projection"
        );
        reset_handle_for_test();
    }

    #[test]
    fn create_retry_after_a_patch_returns_current_truth_and_writes_nothing() {
        // The latent clobber the create fix would otherwise activate: a replay must answer with the
        // resource as it stands, never re-project the bytes the create first wrote over a decision
        // someone has since advanced.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_patched");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-patched-1");
        let body = create_body(&candidate_ref, "pending");
        let (_, Json(created)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let (patch_status, _) = patch_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "patch-after-create-1"),
            &json!({ "decision": "admitted" }),
        );
        assert_eq!(patch_status, StatusCode::OK);
        let patched = load(data_dir, KIND_REVIEW, &id).unwrap();
        assert_eq!(patched["decision"], json!("admitted"));

        let (status, Json(replay)) =
            create_admission_review(data_dir, &caller, &body, moved_governance_snapshot());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["replayed"], json!(true));
        assert_eq!(
            replay["admission_review"], patched,
            "the replay answered with create-time bytes instead of current truth"
        );
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap(),
            patched,
            "the replay overwrote the patched projection"
        );
        assert_eq!(
            admitted_event_count(data_dir, &id),
            2,
            "the replay admitted an event"
        );
        reset_handle_for_test();
    }

    #[test]
    fn create_retry_carrying_a_reviewer_ref_is_still_refused() {
        // Attribution is refused on the KEY BEING PRESENT, before the replay probe can answer
        // anything — otherwise a forged retry would be served the original's success.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_retry_forged");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-retry-forged-1");
        let body = create_body(&candidate_ref, "pending");
        let (_, Json(created)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let before = load(data_dir, KIND_REVIEW, &id).unwrap();

        for forged in forged_reviewer_values() {
            let mut retry = body.clone();
            retry["reviewer_ref"] = forged.clone();
            let (status, Json(reply)) =
                create_admission_review(data_dir, &caller, &retry, moved_governance_snapshot());
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a retry naming its own reviewer must be refused: {forged}"
            );
            assert_eq!(
                reply["error"]["code"],
                json!("marketplace_reviewer_ref_not_client_settable")
            );
        }
        assert_eq!(admitted_event_count(data_dir, &id), 1);
        assert_eq!(load(data_dir, KIND_REVIEW, &id).unwrap(), before);
        reset_handle_for_test();
    }

    #[test]
    fn create_replay_repairs_a_projection_lost_after_admission() {
        // The create's admission is durable and its projection is not. A retry must rebuild the
        // read model from the admitted payload and that operation's OWN stamp and head — never a
        // clock — and the rebuilt record must be the record that was lost.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_repair");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-repair-1");
        let body = create_body(&candidate_ref, "admitted");
        let (_, Json(created)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let original = load(data_dir, KIND_REVIEW, &id).unwrap();
        assert!(remove_record(data_dir, KIND_REVIEW, &id));

        let (status, Json(replay)) =
            create_admission_review(data_dir, &caller, &body, moved_governance_snapshot());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["replayed"], json!(true));
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap(),
            original,
            "the repaired projection is not the record that was admitted"
        );
        assert_eq!(replay["admission_review"], original);
        assert_eq!(admitted_event_count(data_dir, &id), 1);
        // The candidate backlink is fail-closed on the replay path too, so publish gating still
        // resolves after a repair.
        assert_eq!(
            load(data_dir, KIND_CANDIDATE, "mpub_repair").unwrap()["admission_review_ref"],
            json!(format!("marketplace-admission://{id}"))
        );
        reset_handle_for_test();
    }

    #[test]
    fn delete_retry_replays_the_admitted_removal() {
        // The delete this packet closes: a double-submitted form presents one key twice and must be
        // told the removal happened, not that the record never existed.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_delete");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &test_caller(REVIEWER_PRINCIPAL, "create-for-delete-1"),
            &create_body(&candidate_ref, "admitted"),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let deleter = test_caller(REVIEWER_PRINCIPAL, "delete-review-1");

        let (first_status, Json(first)) = delete_admission_review(data_dir, &id, &deleter);
        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(first["removed"], json!(true));
        assert_eq!(first["replayed"], json!(false));
        assert!(load(data_dir, KIND_REVIEW, &id).is_none());

        let (second_status, Json(second)) = delete_admission_review(data_dir, &id, &deleter);
        assert_eq!(
            second_status,
            StatusCode::OK,
            "a retried delete must replay the admitted removal: {second}"
        );
        assert_eq!(second["removed"], json!(true));
        assert_eq!(second["replayed"], json!(true));
        assert_eq!(second["id"], json!(id));
        assert_eq!(
            admitted_event_count(data_dir, &id),
            2,
            "the retry admitted a second terminal event"
        );
        assert!(load(data_dir, KIND_REVIEW, &id).is_none());
        // The unlink is not undone by a replay: the candidate still points at nothing.
        assert_eq!(
            load(data_dir, KIND_CANDIDATE, "mpub_delete").unwrap()["admission_review_ref"],
            Value::Null
        );
        reset_handle_for_test();
    }

    #[test]
    fn a_create_key_re_presented_after_the_delete_resurrects_nothing() {
        // MERGE BLOCKER, fenced. Reading the admitted history early is what makes create replay
        // possible at all, and it is also what makes this reachable: before the fix the retry took
        // the moved-posture 409 and never got near the repair. An admitted delete is the stream's
        // last word, so the create it followed may not be replayed over it — no projection, no
        // candidate backlink, no event, and no 200 claiming a review that is gone.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_resurrect");
        let creator = test_caller(REVIEWER_PRINCIPAL, "create-resurrect-1");
        let body = create_body(&candidate_ref, "admitted");
        let (_, Json(created)) =
            create_admission_review(data_dir, &creator, &body, pinned_governance_snapshot());
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            delete_admission_review(
                data_dir,
                &id,
                &test_caller(REVIEWER_PRINCIPAL, "delete-resurrect-1")
            )
            .0,
            StatusCode::OK
        );
        let events_after_delete = admitted_event_count(data_dir, &id);
        assert_eq!(events_after_delete, 2);

        // The create key, re-presented exactly. Twice, so the refusal is not a one-shot.
        for attempt in 0..2 {
            let (status, Json(reply)) =
                create_admission_review(data_dir, &creator, &body, moved_governance_snapshot());
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "attempt {attempt} replayed a create over an admitted removal: {reply}"
            );
            assert_eq!(reply["error"]["code"], json!("marketplace_review_removed"));
            assert_eq!(reply["ok"], json!(false));
            assert!(
                reply["admitted_head"].is_string(),
                "the refusal must name the terminal head it deferred to: {reply}"
            );
            assert!(
                reply.get("admission_review").is_none(),
                "the refusal returned a record that no longer exists: {reply}"
            );
        }

        // NOTHING was recreated: no projection, no candidate backlink, no event.
        assert!(
            load(data_dir, KIND_REVIEW, &id).is_none(),
            "a create retry resurrected the review projection"
        );
        assert!(read_record_dir(data_dir, KIND_REVIEW).is_empty());
        assert_eq!(
            load(data_dir, KIND_CANDIDATE, "mpub_resurrect").unwrap()["admission_review_ref"],
            Value::Null,
            "a create retry re-linked a deleted review onto its candidate"
        );
        assert_eq!(
            admitted_event_count(data_dir, &id),
            events_after_delete,
            "a create retry admitted an event after the terminal delete"
        );
        // The delete's OWN key still replays: the removal remains the fact both sides agree on.
        let (delete_status, Json(delete_replay)) = delete_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "delete-resurrect-1"),
        );
        assert_eq!(delete_status, StatusCode::OK);
        assert_eq!(delete_replay["removed"], json!(true));
        assert_eq!(delete_replay["replayed"], json!(true));

        // A FRESH key is the supported way to review this candidate again, and it mints its own
        // resource on its own stream rather than reopening the closed one.
        let (fresh_status, Json(fresh)) = create_admission_review(
            data_dir,
            &test_caller(REVIEWER_PRINCIPAL, "create-resurrect-2"),
            &body,
            moved_governance_snapshot(),
        );
        assert_eq!(fresh_status, StatusCode::CREATED);
        assert_ne!(fresh["admission_review"]["id"], json!(id));
        assert_eq!(admitted_event_count(data_dir, &id), events_after_delete);
        reset_handle_for_test();
    }

    #[test]
    fn a_create_retry_whose_candidate_was_deleted_is_refused_before_the_probe() {
        // The other deletion the replay path must weigh: the review's candidate. Command validation
        // runs first and is unchanged, so a retry against a candidate that no longer resolves is
        // refused before the history is read — and, decisively, before `link_candidate_review`
        // could write a backlink onto a record that is gone.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_gone");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-candidate-gone-1");
        let body = create_body(&candidate_ref, "admitted");
        let (_, Json(created)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let projected = load(data_dir, KIND_REVIEW, &id).unwrap();
        assert!(remove_record(data_dir, KIND_CANDIDATE, "mpub_gone"));

        let (status, Json(reply)) =
            create_admission_review(data_dir, &caller, &body, moved_governance_snapshot());
        assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
        assert_eq!(reply["error"]["code"], json!("marketplace_ref_unresolved"));
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap(),
            projected,
            "a refused retry rewrote the review"
        );
        assert!(load(data_dir, KIND_CANDIDATE, "mpub_gone").is_none());
        assert_eq!(admitted_event_count(data_dir, &id), 1);

        // Same for the repair branch: with the projection ALSO gone there is still no write, so a
        // vanished candidate can never be recreated by a retry.
        assert!(remove_record(data_dir, KIND_REVIEW, &id));
        let (repair_status, _) =
            create_admission_review(data_dir, &caller, &body, moved_governance_snapshot());
        assert_eq!(repair_status, StatusCode::BAD_REQUEST);
        assert!(load(data_dir, KIND_REVIEW, &id).is_none());
        assert!(load(data_dir, KIND_CANDIDATE, "mpub_gone").is_none());
        assert_eq!(admitted_event_count(data_dir, &id), 1);
        reset_handle_for_test();
    }

    #[test]
    fn delete_completes_after_an_admitted_removal_whose_projection_survived() {
        // The already-correct half of the delete path, pinned so the probe cannot regress it: when
        // the terminal event admitted but the projection removal failed, the record still carries
        // its pre-delete head, so the retry takes the PRESENT-projection branch, replays through
        // the substrate, and finishes the unlink and removal.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_torn_delete");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &test_caller(REVIEWER_PRINCIPAL, "create-for-torn-1"),
            &create_body(&candidate_ref, "admitted"),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let before_delete = load(data_dir, KIND_REVIEW, &id).unwrap();
        let deleter = test_caller(REVIEWER_PRINCIPAL, "delete-torn-1");
        assert_eq!(
            delete_admission_review(data_dir, &id, &deleter).0,
            StatusCode::OK
        );
        // Exactly the state a failed `remove_record` leaves behind: admitted, still projected, and
        // still carrying the head it read before the delete.
        persist_record(data_dir, KIND_REVIEW, &id, &before_delete).unwrap();

        let (status, Json(reply)) = delete_admission_review(data_dir, &id, &deleter);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply["removed"], json!(true));
        assert_eq!(reply["replayed"], json!(true));
        assert!(load(data_dir, KIND_REVIEW, &id).is_none());
        assert_eq!(admitted_event_count(data_dir, &id), 2);
        reset_handle_for_test();
    }

    #[test]
    fn delete_of_an_id_that_never_existed_is_still_not_found() {
        // The probe must not turn a miss into an existence oracle, a scope binding, or an event.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_absent");
        assert_eq!(
            create_admission_review(
                data_dir,
                &test_caller(REVIEWER_PRINCIPAL, "create-for-absent-1"),
                &create_body(&candidate_ref, "pending"),
                pinned_governance_snapshot(),
            )
            .0,
            StatusCode::CREATED
        );
        let tails_before = bound_scope_tails(data_dir);
        assert!(!tails_before.is_empty(), "the create bound its own scope");

        for unknown in ["madm_never_existed", "madm_00000000000000000"] {
            let (status, Json(reply)) = delete_admission_review(
                data_dir,
                unknown,
                &test_caller(REVIEWER_PRINCIPAL, "delete-absent-1"),
            );
            assert_eq!(status, StatusCode::NOT_FOUND, "{reply}");
            assert_eq!(
                reply["error"]["code"],
                json!("marketplace_review_not_found")
            );
            assert_eq!(reply["error"]["message"], json!("review not found"));
            assert_eq!(reply["ok"], json!(false));
            assert_eq!(admitted_event_count(data_dir, unknown), 0);
        }
        assert_eq!(
            bound_scope_tails(data_dir),
            tails_before,
            "a refused delete bound a request scope for an id that never existed"
        );
        reset_handle_for_test();
    }

    #[test]
    fn delete_after_removal_under_a_different_key_is_not_found() {
        // Replay is bound to the caller's OWN key. A second, different delete command for a record
        // that is already gone is a delete of nothing, exactly as before.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_other_key");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &test_caller(REVIEWER_PRINCIPAL, "create-for-other-key-1"),
            &create_body(&candidate_ref, "pending"),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            delete_admission_review(
                data_dir,
                &id,
                &test_caller(REVIEWER_PRINCIPAL, "delete-first-key")
            )
            .0,
            StatusCode::OK
        );

        let (status, Json(reply)) = delete_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "delete-second-key"),
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            reply["error"]["code"],
            json!("marketplace_review_not_found")
        );
        // A foreign principal presenting the SAME key is also told nothing: the probe answers None
        // rather than confirming another principal's id exists.
        let (foreign_status, Json(foreign)) = delete_admission_review(
            data_dir,
            &id,
            &test_caller("user://intruder", "delete-first-key"),
        );
        assert_eq!(foreign_status, StatusCode::NOT_FOUND);
        assert_eq!(
            foreign["error"]["code"],
            json!("marketplace_review_not_found")
        );
        assert_eq!(
            admitted_event_count(data_dir, &id),
            2,
            "a refused delete admitted an event"
        );
        reset_handle_for_test();
    }

    #[test]
    fn replay_survives_a_restart_for_both_create_and_delete() {
        // Neither replay may be served from process memory. Dropping the handle between attempts
        // forces both answers to be reconstructed from the durable log.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_restart");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-restart-1");
        let body = create_body(&candidate_ref, "admitted");
        let (first_status, Json(created)) =
            create_admission_review(data_dir, &caller, &body, pinned_governance_snapshot());
        assert_eq!(first_status, StatusCode::CREATED);
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        reset_handle_for_test();
        let (status, Json(replay)) =
            create_admission_review(data_dir, &caller, &body, moved_governance_snapshot());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["replayed"], json!(true));
        assert_eq!(replay["admission_review"], created["admission_review"]);
        assert_eq!(admitted_event_count(data_dir, &id), 1);

        let deleter = test_caller(REVIEWER_PRINCIPAL, "delete-restart-1");
        assert_eq!(
            delete_admission_review(data_dir, &id, &deleter).0,
            StatusCode::OK
        );
        reset_handle_for_test();
        let (delete_status, Json(delete_replay)) = delete_admission_review(data_dir, &id, &deleter);
        assert_eq!(delete_status, StatusCode::OK);
        assert_eq!(delete_replay["replayed"], json!(true));
        assert_eq!(delete_replay["removed"], json!(true));
        assert_eq!(admitted_event_count(data_dir, &id), 2);
        reset_handle_for_test();
    }

    #[test]
    fn a_delete_still_binds_the_exact_head_and_refuses_a_record_with_none() {
        // Compare-and-swap is untouched by the probe. A successor still presents the exact admitted
        // head, and a projection that predates admitted mutation is refused rather than advanced.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_head");
        let caller = test_caller(REVIEWER_PRINCIPAL, "create-for-head-1");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &caller,
            &create_body(&candidate_ref, "pending"),
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let at_create = load(data_dir, KIND_REVIEW, &id).unwrap();

        // Advance the stream, then hand the delete a projection carrying the head it has moved past.
        assert_eq!(
            patch_admission_review(
                data_dir,
                &id,
                &test_caller(REVIEWER_PRINCIPAL, "patch-for-head-1"),
                &json!({ "decision": "admitted" })
            )
            .0,
            StatusCode::OK
        );
        persist_record(data_dir, KIND_REVIEW, &id, &at_create).unwrap();
        let (status, Json(reply)) = delete_admission_review(
            data_dir,
            &id,
            &test_caller(REVIEWER_PRINCIPAL, "delete-stale-head-1"),
        );
        assert_eq!(status, StatusCode::CONFLICT, "{reply}");
        assert_eq!(reply["code"], json!("event_stream_expected_head_conflict"));
        assert!(load(data_dir, KIND_REVIEW, &id).is_some());

        // A record written before this plane bound identity carries no head at all.
        persist_record(
            data_dir,
            KIND_REVIEW,
            "madm_headless",
            &json!({ "id": "madm_headless", "candidate_ref": candidate_ref }),
        )
        .unwrap();
        let (headless_status, Json(headless)) = delete_admission_review(
            data_dir,
            "madm_headless",
            &test_caller(REVIEWER_PRINCIPAL, "delete-headless-1"),
        );
        assert_eq!(headless_status, StatusCode::BAD_REQUEST);
        assert_eq!(
            headless["error"]["code"],
            json!("marketplace_expected_head_required")
        );
        reset_handle_for_test();
    }

    #[test]
    fn a_create_replay_cannot_be_borrowed_by_another_principal() {
        // The probe is authorization-bound and answers a foreign caller `None`, so a borrowed key
        // reaches the same scope refusal it reached before rather than being served a replay.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let candidate_ref = seed_candidate(data_dir, "mpub_borrow");
        let body = create_body(&candidate_ref, "admitted");
        let (_, Json(created)) = create_admission_review(
            data_dir,
            &test_caller(REVIEWER_PRINCIPAL, "shared-looking-key"),
            &body,
            pinned_governance_snapshot(),
        );
        let id = created["admission_review"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, _) = create_admission_review(
            data_dir,
            &test_caller("user://intruder", "shared-looking-key"),
            &body,
            moved_governance_snapshot(),
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(admitted_event_count(data_dir, &id), 1);
        assert_eq!(
            load(data_dir, KIND_REVIEW, &id).unwrap()["reviewer_ref"],
            json!(REVIEWER_PRINCIPAL)
        );
        reset_handle_for_test();
    }
}
