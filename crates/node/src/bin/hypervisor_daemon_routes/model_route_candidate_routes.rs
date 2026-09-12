//! THE MODEL-ROUTE CANDIDATE LANE — expiring advisory evidence about routes, and nothing else.
//!
//! Canon (`components/model-router/doctrine.md`) requires two things of route price evidence and
//! this module exists to make both structural rather than procedural:
//!
//!   * A route carries an extensible price SCHEDULE which "enters verbatim through the candidate
//!     lane as expiring advisory evidence; a stale schedule is a typed gap, not a silently aged
//!     number." Until now the estate had the REFERENCE and not the referent: `provider_transport`
//!     reads `price_schedule_ref` off a provider binding and stamps it onto the invocation
//!     receipt, listing it in `evidence_gaps` when absent — with nothing anywhere persisting the
//!     schedule that ref names. "A new provider extends rather than forks" had nothing to extend.
//!
//!   * "Imported capability or price maps enter through the expiring advisory candidate lane and
//!     are confirmed by probes — candidate evidence, NEVER route authority and NEVER billing
//!     truth."
//!
//! WHAT THIS MODULE IS NOT, because both mistakes were available and one was nearly made.
//! It is not the COMPUTE candidate plane: the eight `*_candidate_source.rs` modules serve GPU/VM
//! placement, and putting route price evidence there would attribute shared-pool spend to a route
//! — the double-count canon names as a second spend spine. It is also not a billing surface: the
//! managed-work billing chain in `economics_routes` owns what is charged, this owns only what a
//! ranking may READ. A schedule admitted here has bought no route the right to run.
//!
//! The registered contract carries the lane's shape, so the refusals below are mostly the
//! contract's own: `advisory_only` is a const true (a schedule claiming to authorize placement
//! cannot be admitted at all), and an invariant requires `observed_at_ms < expires_at_ms` so a
//! schedule cannot be born stale. What this module adds is that the window, the identity and the
//! body hash are SERVER-DERIVED — a caller that could set its own expiry could mint an
//! never-stale schedule and defeat the typed gap the ranking depends on.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::{persist_record, read_record_dir, DaemonState};

type Reply = (StatusCode, Json<Value>);

const CANDIDATE_NAMESPACE: &str = "hypervisor-model-route-candidates";
const KIND_PRICE_SCHEDULE: &str = "model-route-price-schedules";
const PRICE_SCHEDULE_CONTRACT_ID: &str =
    "schema://ioi/components/model-router/model-route-price-schedule/v1";
const PRICE_SCHEDULE_SCHEMA_VERSION: &str =
    "ioi.components.model-router.model-route-price-schedule.v1";
const COMPARISON_CONTRACT_ID: &str =
    "schema://ioi/components/model-router/model-route-cost-comparison/v1";
/// One year, matching the economics plane's ceiling. A schedule is advisory evidence; an
/// unbounded one would never become the typed gap a stale schedule is supposed to become.
const MAX_VALIDITY_SECONDS: u64 = 31_536_000;

/// Derived server-side. A caller who could set its own `expires_at_ms` could mint a schedule that
/// never goes stale, and staleness is precisely what makes a ranking refuse to price from it.
const SERVER_DERIVED: &[&str] = &[
    "schema_version",
    "price_schedule_ref",
    "version",
    "body_hash",
    "advisory_only",
    "observed_at_ms",
    "expires_at_ms",
];

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{:x}", sha2::Sha256::digest(bytes))
}

/// Canonical body hash: JCS over the object WITHOUT its own `body_hash`.
fn body_hash_of(object: &Value) -> Result<String, Reply> {
    let mut copy = object.clone();
    if let Some(map) = copy.as_object_mut() {
        map.remove("body_hash");
    }
    serde_jcs::to_vec(&copy)
        .map(|bytes| digest(&bytes))
        .map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "model_route_candidate_body_hash_failed",
                error.to_string(),
            )
        })
}

fn now_ms() -> u64 {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or_default()
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
}

fn require_ref(body: &Value, key: &str) -> Result<String, Reply> {
    let value = str_field(body, key);
    let scheme_ok = value.split_once("://").is_some_and(|(scheme, tail)| {
        !tail.is_empty()
            && scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase())
            && scheme
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+.-".contains(c))
    });
    if !scheme_ok || value.chars().any(char::is_whitespace) || value.len() > 500 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_ref_invalid",
            format!("{key} must be a canonical scheme://ref"),
        ));
    }
    Ok(value.to_string())
}

/// INTEGER-ONLY. A price expressed as a float is refused at the boundary, for the same reason the
/// managed-work billing chain refuses one: a rounding rule nobody declared is a rounding rule
/// nobody can audit.
fn units_field(body: &Value, key: &str) -> Result<u64, Reply> {
    match body.get(key) {
        Some(Value::Number(number)) if number.is_u64() => Ok(number.as_u64().unwrap_or_default()),
        _ => Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_integer_amount_required",
            format!("{key} must be a non-negative integer; no floating-point price is valid"),
        )),
    }
}

fn refuse_server_derived(body: &Value) -> Result<(), Reply> {
    for field in SERVER_DERIVED {
        if body.get(*field).is_some() {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "model_route_candidate_server_derived_field",
                format!(
                    "{field} is derived server-side; a caller-set window or identity would let a schedule outlive the staleness a ranking depends on"
                ),
            ));
        }
    }
    Ok(())
}

fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, kind)
        .into_iter()
        .find(|record| record["id"].as_str() == Some(id))
}

fn project_admission(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(super::iso_now());
}

/// The admitted schedule, built from the caller's declared evidence plus a server-derived window,
/// identity and body hash. Validated against its REGISTERED contract before anything is written:
/// an object that would not survive the offline verifier is not persisted and then explained.
fn mint_price_schedule(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> Result<(Value, bool), Reply> {
    refuse_server_derived(body)?;
    let route_ref = require_ref(body, "route_ref")?;
    let provider_ref = require_ref(body, "provider_ref")?;
    let currency = str_field(body, "currency_code").to_string();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_currency_invalid",
            "currency_code must be a three-letter uppercase ISO code",
        ));
    }
    let seconds = units_field(body, "validity_seconds")?;
    if seconds == 0 || seconds > MAX_VALIDITY_SECONDS {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_validity_invalid",
            format!("validity_seconds must be between 1 and {MAX_VALIDITY_SECONDS}"),
        ));
    }
    let Some(components) = body.get("price_components").and_then(Value::as_array) else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_components_required",
            "price_components must be a non-empty array of {component_class, meter_unit, minor_units_per_meter_unit}",
        ));
    };
    if components.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_components_required",
            "price_components must be non-empty: an empty schedule would rank a route at zero cost",
        ));
    }
    let confidence = str_field(body, "confidence").to_string();
    let provenance = body
        .get("provenance")
        .cloned()
        .unwrap_or_else(|| json!({ "source_class": "operator_declared", "evidence_refs": [] }));

    let now = now_ms();
    let id = replay_stable_id("mrps", &caller.owner_ref, &caller.idempotency_key);
    let price_schedule_ref = format!("price-schedule://{id}");

    // WHAT IS ADMITTED IS THE CALLER'S DECLARED BYTES, NOT THE DERIVED RECORD.
    //
    // The shared write path keys replay on the admitted payload's bytes, so a server-derived
    // CLOCK READING inside that payload makes every retry a different-bytes conflict: the first
    // attempt of this module admitted the finished object and its own replay test failed with
    // `event_stream_same_key_different_bytes`, which was the substrate being right. The declared
    // inputs are stable across retries — `validity_seconds` is what the caller said, while the
    // window it implies is computed once and lives on the projection beside the body hash.
    let admitted = json!({
        "route_ref": route_ref,
        "provider_ref": provider_ref,
        "currency_code": currency,
        "price_components": components,
        "provenance": provenance,
        "confidence": confidence,
        "validity_seconds": seconds,
    });

    let mut object = json!({
        "schema_version": PRICE_SCHEDULE_SCHEMA_VERSION,
        "price_schedule_ref": price_schedule_ref,
        "route_ref": route_ref,
        "provider_ref": provider_ref,
        "version": 1,
        "currency_code": currency,
        "price_components": components,
        "provenance": provenance,
        "confidence": confidence,
        // Never from the caller. Price ranks routes that already qualify; it admits none.
        "advisory_only": true,
        "observed_at_ms": now,
        "expires_at_ms": now.saturating_add(seconds.saturating_mul(1000)),
    });
    object["body_hash"] = json!(body_hash_of(&object)?);

    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            PRICE_SCHEDULE_CONTRACT_ID,
            &object,
        )
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "model_route_candidate_contract_invalid",
            format!("the schedule violates its registered contract and is NOT admitted: {error}"),
        ));
    }

    let commit = admit_owner_scoped_write(
        data_dir,
        caller,
        CANDIDATE_NAMESPACE,
        KIND_PRICE_SCHEDULE,
        &price_schedule_ref,
        "model_route_price_schedule.observed",
        None,
        &admitted,
    )?;
    if commit.replayed {
        if let Some(existing) = load(data_dir, KIND_PRICE_SCHEDULE, &id) {
            return Ok((existing, true));
        }
    }
    let mut record = json!({
        "id": id,
        "owner_ref": caller.owner_ref,
        "object": object,
        "created_at": super::iso_now(),
    });
    project_admission(&mut record, &commit);
    persist_record(data_dir, KIND_PRICE_SCHEDULE, &id, &record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "model_route_candidate_persistence_failed",
            "the schedule is admitted but its projection could not be written; replay to reconcile",
        )
    })?;
    Ok((record, commit.replayed))
}

/// POST /v1/hypervisor/model-routes/price-schedules
pub(crate) async fn handle_price_schedule_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_price_schedule(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => (
            if replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(json!({ "ok": true, "price_schedule": record })),
        ),
        Err(response) => response,
    }
}

/// GET /v1/hypervisor/model-routes/price-schedules/:id — identity resolves BEFORE the record is
/// read, so an anonymous caller is owed 401 rather than a 404 that answers "does this id exist?"
/// for free. The reply states whether the schedule is stale RATHER than hiding it: a stale
/// schedule is a typed gap the caller must see, not an error and not a silently aged number.
pub(crate) async fn handle_price_schedule_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(refusal) => return scope_refusal_reply(refusal),
    };
    let Some(record) = load(&st.data_dir, KIND_PRICE_SCHEDULE, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "model_route_candidate_not_found",
            "no such price schedule",
        );
    };
    let owner = record["owner_ref"].as_str().unwrap_or_default();
    if !identity.tenant_refs.iter().any(|tenant| tenant == owner) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    let expired = record["object"]["expires_at_ms"]
        .as_u64()
        .is_some_and(|expires| expires <= now_ms());
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "price_schedule": record,
            // Stated, not inferred by the reader, and stated as the ranking's own vocabulary so a
            // consumer carries the gap code forward instead of inventing one.
            "stale": expired,
            "gap_reason_code": if expired { json!("price_schedule_expired") } else { Value::Null },
        })),
    )
}

// ---------------------------------------------------------------- the advisory comparison
//
// ELIGIBILITY RESOLVES FIRST AND PRICE RANKS ONLY WHAT ALREADY QUALIFIES. Canon is explicit that
// quality, privacy, residency, latency and availability are ADMISSION FILTERS rather than
// "context displayed beside a price", and that a cheaper ineligible route is a rights violation
// with a price attached. So an ineligible route never enters the ranked list at all: it is
// carried in `excluded_candidates` with a typed reason, where no reader can mistake it for a
// bargain.
//
// THE RIGHTS CONTRACT COMES FROM THE CALLER, and that is the estate's shape rather than a
// shortcut. A model route record does not cite a rights contract anywhere — the token appears in
// exactly one module estate-wide — and M07.2's own resolver takes no route-use argument, so
// per-use eligibility is necessarily the caller's to enforce. Inventing a route→rights join here
// would have minted a second rights spine beside the one three consumer planes already use.
// What this function DOES enforce is that the cited contract is live and actually permits the
// declared use: a contract cited by hash is not a contract applied.
//
// AND THE RANKING FAILS CLOSED ON MISSING EVIDENCE. `TokenMix` keeps `None` distinct from zero
// precisely so an unreported token class cannot be read as a free one, and the transport already
// records what it could not observe in `evidence_gaps`. A route carrying any gap is UNRANKED with
// a typed code rather than priced from a partial mix, because a partial reading as a total is
// exactly how a route becomes cheapest by being least measured.

const ROUTE_USE_DEFAULT: &str = "model_inference";

/// Every model invocation this owner recorded against one route, newest first is irrelevant —
/// what matters is that FAILED attempts are included. A failed attempt the provider metered is
/// real cost, and pricing only the successes would make an unreliable route look cheap.
fn invocations_for_route(data_dir: &str, owner_ref: &str, route_ref: &str) -> Vec<Value> {
    read_record_dir(data_dir, "model-invocations")
        .into_iter()
        .filter(|record| {
            record["owner_ref"].as_str() == Some(owner_ref)
                && record["route_ref"].as_str() == Some(route_ref)
        })
        .collect()
}

/// The live schedule for a route, or the typed gap that stands in for it.
fn schedule_for_route(
    data_dir: &str,
    owner_ref: &str,
    route_ref: &str,
    now: u64,
) -> Result<Value, &'static str> {
    let mut newest: Option<Value> = None;
    for record in read_record_dir(data_dir, KIND_PRICE_SCHEDULE) {
        if record["owner_ref"].as_str() != Some(owner_ref)
            || record["object"]["route_ref"].as_str() != Some(route_ref)
        {
            continue;
        }
        let observed = record["object"]["observed_at_ms"].as_u64().unwrap_or(0);
        if newest
            .as_ref()
            .and_then(|held| held["object"]["observed_at_ms"].as_u64())
            .is_none_or(|held| observed >= held)
        {
            newest = Some(record);
        }
    }
    let Some(schedule) = newest else {
        return Err("no_price_schedule");
    };
    if schedule["object"]["expires_at_ms"]
        .as_u64()
        .is_none_or(|expires| expires <= now)
    {
        // Stale is a TYPED GAP, never a silently aged number.
        return Err("price_schedule_expired");
    }
    Ok(schedule)
}

/// Price one observed token mix against a schedule's components, in integer minor units.
///
/// Only the classes the schedule prices and the mix REPORTS contribute. A class the provider did
/// not report is already a recorded evidence gap upstream, which is what unranks the route — this
/// function is never reached for a route carrying one, and it does not treat absence as zero on
/// its own account either.
fn price_mix(schedule: &Value, mix: &Value) -> Option<u64> {
    const CLASS_FOR_MIX: &[(&str, &str)] = &[
        ("input", "input_tokens"),
        ("output", "output_tokens"),
        ("cache_read", "cache_read_tokens"),
        ("cache_write", "cache_write_tokens"),
        ("reasoning", "reasoning_tokens"),
    ];
    let components = schedule["object"]["price_components"].as_array()?;
    let mut total: u64 = 0;
    for (mix_field, component_class) in CLASS_FOR_MIX {
        let Some(observed) = mix.get(mix_field).and_then(Value::as_u64) else {
            continue;
        };
        // The lowest-tier rate for the class; tiering is priced by the schedule's own bands and a
        // component without a tier applies to the whole quantity.
        let Some(rate) = components
            .iter()
            .filter(|component| component["component_class"].as_str() == Some(*component_class))
            .filter_map(|component| component["minor_units_per_meter_unit"].as_u64())
            .min()
        else {
            continue;
        };
        total = total.checked_add(observed.checked_mul(rate)?)?;
    }
    Some(total)
}

/// Build the advisory comparison. Returns the contract-valid record; the caller decides the
/// status code.
pub(crate) fn build_cost_comparison(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    owner_ref: &str,
    body: &Value,
) -> Result<Value, Reply> {
    let workload_ref = require_ref(body, "workload_ref")?;
    let rights_revision_ref = require_ref(body, "model_route_rights_revision_ref")?;
    let route_use = {
        let declared = str_field(body, "route_use");
        if declared.is_empty() {
            ROUTE_USE_DEFAULT.to_string()
        } else {
            declared.to_string()
        }
    };
    let Some(routes) = body.get("route_refs").and_then(Value::as_array) else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_routes_required",
            "route_refs must be a non-empty array of candidate model-route refs",
        ));
    };
    if routes.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_route_candidate_routes_required",
            "route_refs must be non-empty",
        ));
    }
    let currency = {
        let declared = str_field(body, "currency_code");
        if declared.len() == 3 && declared.chars().all(|c| c.is_ascii_uppercase()) {
            declared.to_string()
        } else {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "model_route_candidate_currency_invalid",
                "currency_code must be a three-letter uppercase ISO code",
            ));
        }
    };

    // RESOLVED ONCE, AND APPLIED — not merely cited. A contract that is not live, or that does not
    // permit the declared use, excludes every candidate: it is the caller's whole basis for
    // eligibility, so its failure is not a per-route condition.
    let rights = super::model_route_rights_routes::resolve_admitted_model_route_rights_contract(
        data_dir,
        identity,
        Some(owner_ref),
        &rights_revision_ref,
    )?;
    let contract_excludes = if !rights.is_live() {
        Some("route_rights_unresolved")
    } else if rights
        .unresolved_route_uses()
        .iter()
        .any(|use_| use_ == &route_use)
    {
        Some("route_rights_unresolved")
    } else if !rights
        .permitted_route_uses()
        .iter()
        .any(|use_| use_ == &route_use)
    {
        Some("route_rights_prohibited_use")
    } else {
        None
    };

    let now = now_ms();
    let mut ranked: Vec<Value> = Vec::new();
    let mut unranked: Vec<Value> = Vec::new();
    let mut excluded: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for entry in routes {
        let Some(route_ref) = entry.as_str() else {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "model_route_candidate_ref_invalid",
                "every route_refs entry must be a canonical scheme://ref",
            ));
        };
        // One route, one verdict: the registered invariant forbids a route appearing twice, and a
        // duplicated input must not become a duplicated row.
        if !seen.insert(route_ref.to_string()) {
            continue;
        }
        if let Some(code) = contract_excludes {
            excluded.push(json!({ "route_ref": route_ref, "exclusion_reason_code": code }));
            continue;
        }
        let schedule = match schedule_for_route(data_dir, owner_ref, route_ref, now) {
            Ok(schedule) => schedule,
            Err(code) => {
                unranked.push(json!({
                    "route_ref": route_ref,
                    "gap_reason_code": code,
                    "evidence_age_ms": Value::Null,
                }));
                continue;
            }
        };
        let invocations = invocations_for_route(data_dir, owner_ref, route_ref);
        if invocations.is_empty() {
            unranked.push(json!({
                "route_ref": route_ref,
                "gap_reason_code": "no_outcome_evidence",
                "evidence_age_ms": Value::Null,
            }));
            continue;
        }
        // FAIL CLOSED. A gap anywhere in this route's lineage means some cost was not observed,
        // and pricing what remains would make the least-measured route the cheapest.
        if invocations.iter().any(|record| {
            record["evidence"]["evidence_gaps"]
                .as_array()
                .is_some_and(|gaps| !gaps.is_empty())
        }) {
            unranked.push(json!({
                "route_ref": route_ref,
                "gap_reason_code": "attempt_evidence_gap",
                "evidence_age_ms": Value::Null,
            }));
            continue;
        }
        let mut total_minor: u64 = 0;
        let mut successes: u64 = 0;
        let mut priced_all = true;
        for record in &invocations {
            if record["outcome"].as_str() == Some("succeeded") {
                successes += 1;
            }
            match price_mix(&schedule, &record["evidence"]["billed_token_mix"]) {
                Some(cost) => total_minor = total_minor.saturating_add(cost),
                None => priced_all = false,
            }
        }
        if !priced_all {
            unranked.push(json!({
                "route_ref": route_ref,
                "gap_reason_code": "attempt_evidence_gap",
                "evidence_age_ms": Value::Null,
            }));
            continue;
        }
        if successes == 0 {
            // A success rate is never synthesized to complete a ranking, and cost per successful
            // unit is undefined with no successes — the contract's positive-integer floor refuses
            // such a row anyway, so it is carried as the typed gap it is.
            unranked.push(json!({
                "route_ref": route_ref,
                "gap_reason_code": "no_successful_unit_observed",
                "evidence_age_ms": Value::Null,
            }));
            continue;
        }
        let observed_at = schedule["object"]["observed_at_ms"].as_u64().unwrap_or(now);
        ranked.push(json!({
            "route_ref": route_ref,
            "rank": 1,
            "cost_per_successful_unit": {
                "currency_code": currency,
                "minor_units": total_minor / successes,
            },
            "successful_unit_count": successes,
            "attempted_unit_count": invocations.len() as u64,
            "explanatory_effective_cost_per_token_minor": Value::Null,
            "break_even_range": { "low_meter_units": 0, "high_meter_units": 0 },
            "evidence": {
                "price_schedule_ref": schedule["object"]["price_schedule_ref"],
                "price_schedule_body_hash": schedule["object"]["body_hash"],
                "evidence_age_ms": now.saturating_sub(observed_at),
                "confidence": schedule["object"]["confidence"],
                "attempt_receipt_refs": invocations
                    .iter()
                    .filter_map(|record| record["model_invocation_receipt"]["receipt_ref"].as_str())
                    .collect::<Vec<_>>(),
            },
            "reason_codes": ["ranked_by_cost_per_successful_unit"],
        }));
    }

    ranked.sort_by_key(|row| {
        row["cost_per_successful_unit"]["minor_units"]
            .as_u64()
            .unwrap_or(0)
    });
    for (index, row) in ranked.iter_mut().enumerate() {
        row["rank"] = json!(index as u64 + 1);
    }

    let comparison = json!({
        "schema_version": "ioi.components.model-router.model-route-cost-comparison.v1",
        "comparison_ref": format!(
            "route-cost-comparison://{}",
            &digest(format!("{workload_ref}|{now}").as_bytes())[7..23]
        ),
        "workload_ref": workload_ref,
        "currency_code": currency,
        "ranked_candidates": ranked,
        "unranked_candidates": unranked,
        "excluded_candidates": excluded,
        // Never negotiable, and never from the caller.
        "advisory_only": true,
        "computed_at_ms": now,
    });
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            COMPARISON_CONTRACT_ID,
            &comparison,
        )
    {
        return Err(bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "model_route_candidate_comparison_invalid",
            format!("the assembled comparison violates its registered contract and is NOT served: {error}"),
        ));
    }
    Ok(comparison)
}

/// POST /v1/hypervisor/model-routes/cost-comparison — advisory, and it authorizes nothing.
pub(crate) async fn handle_cost_comparison(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(refusal) => return scope_refusal_reply(refusal),
    };
    let Some(owner_ref) = identity.tenant_refs.iter().next().cloned() else {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    };
    match build_cost_comparison(&st.data_dir, &identity, &owner_ref, &body) {
        Ok(comparison) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "cost_comparison": comparison })),
        ),
        Err(response) => response,
    }
}

#[cfg(test)]
mod model_route_candidate_tests {
    use super::super::substrate_store::{request_identity_for_test, reset_handle_for_test};
    use super::*;

    const TENANT: &str = "org://acme";
    const PRINCIPAL: &str = "user://acme-operator";

    fn caller(key: &str) -> WriteCaller {
        WriteCaller {
            identity: request_identity_for_test(PRINCIPAL, [TENANT.to_string()]),
            owner_ref: TENANT.to_string(),
            idempotency_key: key.to_string(),
        }
    }

    struct Fx {
        _dir: tempfile::TempDir,
        data_dir: String,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap().to_owned();
        reset_handle_for_test();
        Fx {
            _dir: dir,
            data_dir,
        }
    }

    fn declared() -> Value {
        json!({
            "route_ref": "model-route://provider-alpha/opus-class/1",
            "provider_ref": "provider://provider-alpha",
            "currency_code": "USD",
            "validity_seconds": 3600,
            "price_components": [
                { "component_class": "input_tokens", "meter_unit": "per_token", "minor_units_per_meter_unit": 3 }
            ],
            "provenance": {
                "source_class": "provider_published",
                "evidence_refs": ["evidence://model-router/provider-alpha/page/1"],
                "observed_from_ref": null
            },
            "confidence": "published"
        })
    }

    /// The positive case FIRST: a battery that only proves refusals can pass because nothing
    /// works at all, which this estate has already paid for once.
    #[test]
    fn a_declared_schedule_is_admitted_with_a_server_derived_window_and_authorizes_nothing() {
        let fxt = fx();
        let (record, replayed) = mint_price_schedule(&fxt.data_dir, &caller("s1"), &declared())
            .expect("a well-formed schedule is admitted");
        assert!(!replayed);
        let object = &record["object"];
        assert_eq!(object["advisory_only"], json!(true));
        let observed = object["observed_at_ms"].as_u64().unwrap();
        let expires = object["expires_at_ms"].as_u64().unwrap();
        assert_eq!(
            expires - observed,
            3_600_000,
            "the window is derived from validity_seconds"
        );
        assert!(object["price_schedule_ref"]
            .as_str()
            .unwrap()
            .starts_with("price-schedule://"));
        assert!(object["body_hash"].as_str().unwrap().starts_with("sha256:"));
        // The admitted object is exactly what the registered contract admits.
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            PRICE_SCHEDULE_CONTRACT_ID,
            object,
        )
        .expect("the admitted schedule satisfies its registered contract");
        reset_handle_for_test();
    }

    /// The window is the whole point of the lane: a caller that sets its own expiry mints a
    /// schedule that never goes stale, and staleness is what makes a ranking refuse to price.
    #[test]
    fn a_caller_supplied_window_is_refused_so_a_schedule_cannot_be_born_immortal() {
        let fxt = fx();
        for field in [
            "expires_at_ms",
            "observed_at_ms",
            "advisory_only",
            "body_hash",
        ] {
            let mut body = declared();
            body[field] = json!(1);
            let error = mint_price_schedule(&fxt.data_dir, &caller("s2"), &body)
                .expect_err("a server-derived field cannot be supplied");
            assert_eq!(error.0, StatusCode::BAD_REQUEST, "field {field}");
            assert!(
                error
                    .1
                     .0
                    .to_string()
                    .contains("model_route_candidate_server_derived_field"),
                "field {field}"
            );
        }
        reset_handle_for_test();
    }

    #[test]
    fn a_floating_point_price_and_an_empty_schedule_both_refuse() {
        let fxt = fx();
        let mut floaty = declared();
        floaty["price_components"][0]["minor_units_per_meter_unit"] = json!(3.5);
        let error = mint_price_schedule(&fxt.data_dir, &caller("s3"), &floaty)
            .expect_err("a float price is refused");
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error
            .1
             .0
            .to_string()
            .contains("model_route_candidate_contract_invalid"));

        let mut empty = declared();
        empty["price_components"] = json!([]);
        let error = mint_price_schedule(&fxt.data_dir, &caller("s4"), &empty)
            .expect_err("an empty schedule is refused");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error
            .1
             .0
            .to_string()
            .contains("model_route_candidate_components_required"));
        reset_handle_for_test();
    }

    /// A replayed mint returns the ORIGINAL projection: the same key must not mint a second
    /// schedule with a fresh window, which would silently rejuvenate a stale one.
    #[test]
    fn a_same_key_replay_returns_the_original_window_rather_than_a_fresh_one() {
        let fxt = fx();
        let (first, _) = mint_price_schedule(&fxt.data_dir, &caller("s5"), &declared()).unwrap();
        let (second, replayed) =
            mint_price_schedule(&fxt.data_dir, &caller("s5"), &declared()).unwrap();
        assert!(replayed, "the same idempotency key replays");
        assert_eq!(
            first["object"]["expires_at_ms"], second["object"]["expires_at_ms"],
            "a replay must not rejuvenate the window"
        );
        assert_eq!(first["object"]["body_hash"], second["object"]["body_hash"]);
        reset_handle_for_test();
    }

    // ------------------------------------------------------------ the comparison's arithmetic
    //
    // The end-to-end comparison needs an admitted rights contract and real invocation receipts,
    // which is a JOURNEY and belongs to this unit's verifier rather than to a unit test that
    // would have to mint half the estate to reach one assertion. What IS unit-testable is the
    // arithmetic and the gap selection, and those are where a silent wrong answer would live.

    fn schedule_with(components: Value) -> Value {
        json!({ "object": { "price_components": components } })
    }

    /// Only REPORTED classes contribute. `None` means unreported, never zero — the distinction
    /// the whole meter is built on — so a mix that omits a class must not be priced as if the
    /// provider had reported nought of it.
    #[test]
    fn price_mix_counts_only_what_was_reported_and_only_what_is_priced() {
        let schedule = schedule_with(json!([
            { "component_class": "input_tokens", "meter_unit": "per_token", "minor_units_per_meter_unit": 3 },
            { "component_class": "output_tokens", "meter_unit": "per_token", "minor_units_per_meter_unit": 15 },
        ]));
        // 100 input at 3 + 10 output at 15 = 450. cache_read is REPORTED but unpriced, and
        // reasoning is priced by nothing and reported as null: neither contributes.
        let mix = json!({ "input": 100, "output": 10, "cache_read": 7, "reasoning": Value::Null });
        assert_eq!(price_mix(&schedule, &mix), Some(450));

        // The same mix with output UNREPORTED prices strictly less, rather than the same.
        let partial = json!({ "input": 100, "output": Value::Null });
        assert_eq!(price_mix(&schedule, &partial), Some(300));
    }

    /// Tiering: the lowest rate the schedule carries for a class is the one applied, so a volume
    /// tier cannot be skipped by listing it second.
    #[test]
    fn price_mix_applies_the_lowest_rate_a_class_carries() {
        let schedule = schedule_with(json!([
            { "component_class": "input_tokens", "meter_unit": "per_token", "minor_units_per_meter_unit": 3,
              "tier": { "from_meter_units": 0, "to_meter_units": 1000 } },
            { "component_class": "input_tokens", "meter_unit": "per_token", "minor_units_per_meter_unit": 2,
              "tier": { "from_meter_units": 1000, "to_meter_units": Value::Null } },
        ]));
        assert_eq!(price_mix(&schedule, &json!({ "input": 10 })), Some(20));
    }

    /// Arithmetic REFUSES rather than wraps, exactly as the billing chain does.
    #[test]
    fn price_mix_refuses_an_overflowing_charge_rather_than_wrapping() {
        let schedule = schedule_with(json!([
            { "component_class": "input_tokens", "meter_unit": "per_token",
              "minor_units_per_meter_unit": u64::MAX },
        ]));
        assert_eq!(price_mix(&schedule, &json!({ "input": 2 })), None);
    }

    /// A missing schedule and an expired one are DIFFERENT typed gaps, because the operator's
    /// next action differs: one is "publish a schedule", the other is "refresh it".
    #[test]
    fn a_missing_schedule_and_an_expired_one_are_distinct_typed_gaps() {
        let fxt = fx();
        let route = "model-route://provider-alpha/opus-class/1";
        let now = now_ms();
        assert_eq!(
            schedule_for_route(&fxt.data_dir, TENANT, route, now),
            Err("no_price_schedule")
        );

        mint_price_schedule(&fxt.data_dir, &caller("gap-1"), &declared()).unwrap();
        assert!(
            schedule_for_route(&fxt.data_dir, TENANT, route, now).is_ok(),
            "a live schedule resolves"
        );
        // One second past its one-hour window.
        let expired_at = now + 3_600_001;
        assert_eq!(
            schedule_for_route(&fxt.data_dir, TENANT, route, expired_at),
            Err("price_schedule_expired")
        );
        reset_handle_for_test();
    }

    /// Another owner's schedule is not this owner's evidence.
    #[test]
    fn a_schedule_belonging_to_another_owner_does_not_resolve() {
        let fxt = fx();
        mint_price_schedule(&fxt.data_dir, &caller("owner-1"), &declared()).unwrap();
        assert_eq!(
            schedule_for_route(
                &fxt.data_dir,
                "org://someone-else",
                "model-route://provider-alpha/opus-class/1",
                now_ms(),
            ),
            Err("no_price_schedule")
        );
        reset_handle_for_test();
    }
}
