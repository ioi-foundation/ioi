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
}
