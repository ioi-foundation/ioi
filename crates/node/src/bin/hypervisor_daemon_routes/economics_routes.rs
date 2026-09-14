//! Commercial economics plane (W1.4) — the managed-work billing kernel over REAL substrate,
//! binding the REGISTERED canon shapes (`economics-and-settlement.md`,
//! `schema://ioi/foundations/managed-work-billing-ledger-bundle/v1`):
//!
//!   versioned RateCard + Plan  ->  immutable WorkQuote  ->  finite CreditHold
//!     ->  append-only UsageRecord chain  ->  typed OverrunDecision
//!     ->  exactly one FinalDebit (spend-authority gated)  ->  append-only BillingAdjustment
//!     ->  exportable ManagedWorkBillingLedgerBundle v1 (contract-validated)  ->  reconciliation
//!
//! Hard boundaries (enforced, not decorative):
//!   * INTEGER-ONLY amounts: Work Credits are integer `micro_work_credit`; money is integer
//!     currency-minor. A float, a fraction, or a decimal string refuses typed. The existing
//!     f64 budget substrate is NOT inherited here.
//!   * A caller can never supply a charge, a required hold, a sequence, or a body hash —
//!     every derived quantity is recomputed server-side with checked arithmetic.
//!   * No spend without authority: FinalDebit admission requires a live `spend` authority
//!     grant whose budget covers the debit. The grant ladder is the authority plane's; this
//!     module only consumes it.
//!   * Exactly one FinalDebit per quote — enforced by the substrate (the debit's resource
//!     identity derives from the quote, so a second genesis refuses), not by a read check.
//!   * The usage chain is serialized through one owner-scoped stream per quote (CAS on the
//!     admitted head), so a sequence fork cannot exist even under concurrent appends.
//!   * NO settlement, escrow, payout, or exchange execution lives here. Canon assigns
//!     payments/escrow/exchange APIs to wallet.network (`api-authority-scopes.md`,
//!     `doctrine.md`); the bundle carries evidence for those rails, never their truth.
//!     `assurance_status` is honestly `internal_event_log` until supplier reconciliation.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::{persist_record, read_record_dir, DaemonState};

const ECON_NAMESPACE: &str = "hypervisor-economics";
const KIND_RATE_CARD: &str = "economics-rate-cards";
const KIND_PLAN: &str = "economics-plans";
const KIND_QUOTE: &str = "economics-quotes";
const KIND_HOLD: &str = "economics-holds";
const KIND_USAGE_CHAIN: &str = "economics-usage-chains";
const KIND_OVERRUN: &str = "economics-overrun-decisions";
const KIND_DEBIT: &str = "economics-final-debits";
const KIND_ADJUSTMENT_CHAIN: &str = "economics-adjustment-chains";

/// The meter class a model invocation charges under. Named here, in the ledger that prices it,
/// rather than spelled as a literal at the invocation site — a meter class the rate card does not
/// carry refuses at admission, and a typo would refuse as `economics_meter_unknown` and read like
/// an operator's un-priced rate card rather than a daemon bug.
pub(crate) const METER_MODEL_TOKENS: &str = "model_tokens";
/// The usage-chain stream a quote's appends serialize through. The invocation join records this so
/// a reader can walk from one invocation to the whole billed chain without re-deriving the tail.
pub(crate) fn usage_chain_ref_for(quote_ref: &str) -> String {
    format!("usage-chain://{}", tail_of(quote_ref))
}

const BUNDLE_CONTRACT_ID: &str = "schema://ioi/foundations/managed-work-billing-ledger-bundle/v1";
// M07.5 — the bundle's v2 successor carries the usage record's owner-derived metering members
// (dimensions, frozen price hashes, interval, idempotency identity, entitlement consumption). A
// chain whose every record carries them exports under v2; a chain with pre-M07.5 records still
// exports under v1, which remains registered and valid — the exporter says which contract it met.
const BUNDLE_CONTRACT_ID_V2: &str =
    "schema://ioi/foundations/managed-work-billing-ledger-bundle/v2";
const BUNDLE_SCHEMA_V1: &str = "ioi.foundations.managed-work-billing-ledger-bundle.v1";
const BUNDLE_SCHEMA_V2: &str = "ioi.foundations.managed-work-billing-ledger-bundle.v2";
/// The one runtime-receipt scheme whose owner record this module can read for metering
/// dimensions today (the model-invocation plane). Every other scheme yields typed nulls and a
/// `caller_asserted` derivation — said on the record, never guessed.
const MODEL_INVOCATION_PREFIX: &str = "model-invocation://";
/// The dimensions a usage aggregate may be keyed by. Read-derived over admitted chains; a key
/// outside this set refuses rather than aggregating by a field nobody registered.
const AGGREGATE_DIMENSIONS: &[&str] = &[
    "tenant_ref",
    "principal_ref",
    "provider_ref",
    "model_route_ref",
    "package_release_ref",
    "worker_instance_ref",
    "meter_class",
    "resource_class",
];
const MAX_VALIDITY_SECONDS: u64 = 31_536_000; // one year
const MICRO_PER_WORK_CREDIT: u64 = 1_000_000;
/// The registered charge components (`meter_rate.charge_component`).
const CHARGE_COMPONENTS: &[&str] = &[
    "managed_model",
    "managed_runtime",
    "broker",
    "participant",
    "verifier",
    "ioi_managed_service",
    "non_billable_telemetry",
];
/// ACC-11 clause 9 — NETWORK/OPEN WORK DRAWS A SEPARATE BUDGET FROM MANAGED WORK.
///
/// The registered `charge_component` vocabulary already draws this line, so the budget is
/// partitioned by it rather than by a second classification that could disagree with it.
/// `non_billable_telemetry` is deliberately in NEITHER list: it is zero-rate and fenced out
/// of the billable chain at admission, so it can ride either class's card without funding
/// either budget.
const NETWORK_WORK_CHARGE_COMPONENTS: &[&str] = &["broker", "participant", "verifier"];
const MANAGED_CHARGE_COMPONENTS: &[&str] =
    &["managed_model", "managed_runtime", "ioi_managed_service"];

/// The budget class one set of meter rates funds, or a refusal when it would fund both.
///
/// SEPARATION IS STRUCTURAL, NOT ARITHMETIC. One quote binds one rate card and resolves one
/// billing account, so a card pricing both a managed and a network/open component could only
/// ever draw ONE budget for both — which is precisely what clause 9 forbids. Choosing a class
/// for such a card would make the separation a convention that the next caller can bend; the
/// card is refused at admission instead, so no quote, hold, usage record or debit downstream
/// can straddle the two budgets. A card with no billable meter at all funds the managed
/// budget: it can charge nothing, and minting a third account for it would make the accounts
/// describe cards rather than budgets.
fn budget_class_of_meter_rates(meter_rates: &[Value]) -> Result<&'static str, Reply> {
    let mut managed = false;
    let mut network = false;
    for rate in meter_rates {
        let component = rate["charge_component"].as_str().unwrap_or_default();
        managed |= MANAGED_CHARGE_COMPONENTS.contains(&component);
        network |= NETWORK_WORK_CHARGE_COMPONENTS.contains(&component);
    }
    match (managed, network) {
        (true, true) => Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_budget_class_mixed",
            "network/open work draws a separate budget from managed work, so one rate card cannot price both: put the broker/participant/verifier meters on their own card",
        )),
        (false, true) => Ok("network_work"),
        _ => Ok("managed"),
    }
}

const COMMERCIAL_POSTURES: &[&str] = &[
    "managed",
    "customer_byok",
    "customer_byoa",
    "customer_cloud",
    "self_hosted",
    "local",
];
/// Postures whose provider cost is customer-borne: `provider_cost_minor` MUST be zero.
const CUSTOMER_BORNE_POSTURES: &[&str] = &[
    "customer_byok",
    "customer_byoa",
    "customer_cloud",
    "self_hosted",
    "local",
];
const RESET_POLICIES: &[&str] = &[
    "non_resetting",
    "monthly_expiring",
    "contract_term_expiring",
];

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}

fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
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
                "economics_body_hash_failed",
                error.to_string(),
            )
        })
}

/// INTEGER-ONLY unit extraction. A float, fraction, negative, or decimal string refuses typed —
/// the unit law of economics-and-settlement.md, enforced at the boundary.
fn units_field(body: &Value, key: &str, required: bool) -> Result<Option<u64>, Reply> {
    match body.get(key) {
        None | Some(Value::Null) => {
            if required {
                Err(bad(
                    StatusCode::BAD_REQUEST,
                    "economics_integer_amount_required",
                    format!("{key} is required as an integer micro_work_credit / integer unit count"),
                ))
            } else {
                Ok(None)
            }
        }
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            bad(
                StatusCode::BAD_REQUEST,
                "economics_integer_amount_required",
                format!("{key} must be a non-negative integer — floats, fractions, decimal strings, and implicit conversion are invalid amounts"),
            )
        }),
    }
}

fn work_credits(units: u64) -> Value {
    json!({ "unit": "micro_work_credit", "units": units })
}

fn wc_units(amount: &Value) -> u64 {
    amount.get("units").and_then(Value::as_u64).unwrap_or(0)
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
            "economics_ref_invalid",
            format!("{key} must be a canonical scheme://ref"),
        ));
    }
    Ok(value.to_string())
}

/// Refuse caller-supplied server-derived fields BEFORE any of them could be read.
fn refuse_server_derived(body: &Value, fields: &[&str]) -> Result<(), Reply> {
    for field in fields {
        if body.get(*field).is_some() {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "economics_server_derived_field",
                format!("{field} is derived server-side with checked arithmetic and cannot be supplied by the caller"),
            ));
        }
    }
    Ok(())
}

fn validity_seconds(body: &Value) -> Result<u64, Reply> {
    let seconds = units_field(body, "validity_seconds", true)?.unwrap_or(0);
    if seconds == 0 || seconds > MAX_VALIDITY_SECONDS {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_validity_invalid",
            format!("validity_seconds must be between 1 and {MAX_VALIDITY_SECONDS}"),
        ));
    }
    Ok(seconds)
}

fn project_admission(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(super::iso_now());
}

fn project_or_fail(data_dir: &str, kind: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "economics_persistence_failed",
            "the transition is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

/// Genesis mint with the stored-record replay short-circuit: a replayed mint returns the
/// original projection (original windows, original hashes) rather than recomputing anything.
#[allow(clippy::too_many_arguments)]
fn mint_record(
    data_dir: &str,
    caller: &WriteCaller,
    kind: &str,
    id: &str,
    resource_ref: &str,
    op_kind: &str,
    admitted_payload: &Value,
    record: Value,
) -> Result<(Value, bool), Reply> {
    let commit = admit_owner_scoped_write(
        data_dir,
        caller,
        ECON_NAMESPACE,
        kind,
        resource_ref,
        op_kind,
        None,
        admitted_payload,
    )?;
    if commit.replayed {
        if let Some(existing) = load(data_dir, kind, id) {
            return Ok((existing, true));
        }
        // admitted but never projected (crash between admit and persist): reconcile below.
    }
    let mut record = record;
    record["created_at"] = json!(super::iso_now());
    project_admission(&mut record, &commit);
    project_or_fail(data_dir, kind, id, &record)?;
    Ok((record, commit.replayed))
}

/// Owner-scoped read: identity FIRST (401 before any 404 existence oracle), then the record,
/// then tenant authorization against its owner.
fn authorized_record(
    data_dir: &str,
    headers: &HeaderMap,
    kind: &str,
    id: &str,
) -> Result<Value, Reply> {
    let identity = super::substrate_store::resolve_request_identity(data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let Some(record) = load(data_dir, kind, id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_record_not_found",
            "no record exists at this id",
        ));
    };
    if !record["owner_ref"]
        .as_str()
        .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref))
    {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    Ok(record)
}

fn object_of(record: &Value) -> &Value {
    &record["object"]
}

// ================================ RateCard =====================================================

/// POST /v1/hypervisor/economics/rate-cards — mint one immutable versioned rate card.
pub(crate) async fn handle_rate_card_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_rate_card(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => created_reply("rate_card", record, replayed),
        Err(response) => response,
    }
}

fn mint_rate_card(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> Result<(Value, bool), Reply> {
    refuse_server_derived(
        body,
        &["body_hash", "issued_at_ms", "expires_at_ms", "version"],
    )?;
    let currency = str_field(body, "currency_code");
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_currency_invalid",
            "currency_code must be a three-letter uppercase ISO code",
        ));
    }
    let fee_policy_ref = require_ref(body, "ioi_fee_policy_ref")?;
    let seconds = validity_seconds(body)?;
    let Some(rates) = body.get("meter_rates").and_then(Value::as_array) else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_meter_rates_required",
            "meter_rates must be a non-empty array of {meter_class, work_credit_micro_units_per_meter_unit, charge_component}",
        ));
    };
    if rates.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_meter_rates_required",
            "meter_rates must be non-empty",
        ));
    }
    let mut meter_rates = Vec::new();
    for rate in rates {
        let meter_class = str_field(rate, "meter_class");
        let component = str_field(rate, "charge_component");
        let units = units_field(rate, "work_credit_micro_units_per_meter_unit", true)?.unwrap_or(0);
        if meter_class.is_empty() {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "economics_meter_class_invalid",
                "every meter rate names a non-empty meter_class",
            ));
        }
        if !CHARGE_COMPONENTS.contains(&component) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "economics_charge_component_invalid",
                format!("charge_component must be one of {CHARGE_COMPONENTS:?}"),
            ));
        }
        if component == "non_billable_telemetry" && units != 0 {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "economics_telemetry_never_billable",
                "coarse OCU / telemetry meters are always non-billable: their rate must be zero",
            ));
        }
        meter_rates.push(json!({
            "meter_class": meter_class,
            "work_credit_micro_units_per_meter_unit": units,
            "charge_component": component,
        }));
    }
    // Refused at the SOURCE so no mixed card can exist to be quoted from later.
    budget_class_of_meter_rates(&meter_rates)?;
    let id = replay_stable_id("erc", &caller.owner_ref, &caller.idempotency_key);
    let rate_card_ref = format!("rate-card://{id}");
    let admitted = json!({
        "rate_card_ref": rate_card_ref,
        "version": 1,
        "currency_code": currency,
        "meter_rates": meter_rates,
        "ioi_fee_policy_ref": fee_policy_ref,
        "validity_seconds": seconds,
    });
    let now = now_ms();
    let mut object = admitted.clone();
    if let Some(map) = object.as_object_mut() {
        map.remove("validity_seconds");
    }
    object["issued_at_ms"] = json!(now);
    object["expires_at_ms"] = json!(now.saturating_add(seconds.saturating_mul(1000)));
    object["body_hash"] = json!(body_hash_of(&object)?);
    let record = json!({ "owner_ref": caller.owner_ref, "object": object });
    mint_record(
        data_dir,
        caller,
        KIND_RATE_CARD,
        &id,
        &rate_card_ref,
        "economics.rate_card.create",
        &admitted,
        record,
    )
}

pub(crate) async fn handle_rate_card_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized_record(&st.data_dir, &headers, KIND_RATE_CARD, &id) {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "rate_card": record })),
        ),
        Err(reply) => reply,
    }
}

// ================================ Plan =========================================================

pub(crate) async fn handle_plan_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_plan(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => created_reply("plan", record, replayed),
        Err(response) => response,
    }
}

fn resolve_unexpired<'a>(record: &'a Value, what: &str, now: u64) -> Result<&'a Value, Reply> {
    let object = object_of(record);
    if object["expires_at_ms"].as_u64().unwrap_or(0) <= now {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_input_expired",
            format!("the referenced {what} is expired; admission fails rather than pricing from a dead input"),
        ));
    }
    Ok(object)
}

fn tail_of(reference: &str) -> &str {
    reference.rsplit("://").next().unwrap_or(reference)
}

fn mint_plan(data_dir: &str, caller: &WriteCaller, body: &Value) -> Result<(Value, bool), Reply> {
    refuse_server_derived(
        body,
        &[
            "body_hash",
            "issued_at_ms",
            "expires_at_ms",
            "version",
            "rate_card_body_hash",
        ],
    )?;
    let rate_card_ref = require_ref(body, "rate_card_ref")?;
    let reset_policy = str_field(body, "reset_policy");
    if !RESET_POLICIES.contains(&reset_policy) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_reset_policy_invalid",
            format!("reset_policy must be one of {RESET_POLICIES:?}"),
        ));
    }
    let included = units_field(body, "included_work_credit_units", true)?.unwrap_or(0);
    let seconds = validity_seconds(body)?;
    let now = now_ms();
    let Some(card) = load(data_dir, KIND_RATE_CARD, tail_of(&rate_card_ref)) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_rate_card_not_found",
            "rate_card_ref does not resolve to an admitted rate card",
        ));
    };
    if card["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let card_object = resolve_unexpired(&card, "rate card", now)?;
    let card_hash = card_object["body_hash"].as_str().unwrap_or("").to_string();
    let id = replay_stable_id("epl", &caller.owner_ref, &caller.idempotency_key);
    let plan_ref = format!("plan://{id}");
    let admitted = json!({
        "plan_ref": plan_ref,
        "version": 1,
        "rate_card_ref": rate_card_ref,
        "rate_card_body_hash": card_hash,
        "included_work_credits": work_credits(included),
        "reset_policy": reset_policy,
        "validity_seconds": seconds,
    });
    let mut object = admitted.clone();
    if let Some(map) = object.as_object_mut() {
        map.remove("validity_seconds");
    }
    object["issued_at_ms"] = json!(now);
    object["expires_at_ms"] = json!(now.saturating_add(seconds.saturating_mul(1000)));
    object["body_hash"] = json!(body_hash_of(&object)?);
    let record = json!({ "owner_ref": caller.owner_ref, "object": object });
    mint_record(
        data_dir,
        caller,
        KIND_PLAN,
        &id,
        &plan_ref,
        "economics.plan.create",
        &admitted,
        record,
    )
}

pub(crate) async fn handle_plan_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized_record(&st.data_dir, &headers, KIND_PLAN, &id) {
        Ok(record) => (StatusCode::OK, Json(json!({ "ok": true, "plan": record }))),
        Err(reply) => reply,
    }
}

// ================================ WorkQuote ====================================================

pub(crate) async fn handle_quote_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_quote(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => created_reply("quote", record, replayed),
        Err(response) => response,
    }
}

fn mint_quote(data_dir: &str, caller: &WriteCaller, body: &Value) -> Result<(Value, bool), Reply> {
    refuse_server_derived(
        body,
        &[
            "body_hash",
            "issued_at_ms",
            "expires_at_ms",
            "required_hold",
            "rate_card_body_hash",
            "plan_body_hash",
        ],
    )?;
    let rate_card_ref = require_ref(body, "rate_card_ref")?;
    let plan_ref = require_ref(body, "plan_ref")?;
    let work_ref = require_ref(body, "work_ref")?;
    let estimated = units_field(body, "estimated_work_credit_units", true)?.unwrap_or(0);
    let overrun_policy = str_field(body, "overrun_policy");
    if !["block", "exact_additional_hold"].contains(&overrun_policy) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_overrun_policy_invalid",
            "overrun_policy must be block or exact_additional_hold",
        ));
    }
    let max_attempts = units_field(body, "max_attempt_count", true)?.unwrap_or(0);
    if max_attempts == 0 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_max_attempts_invalid",
            "max_attempt_count must be a positive integer",
        ));
    }
    let postures: Vec<String> = body
        .get("allowed_commercial_postures")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if postures.is_empty()
        || postures
            .iter()
            .any(|p| !COMMERCIAL_POSTURES.contains(&p.as_str()))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_postures_invalid",
            format!(
                "allowed_commercial_postures must be a non-empty subset of {COMMERCIAL_POSTURES:?}"
            ),
        ));
    }
    let seconds = validity_seconds(body)?;
    let now = now_ms();
    let Some(card) = load(data_dir, KIND_RATE_CARD, tail_of(&rate_card_ref)) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_rate_card_not_found",
            "rate_card_ref does not resolve",
        ));
    };
    let Some(plan) = load(data_dir, KIND_PLAN, tail_of(&plan_ref)) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_plan_not_found",
            "plan_ref does not resolve",
        ));
    };
    for record in [&card, &plan] {
        if record["owner_ref"] != json!(caller.owner_ref) {
            return Err(scope_refusal_reply(
                super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
            ));
        }
    }
    let card_object = resolve_unexpired(&card, "rate card", now)?;
    let plan_object = resolve_unexpired(&plan, "plan", now)?;
    if plan_object["rate_card_ref"] != json!(rate_card_ref)
        || plan_object["rate_card_body_hash"] != card_object["body_hash"]
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_plan_rate_card_mismatch",
            "the plan does not bind this exact rate card's bytes; a quote cannot price from a substituted input",
        ));
    }
    // The quote may never outlive either input (registered invariant: quote window inside both).
    let expires = [
        now.saturating_add(seconds.saturating_mul(1000)),
        card_object["expires_at_ms"].as_u64().unwrap_or(0),
        plan_object["expires_at_ms"].as_u64().unwrap_or(0),
    ]
    .into_iter()
    .min()
    .unwrap_or(0);
    if expires <= now {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_quote_window_empty",
            "the quote's validity window is empty because an input expires first",
        ));
    }
    let id = replay_stable_id("eqt", &caller.owner_ref, &caller.idempotency_key);
    let quote_ref = format!("work-quote://{id}");
    let admitted = json!({
        "quote_ref": quote_ref,
        "rate_card_ref": rate_card_ref,
        "rate_card_body_hash": card_object["body_hash"],
        "plan_ref": plan_ref,
        "plan_body_hash": plan_object["body_hash"],
        "estimated_work_credits": work_credits(estimated),
        "overrun_policy": overrun_policy,
        "max_attempt_count": max_attempts,
        "allowed_commercial_postures": postures,
        "work_ref": work_ref,
        "validity_seconds": seconds,
    });
    let mut object = admitted.clone();
    if let Some(map) = object.as_object_mut() {
        map.remove("validity_seconds");
        map.remove("work_ref");
    }
    // required_hold is server-derived: the initial hold must cover the full estimate.
    object["required_hold"] = work_credits(estimated);
    object["issued_at_ms"] = json!(now);
    object["expires_at_ms"] = json!(expires);
    object["body_hash"] = json!(body_hash_of(&object)?);
    let record = json!({
        "owner_ref": caller.owner_ref,
        "object": object,
        "work_ref": work_ref,
        // ONE OWNER, ONE ACCOUNT PER BUDGET CLASS (ACC-11 clause 9). The class is derived from
        // the bound card's own meter rates rather than taken from the caller, so network/open
        // work cannot be billed to the managed budget by asking for it.
        "billing_account_ref": format!(
            "billing-account://{}/{}",
            &digest(caller.owner_ref.as_bytes())[7..23],
            budget_class_of_meter_rates(
                card_object["meter_rates"].as_array().map_or(&[][..], Vec::as_slice)
            )?
        ),
    });
    mint_record(
        data_dir,
        caller,
        KIND_QUOTE,
        &id,
        &quote_ref,
        "economics.quote.create",
        &admitted,
        record,
    )
}

pub(crate) async fn handle_quote_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized_record(&st.data_dir, &headers, KIND_QUOTE, &id) {
        Ok(record) => (StatusCode::OK, Json(json!({ "ok": true, "quote": record }))),
        Err(reply) => reply,
    }
}

// ================================ CreditHold ===================================================

pub(crate) async fn handle_hold_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_hold(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => created_reply("hold", record, replayed),
        Err(response) => response,
    }
}

fn holds_for_quote(data_dir: &str, quote_ref: &str) -> Vec<Value> {
    let mut holds: Vec<Value> = read_record_dir(data_dir, KIND_HOLD)
        .into_iter()
        .filter(|record| record["object"]["quote_ref"].as_str() == Some(quote_ref))
        .collect();
    holds.sort_by(|a, b| {
        a["object"]["created_at_ms"]
            .as_u64()
            .cmp(&b["object"]["created_at_ms"].as_u64())
            .then(
                a["object"]["hold_ref"]
                    .as_str()
                    .cmp(&b["object"]["hold_ref"].as_str()),
            )
    });
    holds
}

fn mint_hold(data_dir: &str, caller: &WriteCaller, body: &Value) -> Result<(Value, bool), Reply> {
    refuse_server_derived(
        body,
        &["body_hash", "created_at_ms", "expires_at_ms", "status"],
    )?;
    let quote_ref = require_ref(body, "quote_ref")?;
    let amount = units_field(body, "amount_units", true)?.unwrap_or(0);
    let hold_kind = str_field(body, "hold_kind");
    if !["initial", "exact_additional"].contains(&hold_kind) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_hold_kind_invalid",
            "hold_kind must be initial or exact_additional",
        ));
    }
    let now = now_ms();
    let Some(quote) = load(data_dir, KIND_QUOTE, tail_of(&quote_ref)) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_quote_not_found",
            "quote_ref does not resolve",
        ));
    };
    if quote["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let quote_object = resolve_unexpired(&quote, "quote", now)?;
    let overrun_decision_ref = match hold_kind {
        "initial" => {
            if amount == 0 || amount > wc_units(&quote_object["required_hold"]) {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "economics_hold_exceeds_required",
                    "the initial hold must be positive and no greater than the quote's required_hold",
                ));
            }
            if holds_for_quote(data_dir, &quote_ref)
                .iter()
                .any(|h| h["object"]["hold_kind"] == json!("initial"))
            {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "economics_initial_hold_exists",
                    "this quote already carries its initial hold; overruns require a typed decision and an exact_additional hold",
                ));
            }
            Value::Null
        }
        _ => {
            let decision_ref = require_ref(body, "overrun_decision_ref")?;
            let Some(decision) = load(data_dir, KIND_OVERRUN, tail_of(&decision_ref)) else {
                return Err(bad(
                    StatusCode::NOT_FOUND,
                    "economics_overrun_decision_not_found",
                    "overrun_decision_ref does not resolve",
                ));
            };
            let decision_object = object_of(&decision);
            if decision_object["quote_ref"] != json!(quote_ref)
                || decision_object["decision"] != json!("exact_additional_hold")
                || wc_units(&decision_object["additional_hold_amount"]) != amount
            {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "economics_hold_decision_mismatch",
                    "an exact_additional hold must match its overrun decision's quote and exact amount",
                ));
            }
            json!(decision_ref)
        }
    };
    let id = replay_stable_id("ehd", &caller.owner_ref, &caller.idempotency_key);
    let hold_ref = format!("credit-hold://{id}");
    let admitted = json!({
        "hold_ref": hold_ref,
        "quote_ref": quote_ref,
        "idempotency_key": caller.idempotency_key,
        "hold_kind": hold_kind,
        "overrun_decision_ref": overrun_decision_ref,
        "amount": work_credits(amount),
    });
    let mut object = admitted.clone();
    object["created_at_ms"] = json!(now);
    // A hold never outlives its quote.
    object["expires_at_ms"] = quote_object["expires_at_ms"].clone();
    object["status"] = json!("active");
    object["body_hash"] = json!(body_hash_of(&object)?);
    let record = json!({ "owner_ref": caller.owner_ref, "object": object });
    mint_record(
        data_dir,
        caller,
        KIND_HOLD,
        &id,
        &hold_ref,
        "economics.hold.create",
        &admitted,
        record,
    )
}

/// POST /v1/hypervisor/economics/holds/:id/release — an active hold releases; consumed and
/// released are terminal. Idempotent on the released state.
pub(crate) async fn handle_hold_release(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match transition_hold(
        &st.data_dir,
        &caller,
        &id,
        "released",
        "economics.hold.release",
    ) {
        Ok(record) => (StatusCode::OK, Json(json!({ "ok": true, "hold": record }))),
        Err(response) => response,
    }
}

fn transition_hold(
    data_dir: &str,
    caller: &WriteCaller,
    id: &str,
    to_status: &str,
    op_kind: &str,
) -> Result<Value, Reply> {
    let Some(record) = load(data_dir, KIND_HOLD, id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_record_not_found",
            "no hold exists at this id",
        ));
    };
    if record["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let current = record["object"]["status"].as_str().unwrap_or("");
    if current == to_status {
        return Ok(record);
    }
    if current != "active" {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_hold_terminal",
            format!(
                "a {current} hold cannot become {to_status}; consumed and released are terminal"
            ),
        ));
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_expected_head_required",
            "this record predates admitted mutation; it cannot be advanced without a head",
        ));
    };
    let hold_ref = record["object"]["hold_ref"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let commit = admit_owner_scoped_write(
        data_dir,
        caller,
        ECON_NAMESPACE,
        KIND_HOLD,
        &hold_ref,
        op_kind,
        Some(&expected_head),
        &json!({ "hold_ref": hold_ref, "status": to_status }),
    )?;
    let mut successor = record;
    successor["object"]["status"] = json!(to_status);
    successor["object"]["body_hash"] = json!(body_hash_of(&successor["object"])?);
    project_admission(&mut successor, &commit);
    project_or_fail(data_dir, KIND_HOLD, id, &successor)?;
    Ok(successor)
}

pub(crate) async fn handle_hold_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized_record(&st.data_dir, &headers, KIND_HOLD, &id) {
        Ok(record) => (StatusCode::OK, Json(json!({ "ok": true, "hold": record }))),
        Err(reply) => reply,
    }
}

// ================================ UsageRecord chain ============================================

pub(crate) async fn handle_usage_append(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match append_usage(&st.data_dir, &caller, &body) {
        Ok((usage, chain)) => (
            StatusCode::CREATED,
            Json(json!({ "ok": true, "usage_record": usage, "chain_length": chain })),
        ),
        Err(response) => response,
    }
}

fn usage_chain(data_dir: &str, quote_id: &str) -> Option<Value> {
    load(data_dir, KIND_USAGE_CHAIN, quote_id)
}

fn cost_breakdown_from(body: &Value, currency: &str, posture: &str) -> Result<Value, Reply> {
    let supplied = body.get("cost_breakdown");
    let minor = |key: &str| -> Result<u64, Reply> {
        match supplied.and_then(|b| b.get(key)) {
            None | Some(Value::Null) => Ok(0),
            Some(value) => value.as_u64().ok_or_else(|| {
                bad(
                    StatusCode::BAD_REQUEST,
                    "economics_integer_amount_required",
                    format!(
                        "cost_breakdown.{key} must be a non-negative integer currency-minor amount"
                    ),
                )
            }),
        }
    };
    let provider_cost = minor("provider_cost_minor")?;
    if CUSTOMER_BORNE_POSTURES.contains(&posture) && provider_cost != 0 {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_customer_borne_provider_cost",
            "customer-borne postures carry provider cost outside this ledger: provider_cost_minor must be zero",
        ));
    }
    Ok(json!({
        "currency_code": currency,
        "provider_cost_minor": provider_cost,
        "broker_fee_minor": minor("broker_fee_minor")?,
        "participant_cost_minor": minor("participant_cost_minor")?,
        "verifier_cost_minor": minor("verifier_cost_minor")?,
        "ioi_fee_minor": minor("ioi_fee_minor")?,
        "excluded_customer_borne_provider_cost_minor": minor("excluded_customer_borne_provider_cost_minor")?,
        "supplier_reconciliation_state": if supplied.is_some() { "estimated" } else { "not_applicable" },
    }))
}

/// Everything the quote and its rate card determine about ONE metered append, resolved by exactly
/// one function so a PREFLIGHT and the append itself can never disagree.
///
/// The two callers are asymmetric in cost, which is why the shared owner matters: an invocation
/// preflights before it spends a provider call, and the append happens after. A preflight that says
/// yes where the append then says no is a spent provider call with no bill; the reverse is a bill
/// the caller was never warned about. A second copy of this resolution would drift into exactly one
/// of those two.
pub(crate) struct UsageTarget {
    rate_work_credit_micro_units_per_meter_unit: u64,
    charge_component: String,
    currency_code: String,
    // M07.5 — the exact prices a charge was produced under, and the plan allowance it draws on,
    // resolved here once so the record and the entitlement check cannot disagree about them.
    quote_body_hash: String,
    rate_card_body_hash: String,
    plan_ref: String,
    plan_body_hash: String,
    plan_included_units: u64,
    plan_reset_policy: String,
    plan_issued_at_ms: u64,
}

/// PURE READ. Resolves and authorizes a metered append without admitting anything, so a probe on a
/// path that then refuses leaves the substrate exactly as it found it.
pub(crate) fn resolve_usage_target(
    data_dir: &str,
    caller: &WriteCaller,
    quote_ref: &str,
    meter_class: &str,
    posture: &str,
    now: u64,
) -> Result<UsageTarget, Reply> {
    let quote_id = tail_of(quote_ref).to_string();
    let Some(quote) = load(data_dir, KIND_QUOTE, &quote_id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_quote_not_found",
            "quote_ref does not resolve",
        ));
    };
    if quote["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let quote_object = resolve_unexpired(&quote, "quote", now)?;
    if !quote_object["allowed_commercial_postures"]
        .as_array()
        .is_some_and(|allowed| allowed.iter().any(|p| p.as_str() == Some(posture)))
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_posture_not_quoted",
            "commercial_posture is outside the quote's allowed set",
        ));
    }
    // The rate comes from the quote's EXACT rate card bytes — never from the caller.
    let Some(card) = load(
        data_dir,
        KIND_RATE_CARD,
        tail_of(quote_object["rate_card_ref"].as_str().unwrap_or("")),
    ) else {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_rate_card_missing",
            "the quote's rate card projection is unavailable; replay to reconcile",
        ));
    };
    let card_object = object_of(&card);
    if card_object["body_hash"] != quote_object["rate_card_body_hash"] {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_rate_card_substituted",
            "the stored rate card no longer matches the quote's exact bytes; nothing is charged from a substituted card",
        ));
    }
    let Some(meter) = card_object["meter_rates"].as_array().and_then(|rates| {
        rates
            .iter()
            .find(|r| r["meter_class"].as_str() == Some(meter_class))
    }) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_meter_unknown",
            "meter_class is not priced by the quote's rate card",
        ));
    };
    // The plan the quote froze is resolved the same way the card is: exact bytes or nothing. A
    // substituted plan would change the allowance a charge is measured against, silently.
    let plan_ref = quote_object["plan_ref"].as_str().unwrap_or("").to_string();
    let Some(plan) = load(data_dir, KIND_PLAN, tail_of(&plan_ref)) else {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_plan_missing",
            "the quote's plan projection is unavailable; replay to reconcile",
        ));
    };
    let plan_object = object_of(&plan);
    if plan_object["body_hash"] != quote_object["plan_body_hash"] {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_plan_substituted",
            "the stored plan no longer matches the quote's exact bytes; nothing is charged against a substituted plan",
        ));
    }
    Ok(UsageTarget {
        rate_work_credit_micro_units_per_meter_unit: meter
            ["work_credit_micro_units_per_meter_unit"]
            .as_u64()
            .unwrap_or(0),
        charge_component: meter["charge_component"].as_str().unwrap_or("").to_string(),
        currency_code: card_object["currency_code"]
            .as_str()
            .unwrap_or("USD")
            .to_string(),
        quote_body_hash: quote_object["body_hash"].as_str().unwrap_or("").to_string(),
        rate_card_body_hash: card_object["body_hash"].as_str().unwrap_or("").to_string(),
        plan_ref,
        plan_body_hash: plan_object["body_hash"].as_str().unwrap_or("").to_string(),
        plan_included_units: wc_units(&plan_object["included_work_credits"]),
        plan_reset_policy: plan_object["reset_policy"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        plan_issued_at_ms: plan_object["issued_at_ms"].as_u64().unwrap_or(0),
    })
}

// ================================ M07.5 — metering the substrate ==============================
//
// The substrate meters, attests, authorizes, records or settles; only a product owner defines and
// sells product value. What this section adds to the usage chain is ATTRIBUTION and ACCOUNTING,
// never price: every record now says whose work it was (derived from the cited runtime receipts'
// owner records, never from the caller), under which exact frozen prices, over which interval,
// under which idempotent command, and how much of the plan's allowance it consumed — and the chain
// refuses to meter one receipt twice, to charge another tenant's receipt here, or to draw past the
// allowance without a hold that covers the excess.

/// The metering dimensions one append is attributed with, DERIVED from the cited runtime
/// receipts. A `model-invocation://` receipt is read through the model-invocation plane's own
/// admitted record and must belong to the caller's tenant; any other scheme yields typed nulls.
/// The tenant is always the caller's owner (the scope the append was authorized under).
fn derive_metering_dimensions(
    data_dir: &str,
    caller: &WriteCaller,
    receipt_refs: &[String],
    meter_class: &str,
    charge_component: &str,
) -> Result<Value, Reply> {
    let mut principal: Option<Option<String>> = None;
    let mut provider: Option<Option<String>> = None;
    let mut route: Option<Option<String>> = None;
    let mut model: Option<Option<String>> = None;
    let mut resolved_any = false;
    // Merge one dimension across several receipts: equal values keep, a disagreement reads as
    // null (mixed), and a receipt that carries nothing leaves the merge untouched.
    let merge = |slot: &mut Option<Option<String>>, value: Option<String>| match slot {
        None => *slot = Some(value),
        Some(existing) => {
            if *existing != value {
                *existing = None;
            }
        }
    };
    for reference in receipt_refs {
        let Some(id) = reference.strip_prefix(MODEL_INVOCATION_PREFIX) else {
            continue;
        };
        let Some(invocation) = super::provider_transport::admitted_invocation(data_dir, id) else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "economics_receipt_unresolved",
                format!("{reference} names no admitted model invocation; a charge binds to evidence that exists"),
            ));
        };
        if invocation["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
            return Err(bad(
                StatusCode::FORBIDDEN,
                "economics_receipt_foreign_owner",
                format!("{reference} was admitted for another tenant; a tenant's quote cannot be charged with another tenant's work"),
            ));
        }
        resolved_any = true;
        merge(
            &mut principal,
            invocation["acting_principal_ref"]
                .as_str()
                .filter(|value| value.starts_with("user://"))
                .map(str::to_owned),
        );
        merge(
            &mut provider,
            match (
                invocation["transport"].as_str(),
                invocation["base_url"].as_str(),
            ) {
                (Some(transport), Some(base_url)) => Some(format!("{transport}:{base_url}")),
                _ => None,
            },
        );
        merge(
            &mut route,
            invocation["route_ref"].as_str().map(str::to_owned),
        );
        merge(
            &mut model,
            invocation["model_id"].as_str().map(str::to_owned),
        );
    }
    let resource_class = match (meter_class, charge_component) {
        (METER_MODEL_TOKENS, _) => "model",
        (_, "non_billable_telemetry") => "telemetry",
        (_, "managed_runtime") => "compute",
        (_, "verifier") => "verifier",
        (_, "managed_model") => "model",
        _ => "network",
    };
    let flat = |slot: &Option<Option<String>>| -> Value {
        slot.clone()
            .flatten()
            .map(Value::String)
            .unwrap_or(Value::Null)
    };
    Ok(json!({
        "tenant_ref": caller.owner_ref,
        "principal_ref": flat(&principal),
        "worker_instance_ref": Value::Null,
        "package_release_ref": Value::Null,
        "goal_run_ref": Value::Null,
        "session_ref": Value::Null,
        "environment_ref": Value::Null,
        "provider_ref": flat(&provider),
        "model_route_ref": flat(&route),
        "model_id": flat(&model),
        "resource_class": resource_class,
        "usage_class": meter_class,
        "derivation": if resolved_any { "owner_receipt" } else { "caller_asserted" },
    }))
}

/// Every usage chain this owner has admitted, as (quote_id, chain record) pairs — the population
/// dedup and entitlement are derived over. Read from the owner's projections on every call;
/// nothing here is a second index.
fn owner_usage_chains(data_dir: &str, owner_ref: &str) -> Vec<(String, Value)> {
    read_record_dir(data_dir, KIND_USAGE_CHAIN)
        .into_iter()
        .filter(|chain| chain["owner_ref"].as_str() == Some(owner_ref))
        .map(|chain| {
            let quote_id = tail_of(chain["object"]["quote_ref"].as_str().unwrap_or("")).to_string();
            (quote_id, chain)
        })
        .collect()
}

/// A runtime receipt is metered AT MOST ONCE per tenant. The one exception is the same command
/// replaying under the same idempotency key, which the substrate answers with the stored append;
/// a record that cites the receipt under a DIFFERENT key (or a pre-M07.5 record with no key) is a
/// second charge for the same work and is named here.
fn receipt_already_metered(
    data_dir: &str,
    owner_ref: &str,
    receipt_refs: &[String],
    idempotency_key: &str,
) -> Option<(String, String)> {
    for (_, chain) in owner_usage_chains(data_dir, owner_ref) {
        for record in chain["object"]["usage_records"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if record["idempotency_key"].as_str() == Some(idempotency_key) {
                continue;
            }
            let cited = record["runtime_receipt_refs"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            for reference in cited {
                if receipt_refs.iter().any(|candidate| candidate == reference) {
                    return Some((
                        reference.to_owned(),
                        record["usage_ref"].as_str().unwrap_or("").to_owned(),
                    ));
                }
            }
        }
    }
    None
}

/// The first millisecond of the UTC month containing `now_ms` (civil-from-days, no clock crate).
fn utc_month_start_ms(now_ms: u64) -> u64 {
    let days = (now_ms / 86_400_000) as i64;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day_of_month = doy - (153 * mp + 2) / 5; // 0-based
    let month_start_days = days - day_of_month;
    (month_start_days.max(0) as u64) * 86_400_000
}

/// The plan allowance this owner has already drawn under `plan_ref` in the current reset period:
/// the checked sum of every admitted charge on the owner's chains whose quote froze that plan.
fn plan_allowance_consumed(
    data_dir: &str,
    owner_ref: &str,
    target: &UsageTarget,
    now: u64,
) -> Result<u64, Reply> {
    let period_start = match target.plan_reset_policy.as_str() {
        "monthly_expiring" => utc_month_start_ms(now),
        "contract_term_expiring" => target.plan_issued_at_ms,
        _ => 0,
    };
    let mut consumed: u64 = 0;
    for (quote_id, chain) in owner_usage_chains(data_dir, owner_ref) {
        let Some(quote) = load(data_dir, KIND_QUOTE, &quote_id) else {
            continue;
        };
        if object_of(&quote)["plan_ref"].as_str() != Some(target.plan_ref.as_str()) {
            continue;
        }
        for record in chain["object"]["usage_records"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if record["occurred_at_ms"].as_u64().unwrap_or(0) < period_start {
                continue;
            }
            consumed = consumed
                .checked_add(wc_units(&record["charged_work_credits"]))
                .ok_or_else(|| {
                    bad(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "economics_charge_overflow",
                        "the plan's consumed allowance exceeds the safe integer domain",
                    )
                })?;
        }
    }
    Ok(consumed)
}

/// How this charge is covered, or a typed refusal: the plan allowance first, then the quote's
/// active holds for the excess (net of what earlier hold-covered charges on the quote already
/// drew). Nothing here permits an approximate or unbounded draw.
fn entitlement_consumption_for(
    data_dir: &str,
    caller: &WriteCaller,
    target: &UsageTarget,
    quote_ref: &str,
    prior_records: &[Value],
    charged: u64,
    now: u64,
) -> Result<Value, Reply> {
    let consumed_before = plan_allowance_consumed(data_dir, &caller.owner_ref, target, now)?;
    let allowance_left = target.plan_included_units.saturating_sub(consumed_before);
    let covered_by = if charged <= allowance_left {
        "plan_allowance"
    } else {
        let excess = charged - allowance_left;
        let active_holds: u64 = holds_for_quote(data_dir, quote_ref)
            .iter()
            .filter(|hold| hold["object"]["status"].as_str() == Some("active"))
            .map(|hold| wc_units(&hold["object"]["amount"]))
            .sum();
        let already_hold_covered: u64 = prior_records
            .iter()
            .filter(|record| {
                record["entitlement_consumption"]["covered_by"]
                    .as_str()
                    .is_some_and(|covered| covered != "plan_allowance")
            })
            .map(|record| wc_units(&record["charged_work_credits"]))
            .sum();
        if active_holds.saturating_sub(already_hold_covered) < excess {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "economics_entitlement_exhausted",
                format!(
                    "this charge of {charged} micro work credits exceeds the plan allowance left ({allowance_left}) and the quote's uncovered active holds ({}); reserve an exact additional hold through the overrun decision or stop",
                    active_holds.saturating_sub(already_hold_covered)
                ),
            ));
        }
        if allowance_left > 0 {
            "plan_allowance_and_credit_hold"
        } else {
            "credit_hold"
        }
    };
    let Some(consumed_after) = consumed_before.checked_add(charged) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_charge_overflow",
            "consumed allowance plus this charge exceeds the safe integer domain",
        ));
    };
    Ok(json!({
        "plan_ref": target.plan_ref,
        "included_work_credits": work_credits(target.plan_included_units),
        "consumed_before": work_credits(consumed_before),
        "consumed_after": work_credits(consumed_after),
        "covered_by": covered_by,
    }))
}

/// GET /v1/hypervisor/economics/usage/aggregate?by=<dimension> — a READ-DERIVED projection over
/// the caller's admitted usage chains, keyed by one registered metering dimension. Integer sums
/// with checked arithmetic; records admitted before M07.5 carry no dimensions and are counted as
/// `unattributed` rather than dropped. A projection, never a ledger and never settlement.
pub(crate) async fn handle_usage_aggregate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let by = params.get("by").map(String::as_str).unwrap_or("");
    match usage_aggregate(&st.data_dir, &identity, by) {
        Ok(projection) => (StatusCode::OK, Json(projection)),
        Err(reply) => reply,
    }
}

/// The aggregate's derivation, separable from transport so the projection can be tested as the
/// pure function of admitted chains it is.
fn usage_aggregate(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    by: &str,
) -> Result<Value, Reply> {
    if !AGGREGATE_DIMENSIONS.contains(&by) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_aggregate_dimension_unknown",
            format!("by must be one of {AGGREGATE_DIMENSIONS:?}"),
        ));
    }
    let mut buckets: std::collections::BTreeMap<String, (u64, u64, u64)> =
        std::collections::BTreeMap::new();
    let mut without_dimensions: u64 = 0;
    for chain in read_record_dir(data_dir, KIND_USAGE_CHAIN) {
        let Some(owner_ref) = chain["owner_ref"].as_str() else {
            continue;
        };
        if !identity.authorizes_tenant(owner_ref) {
            continue;
        }
        for record in chain["object"]["usage_records"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let key = match by {
                "meter_class" => record["meter_class"].as_str().map(str::to_owned),
                _ => {
                    if record.get("metering_dimensions").is_none() {
                        without_dimensions += 1;
                        None
                    } else {
                        record["metering_dimensions"][by]
                            .as_str()
                            .map(str::to_owned)
                    }
                }
            }
            .unwrap_or_else(|| "unattributed".to_string());
            let entry = buckets.entry(key).or_insert((0, 0, 0));
            entry.0 += 1;
            entry.1 = entry
                .1
                .saturating_add(record["quantity_units"].as_u64().unwrap_or(0));
            entry.2 = entry
                .2
                .saturating_add(wc_units(&record["charged_work_credits"]));
        }
    }
    let rows: Vec<Value> = buckets
        .into_iter()
        .map(|(key, (records, quantity, charged))| {
            json!({
                "key": key,
                "records": records,
                "quantity_units": quantity,
                "charged_work_credits": work_credits(charged),
            })
        })
        .collect();
    Ok(json!({
        "ok": true,
        "by": by,
        "buckets": rows,
        "records_without_dimensions": without_dimensions,
        "projection_source": "economics_usage_chains",
        "nonclaim": "A read-derived projection over admitted usage chains: integer sums by one registered dimension. Not a ledger, not a debit, not settlement, and not supplier-reconciled unless the underlying records say so."
    }))
}

/// The FIRST production path for the `model_tokens` meter class. Until this cut the class existed
/// only in `#[cfg(test)]` rate-card fixtures: nothing in the running daemon ever priced a model
/// invocation, so `runtime_receipt_refs` — the registered contract's own binding from a charge back
/// to the runtime evidence that earned it — had no producer either.
///
/// WHY A WRAPPER RATHER THAN A CALLER-BUILT BODY: [`append_usage`] reads `quantity_units` out of
/// JSON. If the invocation path assembled that JSON itself, one later edit could let a request
/// field reach it — and a caller who can name their own token count can name their own bill. The
/// quantity crosses this boundary as a `u64` the transport OBSERVED, in a parameter that cannot
/// carry a caller's value.
pub(crate) fn append_model_token_usage(
    data_dir: &str,
    caller: &WriteCaller,
    quote_ref: &str,
    commercial_posture: &str,
    observed_quantity_units: u64,
    runtime_receipt_refs: &[String],
) -> Result<(Value, usize), Reply> {
    append_usage(
        data_dir,
        caller,
        &json!({
            "quote_ref": quote_ref,
            "meter_class": METER_MODEL_TOKENS,
            "quantity_units": observed_quantity_units,
            "commercial_posture": commercial_posture,
            "runtime_receipt_refs": runtime_receipt_refs,
        }),
    )
}

fn append_usage(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> Result<(Value, usize), Reply> {
    refuse_server_derived(
        body,
        &[
            "body_hash",
            "charged_work_credits",
            "sequence",
            "previous_usage_hash",
            "occurred_at_ms",
            // M07.5 — attribution and accounting are the OWNER's derivations. A caller who can
            // name their own dimensions can bill another tenant's work to a quote of their choice.
            "metering_dimensions",
            "quote_body_hash",
            "rate_card_body_hash",
            "plan_body_hash",
            "measurement_interval",
            "idempotency_key",
            "idempotency_identity",
            "entitlement_consumption",
        ],
    )?;
    let quote_ref = require_ref(body, "quote_ref")?;
    let meter_class = str_field(body, "meter_class").to_string();
    let posture = str_field(body, "commercial_posture").to_string();
    let quantity = units_field(body, "quantity_units", true)?.unwrap_or(0);
    let coarse = body
        .get("coarse_ocu_projection")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let now = now_ms();
    let quote_id = tail_of(&quote_ref).to_string();
    let target = resolve_usage_target(data_dir, caller, &quote_ref, &meter_class, &posture, now)?;
    let rate = target.rate_work_credit_micro_units_per_meter_unit;
    let component = target.charge_component.as_str();
    if coarse && component != "non_billable_telemetry" {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_coarse_ocu_billable",
            "a coarse OCU projection is always non-billable telemetry; it cannot ride a billable meter",
        ));
    }
    // Checked integer arithmetic — an overflowing charge refuses rather than wrapping.
    let Some(charged) = quantity.checked_mul(rate) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_charge_overflow",
            "quantity * rate exceeds the safe integer domain",
        ));
    };
    let breakdown = cost_breakdown_from(body, &target.currency_code, &posture)?;
    let refs = |key: &str| -> Vec<String> {
        body.get(key)
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    // The registered contract requires every usage record to cite runtime evidence: a charge
    // that binds to no receipt is unauditable and is refused at admission, not at export.
    if refs("runtime_receipt_refs").is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_usage_evidence_required",
            "runtime_receipt_refs must cite at least one runtime receipt — a charge binds to real work evidence",
        ));
    }

    // Serialize through the per-quote chain stream: CAS on the admitted head makes a
    // sequence fork impossible even under concurrent appends.
    let chain_ref = format!("usage-chain://{quote_id}");
    let existing_chain = usage_chain(data_dir, &quote_id);
    let (expected_head, prior_records) = match &existing_chain {
        Some(chain) => (
            chain["admitted_head"].as_str().map(str::to_owned),
            chain["object"]["usage_records"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        ),
        None => (None, Vec::new()),
    };
    let sequence = prior_records.len() as u64 + 1;
    let previous_usage_hash = prior_records
        .last()
        .and_then(|r| r["body_hash"].as_str())
        .map(|h| json!(h))
        .unwrap_or(Value::Null);
    // M07.5 — METERED ONCE, ATTRIBUTED BY THE OWNER, ACCOUNTED AGAINST THE PLAN. All three are
    // derived from admitted truth before the append is admitted, so a refusal leaves the chain
    // exactly as it was and an admitted record carries what it was measured against.
    let receipt_refs = refs("runtime_receipt_refs");
    if let Some((receipt, usage_ref)) = receipt_already_metered(
        data_dir,
        &caller.owner_ref,
        &receipt_refs,
        &caller.idempotency_key,
    ) {
        return Err(bad(
            StatusCode::CONFLICT,
            "economics_receipt_already_metered",
            format!("{receipt} is already bound to {usage_ref}; a runtime receipt is metered at most once per tenant, and a retry of that command must reuse its idempotency key"),
        ));
    }
    let metering_dimensions =
        derive_metering_dimensions(data_dir, caller, &receipt_refs, &meter_class, component)?;
    let mut sorted_receipts = receipt_refs.clone();
    sorted_receipts.sort();
    let idempotency_identity = body_hash_of(&json!({
        "quote_ref": quote_ref,
        "meter_class": meter_class,
        "runtime_receipt_refs": sorted_receipts,
    }))?;
    let entitlement_consumption = entitlement_consumption_for(
        data_dir,
        caller,
        &target,
        &quote_ref,
        &prior_records,
        charged,
        now,
    )?;
    let usage_id = format!("{}-{}", quote_id, sequence);
    let mut usage = json!({
        "usage_ref": format!("usage://{usage_id}"),
        "quote_ref": quote_ref,
        "sequence": sequence,
        "previous_usage_hash": previous_usage_hash,
        "runtime_receipt_refs": receipt_refs,
        "supplier_statement_refs": refs("supplier_statement_refs"),
        "meter_class": meter_class,
        "quantity_units": quantity,
        "rate_work_credit_micro_units_per_meter_unit": rate,
        "charged_work_credits": work_credits(charged),
        "commercial_posture": posture,
        "cost_breakdown": breakdown,
        "coarse_ocu_projection": coarse,
        "occurred_at_ms": now,
        "metering_dimensions": metering_dimensions,
        "quote_body_hash": target.quote_body_hash,
        "rate_card_body_hash": target.rate_card_body_hash,
        "plan_body_hash": target.plan_body_hash,
        // No runtime receipt this module can read carries a measured interval yet, so the
        // interval is the admission instant and SAYS so; a receipt-timestamped interval is a
        // later producer's fact, never this module's guess.
        "measurement_interval": { "started_at_ms": now, "ended_at_ms": now, "interval_basis": "admission_time" },
        "idempotency_key": caller.idempotency_key,
        "idempotency_identity": idempotency_identity,
        "entitlement_consumption": entitlement_consumption,
    });
    usage["body_hash"] = json!(body_hash_of(&usage)?);
    let admitted = json!({
        "chain_ref": chain_ref,
        "append": { "sequence": sequence, "usage_body_hash": usage["body_hash"] },
    });
    let commit = admit_owner_scoped_write(
        data_dir,
        caller,
        ECON_NAMESPACE,
        KIND_USAGE_CHAIN,
        &chain_ref,
        "economics.usage.append",
        expected_head.as_deref(),
        &admitted,
    )?;
    if commit.replayed {
        // The append already landed; the stored chain is the truth.
        if let Some(chain) = usage_chain(data_dir, &quote_id) {
            let length = chain["object"]["usage_records"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0);
            let last = chain["object"]["usage_records"]
                .as_array()
                .and_then(|records| records.last())
                .cloned()
                .unwrap_or(Value::Null);
            return Ok((last, length));
        }
    }
    let mut records = prior_records;
    records.push(usage.clone());
    let mut chain_record = json!({
        "owner_ref": caller.owner_ref,
        "object": { "chain_ref": chain_ref, "quote_ref": usage["quote_ref"], "usage_records": records },
    });
    if let Some(existing) = existing_chain {
        chain_record["created_at"] = existing["created_at"].clone();
    } else {
        chain_record["created_at"] = json!(super::iso_now());
    }
    project_admission(&mut chain_record, &commit);
    let length = chain_record["object"]["usage_records"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    project_or_fail(data_dir, KIND_USAGE_CHAIN, &quote_id, &chain_record)?;
    Ok((usage, length))
}

// ================================ OverrunDecision ==============================================

pub(crate) async fn handle_overrun_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_overrun(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => created_reply("overrun_decision", record, replayed),
        Err(response) => response,
    }
}

fn mint_overrun(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> Result<(Value, bool), Reply> {
    refuse_server_derived(
        body,
        &[
            "body_hash",
            "created_at_ms",
            "decision",
            "held_work_credits",
            "exact_overage_work_credits",
            "additional_hold_amount",
            "usage_head_hash",
        ],
    )?;
    let quote_ref = require_ref(body, "quote_ref")?;
    let projected = units_field(body, "projected_work_credit_units", true)?.unwrap_or(0);
    let now = now_ms();
    let quote_id = tail_of(&quote_ref).to_string();
    let Some(quote) = load(data_dir, KIND_QUOTE, &quote_id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_quote_not_found",
            "quote_ref does not resolve",
        ));
    };
    if quote["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let quote_object = object_of(&quote);
    // The decision is DERIVED from the immutable quote's overrun_policy — never caller-chosen.
    let policy = quote_object["overrun_policy"].as_str().unwrap_or("block");
    let held: u64 = holds_for_quote(data_dir, &quote_ref)
        .iter()
        .filter(|h| h["object"]["status"].as_str() != Some("released"))
        .map(|h| wc_units(&h["object"]["amount"]))
        .sum();
    let overage = projected.saturating_sub(held);
    let usage_head_hash = usage_chain(data_dir, &quote_id)
        .and_then(|chain| {
            chain["object"]["usage_records"]
                .as_array()
                .and_then(|records| records.last())
                .and_then(|r| r["body_hash"].as_str())
                .map(str::to_owned)
        })
        .map(|h| json!(h))
        .unwrap_or(Value::Null);
    let id = replay_stable_id("eov", &caller.owner_ref, &caller.idempotency_key);
    let decision_ref = format!("overrun-decision://{id}");
    let admitted = json!({
        "overrun_decision_ref": decision_ref,
        "quote_ref": quote_ref,
        "projected_work_credits": work_credits(projected),
    });
    let mut object = admitted.clone();
    object["usage_head_hash"] = usage_head_hash;
    object["held_work_credits"] = work_credits(held);
    object["exact_overage_work_credits"] = work_credits(overage);
    object["decision"] = json!(policy);
    object["additional_hold_amount"] = work_credits(if policy == "exact_additional_hold" {
        overage
    } else {
        0
    });
    object["created_at_ms"] = json!(now);
    object["body_hash"] = json!(body_hash_of(&object)?);
    let record = json!({ "owner_ref": caller.owner_ref, "object": object });
    mint_record(
        data_dir,
        caller,
        KIND_OVERRUN,
        &id,
        &decision_ref,
        "economics.overrun.decide",
        &admitted,
        record,
    )
}

// ================================ FinalDebit ===================================================

pub(crate) async fn handle_final_debit_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match mint_final_debit(&st.data_dir, &caller, &body) {
        Ok((record, replayed)) => created_reply("final_debit", record, replayed),
        Err(response) => response,
    }
}

/// NO SPEND WITHOUT AUTHORITY. The debit requires a live `spend` authority grant whose budget
/// covers it. Grant budgets are denominated in WHOLE work credits (owner ruling, recorded in
/// canon-to-code-delta.md): budget.spend * 1_000_000 must cover the debited micro units.
fn require_spend_authority(
    data_dir: &str,
    body: &Value,
    debit_units: u64,
) -> Result<String, Reply> {
    let grant_ref = str_field(body, "authority_grant_ref");
    if grant_ref.is_empty() {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "economics_spend_authority_required",
            "a FinalDebit is a spend: it requires authority_grant_ref naming a live spend grant — nothing debits from UI state or silence",
        ));
    }
    let Some(grant) = super::authority_routes::load_grant(data_dir, grant_ref) else {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "economics_spend_authority_unknown",
            "authority_grant_ref does not resolve to an issued grant",
        ));
    };
    if super::authority_routes::live_grant_status(&grant) != "active" {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "economics_spend_authority_not_live",
            format!(
                "the grant is {}; only an active grant authorizes a debit",
                super::authority_routes::live_grant_status(&grant)
            ),
        ));
    }
    let effect_ok = ["action", "effect"]
        .iter()
        .any(|key| grant.get(*key).and_then(Value::as_str) == Some("spend"));
    if !effect_ok {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "economics_spend_authority_effect_mismatch",
            "the grant does not authorize the spend effect",
        ));
    }
    let budget_whole = grant
        .pointer("/budget/spend")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if budget_whole.saturating_mul(MICRO_PER_WORK_CREDIT) < debit_units {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "economics_spend_authority_insufficient",
            "the grant's spend budget does not cover this debit; nothing is debited partially or on credit",
        ));
    }
    Ok(grant
        .get("grant_ref")
        .and_then(Value::as_str)
        .unwrap_or(grant_ref)
        .to_string())
}

fn mint_final_debit(
    data_dir: &str,
    caller: &WriteCaller,
    body: &Value,
) -> Result<(Value, bool), Reply> {
    refuse_server_derived(
        body,
        &[
            "body_hash",
            "finalized_at_ms",
            "debited_work_credits",
            "usage_head_hash",
            "usage_record_refs",
            "hold_refs",
        ],
    )?;
    let quote_ref = require_ref(body, "quote_ref")?;
    let now = now_ms();
    let quote_id = tail_of(&quote_ref).to_string();
    let Some(quote) = load(data_dir, KIND_QUOTE, &quote_id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_quote_not_found",
            "quote_ref does not resolve",
        ));
    };
    if quote["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let chain = usage_chain(data_dir, &quote_id);
    let usage_records = chain
        .as_ref()
        .and_then(|c| c["object"]["usage_records"].as_array().cloned())
        .unwrap_or_default();
    let debited: u64 = usage_records
        .iter()
        .map(|r| wc_units(&r["charged_work_credits"]))
        .sum();
    let usage_head_hash = usage_records
        .last()
        .and_then(|r| r["body_hash"].as_str())
        .map(|h| json!(h))
        .unwrap_or(Value::Null);
    let holds = holds_for_quote(data_dir, &quote_ref);
    let active_units: u64 = holds
        .iter()
        .filter(|h| h["object"]["status"].as_str() == Some("active"))
        .map(|h| wc_units(&h["object"]["amount"]))
        .sum();
    let already_consumed: u64 = holds
        .iter()
        .filter(|h| h["object"]["status"].as_str() == Some("consumed"))
        .map(|h| wc_units(&h["object"]["amount"]))
        .sum();
    // The registered contract requires the billing chain to carry at least one finite hold:
    // a quote that never held credits cannot finalize a debit, even a zero one.
    if holds
        .iter()
        .all(|h| h["object"]["status"].as_str() == Some("released"))
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_debit_requires_hold",
            "a FinalDebit requires at least one non-released CreditHold on the quote",
        ));
    }
    // Funding preflight law: charged work must be covered by held credits before it debits.
    if debited > active_units.saturating_add(already_consumed) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_debit_exceeds_held",
            "charged usage exceeds held credits; take a typed OverrunDecision and an exact_additional hold — nothing debits on credit",
        ));
    }
    let grant_ref = require_spend_authority(data_dir, body, debited)?;
    // Exactly one FinalDebit per quote: the resource identity derives from the quote, so a
    // second genesis (any idempotency key) refuses at the substrate.
    let debit_ref = format!("final-debit://{quote_id}");
    let admitted = json!({
        "final_debit_ref": debit_ref,
        "quote_ref": quote_ref,
        "authority_grant_ref": grant_ref,
        "debit": { "usage_count": usage_records.len(), "usage_head": usage_head_hash },
    });
    let mut object = json!({
        "final_debit_ref": debit_ref,
        "quote_ref": quote_ref,
        "usage_head_hash": usage_head_hash,
        "usage_record_refs": usage_records.iter().filter_map(|r| r["usage_ref"].as_str()).collect::<Vec<_>>(),
        "hold_refs": holds
            .iter()
            .filter(|h| h["object"]["status"].as_str() != Some("released"))
            .filter_map(|h| h["object"]["hold_ref"].as_str())
            .collect::<Vec<_>>(),
        "debited_work_credits": work_credits(debited),
        "finalized_at_ms": now,
    });
    object["body_hash"] = json!(body_hash_of(&object)?);
    let record = json!({
        "owner_ref": caller.owner_ref,
        "object": object,
        "authority_grant_ref": grant_ref,
    });
    let (record, replayed) = mint_record(
        data_dir,
        caller,
        KIND_DEBIT,
        &quote_id,
        &debit_ref,
        "economics.debit.finalize",
        &admitted,
        record,
    )?;
    // Consume the covering holds. Runs on fresh mint AND on replay, so a crash between the
    // debit admission and the hold transitions reconciles on retry; an already-consumed hold
    // short-circuits idempotently inside transition_hold.
    for hold in holds_for_quote(data_dir, &quote_ref) {
        if hold["object"]["status"].as_str() == Some("active") {
            let hold_id = tail_of(hold["object"]["hold_ref"].as_str().unwrap_or("")).to_string();
            let consume_caller = WriteCaller {
                identity: caller.identity.clone(),
                owner_ref: caller.owner_ref.clone(),
                idempotency_key: format!("consume:{}:{}", quote_id, hold_id),
            };
            transition_hold(
                data_dir,
                &consume_caller,
                &hold_id,
                "consumed",
                "economics.hold.consume",
            )?;
        }
    }
    Ok((record, replayed))
}

// ================================ BillingAdjustment ============================================

pub(crate) async fn handle_adjustment_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match append_adjustment(&st.data_dir, &caller, &body) {
        Ok(adjustment) => (
            StatusCode::CREATED,
            Json(json!({ "ok": true, "adjustment": adjustment })),
        ),
        Err(response) => response,
    }
}

fn append_adjustment(data_dir: &str, caller: &WriteCaller, body: &Value) -> Result<Value, Reply> {
    refuse_server_derived(
        body,
        &["body_hash", "created_at_ms", "previous_adjustment_hash"],
    )?;
    let debit_ref = require_ref(body, "final_debit_ref")?;
    let kind = str_field(body, "adjustment_kind");
    if !["refund", "writeoff"].contains(&kind) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_adjustment_kind_invalid",
            "adjustment_kind must be refund or writeoff",
        ));
    }
    let amount = units_field(body, "amount_units", true)?.unwrap_or(0);
    if amount == 0 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_adjustment_amount_invalid",
            "an adjustment must move a positive integer amount",
        ));
    }
    let reason = str_field(body, "reason_code");
    if reason.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_adjustment_reason_required",
            "reason_code is required — an unexplained adjustment is not auditable",
        ));
    }
    let now = now_ms();
    let quote_id = tail_of(&debit_ref).to_string();
    let Some(debit) = load(data_dir, KIND_DEBIT, &quote_id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "economics_final_debit_not_found",
            "final_debit_ref does not resolve; adjustments exist only against the one debit",
        ));
    };
    if debit["owner_ref"] != json!(caller.owner_ref) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let debited = wc_units(&debit["object"]["debited_work_credits"]);
    let chain_ref = format!("adjustment-chain://{quote_id}");
    let existing = load(data_dir, KIND_ADJUSTMENT_CHAIN, &quote_id);
    let (expected_head, prior) = match &existing {
        Some(chain) => (
            chain["admitted_head"].as_str().map(str::to_owned),
            chain["object"]["adjustments"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        ),
        None => (None, Vec::new()),
    };
    let adjusted_so_far: u64 = prior.iter().map(|a| wc_units(&a["amount"])).sum();
    // Downward-only, never below zero: cumulative adjustments stay within the one debit.
    if adjusted_so_far.saturating_add(amount) > debited {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "economics_adjustment_exceeds_debit",
            "cumulative adjustments cannot exceed the final debit; an adjustment corrects the ledger, it never mints credit",
        ));
    }
    let previous_adjustment_hash = prior
        .last()
        .and_then(|a| a["body_hash"].as_str())
        .map(|h| json!(h))
        .unwrap_or(Value::Null);
    let sequence = prior.len() as u64 + 1;
    let evidence: Vec<String> = body
        .get("evidence_refs")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if evidence.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "economics_adjustment_evidence_required",
            "evidence_refs must cite at least one evidence ref — an unevidenced adjustment is not auditable",
        ));
    }
    let mut adjustment = json!({
        "adjustment_ref": format!("billing-adjustment://{}-{}", quote_id, sequence),
        "final_debit_ref": debit_ref,
        "previous_adjustment_hash": previous_adjustment_hash,
        "adjustment_kind": kind,
        "amount": work_credits(amount),
        "reason_code": reason,
        "evidence_refs": evidence,
        "created_at_ms": now,
    });
    adjustment["body_hash"] = json!(body_hash_of(&adjustment)?);
    let admitted = json!({
        "chain_ref": chain_ref,
        "append": { "sequence": sequence, "adjustment_body_hash": adjustment["body_hash"] },
    });
    let commit = admit_owner_scoped_write(
        data_dir,
        caller,
        ECON_NAMESPACE,
        KIND_ADJUSTMENT_CHAIN,
        &chain_ref,
        "economics.adjustment.append",
        expected_head.as_deref(),
        &admitted,
    )?;
    if commit.replayed {
        if let Some(chain) = load(data_dir, KIND_ADJUSTMENT_CHAIN, &quote_id) {
            if let Some(last) = chain["object"]["adjustments"]
                .as_array()
                .and_then(|a| a.last())
            {
                return Ok(last.clone());
            }
        }
    }
    let mut records = prior;
    records.push(adjustment.clone());
    let mut chain_record = json!({
        "owner_ref": caller.owner_ref,
        "object": { "chain_ref": chain_ref, "final_debit_ref": debit_ref, "adjustments": records },
        "created_at": existing.as_ref().and_then(|c| c["created_at"].as_str()).map(|s| json!(s)).unwrap_or(json!(super::iso_now())),
    });
    project_admission(&mut chain_record, &commit);
    project_or_fail(data_dir, KIND_ADJUSTMENT_CHAIN, &quote_id, &chain_record)?;
    Ok(adjustment)
}

// ================================ Bundle export + preflight + reconciliation ===================

fn created_reply(key: &str, record: Value, replayed: bool) -> Reply {
    let mut body = serde_json::Map::new();
    body.insert("ok".into(), json!(true));
    body.insert("replayed".into(), json!(replayed));
    body.insert(key.to_string(), record);
    (
        if replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(Value::Object(body)),
    )
}

/// GET /v1/hypervisor/economics/quotes/:id/funding-preflight — the typed answer to "may work
/// under this quote proceed": hold coverage, quote freshness, spend-authority posture. A read;
/// it admits nothing.
pub(crate) async fn handle_funding_preflight(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let quote = match authorized_record(&st.data_dir, &headers, KIND_QUOTE, &id) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    let quote_object = object_of(&quote);
    let quote_ref = quote_object["quote_ref"].as_str().unwrap_or("").to_string();
    let now = now_ms();
    let holds = holds_for_quote(&st.data_dir, &quote_ref);
    let active: u64 = holds
        .iter()
        .filter(|h| h["object"]["status"].as_str() == Some("active"))
        .map(|h| wc_units(&h["object"]["amount"]))
        .sum();
    let required = wc_units(&quote_object["required_hold"]);
    let charged: u64 = usage_chain(&st.data_dir, &id)
        .and_then(|c| c["object"]["usage_records"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|r| wc_units(&r["charged_work_credits"]))
        .sum();
    let expired = quote_object["expires_at_ms"].as_u64().unwrap_or(0) <= now;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "funding_preflight": {
                "quote_ref": quote_ref,
                "quote_expired": expired,
                "required_hold_units": required,
                "active_hold_units": active,
                "charged_units": charged,
                "hold_covers_required": active >= required,
                "hold_covers_charged": active >= charged,
                "may_proceed": !expired && active >= required && active >= charged,
                "spend_authority": {
                    "required_for_final_debit": true,
                    "effect": "spend",
                    "note": "the debit refuses without a live spend grant covering it; this preflight asserts nothing about a specific grant"
                },
            }
        })),
    )
}

/// GET /v1/hypervisor/economics/quotes/:id/ledger-bundle — export the REGISTERED
/// ManagedWorkBillingLedgerBundle v1, validated against the contract before a byte leaves.
pub(crate) async fn handle_ledger_bundle(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let quote = match authorized_record(&st.data_dir, &headers, KIND_QUOTE, &id) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    let quote_object = object_of(&quote).clone();
    let quote_ref = quote_object["quote_ref"].as_str().unwrap_or("").to_string();
    let Some(card) = load(
        &st.data_dir,
        KIND_RATE_CARD,
        tail_of(quote_object["rate_card_ref"].as_str().unwrap_or("")),
    ) else {
        return bad(
            StatusCode::CONFLICT,
            "economics_rate_card_missing",
            "the quote's rate card projection is unavailable",
        );
    };
    let Some(plan) = load(
        &st.data_dir,
        KIND_PLAN,
        tail_of(quote_object["plan_ref"].as_str().unwrap_or("")),
    ) else {
        return bad(
            StatusCode::CONFLICT,
            "economics_plan_missing",
            "the quote's plan projection is unavailable",
        );
    };
    let holds: Vec<Value> = holds_for_quote(&st.data_dir, &quote_ref)
        .iter()
        .map(|h| h["object"].clone())
        .collect();
    let usage_records: Vec<Value> = usage_chain(&st.data_dir, &id)
        .and_then(|c| c["object"]["usage_records"].as_array().cloned())
        .unwrap_or_default();
    let overruns: Vec<Value> = {
        let mut decisions: Vec<Value> = read_record_dir(&st.data_dir, KIND_OVERRUN)
            .into_iter()
            .filter(|r| r["object"]["quote_ref"].as_str() == Some(quote_ref.as_str()))
            .map(|r| r["object"].clone())
            .collect();
        decisions.sort_by_key(|d| d["created_at_ms"].as_u64().unwrap_or(0));
        decisions
    };
    let debit = load(&st.data_dir, KIND_DEBIT, &id).map(|r| r["object"].clone());
    let adjustments: Vec<Value> = load(&st.data_dir, KIND_ADJUSTMENT_CHAIN, &id)
        .and_then(|c| c["object"]["adjustments"].as_array().cloned())
        .unwrap_or_default();
    let ledger_head_hash = adjustments
        .last()
        .and_then(|a| a["body_hash"].as_str())
        .or(debit.as_ref().and_then(|d| d["body_hash"].as_str()))
        .or(usage_records.last().and_then(|u| u["body_hash"].as_str()))
        .or(holds.last().and_then(|h| h["body_hash"].as_str()))
        .or(quote_object["body_hash"].as_str())
        .unwrap_or_default()
        .to_string();
    // M07.5 — a chain whose every record carries the owner-derived metering members exports under
    // the v2 successor; a chain with pre-M07.5 records exports under v1 (still registered, still
    // valid). The exporter names the contract it met rather than letting a reader infer it.
    let all_metered = usage_records
        .iter()
        .all(|record| record.get("metering_dimensions").is_some());
    let (bundle_schema, bundle_contract_id) = if all_metered {
        (BUNDLE_SCHEMA_V2, BUNDLE_CONTRACT_ID_V2)
    } else {
        (BUNDLE_SCHEMA_V1, BUNDLE_CONTRACT_ID)
    };
    let bundle = json!({
        "schema_version": bundle_schema,
        "bundle_ref": format!("billing-bundle://{id}"),
        "billing_account_ref": quote["billing_account_ref"],
        "work_ref": quote["work_ref"],
        "rate_card": object_of(&card),
        "plan": object_of(&plan),
        "quote": quote_object,
        "holds": holds,
        "usage_records": usage_records,
        "overrun_decisions": overruns,
        "final_debit": debit.unwrap_or(Value::Null),
        "adjustments": adjustments,
        "ledger_head_hash": ledger_head_hash,
        "exported_at_ms": now_ms(),
        // Honest assurance: this bundle is derived from the daemon's own event log. It becomes
        // supplier-reconciled only when real supplier statements bind — never by assertion.
        "assurance_status": "internal_event_log",
    });
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            bundle_contract_id,
            &bundle,
        )
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "economics_bundle_contract_invalid",
            format!(
                "the assembled bundle violates its registered contract and is NOT served: {error}"
            ),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "contract_id": bundle_contract_id, "ledger_bundle": bundle })),
    )
}

/// GET /v1/hypervisor/economics/reconciliation — integer sums per quote the caller owns.
/// Not billing settlement: `assurance` names the internal-event-log basis explicitly.
pub(crate) async fn handle_reconciliation(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let mut rows = Vec::new();
    let mut totals = (0u64, 0u64, 0u64, 0u64); // held_active, charged, debited, adjusted
    for quote in read_record_dir(&st.data_dir, KIND_QUOTE) {
        let Some(owner_ref) = quote["owner_ref"].as_str() else {
            continue;
        };
        if !identity.authorizes_tenant(owner_ref) {
            continue;
        }
        let object = object_of(&quote);
        let quote_ref = object["quote_ref"].as_str().unwrap_or("").to_string();
        let quote_id = tail_of(&quote_ref).to_string();
        let holds = holds_for_quote(&st.data_dir, &quote_ref);
        let active: u64 = holds
            .iter()
            .filter(|h| h["object"]["status"].as_str() == Some("active"))
            .map(|h| wc_units(&h["object"]["amount"]))
            .sum();
        let consumed: u64 = holds
            .iter()
            .filter(|h| h["object"]["status"].as_str() == Some("consumed"))
            .map(|h| wc_units(&h["object"]["amount"]))
            .sum();
        let charged: u64 = usage_chain(&st.data_dir, &quote_id)
            .and_then(|c| c["object"]["usage_records"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .map(|r| wc_units(&r["charged_work_credits"]))
            .sum();
        let debit = load(&st.data_dir, KIND_DEBIT, &quote_id);
        let debited = debit
            .as_ref()
            .map(|d| wc_units(&d["object"]["debited_work_credits"]))
            .unwrap_or(0);
        let adjusted: u64 = load(&st.data_dir, KIND_ADJUSTMENT_CHAIN, &quote_id)
            .and_then(|c| c["object"]["adjustments"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .map(|a| wc_units(&a["amount"]))
            .sum();
        totals.0 += active;
        totals.1 += charged;
        totals.2 += debited;
        totals.3 += adjusted;
        rows.push(json!({
            "quote_ref": quote_ref,
            "estimated_units": wc_units(&object["estimated_work_credits"]),
            "required_hold_units": wc_units(&object["required_hold"]),
            "held_active_units": active,
            "held_consumed_units": consumed,
            "charged_units": charged,
            "debited_units": debited,
            "adjusted_units": adjusted,
            "net_debited_units": debited.saturating_sub(adjusted),
            "debit_state": if debit.is_some() { "finalized" } else if charged > 0 { "accruing" } else { "open" },
            "coverage_consistent": debited <= consumed.saturating_add(active) && adjusted <= debited,
        }));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema_version": "ioi.hypervisor.economics-reconciliation.v1",
            "reconciliation": {
                "rows": rows,
                "totals": {
                    "held_active_units": totals.0,
                    "charged_units": totals.1,
                    "debited_units": totals.2,
                    "adjusted_units": totals.3,
                    "net_debited_units": totals.2.saturating_sub(totals.3),
                },
                "assurance": "internal_event_log — the daemon's own admitted chain; no supplier statement, settlement, escrow, payout, or exchange execution is claimed here (those rails are wallet.network-side by doctrine)",
            },
            "at": super::iso_now(),
        })),
    )
}

// ================================ tests ========================================================

#[cfg(test)]
mod economics_tests {
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

    fn seed_card(fxt: &Fx) -> String {
        let (card, _) = mint_rate_card(
            &fxt.data_dir,
            &caller("card-1"),
            &json!({
                "currency_code": "USD",
                "ioi_fee_policy_ref": "policy://acme/fees",
                "validity_seconds": 3600,
                "meter_rates": [
                    { "meter_class": "model_tokens", "work_credit_micro_units_per_meter_unit": 5, "charge_component": "managed_model" },
                    { "meter_class": "ocu_coarse", "work_credit_micro_units_per_meter_unit": 0, "charge_component": "non_billable_telemetry" },
                ],
            }),
        )
        .unwrap();
        card["object"]["rate_card_ref"].as_str().unwrap().to_owned()
    }

    /// A card with caller-chosen meters and an explicit idempotency key, so one test can seed
    /// TWO distinct cards for the same owner (the ids are replay-stable on that key).
    fn seed_card_with(fxt: &Fx, key: &str, meter_rates: Value) -> String {
        let (card, _) = mint_rate_card(
            &fxt.data_dir,
            &caller(key),
            &json!({
                "currency_code": "USD",
                "ioi_fee_policy_ref": "policy://acme/fees",
                "validity_seconds": 3600,
                "meter_rates": meter_rates,
            }),
        )
        .unwrap();
        card["object"]["rate_card_ref"].as_str().unwrap().to_owned()
    }

    /// The billing account one card actually resolves to, taken from a real minted quote
    /// rather than from the classifier, so the assertion is about the exported record.
    fn billing_account_for(fxt: &Fx, key: &str, card_ref: &str) -> String {
        let (plan, _) = mint_plan(
            &fxt.data_dir,
            &caller(&format!("{key}-plan")),
            &json!({
                "rate_card_ref": card_ref,
                "included_work_credit_units": 0,
                "reset_policy": "non_resetting",
                "validity_seconds": 3600,
            }),
        )
        .unwrap();
        let plan_ref = plan["object"]["plan_ref"].as_str().unwrap().to_owned();
        let (quote, _) = mint_quote(
            &fxt.data_dir,
            &caller(&format!("{key}-quote")),
            &json!({
                "rate_card_ref": card_ref,
                "plan_ref": plan_ref,
                "work_ref": "work://acme/w1",
                "estimated_work_credit_units": 10,
                "overrun_policy": "exact_additional_hold",
                "max_attempt_count": 3,
                "allowed_commercial_postures": ["managed", "local"],
                "validity_seconds": 600,
            }),
        )
        .unwrap();
        quote["billing_account_ref"].as_str().unwrap().to_owned()
    }

    /// ACC-11 clause 9 — NETWORK/OPEN WORK DRAWS A SEPARATE BUDGET.
    ///
    /// Asserted on the `billing_account_ref` the bundle actually exports, for ONE owner, so
    /// what is proved is the separation of the accounts rather than the behaviour of the
    /// classifier in isolation. Both halves are asserted positively first: each card resolves
    /// to the account its own class names, and only then are the two compared.
    #[test]
    fn network_work_draws_a_separate_budget_from_managed_work_for_one_owner() {
        let fxt = fx();
        let managed = billing_account_for(
            &fxt,
            "managed",
            &seed_card_with(
                &fxt,
                "managed-card",
                json!([
                    { "meter_class": "model_tokens", "work_credit_micro_units_per_meter_unit": 5, "charge_component": "managed_model" },
                ]),
            ),
        );
        let network = billing_account_for(
            &fxt,
            "network",
            &seed_card_with(
                &fxt,
                "network-card",
                json!([
                    { "meter_class": "verified_unit", "work_credit_micro_units_per_meter_unit": 7, "charge_component": "verifier" },
                ]),
            ),
        );
        assert!(
            managed.ends_with("/managed"),
            "managed card resolved {managed}"
        );
        assert!(
            network.ends_with("/network_work"),
            "network card resolved {network}"
        );
        assert_ne!(
            managed, network,
            "one owner's network and managed work must not share a budget"
        );
        reset_handle_for_test();
    }

    /// Telemetry is class-NEUTRAL, and this is the regression that would otherwise be silent:
    /// a zero-rate coarse meter rides a managed card without moving it to the network budget
    /// or making the card look mixed.
    #[test]
    fn a_zero_rate_telemetry_meter_does_not_move_a_card_between_budgets() {
        let fxt = fx();
        let with_telemetry = billing_account_for(&fxt, "mixed-telemetry", &seed_card(&fxt));
        assert!(
            with_telemetry.ends_with("/managed"),
            "a managed card carrying a telemetry meter resolved {with_telemetry}"
        );
        reset_handle_for_test();
    }

    /// The separation is kept STRUCTURAL by refusing the card that would straddle it, at the
    /// source — one quote binds one card and resolves one account, so a card pricing both
    /// classes could only ever draw one budget for both.
    #[test]
    fn a_rate_card_pricing_both_classes_is_refused_at_admission() {
        let fxt = fx();
        let error = mint_rate_card(
            &fxt.data_dir,
            &caller("mixed-card"),
            &json!({
                "currency_code": "USD",
                "ioi_fee_policy_ref": "policy://acme/fees",
                "validity_seconds": 3600,
                "meter_rates": [
                    { "meter_class": "model_tokens", "work_credit_micro_units_per_meter_unit": 5, "charge_component": "managed_model" },
                    { "meter_class": "verified_unit", "work_credit_micro_units_per_meter_unit": 7, "charge_component": "verifier" },
                ],
            }),
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_budget_class_mixed"));
        reset_handle_for_test();
    }

    fn seed_plan(fxt: &Fx, card_ref: &str) -> String {
        let (plan, _) = mint_plan(
            &fxt.data_dir,
            &caller("plan-1"),
            &json!({
                "rate_card_ref": card_ref,
                "included_work_credit_units": 0,
                "reset_policy": "non_resetting",
                "validity_seconds": 3600,
            }),
        )
        .unwrap();
        plan["object"]["plan_ref"].as_str().unwrap().to_owned()
    }

    fn seed_quote(fxt: &Fx, card_ref: &str, plan_ref: &str, estimated: u64) -> String {
        let (quote, _) = mint_quote(
            &fxt.data_dir,
            &caller("quote-1"),
            &json!({
                "rate_card_ref": card_ref,
                "plan_ref": plan_ref,
                "work_ref": "work://acme/w1",
                "estimated_work_credit_units": estimated,
                "overrun_policy": "exact_additional_hold",
                "max_attempt_count": 3,
                "allowed_commercial_postures": ["managed", "local"],
                "validity_seconds": 600,
            }),
        )
        .unwrap();
        quote["object"]["quote_ref"].as_str().unwrap().to_owned()
    }

    fn seed_grant(fxt: &Fx, whole_credits: u64) -> String {
        let grant = json!({
            "schema_version": "ioi.hypervisor.authority-grant.v1",
            "grant_id": "agr_test1",
            "grant_ref": "authority-grant://agr_test1",
            "decision": "granted",
            "action": "spend",
            "effect": "spend",
            "subject": PRINCIPAL,
            "budget": { "spend": whole_credits },
            "expires_at_unix": (now_ms() / 1000 + 3600) as i64,
            "revoked": false,
        });
        persist_record(&fxt.data_dir, "authority-grants", "agr_test1", &grant).unwrap();
        "authority-grant://agr_test1".to_string()
    }

    #[test]
    fn amounts_are_integer_only() {
        let fxt = fx();
        let error = mint_rate_card(
            &fxt.data_dir,
            &caller("c"),
            &json!({
                "currency_code": "USD",
                "ioi_fee_policy_ref": "policy://acme/fees",
                "validity_seconds": 3600,
                "meter_rates": [
                    { "meter_class": "m", "work_credit_micro_units_per_meter_unit": 1.5, "charge_component": "managed_model" },
                ],
            }),
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_integer_amount_required"));
        reset_handle_for_test();
    }

    #[test]
    fn caller_supplied_charges_and_hashes_refuse() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan(&fxt, &card);
        let quote = seed_quote(&fxt, &card, &plan, 100);
        let error = append_usage(
            &fxt.data_dir,
            &caller("u"),
            &json!({
                "quote_ref": quote,
                "meter_class": "model_tokens",
                "quantity_units": 10,
                "commercial_posture": "managed",
                "charged_work_credits": { "unit": "micro_work_credit", "units": 1 },
            }),
        )
        .unwrap_err();
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_server_derived_field"));
        reset_handle_for_test();
    }

    #[test]
    fn the_full_chain_holds_charges_debits_and_adjusts_with_authority() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan(&fxt, &card);
        let quote = seed_quote(&fxt, &card, &plan, 1_000);
        let quote_id = tail_of(&quote).to_string();

        // initial hold covers the estimate; a second initial refuses.
        let (hold, _) = mint_hold(
            &fxt.data_dir,
            &caller("hold-1"),
            &json!({ "quote_ref": quote, "amount_units": 1_000, "hold_kind": "initial" }),
        )
        .unwrap();
        assert_eq!(hold["object"]["status"], json!("active"));
        let dup = mint_hold(
            &fxt.data_dir,
            &caller("hold-2"),
            &json!({ "quote_ref": quote, "amount_units": 1, "hold_kind": "initial" }),
        )
        .unwrap_err();
        assert!(dup
            .1
             .0
            .to_string()
            .contains("economics_initial_hold_exists"));

        // usage chain: charges recomputed, sequence + hash chain server-derived.
        let (u1, len1) = append_usage(
            &fxt.data_dir,
            &caller("use-1"),
            &json!({ "quote_ref": quote, "meter_class": "model_tokens", "quantity_units": 60, "commercial_posture": "managed", "runtime_receipt_refs": ["receipt://acme/r1"] }),
        )
        .unwrap();
        assert_eq!(len1, 1);
        assert_eq!(u1["charged_work_credits"]["units"], json!(300));
        assert_eq!(u1["previous_usage_hash"], Value::Null);
        let (u2, len2) = append_usage(
            &fxt.data_dir,
            &caller("use-2"),
            &json!({ "quote_ref": quote, "meter_class": "model_tokens", "quantity_units": 40, "commercial_posture": "local", "runtime_receipt_refs": ["receipt://acme/r2"] }),
        )
        .unwrap();
        assert_eq!(len2, 2);
        assert_eq!(u2["sequence"], json!(2));
        assert_eq!(u2["previous_usage_hash"], u1["body_hash"]);

        // telemetry meters never bill.
        let (telemetry, _) = append_usage(
            &fxt.data_dir,
            &caller("use-3"),
            &json!({ "quote_ref": quote, "meter_class": "ocu_coarse", "quantity_units": 999, "commercial_posture": "managed", "coarse_ocu_projection": true, "runtime_receipt_refs": ["receipt://acme/r3"] }),
        )
        .unwrap();
        assert_eq!(telemetry["charged_work_credits"]["units"], json!(0));

        // no spend without authority.
        let refused = mint_final_debit(
            &fxt.data_dir,
            &caller("debit-1"),
            &json!({ "quote_ref": quote }),
        )
        .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN);
        assert!(refused
            .1
             .0
            .to_string()
            .contains("economics_spend_authority_required"));

        // an insufficient grant refuses; a covering grant debits and consumes the hold.
        seed_grant(&fxt, 0);
        let poor = mint_final_debit(
            &fxt.data_dir,
            &caller("debit-1"),
            &json!({ "quote_ref": quote, "authority_grant_ref": "authority-grant://agr_test1" }),
        )
        .unwrap_err();
        assert!(poor
            .1
             .0
            .to_string()
            .contains("economics_spend_authority_insufficient"));
        seed_grant(&fxt, 1); // 1 whole credit = 1_000_000 micro >= 500
        let (debit, replayed) = mint_final_debit(
            &fxt.data_dir,
            &caller("debit-1"),
            &json!({ "quote_ref": quote, "authority_grant_ref": "authority-grant://agr_test1" }),
        )
        .unwrap();
        assert!(!replayed);
        assert_eq!(debit["object"]["debited_work_credits"]["units"], json!(500));
        let hold_after = load(
            &fxt.data_dir,
            KIND_HOLD,
            tail_of(hold["object"]["hold_ref"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(hold_after["object"]["status"], json!("consumed"));

        // exactly one debit per quote: a different-key second attempt refuses at the substrate.
        let second = mint_final_debit(
            &fxt.data_dir,
            &caller("debit-2"),
            &json!({ "quote_ref": quote, "authority_grant_ref": "authority-grant://agr_test1" }),
        );
        assert!(second.is_err(), "a second FinalDebit must refuse");
        // same-key replay converges on the one debit.
        let (again, replayed) = mint_final_debit(
            &fxt.data_dir,
            &caller("debit-1"),
            &json!({ "quote_ref": quote, "authority_grant_ref": "authority-grant://agr_test1" }),
        )
        .unwrap();
        assert!(replayed);
        assert_eq!(again["object"]["body_hash"], debit["object"]["body_hash"]);

        // adjustments: downward-only, chained, capped by the debit.
        let a1 = append_adjustment(
            &fxt.data_dir,
            &caller("adj-1"),
            &json!({ "final_debit_ref": format!("final-debit://{quote_id}"), "adjustment_kind": "refund", "amount_units": 200, "reason_code": "quality_shortfall", "evidence_refs": ["receipt://acme/quality"] }),
        )
        .unwrap();
        assert_eq!(a1["previous_adjustment_hash"], Value::Null);
        let over = append_adjustment(
            &fxt.data_dir,
            &caller("adj-2"),
            &json!({ "final_debit_ref": format!("final-debit://{quote_id}"), "adjustment_kind": "writeoff", "amount_units": 301, "reason_code": "x", "evidence_refs": ["receipt://acme/writeoff"] }),
        )
        .unwrap_err();
        assert!(over
            .1
             .0
            .to_string()
            .contains("economics_adjustment_exceeds_debit"));
        reset_handle_for_test();
    }

    #[test]
    fn overrun_decision_derives_from_the_immutable_quote() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan(&fxt, &card);
        let quote = seed_quote(&fxt, &card, &plan, 100);
        let (_hold, _) = mint_hold(
            &fxt.data_dir,
            &caller("h"),
            &json!({ "quote_ref": quote, "amount_units": 100, "hold_kind": "initial" }),
        )
        .unwrap();
        let (decision, _) = mint_overrun(
            &fxt.data_dir,
            &caller("ov-1"),
            &json!({ "quote_ref": quote, "projected_work_credit_units": 250 }),
        )
        .unwrap();
        let object = &decision["object"];
        assert_eq!(
            object["decision"],
            json!("exact_additional_hold"),
            "policy comes from the quote"
        );
        assert_eq!(object["held_work_credits"]["units"], json!(100));
        assert_eq!(object["exact_overage_work_credits"]["units"], json!(150));
        assert_eq!(object["additional_hold_amount"]["units"], json!(150));
        // the exact_additional hold must match the decision's exact amount.
        let wrong = mint_hold(
            &fxt.data_dir,
            &caller("h2"),
            &json!({ "quote_ref": quote, "amount_units": 149, "hold_kind": "exact_additional",
                     "overrun_decision_ref": object["overrun_decision_ref"] }),
        )
        .unwrap_err();
        assert!(wrong
            .1
             .0
            .to_string()
            .contains("economics_hold_decision_mismatch"));
        let (extra, _) = mint_hold(
            &fxt.data_dir,
            &caller("h3"),
            &json!({ "quote_ref": quote, "amount_units": 150, "hold_kind": "exact_additional",
                     "overrun_decision_ref": object["overrun_decision_ref"] }),
        )
        .unwrap();
        assert_eq!(extra["object"]["status"], json!("active"));
        reset_handle_for_test();
    }

    #[test]
    fn customer_borne_postures_carry_no_provider_cost() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan(&fxt, &card);
        let quote = seed_quote(&fxt, &card, &plan, 100);
        let error = append_usage(
            &fxt.data_dir,
            &caller("u"),
            &json!({
                "quote_ref": quote,
                "meter_class": "model_tokens",
                "quantity_units": 1,
                "commercial_posture": "local",
                "cost_breakdown": { "provider_cost_minor": 5 },
            }),
        )
        .unwrap_err();
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_customer_borne_provider_cost"));
        reset_handle_for_test();
    }

    // -------------------------------------------------- M07.5: metering the substrate

    fn seed_plan_with_allowance(
        fxt: &Fx,
        card_ref: &str,
        key: &str,
        included_units: u64,
    ) -> String {
        let (plan, _) = mint_plan(
            &fxt.data_dir,
            &caller(key),
            &json!({
                "rate_card_ref": card_ref,
                "included_work_credit_units": included_units,
                "reset_policy": "non_resetting",
                "validity_seconds": 3600,
            }),
        )
        .unwrap();
        plan["object"]["plan_ref"].as_str().unwrap().to_owned()
    }

    /// An admitted model-invocation projection as the invocation plane persists it — the owner
    /// record a `model-invocation://` receipt resolves through.
    fn seed_invocation(fxt: &Fx, id: &str, owner_ref: &str) -> String {
        persist_record(
            &fxt.data_dir,
            "model-invocations",
            id,
            &json!({
                "invocation_id": id,
                "owner_ref": owner_ref,
                "acting_principal_ref": "user://operator-7",
                "route_id": "managed-default",
                "route_ref": "route://managed/default",
                "transport": "openai_compatible",
                "model_id": "example-large",
                "base_url": "https://api.example.test/v1",
            }),
        )
        .unwrap();
        format!("model-invocation://{id}")
    }

    fn usage_body(quote: &str, quantity: u64, receipt: &str) -> Value {
        json!({
            "quote_ref": quote,
            "meter_class": "model_tokens",
            "quantity_units": quantity,
            "commercial_posture": "managed",
            "runtime_receipt_refs": [receipt],
        })
    }

    fn chain_length(fxt: &Fx, quote: &str) -> usize {
        usage_chain(&fxt.data_dir, tail_of(quote))
            .and_then(|chain| chain["object"]["usage_records"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    #[test]
    fn usage_dimensions_are_derived_from_the_invocation_record_and_never_from_the_caller() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan_with_allowance(&fxt, &card, "plan-m075-a", 10_000);
        let quote = seed_quote(&fxt, &card, &plan, 1_000);
        let receipt = seed_invocation(&fxt, "inv-a1", TENANT);
        let (u1, _) = append_usage(
            &fxt.data_dir,
            &caller("m075-a-1"),
            &usage_body(&quote, 12, &receipt),
        )
        .unwrap();
        let dims = &u1["metering_dimensions"];
        assert_eq!(dims["tenant_ref"], json!(TENANT));
        assert_eq!(dims["principal_ref"], json!("user://operator-7"));
        assert_eq!(
            dims["provider_ref"],
            json!("openai_compatible:https://api.example.test/v1")
        );
        assert_eq!(dims["model_route_ref"], json!("route://managed/default"));
        assert_eq!(dims["model_id"], json!("example-large"));
        assert_eq!(dims["resource_class"], json!("model"));
        assert_eq!(dims["usage_class"], json!("model_tokens"));
        assert_eq!(dims["derivation"], json!("owner_receipt"));
        assert_eq!(dims["session_ref"], Value::Null);
        assert_eq!(dims["package_release_ref"], Value::Null);
        for hash in ["quote_body_hash", "rate_card_body_hash", "plan_body_hash"] {
            assert!(u1[hash].as_str().unwrap().starts_with("sha256:"), "{hash}");
        }
        assert_eq!(
            u1["measurement_interval"]["interval_basis"],
            json!("admission_time")
        );
        assert_eq!(u1["idempotency_key"], json!("m075-a-1"));
        assert!(u1["idempotency_identity"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(
            u1["entitlement_consumption"]["covered_by"],
            json!("plan_allowance")
        );
        assert_eq!(
            u1["entitlement_consumption"]["consumed_before"]["units"],
            json!(0)
        );
        assert_eq!(
            u1["entitlement_consumption"]["consumed_after"]["units"],
            json!(60)
        );
        // A receipt no owner record can inform is typed caller_asserted — never invented.
        let (u2, _) = append_usage(
            &fxt.data_dir,
            &caller("m075-a-2"),
            &usage_body(&quote, 1, "receipt://runtime/opaque-1"),
        )
        .unwrap();
        assert_eq!(
            u2["metering_dimensions"]["derivation"],
            json!("caller_asserted")
        );
        assert_eq!(u2["metering_dimensions"]["principal_ref"], Value::Null);
        assert_eq!(u2["metering_dimensions"]["tenant_ref"], json!(TENANT));
        // The caller may author none of the derivations.
        for field in [
            "metering_dimensions",
            "entitlement_consumption",
            "idempotency_identity",
            "idempotency_key",
            "quote_body_hash",
            "measurement_interval",
        ] {
            let mut forged = usage_body(&quote, 1, "receipt://runtime/opaque-2");
            forged[field] = json!({ "tenant_ref": "org://other" });
            let error = append_usage(&fxt.data_dir, &caller("m075-a-forged"), &forged).unwrap_err();
            assert!(
                error
                    .1
                     .0
                    .to_string()
                    .contains("economics_server_derived_field"),
                "{field}"
            );
        }
        assert_eq!(chain_length(&fxt, &quote), 2);
        reset_handle_for_test();
    }

    #[test]
    fn a_receipt_is_metered_at_most_once_per_tenant_and_never_across_tenants() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan_with_allowance(&fxt, &card, "plan-m075-b", 10_000);
        let quote = seed_quote(&fxt, &card, &plan, 1_000);
        let receipt = seed_invocation(&fxt, "inv-b1", TENANT);
        let body = usage_body(&quote, 3, &receipt);
        let (first, len1) = append_usage(&fxt.data_dir, &caller("m075-b-1"), &body).unwrap();
        assert_eq!(len1, 1);
        // The same command under the same key is the substrate's replay, not a second charge:
        // whatever it answers, the chain holds one record and nothing calls it "already metered".
        match append_usage(&fxt.data_dir, &caller("m075-b-1"), &body) {
            Ok((replayed, length)) => {
                assert_eq!(length, 1);
                assert_eq!(replayed["usage_ref"], first["usage_ref"]);
            }
            Err(error) => assert!(!error
                .1
                 .0
                .to_string()
                .contains("economics_receipt_already_metered")),
        }
        assert_eq!(chain_length(&fxt, &quote), 1);
        // The same receipt under a NEW key is a second charge for the same work — refused by
        // name, naming the record that already binds it, chain unchanged.
        let error = append_usage(&fxt.data_dir, &caller("m075-b-2"), &body).unwrap_err();
        let text = error.1 .0.to_string();
        assert!(text.contains("economics_receipt_already_metered"), "{text}");
        assert!(
            text.contains(first["usage_ref"].as_str().unwrap()),
            "{text}"
        );
        assert_eq!(chain_length(&fxt, &quote), 1);
        // Another tenant's invocation cannot be charged to this tenant's quote.
        let foreign = seed_invocation(&fxt, "inv-b-foreign", "org://someone-else");
        let error = append_usage(
            &fxt.data_dir,
            &caller("m075-b-3"),
            &usage_body(&quote, 3, &foreign),
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_receipt_foreign_owner"));
        // An invocation ref that resolves to nothing is unresolved, not silently attributed.
        let error = append_usage(
            &fxt.data_dir,
            &caller("m075-b-4"),
            &usage_body(&quote, 3, "model-invocation://does-not-exist"),
        )
        .unwrap_err();
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_receipt_unresolved"));
        assert_eq!(chain_length(&fxt, &quote), 1);
        reset_handle_for_test();
    }

    #[test]
    fn the_plan_allowance_is_consumed_then_exhausted_typed_and_a_hold_covers_the_excess() {
        let fxt = fx();
        let card = seed_card(&fxt);
        // 100 micro work credits of allowance; each append below charges 10 units x rate 5 = 50.
        let plan = seed_plan_with_allowance(&fxt, &card, "plan-m075-c", 100);
        let quote = seed_quote(&fxt, &card, &plan, 1_000);
        let body = |n: u32| usage_body(&quote, 10, &format!("receipt://runtime/e-{n}"));
        let (u1, _) = append_usage(&fxt.data_dir, &caller("m075-c-1"), &body(1)).unwrap();
        assert_eq!(
            u1["entitlement_consumption"]["covered_by"],
            json!("plan_allowance")
        );
        let (u2, _) = append_usage(&fxt.data_dir, &caller("m075-c-2"), &body(2)).unwrap();
        assert_eq!(
            u2["entitlement_consumption"]["consumed_after"]["units"],
            json!(100)
        );
        // Past the allowance with no hold: refused by name, chain unchanged.
        let error = append_usage(&fxt.data_dir, &caller("m075-c-3"), &body(3)).unwrap_err();
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_entitlement_exhausted"));
        assert_eq!(chain_length(&fxt, &quote), 2);
        // An exact finite hold covers exactly one more charge, and the record says the hold did.
        mint_hold(
            &fxt.data_dir,
            &caller("m075-c-hold"),
            &json!({ "quote_ref": quote, "amount_units": 50, "hold_kind": "initial" }),
        )
        .unwrap();
        let (u3, length) = append_usage(&fxt.data_dir, &caller("m075-c-4"), &body(4)).unwrap();
        assert_eq!(length, 3);
        assert_eq!(
            u3["entitlement_consumption"]["covered_by"],
            json!("credit_hold")
        );
        let error = append_usage(&fxt.data_dir, &caller("m075-c-5"), &body(5)).unwrap_err();
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_entitlement_exhausted"));
        assert_eq!(chain_length(&fxt, &quote), 3);
        reset_handle_for_test();
    }

    #[test]
    fn usage_aggregation_is_a_read_projection_over_admitted_chains() {
        let fxt = fx();
        let card = seed_card(&fxt);
        let plan = seed_plan_with_allowance(&fxt, &card, "plan-m075-d", 10_000);
        let quote = seed_quote(&fxt, &card, &plan, 1_000);
        let receipt = seed_invocation(&fxt, "inv-d1", TENANT);
        append_usage(
            &fxt.data_dir,
            &caller("m075-d-1"),
            &usage_body(&quote, 4, &receipt),
        )
        .unwrap();
        append_usage(
            &fxt.data_dir,
            &caller("m075-d-2"),
            &usage_body(&quote, 6, "receipt://runtime/opaque-d"),
        )
        .unwrap();
        let identity = request_identity_for_test(PRINCIPAL, [TENANT.to_string()]);
        let by_principal = usage_aggregate(&fxt.data_dir, &identity, "principal_ref").unwrap();
        let buckets = by_principal["buckets"].as_array().unwrap();
        let find = |key: &str| {
            buckets
                .iter()
                .find(|row| row["key"] == json!(key))
                .cloned()
                .unwrap_or(Value::Null)
        };
        assert_eq!(find("user://operator-7")["records"], json!(1));
        assert_eq!(find("user://operator-7")["quantity_units"], json!(4));
        assert_eq!(
            find("user://operator-7")["charged_work_credits"]["units"],
            json!(20)
        );
        assert_eq!(find("unattributed")["records"], json!(1));
        assert_eq!(find("unattributed")["quantity_units"], json!(6));
        let by_meter = usage_aggregate(&fxt.data_dir, &identity, "meter_class").unwrap();
        assert_eq!(by_meter["buckets"][0]["key"], json!("model_tokens"));
        assert_eq!(by_meter["buckets"][0]["records"], json!(2));
        assert_eq!(
            by_meter["buckets"][0]["charged_work_credits"]["units"],
            json!(50)
        );
        // An unregistered dimension refuses rather than aggregating by a field nobody registered.
        let error = usage_aggregate(&fxt.data_dir, &identity, "favourite_colour").unwrap_err();
        assert!(error
            .1
             .0
            .to_string()
            .contains("economics_aggregate_dimension_unknown"));
        // Another tenant's identity sees nothing of this tenant's chains.
        let outsider = request_identity_for_test("outsider", ["org://someone-else".to_string()]);
        let empty = usage_aggregate(&fxt.data_dir, &outsider, "meter_class").unwrap();
        assert!(empty["buckets"].as_array().unwrap().is_empty());
        reset_handle_for_test();
    }

    #[test]
    fn source_discipline_identity_first_and_no_hardcoded_principals() {
        let source = include_str!("economics_routes.rs");
        for handler in [
            "handle_rate_card_create",
            "handle_plan_create",
            "handle_quote_create",
            "handle_hold_create",
            "handle_hold_release",
            "handle_usage_append",
            "handle_overrun_create",
            "handle_final_debit_create",
            "handle_adjustment_create",
        ] {
            let marker = format!("pub(crate) async fn {handler}");
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("missing {handler}"));
            let block = &source[start..start + 600];
            assert!(
                block.contains("require_write_caller("),
                "{handler} must resolve identity as its first act"
            );
        }
        let production = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];
        assert!(!production.contains("user://local-operator"));
        assert!(
            !production.contains("as f64"),
            "no float amounts in the economics plane"
        );
        assert!(
            !production.contains(".as_f64()"),
            "no float amounts in the economics plane"
        );
    }
}
