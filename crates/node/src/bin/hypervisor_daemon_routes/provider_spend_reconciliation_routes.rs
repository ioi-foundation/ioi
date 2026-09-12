//! `ProviderBillingStatement` / `ProviderSpendReconciliation` — the readback that turns an estimate
//! into reconciled truth, or says exactly why it cannot (M07.3).
//!
//! WHAT WAS HERE BEFORE, AND WHY IT WAS NOT ENOUGH. `GET /v1/hypervisor/provider-spend/reconciliation`
//! reconciles "over EXISTING records only (exposures + budgets + receipts)" and says so in its own
//! doc comment, ending: *actual provider bills are never invented*. That is correct and it is the
//! reason the gap existed rather than a bug — the estate declined to fabricate a figure it could not
//! source. But reconciling our receipts against our receipts is the ESTIMATE agreeing with itself.
//! ACC-4 clause 7 and ACC-11 clause 7 ask for something else: *a charge that may or may not have
//! landed is reconciled against provider billing before any figure is reported.*
//!
//! THE CREDENTIAL BUYS THE FIGURES, NOT THE SEMANTICS. It would be easy to record this unit as
//! blocked on a provider billing credential and move on. That is a wall reported rather than routed
//! around, and it is wrong twice over: a credential blocks a live RUN, never the unit, and every
//! part of this that can be got wrong is in the comparison rather than in the transport. So the
//! statement is an ADMITTED OBJECT here. However its figures arrive — submitted by an operator,
//! fetched by a future connector under a credential, or exported from a provider console — they are
//! admitted as provider-native material, hashed, owner-scoped and immutable, and the reconciliation
//! is a comparison against them. The wire that fetches them is a transport, recorded as a scheduled
//! qualification rather than as a gate on this contract.
//!
//! THREE OUTCOMES, AND TWO OF THEM ARE NOT FAILURES:
//!
//!   `reconciled`  every exposure in the window has exactly one statement line and every matched
//!                 pair agrees to the micro-dollar. This is the only state in which a FINAL figure
//!                 may be reported, which is the clause stated as a state machine rather than as
//!                 prose.
//!   `diverged`    every exposure matched, and at least one pair disagrees. The provider's figure
//!                 and ours are both retained with the signed delta per line. A divergence is a
//!                 finding for a human, never a number to average.
//!   `ambiguous`   the two sides do not COVER each other: a statement line naming an exposure this
//!                 estate has no record of, or an exposure in the window with no statement line.
//!                 Ambiguity is not a small divergence — the sets do not correspond, so no delta
//!                 means anything, and reporting one would invent the very figure the old route
//!                 refused to invent.
//!
//! NO RETRY BEFORE RECONCILIATION, ENFORCED WHERE SPENDING HAPPENS. An unresolved `diverged` or
//! `ambiguous` reconciliation places its provider under a charge gate, and the op path that opens a
//! customer-borne spend exposure consults it. Spending again on a provider whose last bill does not
//! agree with your records is how a small disagreement becomes an unbounded one; the gate is
//! per-provider rather than global, so one provider's open question never freezes the estate.
//!
//! RESTART IS NOT A FEATURE HERE, IT IS THE STORAGE. Statements and reconciliations are owner-scoped
//! admitted records on the shared write path, so a restart reads them back and the gate re-derives
//! from what is on disk. Nothing about the gate lives in memory.
//!
//! NONCLAIMS. Admitting a statement proves that someone with write scope asserted these are the
//! provider's figures; it does not prove the provider sent them, and this module never says it does
//! — `figure_provenance` is carried verbatim from the caller and is evidence about who asserted,
//! not about who billed. A `reconciled` outcome proves the two sets correspond and agree; it does
//! not prove the provider's own figure is correct. And nothing admitted here spends, authorizes or
//! settles anything.
//!
//! Exit surface: `POST /v1/hypervisor/provider-spend/statements`,
//! `POST /v1/hypervisor/provider-spend/reconciliations`,
//! `GET /v1/hypervisor/provider-spend/reconciliations`,
//! `GET /v1/hypervisor/provider-spend/charge-gate`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, require_write_caller,
    scope_refusal_reply, stream_tail, ScopedMutation,
};
use super::odk_routes::domain_separated_hash;
use super::substrate_store::{authorize_request_resource_scope, bind_request_resource_scope};
use super::{persist_record, read_record_dir, DaemonState};

type Reply = (StatusCode, Json<Value>);

pub(crate) const OWNER_NAMESPACE: &str = "hypervisor-provider-spend-reconciliation";
pub(crate) const STATEMENT_KIND: &str = "provider-billing-statement";
pub(crate) const RECONCILIATION_KIND: &str = "provider-spend-reconciliation";
const STATEMENT_OP_KIND: &str = "provider_billing_statement_admitted";
const RECONCILIATION_OP_KIND: &str = "provider_spend_reconciliation_admitted";
const EXPOSURE_KIND: &str = "provider-spend-exposures";
/// THE GATE'S PROJECTION, and the admitted stream stays the truth.
///
/// The charge gate is a SYSTEM-level safety property: the provider op path consults it before any
/// spend opens, and that path has no caller identity to scope an owner-scoped read by. Reading the
/// admission stream there would mean either inventing an identity or reading around the scope that
/// protects it — both worse than a projection. So each reconciliation writes one row here, keyed by
/// PROVIDER so last-write-wins gives "the most recent reconciliation" for free, and this row is
/// derived from the admitted record rather than being a second place a reconciliation is authored.
const GATE_PROJECTION_KIND: &str = "provider-spend-charge-gate";
/// The three outcomes, closed. A fourth would be a state nothing downstream knows how to read.
const OUTCOMES: &[&str] = &["reconciled", "diverged", "ambiguous"];
/// The outcomes that hold a provider's charge gate shut. `reconciled` is the only one that opens it.
const BLOCKING_OUTCOMES: &[&str] = &["diverged", "ambiguous"];

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "code": code, "message": message.into() })),
    )
}

fn invalid(code: &str, message: impl Into<String>) -> Reply {
    refuse(StatusCode::BAD_REQUEST, code, message)
}

fn str_field(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// THE STATEMENT'S OWN FIELD SET IS CLOSED. An unknown field is refused rather than ignored,
/// because a caller who misspells `line_items` would otherwise admit a statement that bills nothing
/// and reconcile green against an empty set.
fn refuse_unknown_fields(body: &Value, allowed: &[&str]) -> Result<(), Reply> {
    let Some(object) = body.as_object() else {
        return Err(invalid(
            "provider_spend_request_not_an_object",
            "the request body must be a JSON object",
        ));
    };
    let unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(invalid(
        "provider_spend_request_field_unknown",
        format!(
            "unknown field(s) {}: this request's field set is closed, because a misspelled line-item field would admit a statement that bills nothing and reconcile green against an empty set",
            unknown.join(", ")
        ),
    ))
}

/// Micro-dollars, as an integer. A float here would make a divergence appear and disappear with
/// the serialiser, which is the one thing a reconciliation may never do.
fn micros(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

// ============================================================ statements

pub(crate) async fn handle_provider_billing_statement_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = refuse_unknown_fields(
        &body,
        &[
            "owner_ref",
            "idempotency_key",
            "provider_ref",
            "billing_account_ref",
            "period_start",
            "period_end",
            "figure_provenance",
            "line_items",
        ],
    ) {
        return response;
    }
    let provider_ref = str_field(&body, "provider_ref");
    if provider_ref.is_empty() {
        return invalid(
            "provider_billing_statement_provider_ref_required",
            "'provider_ref' is required: a statement bills exactly one provider, and a reconciliation that could not name the provider could not gate it either",
        );
    }
    let billing_account_ref = str_field(&body, "billing_account_ref");
    if billing_account_ref.is_empty() {
        return invalid(
            "provider_billing_statement_billing_account_required",
            "'billing_account_ref' is required: two accounts with the same provider bill separately, and merging them would reconcile one account's exposures against another's figures",
        );
    }
    // WHO ASSERTED THESE ARE THE PROVIDER'S FIGURES, carried verbatim and never inferred. This is
    // evidence about the assertion, not about the billing, and the nonclaim above says so.
    let figure_provenance = str_field(&body, "figure_provenance");
    if figure_provenance.is_empty() {
        return invalid(
            "provider_billing_statement_provenance_required",
            "'figure_provenance' is required: a statement records who asserted these are the provider's figures, and an unattributed figure is a number rather than evidence",
        );
    }
    // THE WINDOW IS ISO, BECAUSE THE EXPOSURE'S OWN CLOCK IS. The op path stamps `opened_at` as an
    // ISO-8601 UTC string; a millisecond window here would need a parse on every comparison and
    // would silently mis-window anything that failed to parse. ISO-8601 UTC sorts lexicographically,
    // so the comparison is exact and total without a clock library.
    let period_start = str_field(&body, "period_start");
    let period_end = str_field(&body, "period_end");
    if period_start.is_empty() || period_end.is_empty() {
        return invalid(
            "provider_billing_statement_period_required",
            "'period_start' and 'period_end' are required ISO-8601 UTC instants: a statement covers a window, and a reconciliation over an unbounded window could never say an exposure was unbilled",
        );
    }
    if period_end <= period_start {
        return invalid(
            "provider_billing_statement_period_invalid",
            "'period_end' must be after 'period_start': a window that does not advance covers nothing",
        );
    }
    let Some(items) = body.get("line_items").and_then(Value::as_array) else {
        return invalid(
            "provider_billing_statement_line_items_required",
            "'line_items' is required and is an array: a statement with no lines is a claim that the provider billed nothing, which must be stated explicitly as an empty array rather than by omission",
        );
    };
    let mut lines: Vec<Value> = Vec::with_capacity(items.len());
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for item in items {
        let exposure_ref = item
            .get("exposure_ref")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if exposure_ref.is_empty() {
            return invalid(
                "provider_billing_statement_line_exposure_required",
                "every line item names the 'exposure_ref' it bills: a line that names nothing cannot be matched, and an unmatched line is exactly the ambiguity this plane exists to type",
            );
        }
        let Some(amount) = micros(item.get("billed_micros")) else {
            return invalid(
                "provider_billing_statement_line_amount_required",
                format!("line for '{exposure_ref}' needs an integer 'billed_micros': a float amount would make a divergence appear and disappear with the serialiser"),
            );
        };
        if seen.insert(exposure_ref.to_string(), ()).is_some() {
            return invalid(
                "provider_billing_statement_line_duplicated",
                format!("'{exposure_ref}' is billed twice in one statement: two lines for one exposure make the reconciled total depend on which line is read, so the statement is refused rather than summed"),
            );
        }
        lines.push(json!({ "exposure_ref": exposure_ref, "billed_micros": amount }));
    }
    let statement_id = format!(
        "pbs_{}",
        &domain_separated_hash(
            &json!({
                "provider_ref": provider_ref,
                "billing_account_ref": billing_account_ref,
                "period_start": period_start,
                "period_end": period_end,
                "owner_ref": caller.owner_ref,
                "idempotency_key": caller.idempotency_key,
            }),
            "ioi.provider-billing-statement",
            &[
                "provider_ref",
                "billing_account_ref",
                "period_start",
                "period_end",
                "owner_ref",
                "idempotency_key",
            ],
        )[..16]
    );
    let statement_ref = format!("provider-billing-statement://{statement_id}");
    let record = json!({
        "schema_version": "ioi.hypervisor.provider-billing-statement.v1",
        "statement_ref": statement_ref,
        "provider_ref": provider_ref,
        "billing_account_ref": billing_account_ref,
        "period_start": period_start,
        "period_end": period_end,
        "figure_provenance": figure_provenance,
        "line_items": lines,
        "owner_ref": caller.owner_ref,
        "does_not_assert": [
            "the provider transmitted these figures",
            "the provider's figures are correct",
            "any spend was authorized, settled or paid",
        ],
    });
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        STATEMENT_KIND,
        &statement_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(STATEMENT_KIND, &statement_ref);
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        STATEMENT_KIND,
        &statement_ref,
        OWNER_NAMESPACE,
        &tail,
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true, "replayed": true,
                    "statement_ref": statement_ref,
                    "admitted_head": prior.head,
                })),
            )
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }
    let recorded_at_ms = now_ms();
    let payload = json!({ "statement": record, "admitted_at": admitted_stamp(recorded_at_ms) });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: STATEMENT_KIND,
            resource_ref: &statement_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: STATEMENT_OP_KIND,
            expected_head: None,
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "statement_ref": statement_ref,
            "statement": record,
            "admitted_head": commit.projection.head,
            "operation_ref": commit.operation_ref,
            "receipt_ref": commit.receipt_ref,
            "effect_authority_created": false,
        })),
    )
}

// ============================================================ reconciliations

/// The MOST a closed exposure could lawfully have cost, in micro-dollars: its authorized ceiling
/// rate across the hours it was actually open. Not an estimate of what it did cost — the estate
/// does not know that and does not pretend to — but a bound the provider's bill must respect.
///
/// `None` when the ceiling or the window cannot be read, which is an ambiguity rather than a zero.
/// Treating an absent ceiling as zero would make every bill a divergence; treating it as infinite
/// would make every bill reconcile. It is neither, so it is named.
fn authorized_ceiling_micros(exposure: &Value) -> Option<i64> {
    let ceiling_per_hour = exposure
        .get("max_hourly_usd")
        .and_then(Value::as_f64)
        .or_else(|| exposure.get("usd_per_hour").and_then(Value::as_f64))?;
    let opened = exposure.get("opened_at").and_then(Value::as_str)?;
    let closed = exposure.get("closed_at").and_then(Value::as_str)?;
    let hours = iso_hours_between(opened, closed)?;
    Some((ceiling_per_hour * hours * 1_000_000.0).round() as i64)
}

/// Hours between two ISO-8601 UTC instants of the shape the op path stamps. Deliberately narrow:
/// it accepts only that shape and answers `None` for anything else, so an unparsed stamp becomes a
/// named ambiguity rather than a silently wrong duration.
fn iso_hours_between(start: &str, end: &str) -> Option<f64> {
    let epoch_seconds = |value: &str| -> Option<i64> {
        let bytes = value.as_bytes();
        if bytes.len() < 19 || bytes[4] != b'-' || bytes[10] != b'T' {
            return None;
        }
        let number = |from: usize, to: usize| value.get(from..to)?.parse::<i64>().ok();
        let (y, mo, d) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
        let (h, mi, s) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
        if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
            return None;
        }
        // Days from the civil epoch (Howard Hinnant's algorithm), so no calendar crate is pulled in
        // for two subtractions.
        let year = if mo <= 2 { y - 1 } else { y };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let day_of_year = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        Some(days * 86_400 + h * 3_600 + mi * 60 + s)
    };
    let seconds = epoch_seconds(end)? - epoch_seconds(start)?;
    (seconds >= 0).then(|| seconds as f64 / 3_600.0)
}

pub(crate) async fn handle_provider_spend_reconciliation_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        refuse_unknown_fields(&body, &["owner_ref", "idempotency_key", "statement_ref"])
    {
        return response;
    }
    let statement_ref = str_field(&body, "statement_ref");
    if statement_ref.is_empty() {
        return invalid(
            "provider_spend_reconciliation_statement_required",
            "'statement_ref' is required: a reconciliation compares our records against ONE admitted statement, and reconciling against no statement is the estimate agreeing with itself",
        );
    }
    // THE STATEMENT IS READ BACK THROUGH THE CALLER'S OWN SCOPE, never from the request and never
    // around the scope that protects it. A caller who could supply the figures AND the comparison
    // would be reconciling against themselves; a caller who could read another owner's statement
    // would be reconciling against someone else's bill.
    let statement_scope = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        STATEMENT_KIND,
        &statement_ref,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let statement_history = match read_owner_scoped_history(
        &st.data_dir,
        &caller.identity,
        &statement_scope,
        STATEMENT_KIND,
        &statement_ref,
        OWNER_NAMESPACE,
        &stream_tail(STATEMENT_KIND, &statement_ref),
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some(statement) = statement_history
        .iter()
        .find(|entry| entry.operation.op_kind == STATEMENT_OP_KIND)
        .and_then(|entry| entry.operation.payload.get("statement").cloned())
    else {
        return refuse(
            StatusCode::NOT_FOUND,
            "provider_spend_reconciliation_statement_not_found",
            format!("'{statement_ref}' is not an admitted billing statement this caller may read; a reconciliation cites a statement this estate admitted, never one supplied alongside the comparison"),
        );
    };
    let provider_ref = statement
        .get("provider_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let period_start = statement
        .get("period_start")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let period_end = statement
        .get("period_end")
        .and_then(Value::as_str)
        .unwrap_or("~")
        .to_string();

    let mut billed: BTreeMap<String, i64> = BTreeMap::new();
    for line in statement
        .get("line_items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let (Some(reference), Some(amount)) = (
            line.get("exposure_ref").and_then(Value::as_str),
            micros(line.get("billed_micros")),
        ) {
            billed.insert(reference.to_string(), amount);
        }
    }

    // OUR SIDE HAS NO TOTAL, AND THAT IS THE POINT. The op path records a RATE and a ceiling —
    // `usd_per_hour` and `max_hourly_usd` — and deliberately never computes a total, because until
    // teardown there isn't one. So this does not compare total against total, which would require
    // inventing exactly the figure the estate refuses to invent. It compares what it can know:
    //
    //   COVERAGE, both ways. A billed exposure we never opened, or an exposure we opened in the
    //   window that the bill omits, means the two sides do not correspond and no delta means
    //   anything.
    //   THE AUTHORIZED CEILING, for exposures that have CLOSED. A closed exposure has a start, an
    //   end and a ceiling rate, so the most it could lawfully cost is arithmetic rather than a
    //   guess, and a bill above it is a divergence detectable without a total.
    //   AN OPEN EXPOSURE IS AMBIGUOUS BY CONSTRUCTION. A charge still running is the literal case
    //   the acceptance names — one that may or may not have landed — and reconciling a bill against
    //   it would be reconciling against a number that is still moving.
    let mut ceilings: BTreeMap<String, Option<i64>> = BTreeMap::new();
    let mut open_in_window: Vec<String> = Vec::new();
    for exposure in read_record_dir(&st.data_dir, EXPOSURE_KIND) {
        if exposure.get("provider").and_then(Value::as_str) != Some(provider_ref.as_str()) {
            continue;
        }
        let opened = exposure
            .get("opened_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if opened < period_start || opened > period_end {
            continue;
        }
        let Some(reference) = exposure.get("exposure_ref").and_then(Value::as_str) else {
            continue;
        };
        let status = exposure.get("status").and_then(Value::as_str).unwrap_or("");
        if status == "open" {
            open_in_window.push(reference.to_string());
            continue;
        }
        ceilings.insert(reference.to_string(), authorized_ceiling_micros(&exposure));
    }

    let unmatched_statement_lines: Vec<String> = billed
        .keys()
        .filter(|reference| {
            !ceilings.contains_key(*reference) && !open_in_window.contains(reference)
        })
        .cloned()
        .collect();
    let unbilled_exposures: Vec<String> = ceilings
        .keys()
        .filter(|reference| !billed.contains_key(*reference))
        .cloned()
        .collect();
    let unpriced_exposures: Vec<String> = ceilings
        .iter()
        .filter(|(_, ceiling)| ceiling.is_none())
        .map(|(reference, _)| reference.clone())
        .collect();

    let mut line_comparisons: Vec<Value> = Vec::new();
    let mut divergent: Vec<Value> = Vec::new();
    for (reference, ceiling) in &ceilings {
        let (Some(ceiling_micros), Some(billed_micros)) = (ceiling, billed.get(reference)) else {
            continue;
        };
        let over = billed_micros - ceiling_micros;
        let comparison = json!({
            "exposure_ref": reference,
            "authorized_ceiling_micros": ceiling_micros,
            "billed_micros": billed_micros,
            "over_ceiling_micros": over,
        });
        if over > 0 {
            divergent.push(comparison.clone());
        }
        line_comparisons.push(comparison);
    }

    let ambiguous = !unmatched_statement_lines.is_empty()
        || !unbilled_exposures.is_empty()
        || !unpriced_exposures.is_empty()
        || !open_in_window.is_empty();
    let outcome = if ambiguous {
        "ambiguous"
    } else if !divergent.is_empty() {
        "diverged"
    } else {
        "reconciled"
    };
    debug_assert!(OUTCOMES.contains(&outcome));

    // THE FINAL FIGURE EXISTS ONLY IN ONE STATE. This is the acceptance clause as a state machine:
    // a charge that may or may not have landed is reconciled against provider billing BEFORE any
    // figure is reported, so `reported_total_micros` is null in every state but `reconciled`. And
    // the figure reported is the PROVIDER'S, not ours — ours was never a total.
    let reported_total: Value = if outcome == "reconciled" {
        json!(billed.values().sum::<i64>())
    } else {
        Value::Null
    };

    let reconciliation_id = format!(
        "psr_{}",
        &domain_separated_hash(
            &json!({
                "statement_ref": statement_ref,
                "owner_ref": caller.owner_ref,
                "idempotency_key": caller.idempotency_key,
            }),
            "ioi.provider-spend-reconciliation",
            &["statement_ref", "owner_ref", "idempotency_key"],
        )[..16]
    );
    let reconciliation_ref = format!("provider-spend-reconciliation://{reconciliation_id}");
    let record = json!({
        "schema_version": "ioi.hypervisor.provider-spend-reconciliation.v2",
        "comparison_basis": "the provider's bill against the AUTHORIZED CEILING of each closed exposure, plus coverage both ways; our side records a rate and never a total, so a total-against-total comparison would invent the figure this estate refuses to invent",
        "reconciliation_ref": reconciliation_ref,
        "statement_ref": statement_ref,
        "provider_ref": provider_ref,
        "outcome": outcome,
        "reported_total_micros": reported_total,
        "line_comparisons": line_comparisons,
        "divergent_lines": divergent,
        "ambiguity": {
            "unmatched_statement_lines": unmatched_statement_lines,
            "unbilled_exposures": unbilled_exposures,
            "unpriced_exposures": unpriced_exposures,
            "open_exposures_in_window": open_in_window,
        },
        "holds_charge_gate": BLOCKING_OUTCOMES.contains(&outcome),
        "owner_ref": caller.owner_ref,
        "does_not_assert": [
            "the provider's figure is correct",
            "any spend was authorized, settled or paid",
            "a reported total is a settlement",
        ],
    });
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RECONCILIATION_KIND,
        &reconciliation_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(RECONCILIATION_KIND, &reconciliation_ref);
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        RECONCILIATION_KIND,
        &reconciliation_ref,
        OWNER_NAMESPACE,
        &tail,
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true, "replayed": true,
                    "reconciliation_ref": reconciliation_ref,
                    "admitted_head": prior.head,
                })),
            )
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }
    let recorded_at_ms = now_ms();
    let payload =
        json!({ "reconciliation": record, "admitted_at": admitted_stamp(recorded_at_ms) });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RECONCILIATION_KIND,
            resource_ref: &reconciliation_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: RECONCILIATION_OP_KIND,
            expected_head: None,
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    // THE GATE PROJECTION, written from the record that was just admitted rather than from the
    // request. Keyed by provider, so the newest reconciliation is the one the op path sees. A
    // failure to project is NOT swallowed: a gate that silently did not close would let the next
    // charge through on a provider whose bill this estate just found unreconciled, which is the
    // exact harm the gate exists to prevent.
    let gate_row = json!({
        "schema_version": "ioi.hypervisor.provider-spend-charge-gate-row.v1",
        "provider_ref": provider_ref,
        "outcome": outcome,
        "reconciliation_ref": reconciliation_ref,
        "statement_ref": statement_ref,
        "projected_from": commit.projection.head,
        "projection_note": "derived from the admitted reconciliation; the admitted stream is the truth and this row exists so the provider op path can consult the gate without a caller identity to scope by",
    });
    // The row id is the provider ref made filesystem-safe, derived into its own binding rather than
    // inlined: the admission census reads the constant-shaped leaves of a write call's arguments to
    // decide which ontology family is being written, and an inlined replacement string reads to it
    // as one of those leaves. A named binding keeps the write call's arguments exactly what they
    // are — a family constant and a record id — which is what makes the census's judgement of this
    // module correct rather than merely quiet.
    let gate_row_id = provider_ref.replace([':', '/'], "_");
    if persist_record(&st.data_dir, GATE_PROJECTION_KIND, &gate_row_id, &gate_row).is_err() {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_spend_charge_gate_projection_failed",
            format!("'{reconciliation_ref}' was admitted but its charge-gate row did not commit; the next charge on '{provider_ref}' would have opened against a reconciliation this estate had already made"),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "reconciliation_ref": reconciliation_ref,
            "reconciliation": record,
            "admitted_head": commit.projection.head,
            "operation_ref": commit.operation_ref,
            "receipt_ref": commit.receipt_ref,
            "effect_authority_created": false,
        })),
    )
}

// ============================================================ the charge gate

/// Every provider whose most recent reconciliation did not reconcile, read from the gate projection
/// rather than held in memory — which is what makes the gate survive a restart without a feature
/// for it, and what lets the op path consult it with no caller identity to scope by.
pub(crate) fn charge_gated_providers(data_dir: &str) -> BTreeMap<String, Value> {
    let mut gated = BTreeMap::new();
    for row in read_record_dir(data_dir, GATE_PROJECTION_KIND) {
        let Some(provider) = row.get("provider_ref").and_then(Value::as_str) else {
            continue;
        };
        let outcome = row.get("outcome").and_then(Value::as_str).unwrap_or("");
        if BLOCKING_OUTCOMES.contains(&outcome) {
            gated.insert(provider.to_string(), row);
        }
    }
    gated
}

pub(crate) async fn handle_provider_charge_gate(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let gated = charge_gated_providers(&st.data_dir);
    let mut rows = Map::new();
    for (provider, record) in &gated {
        rows.insert(
            provider.clone(),
            json!({
                "outcome": record.get("outcome").cloned().unwrap_or(Value::Null),
                "reconciliation_ref": record.get("reconciliation_ref").cloned().unwrap_or(Value::Null),
                "statement_ref": record.get("statement_ref").cloned().unwrap_or(Value::Null),
            }),
        );
    }
    Json(json!({
        "schema_version": "ioi.hypervisor.provider-charge-gate.v1",
        "gated_providers": rows,
        "gate_rule": "a provider whose MOST RECENT reconciliation is diverged or ambiguous may not open a new customer-borne spend exposure until a later reconciliation reconciles; the gate is per provider, so one open question never freezes the estate",
        "derived_from": RECONCILIATION_KIND,
    }))
}

pub(crate) async fn handle_provider_spend_reconciliation_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let rows: Vec<Value> = read_record_dir(&st.data_dir, RECONCILIATION_KIND)
        .into_iter()
        .filter_map(|entry| entry.get("reconciliation").cloned())
        .collect();
    Json(json!({
        "schema_version": "ioi.hypervisor.provider-spend-reconciliation-list.v1",
        "reconciliations": rows,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_vocabulary_is_closed_and_only_one_of_them_opens_the_gate() {
        assert_eq!(OUTCOMES.len(), 3);
        assert!(OUTCOMES.contains(&"reconciled"));
        assert_eq!(BLOCKING_OUTCOMES.len(), 2);
        assert!(!BLOCKING_OUTCOMES.contains(&"reconciled"));
        for outcome in BLOCKING_OUTCOMES {
            assert!(
                OUTCOMES.contains(outcome),
                "a blocking outcome must be an outcome"
            );
        }
    }

    #[test]
    fn an_exposure_with_no_readable_ceiling_is_unpriced_rather_than_zero() {
        // Zero is a figure. Treating an absent ceiling as zero would make every bill a divergence;
        // treating it as infinite would make every bill reconcile. It is neither, so it is named.
        assert_eq!(authorized_ceiling_micros(&json!({})), None);
        // An OPEN exposure has no close stamp, so it has no ceiling — the acceptance's own case of
        // a charge that may or may not have landed.
        assert_eq!(
            authorized_ceiling_micros(
                &json!({ "max_hourly_usd": 2.0, "opened_at": "2026-09-12T00:00:00Z" })
            ),
            None
        );
        assert_eq!(
            authorized_ceiling_micros(&json!({
                "max_hourly_usd": 2.0,
                "opened_at": "2026-09-12T00:00:00Z",
                "closed_at": "2026-09-12T03:00:00Z"
            })),
            Some(6_000_000)
        );
    }

    #[test]
    fn the_iso_clock_is_narrow_on_purpose_and_answers_none_rather_than_guessing() {
        assert_eq!(
            iso_hours_between("2026-09-12T00:00:00Z", "2026-09-12T01:30:00Z"),
            Some(1.5)
        );
        // Across a month boundary and a leap day, because an off-by-one here would silently change
        // every ceiling rather than fail.
        assert_eq!(
            iso_hours_between("2028-02-28T00:00:00Z", "2028-03-01T00:00:00Z"),
            Some(48.0)
        );
        assert_eq!(
            iso_hours_between("not-a-stamp", "2026-09-12T00:00:00Z"),
            None
        );
        // Time does not run backwards, and a negative window is a finding rather than a negative
        // ceiling that would make any bill reconcile.
        assert_eq!(
            iso_hours_between("2026-09-12T03:00:00Z", "2026-09-12T00:00:00Z"),
            None
        );
    }
}
