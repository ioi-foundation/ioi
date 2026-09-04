//! M15.3 — `CloudJobRequest`, the composition surface.
//!
//! A job request is an ENVELOPE over exactly one `CloudResourceIntent`. It is not a
//! second intent type, it is not authority, and it owns nothing: no credential store,
//! no session plane, no provider adapter, no placement scorer, no receipt format.
//! Every one of those exists and is owned elsewhere (ADR 0051 §1, §7). The envelope's
//! whole job is to compose them, which is why this file is short and mostly refusals.
//!
//!   decentralized.cloud proposes.   wallet.network authorizes.
//!   Hypervisor places and executes. Agentgres records what ran and what it cost.
//!
//! THE ONE RULE THAT SHAPES EVERYTHING HERE: a human and an agent submit the SAME
//! envelope and receive the SAME receipts. `caller_kind` selects the authority path —
//! a wallet grant for a person, a CapabilityLease draw-down for an agent — and
//! nothing else. It never changes the placement, never the price, never the receipt
//! shape. If those two paths ever diverge in anything but authority, one caller is
//! being offered a privilege the other is not, and that is the second spine this
//! design exists to avoid.
//!
//! Admission is a PROPOSAL. Nothing here mutates a provider. Execution runs through
//! the existing placement decision and the per-kind gate ladder, in process, through
//! the single mutation lane — never a second one.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

const JOB_KIND: &str = "cloud-jobs";

/// The five receipt kinds a completed job can be required to return. A requirement
/// this list does not contain is refused rather than ignored: a caller who asked for
/// a receipt that will never be minted has been told they will get evidence they
/// will not get.
const RECEIPT_REQUIREMENTS: &[&str] = &[
    "placement",
    "provider-operation",
    "spend",
    "failover",
    "offline-verifiable",
];

/// `none` is the only posture this cut accepts. `warm_standby` and `active_active`
/// need replica placement, a per-replica exposure set and a switch policy, none of
/// which exist — so they are refused BY NAME rather than silently downgraded to
/// `none`. A caller who asked for redundancy and quietly got none would believe
/// their work was protected when it was not, which is worse than a refusal.
const REDUNDANCY_ACCEPTED: &str = "none";
const REDUNDANCY_KNOWN: &[&str] = &["none", "warm_standby", "active_active"];

/// Keys that would mean the caller is carrying a provider credential. The caller
/// NEVER holds one: `credential_connector_id` and `credential_store` stay daemon-side
/// in the vault for both authority paths. A request bearing any of these is refused
/// typed rather than having the field dropped, because dropping it silently would
/// leave the caller believing they had supplied something that was used.
const CALLER_CREDENTIAL_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "provider_api_key",
    "credential",
    "credentials",
    "secret",
    "token",
    "bearer",
    "password",
    "private_key",
    "ssh_key",
];

/// Keys that would mean the caller is naming a venue. The venue is EVIDENCE in the
/// receipt, not an input to the request — a caller who must name a provider is using
/// the "Pick a cloud" surface, not the job API. Refused rather than honoured, because
/// honouring it would make the placement decision the caller's and the receipt a
/// record of something the router did not choose.
const VENUE_KEYS: &[&str] = &[
    "venue",
    "provider_kind",
    "provider_account_ref",
    "adapter_ref",
];

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn refuse(code: &str, message: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

/// Walk the envelope for a forbidden key at any depth. A credential nested inside
/// `intent` is still a credential the caller supplied.
fn find_key<'a>(body: &Value, keys: &'a [&'a str]) -> Option<&'a str> {
    match body {
        Value::Object(map) => {
            for k in keys {
                if map.contains_key(*k) {
                    return Some(k);
                }
            }
            map.values().find_map(|v| find_key(v, keys))
        }
        Value::Array(items) => items.iter().find_map(|v| find_key(v, keys)),
        _ => None,
    }
}

/// `caller_kind` -> the authority path. This is the only genuinely new resolver in
/// M15.3, and it is small on purpose: both paths converge on the same
/// `CapabilityLeaseRequest` and the same authorization call, so what differs is how
/// the authority was OBTAINED, not what it permits.
///
/// A lease draw-down is a NARROWING of a grant a human made earlier. It is never a
/// new grant an agent minted for itself, and it can never widen what the underlying
/// grant already permits.
fn resolve_authority_mode(caller_kind: &str, authority_ref: &str) -> Result<Value, (String, String)> {
    match caller_kind {
        "human" => {
            if !authority_ref.starts_with("wallet-grant://") {
                return Err((
                    "job_authority_mode_mismatch".into(),
                    format!("caller_kind 'human' resolves to a wallet grant, but authority_ref '{authority_ref}' is not a wallet-grant:// ref"),
                ));
            }
            Ok(json!({
                "caller_kind": "human",
                "mode": "wallet_grant",
                "authority_ref": authority_ref,
                "resolution": "the grant is presented at submit and authorized as PR:9574 does today",
                "credential_held_by_caller": false,
            }))
        }
        "agent" => {
            if !authority_ref.starts_with("capability-lease://") {
                return Err((
                    "job_authority_mode_mismatch".into(),
                    format!("caller_kind 'agent' resolves to a CapabilityLease draw-down, but authority_ref '{authority_ref}' is not a capability-lease:// ref"),
                ));
            }
            Ok(json!({
                "caller_kind": "agent",
                "mode": "capability_lease_drawdown",
                "authority_ref": authority_ref,
                "resolution": "drawn down against the lease following the broker authority shape at PR:8950; never a grant the agent minted for itself",
                "narrowing_only": "a draw-down cannot widen what the underlying grant permits",
                "credential_held_by_caller": false,
            }))
        }
        other => Err((
            "caller_kind_invalid".into(),
            format!("caller_kind must be 'human' or 'agent'; got '{other}'"),
        )),
    }
}

/// POST /v1/hypervisor/cloud-jobs — admit a `CloudJobRequest` as a PROPOSAL.
///
/// Admission mutates nothing at a provider. It validates the envelope, resolves the
/// authority path, discovers the budget BEFORE anything else, opens exactly one
/// intent, and records the job. Execution is a separate, authorized step.
pub(crate) async fn handle_cloud_job_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // ── The caller never holds a provider credential, in either authority path. ──
    if let Some(k) = find_key(&body, CALLER_CREDENTIAL_KEYS) {
        return refuse(
            "provider_credential_caller_supplied_refused",
            format!("the envelope carries '{k}'; a caller never holds a provider credential — credential_connector_id and credential_store stay daemon-side in the vault for both the wallet-grant and the CapabilityLease path"),
        );
    }

    // ── The venue is evidence in the receipt, not an input to the request. ──
    if let Some(k) = find_key(&body, VENUE_KEYS) {
        return refuse(
            "venue_not_an_input_to_a_job",
            format!("the envelope names a venue via '{k}'; a job states capacity, budget and deadline, and the venue is chosen by placement and recorded as evidence — a caller who must name a provider wants the 'Pick a cloud' surface, not the job API"),
        );
    }

    // ── caller_kind -> authority path. ──
    let caller_kind = text(&body, "caller_kind");
    let authority_ref = text(&body, "authority_ref");
    if authority_ref.is_empty() {
        return refuse(
            "job_authority_ref_required",
            "a job request carries the authority it will draw on: a wallet-grant:// for a human, a capability-lease:// for an agent".into(),
        );
    }
    let authority = match resolve_authority_mode(caller_kind, authority_ref) {
        Ok(a) => a,
        Err((code, message)) => return refuse(&code, message),
    };

    // ── Redundancy: declared or absent, never inferred. ──
    let redundancy = match body.get("redundancy") {
        None | Some(Value::Null) => REDUNDANCY_ACCEPTED.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => {
            return refuse(
                "redundancy_posture_invalid",
                format!("redundancy must be a string naming a posture; got {other}"),
            )
        }
    };
    if !REDUNDANCY_KNOWN.contains(&redundancy.as_str()) {
        return refuse(
            "redundancy_posture_unknown",
            format!("'{redundancy}' is not a RedundancyPosture — known: {REDUNDANCY_KNOWN:?}"),
        );
    }
    if redundancy != REDUNDANCY_ACCEPTED {
        return refuse(
            "redundancy_posture_unsupported",
            format!("'{redundancy}' is a known posture but is not accepted until M15.9: replica placement, a per-replica exposure set and a switch policy do not exist yet. It is refused rather than downgraded to 'none', because a caller who asked for redundancy and silently received none would believe their work was protected when it was not"),
        );
    }

    // ── Receipt requirements must all be mintable. ──
    let requirements = match body.get("receipt_requirements") {
        None | Some(Value::Null) => vec![
            "placement".to_string(),
            "provider-operation".to_string(),
            "spend".to_string(),
        ],
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for it in items {
                let Some(s) = it.as_str() else {
                    return refuse(
                        "receipt_requirement_invalid",
                        format!("receipt_requirements entries must be strings; got {it}"),
                    );
                };
                if !RECEIPT_REQUIREMENTS.contains(&s) {
                    return refuse(
                        "receipt_requirement_unknown",
                        format!("'{s}' is not a receipt kind this system mints — known: {RECEIPT_REQUIREMENTS:?}"),
                    );
                }
                out.push(s.to_string());
            }
            out
        }
        Some(other) => {
            return refuse(
                "receipt_requirement_invalid",
                format!("receipt_requirements must be an array of receipt kinds; got {other}"),
            )
        }
    };

    // ── A deadline is required: a job with no deadline has no completion boundary. ──
    let deadline = body.get("deadline").cloned().unwrap_or(Value::Null);
    if deadline.is_null() {
        return refuse(
            "job_deadline_required",
            "a job states how long it may run — an absolute deadline or a max duration; without one there is no boundary at which an unfinished job becomes a failed one".into(),
        );
    }

    // ── The budget is discovered BEFORE anything else, and named if it is not there. ──
    let budget_ref = text(&body, "budget_ref");
    if budget_ref.is_empty() {
        return refuse(
            "budget_ref_required",
            "a job names an EXISTING external_spend budget; an amount typed into a request is not a budget, and a request with no resolvable budget is refused before any mutation is attempted".into(),
        );
    }
    let budgets = read_record_dir(&st.data_dir, "resource-budgets");
    let budget = budgets.iter().find(|b| {
        let id = text(b, "budget_id");
        budget_ref == format!("budget://{id}") || budget_ref == id
    });
    let Some(budget) = budget else {
        return refuse(
            "budget_undiscovered_before_mutation",
            format!("no resource budget resolves '{budget_ref}' — discovery runs before admission, not after a provider has been touched"),
        );
    };
    if text(budget, "scope") != "external_spend" {
        return refuse(
            "budget_scope_invalid",
            format!("'{budget_ref}' has scope '{}', but metered provider spend draws on an external_spend budget", text(budget, "scope")),
        );
    }
    let limit = budget.get("limit").and_then(Value::as_f64).unwrap_or(0.0);
    let spent = budget.get("spent").and_then(Value::as_f64).unwrap_or(0.0);
    if spent >= limit {
        return refuse(
            "budget_exhausted_before_mutation",
            format!("external_spend budget '{}' has {spent}/{limit} spent; refusing before any provider is touched", text(budget, "budget_id")),
        );
    }

    // ── Exactly one intent. The envelope composes it; it does not become one. ──
    let intent_body = body.get("intent").cloned().unwrap_or(Value::Null);
    if intent_body.is_null() {
        return refuse(
            "job_intent_required",
            "a job request wraps exactly one CloudResourceIntent describing the capacity wanted".into(),
        );
    }
    let intent_id = format!("cri_{:x}", nanos());
    let intent = super::decentralized_cloud_routes::intent_record_for_job(&intent_id, &intent_body);
    if persist_record(
        &st.data_dir,
        "cloud-resource-intents",
        &intent_id,
        &intent,
    )
    .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": { "code": "intent_persist_failed",
                "message": "the intent could not be persisted; a job that references an intent no reader can find is not honest evidence" } })),
        );
    }

    // ── The job record. ──
    let job_id = format!("cjob_{:x}", nanos());
    let record = json!({
        "schema_version": "ioi.cloud.job-request.v1",
        "job_id": job_id,
        "job_ref": format!("cloud-job://{job_id}"),
        "state": "admitted_proposal",
        "intent_ref": intent["intent_ref"],
        "caller_kind": caller_kind,
        "authority": authority,
        "budget_ref": format!("budget://{}", text(budget, "budget_id")),
        "budget_discovery": {
            "discovered_before_mutation": true,
            "scope": "external_spend",
            "remaining": limit - spent,
            "basis": "resource-budgets record read at admission, before any provider was touched",
        },
        "deadline": deadline,
        "redundancy": redundancy,
        "receipt_requirements": requirements,
        "failover_policy_ref": body.get("failover_policy_ref").cloned().unwrap_or(Value::Null),
        "evidence_refs": body.get("evidence_refs").cloned().unwrap_or(json!([])),
        "receipts": [],
        "authority_note": "admission is a proposal — this record authorizes nothing; execution draws on the authority above through the single mutation lane",
        "fee_object_minted": false,
        "created_at": iso_now(),
    });
    if persist_record(&st.data_dir, JOB_KIND, &job_id, &record).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": { "code": "job_persist_failed",
                "message": "the job could not be persisted" } })),
        );
    }

    (StatusCode::CREATED, Json(json!({ "ok": true, "job": record })))
}

/// A CapabilityLease draw-down, resolved to the broker authority the provider lane needs.
///
/// THIS IS THE ONLY DOOR from a lease to broker authority. Everything it refuses, it refuses
/// BEFORE any provider is contacted, because a refusal that arrives after the venue has been
/// touched is not a refusal — it is a report.
///
/// The acting principal is the LEASE's, never the session's. That distinction is the whole
/// point: an agent presenting a lease is acting under authority a person delegated earlier,
/// and INV-37 requires the receipt to name whoever actually held it. Reading the principal
/// from the session would name a caller who did not act, which is worse than refusing —
/// a false acting principal is evidence that reads as true.
fn resolve_lease_drawdown(
    data_dir: &str,
    authority_ref: &str,
    resource_ref: &str,
    idempotency_key: &str,
    session_binding: &str,
    correlation_ref: &str,
) -> Result<super::provider_routes::WorkloadBrokerProviderAuthority, (String, String)> {
    let lease_id = authority_ref.trim_start_matches("capability-lease://");
    let Some(lease) = read_record_dir(data_dir, "capability-leases")
        .into_iter()
        .find(|l| text(l, "lease_id") == lease_id)
    else {
        return Err((
            "capability_lease_absent".into(),
            format!("no capability lease '{lease_id}' exists"),
        ));
    };

    // Revoked and expired come first: a lease that should not be usable at all must not get
    // as far as being checked for scope.
    if text(&lease, "state") == "revoked" {
        return Err((
            "capability_lease_revoked".into(),
            format!("lease '{lease_id}' was revoked and confers nothing"),
        ));
    }
    if text(&lease, "state") == "exhausted" {
        return Err((
            "capability_lease_exhausted".into(),
            format!("lease '{lease_id}' has no remaining calls"),
        ));
    }
    let expires_ms = lease.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
    let now_ms = (nanos() / 1_000_000) as i64;
    if expires_ms > 0 && expires_ms <= now_ms {
        return Err((
            "capability_lease_expired".into(),
            format!("lease '{lease_id}' expired; a lapsed lease is re-obtained, never extended here"),
        ));
    }

    // Scope: the lease must actually be bound to the thing about to be touched. A lease for
    // one resource is not a lease for another, however similar.
    let in_scope = lease
        .get("resource_refs")
        .and_then(Value::as_array)
        .map(|refs| refs.iter().any(|r| r.as_str() == Some(resource_ref)))
        .unwrap_or(false);
    if !in_scope {
        // This is the refusal the agent lane actually meets today, so it carries the
        // dependency rather than leaving a reader to infer it. Leases are minted as a
        // side effect of authorized operations and scoped to [account_ref, env_ref],
        // never to an intent — so nothing a human authorizes today leaves behind a lease
        // an agent could later present for a JOB.
        return Err((
            "capability_lease_out_of_scope".into(),
            format!(
                "lease '{lease_id}' is not bound to {resource_ref}. A lease is scoped to the \
                 resources it names, and widening that here would be minting authority by \
                 interpretation. Agent draw-down requires an intent-scoped bound lease issued \
                 under M03's delegation envelope; no caller-facing issuance exists and none is \
                 added here"
            ),
        ));
    }

    // The principal the lease was issued to. Absent on every lease minted before this binding
    // existed, and refused by name rather than substituted — the substitution is the defect.
    let principal_ref = text(&lease, "principal_ref");
    let owner_ref = text(&lease, "owner_ref");
    if principal_ref.is_empty() || owner_ref.is_empty() {
        return Err((
            "lease_predates_principal_binding".into(),
            format!("lease '{lease_id}' records no principal, so there is no acting principal to name (INV-37). Leases issued before principals were bound are not back-filled: a principal inferred after the fact is a principal nobody granted. Obtain a new lease"),
        ));
    }

    super::provider_routes::WorkloadBrokerProviderAuthority::resolve(
        data_dir,
        principal_ref,
        owner_ref,
        idempotency_key,
        session_binding,
        correlation_ref,
    )
    .map_err(|_| {
        (
            "lease_principal_no_longer_authorized".into(),
            format!("lease '{lease_id}' names a principal that does not currently hold {owner_ref}; authority is checked at USE, not only at issue"),
        )
    })
}

/// POST /v1/hypervisor/cloud-jobs/:id/execute — run an admitted job.
///
/// Seams F/G/K, and none of them reimplemented here. The placement decision comes from
/// the EXISTING decide handler, so the job is ranked and recorded by the same scorer
/// that ranks everything else — a job that scored candidates its own way would be a
/// second placement plane wearing the first one's receipts. The mutation goes through
/// `handle_provider_op`, the same entry the rest of the system uses; there is no second
/// mutation lane and this function opens none.
pub(crate) async fn handle_cloud_job_execute(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    inbound: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let want = id.trim_start_matches("cloud-job://").to_string();
    let Some(mut job) = read_record_dir(&st.data_dir, JOB_KIND)
        .into_iter()
        .find(|j| text(j, "job_id") == want)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "cloud_job_absent",
                "message": format!("no job '{want}' exists") } })),
        );
    };

    // A job executes once. Re-running an executed job would mint a second set of
    // receipts against one authorization, which is how one approval becomes two spends.
    if text(&job, "state") != "admitted_proposal" {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "error": { "code": "cloud_job_not_admitted",
                "message": format!("job '{want}' is in state '{}'; only an admitted_proposal executes, and it executes once", text(&job, "state")) } })),
        );
    }

    // ── The agent lane: a CapabilityLease draw-down, resolved BEFORE anything is touched. ──
    //
    // Every lease refusal happens here, ahead of placement — and placement is not a local
    // ranking, it refreshes candidates and therefore CONTACTS PROVIDERS. A revoked or
    // out-of-scope lease that got as far as a provider would have been reported rather than
    // refused. This is also why the resolution is not deferred to the mutation itself.
    let mut broker_authority = None;
    if text(&job, "caller_kind") == "agent" {
        let authority_ref = job
            .pointer("/authority/authority_ref")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // The lease must be scoped to the intent this job is executing.
        let resource_ref = text(&job, "intent_ref").to_string();
        let idempotency_key = body
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap_or(text(&job, "job_id"))
            .to_string();
        let session_binding = body
            .get("proposal_session_binding")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match resolve_lease_drawdown(
            &st.data_dir,
            &authority_ref,
            &resource_ref,
            &idempotency_key,
            &session_binding,
            text(&job, "job_ref"),
        ) {
            Ok(authority) => broker_authority = Some(authority),
            Err((code, message)) => {
                job["state"] = json!("refused_authority");
                job["refusal"] = json!({ "code": code, "detail": message, "at": iso_now() });
                let _ = persist_record(&st.data_dir, JOB_KIND, &want, &job);
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "ok": false, "error": { "code": code, "message": message },
                        "job": job })),
                );
            }
        }
    }

    // ── Seam F/G: the existing placement decision, not a private one. ──
    let (decide_code, Json(decision_body)) = super::placement_failover_routes::handle_placement_decide(
        State(st.clone()),
        inbound.clone(),
        Json(json!({ "intent_ref": job["intent_ref"] })),
    )
    .await;
    if decide_code != StatusCode::OK {
        // A job whose venue vanished between admission and execution fails HERE, with the
        // decision plane's own reason, and is recorded as refused rather than left open.
        job["state"] = json!("refused_no_placement");
        job["refusal"] = json!({
            "code": decision_body.get("reason").cloned().unwrap_or(json!("placement_refused")),
            "detail": decision_body.get("detail").cloned().unwrap_or(Value::Null),
            "at": iso_now(),
        });
        let _ = persist_record(&st.data_dir, JOB_KIND, &want, &job);
        return (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "error": { "code": "cloud_job_no_placement",
                "message": "no placement-eligible candidate exists for this job's intent; the job is recorded as refused rather than retried silently" },
                "placement": decision_body, "job": job })),
        );
    }

    let decision = decision_body.get("decision").cloned().unwrap_or(Value::Null);
    let placement_receipt = decision_body.get("receipt").cloned().unwrap_or(Value::Null);

    // The venue is EVIDENCE, recorded now that placement chose it — never an input.
    //
    // These read `decision.selected.*`, which is where the decision record actually
    // carries the chosen venue. An earlier cut read them off the decision's top level,
    // found nothing, and wrote nulls without complaining — the same silent-absence
    // failure that a `.get()` on a wrong path always produces. The gate caught it by
    // asserting the venue is present rather than that the field exists.
    let selected = decision.get("selected").cloned().unwrap_or(Value::Null);
    job["placement"] = json!({
        "decision_ref": decision.get("decision_ref").cloned().unwrap_or(Value::Null),
        "venue": selected.get("provider_kind").cloned().unwrap_or(Value::Null),
        "provider_account_ref": selected.get("provider_account_ref").cloned().unwrap_or(Value::Null),
        "candidate_ref": decision.get("selected_candidate_ref").cloned().unwrap_or(Value::Null),
        "quote_ref": selected.get("quote_ref").cloned().unwrap_or(Value::Null),
        "decided_at": decision.get("decided_at").cloned().unwrap_or(Value::Null),
    });
    job["receipts"] = json!([placement_receipt]);
    job["state"] = json!("placed");
    let _ = persist_record(&st.data_dir, JOB_KIND, &want, &job);

    // ── Seam K: the single mutation lane. ──
    // `dry_run` stops here with the placement receipt and touches no provider, which is
    // what the gate uses: the whole ladder is exercised and nothing is ever spent.
    if body.get("dry_run").and_then(Value::as_bool) == Some(true) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "job": job, "dry_run": true,
                "note": "placement decided and receipted; no provider was contacted" })),
        );
    }

    let op_body = json!({
        "provider_id": selected.get("provider_account_ref").cloned().unwrap_or(Value::Null),
        "op": body.get("op").cloned().unwrap_or(json!("create")),
        "environment_ref": body.get("environment_ref").cloned().unwrap_or(json!("env-default")),
        "job_ref": job["job_ref"],
        "budget_ref": job["budget_ref"],
        "owner_ref": body.get("owner_ref").cloned().unwrap_or(Value::Null),
        "idempotency_key": body.get("idempotency_key").cloned().unwrap_or(Value::Null),
        "wallet_approval_grant": body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
    });
    // Seam K, both doors. These are two ENTRY POINTS to one handler, not two lanes: the
    // human path presents its session, the agent path presents the authority resolved from
    // its lease, and `handle_provider_op_internal` is the single place either reaches. What
    // differs is how authority was obtained — never what it permits, never the placement,
    // never the receipt shape.
    let (op_code, Json(op_result)) = match broker_authority {
        Some(authority) => {
            super::provider_routes::invoke_workload_brokered_provider_operation(
                st.clone(),
                op_body,
                authority,
            )
            .await
        }
        None => {
            super::provider_routes::handle_provider_op(State(st.clone()), inbound, Json(op_body))
                .await
        }
    };

    let succeeded = op_code.is_success();
    if let Some(r) = op_result.get("receipt") {
        if let Some(arr) = job["receipts"].as_array_mut() {
            arr.push(r.clone());
        }
    }
    job["state"] = json!(if succeeded { "executed" } else { "refused_provider_operation" });
    job["provider_operation"] = json!({
        "http_status": op_code.as_u16(),
        "ok": succeeded,
        "at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, JOB_KIND, &want, &job);

    (
        op_code,
        Json(json!({ "ok": succeeded, "job": job, "provider_result": op_result })),
    )
}

#[cfg(test)]
mod lease_drawdown_tests {
    use super::*;
    use std::path::PathBuf;

    // Records are written exactly as `authorize_capability_lease` writes them — the same
    // 14 fields plus the new binding — so these tests exercise the REAL resolver against
    // the REAL descriptor shape. Nothing here is a test-only minter: the production
    // minter is wallet-gated by construction (it admits only through Exact, Portable or
    // Standing admission, each requiring real grant evidence) and cannot be called
    // without a grant. That is a property to keep, not a gap to route around — a
    // fabricated grant would be the forbidden test-only minter in different clothes.
    //
    // READ THE POSITIVE CONTROL BEFORE READING ANY REFUSAL AS A FAILURE. The resolver
    // ends at a substrate tenancy check that a temp directory cannot satisfy, so a
    // perfectly-formed lease cannot complete here. `a_well_formed_bound_lease_...`
    // therefore asserts that such a lease fails LAST — at the tenant check — because its
    // refusal CODE proves it cleared all six lease checks first. Without that control,
    // every refusal below could be passing for the wrong reason.
    //
    // Still unproven in-process and waiting on M03.12: the binding WRITE on a real mint,
    // and byte-identical receipts on a live agent execution. Both are M03's proof to run.
    fn tmp_dir(name: &str) -> String {
        let dir: PathBuf = std::env::temp_dir().join(format!("ioi-lease-test-{name}-{}", nanos()));
        std::fs::create_dir_all(dir.join("capability-leases")).expect("test dir");
        dir.to_string_lossy().into_owned()
    }

    fn write_lease(data_dir: &str, lease: Value) {
        let id = text(&lease, "lease_id").to_string();
        persist_record(data_dir, "capability-leases", &id, &lease).expect("persist lease");
    }

    fn base_lease(id: &str, intent: &str) -> Value {
        json!({
            "schema_version": "ioi.hypervisor.capability-lease.v1",
            "lease_id": id,
            "authority_provider_ref": "wallet.network",
            "backing_provider": "provider:account:pacc_test",
            "allowed_tools": ["provider.create"],
            "resource_refs": [intent],
            "policy_hash": "sha256:test",
            "request_hash": "sha256:test",
            // Far future, in epoch milliseconds, matching the production field.
            "expires_at": 4_102_444_800_000_i64,
            "receipt_required": true,
            "revocation_ref": "provider-accounts/pacc_test/credential",
            "grant_ref": "wallet.network://grant/approval/test",
            "state": "active",
            "issued_at": "2026-09-04T00:00:00Z",
            "principal_ref": "user://tester",
            "owner_ref": "org://acme",
        })
    }

    fn resolve(data_dir: &str, lease_ref: &str, intent: &str) -> Result<(), String> {
        resolve_lease_drawdown(
            data_dir,
            lease_ref,
            intent,
            "idem-key",
            &format!("sha256:{}", "0".repeat(64)),
            "cloud-job://cjob_test",
        )
        .map(|_| ())
        .map_err(|(code, _)| code)
    }

    #[test]
    fn a_lease_that_does_not_exist_confers_nothing() {
        let dir = tmp_dir("absent");
        assert_eq!(
            resolve(&dir, "capability-lease://nope", "cloud-resource-intent://cri_1"),
            Err("capability_lease_absent".into())
        );
    }

    #[test]
    fn revoked_and_exhausted_leases_are_refused_before_scope_is_considered() {
        // Ordering matters: a lease that should not be usable AT ALL must not get as far
        // as being checked for scope, or a revoked lease would be reported as merely
        // mis-scoped and someone would "fix" it by re-scoping.
        let dir = tmp_dir("revoked");
        let intent = "cloud-resource-intent://cri_1";
        let mut revoked = base_lease("lease_revoked", "cloud-resource-intent://OTHER");
        revoked["state"] = json!("revoked");
        write_lease(&dir, revoked);
        assert_eq!(
            resolve(&dir, "capability-lease://lease_revoked", intent),
            Err("capability_lease_revoked".into())
        );

        let mut exhausted = base_lease("lease_exhausted", "cloud-resource-intent://OTHER");
        exhausted["state"] = json!("exhausted");
        write_lease(&dir, exhausted);
        assert_eq!(
            resolve(&dir, "capability-lease://lease_exhausted", intent),
            Err("capability_lease_exhausted".into())
        );
    }

    #[test]
    fn an_expired_lease_is_refused() {
        let dir = tmp_dir("expired");
        let intent = "cloud-resource-intent://cri_1";
        let mut lease = base_lease("lease_expired", intent);
        lease["expires_at"] = json!(1_000_000_000_i64); // 2001
        write_lease(&dir, lease);
        assert_eq!(
            resolve(&dir, "capability-lease://lease_expired", intent),
            Err("capability_lease_expired".into())
        );
    }

    #[test]
    fn a_lease_for_another_resource_does_not_authorize_this_one() {
        let dir = tmp_dir("scope");
        write_lease(&dir, base_lease("lease_other", "cloud-resource-intent://cri_OTHER"));
        assert_eq!(
            resolve(&dir, "capability-lease://lease_other", "cloud-resource-intent://cri_MINE"),
            Err("capability_lease_out_of_scope".into())
        );
    }

    #[test]
    fn an_account_scoped_lease_does_not_satisfy_a_job() {
        // The shortcut that was refused by ruling: every lease issued today is scoped to
        // [account_ref, env_ref]. If the resolver accepted an account ref, ONE lease would
        // authorize any workload on that account.
        let dir = tmp_dir("account");
        let mut lease = base_lease("lease_account", "unused");
        lease["resource_refs"] = json!(["provider-account://pacc_test", "env-default"]);
        write_lease(&dir, lease);
        assert_eq!(
            resolve(&dir, "capability-lease://lease_account", "cloud-resource-intent://cri_1"),
            Err("capability_lease_out_of_scope".into())
        );
    }

    #[test]
    fn a_lease_without_a_principal_is_refused_and_never_substituted() {
        // The 2248 leases issued before the binding existed. They must refuse by NAME
        // rather than resolve against whoever's session happened to carry the request.
        let dir = tmp_dir("unbound");
        let intent = "cloud-resource-intent://cri_1";
        let mut lease = base_lease("lease_unbound", intent);
        lease.as_object_mut().unwrap().remove("principal_ref");
        lease.as_object_mut().unwrap().remove("owner_ref");
        write_lease(&dir, lease);
        assert_eq!(
            resolve(&dir, "capability-lease://lease_unbound", intent),
            Err("lease_predates_principal_binding".into())
        );

        // A half-bound lease is still unbound: an owner without a principal names no actor.
        let mut half = base_lease("lease_half", intent);
        half.as_object_mut().unwrap().remove("principal_ref");
        write_lease(&dir, half);
        assert_eq!(
            resolve(&dir, "capability-lease://lease_half", intent),
            Err("lease_predates_principal_binding".into())
        );
    }

    #[test]
    fn a_well_formed_bound_lease_passes_every_lease_check_and_reaches_the_tenant_check() {
        // The positive control for the ladder. A lease that is present, active, unexpired,
        // in scope and bound must clear all six lease checks — proven by the fact that the
        // refusal it DOES get is the last one, which is the substrate's tenant check
        // rather than anything this resolver owns. Without this, every refusal above
        // could be passing for the wrong reason.
        let dir = tmp_dir("wellformed");
        let intent = "cloud-resource-intent://cri_1";
        write_lease(&dir, base_lease("lease_good", intent));
        assert_eq!(
            resolve(&dir, "capability-lease://lease_good", intent),
            Err("lease_principal_no_longer_authorized".into()),
            "a well-formed bound lease must fail LAST, at the tenant check, not earlier"
        );
    }
}

/// GET /v1/hypervisor/cloud-jobs
pub(crate) async fn handle_cloud_jobs_list(
    State(st): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let jobs = read_record_dir(&st.data_dir, JOB_KIND);
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.cloud.job-list.v1",
            "at": iso_now(),
            "jobs": jobs,
        })),
    )
}

/// GET /v1/hypervisor/cloud-jobs/:id
pub(crate) async fn handle_cloud_job_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let want = id.trim_start_matches("cloud-job://").to_string();
    match read_record_dir(&st.data_dir, JOB_KIND)
        .into_iter()
        .find(|j| text(j, "job_id") == want)
    {
        Some(job) => (StatusCode::OK, Json(json!({ "ok": true, "job": job }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "cloud_job_absent",
                "message": format!("no job '{want}' exists") } })),
        ),
    }
}
