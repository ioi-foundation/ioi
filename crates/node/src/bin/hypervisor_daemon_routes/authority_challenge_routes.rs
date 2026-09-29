//! Master guide G5 / W0.2 part 2 — the in-app approval goes THROUGH THE DAEMON, and the UI server
//! holds no signing key (§0.5.2, N9).
//!
//! Until this plane existed the served App minted a run's one-use grant in its own process with a
//! local approver seed. The deployment authority (ADR 0052) now keeps that key SEALED under the
//! operator passphrase, and only its `approve` act can mint. This module is the daemon's half of the
//! relay:
//!
//! 1. **The daemon keeps each parked challenge.** When the session-execute gate or the capability
//!    lease gateway refuses an effect for want of a grant (the deployment authority resolved, and no
//!    grant was presented), the gate writes `wallet-approval-challenges/<id>`: the exact hashes, the
//!    preimage they commit to, the target scope, the audience, the requester and an expiry. The id is
//!    deterministic in (scope, policy hash, request hash, audience), so a re-park of the same effect
//!    is the same challenge. Pending challenges are rows in the approvals inbox.
//! 2. **`POST /v1/hypervisor/authority/challenges/:id/decision`** takes
//!    `{decision: approve|deny, reason, operator_passphrase}` from an authenticated administrator.
//!    It signs ONLY the coordinates in the daemon's own record: a body naming any hash, scope,
//!    audience or grant is refused before anything runs. Approve runs the authority binary's
//!    `approve` (IOI_WALLET_AUTHORITY_BINARY against IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR) with
//!    the passphrase in THAT CHILD's environment only. The passphrase is never logged, persisted or
//!    echoed, and the daemon's copy is zeroized once the child exits. A refused passphrase records
//!    nothing. The returned grant is checked against the record, stored single-use in the record,
//!    and the reply carries only `approval_ref` and the grant's public ref.
//! 3. **Resume.** The client retries the original request with `approval_ref`. The gate claims the
//!    stored grant only if the record's hashes equal the ones it derives afresh from the retried
//!    request, presents it to the unchanged resolution + consumption path, and marks it consumed
//!    once admitted. A consumed challenge never admits again.
//!
//! No second authority plane: wallet.network resolution, grant verification and on-chain
//! consumption are the existing `governed_authority` path; this module only parks, relays the
//! operator's decision to the authority's own `approve`, and hands the one grant back to the gate.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{iso_now, read_record_dir, DaemonState};

pub(crate) const CHALLENGE_FAMILY: &str = "wallet-approval-challenges";
pub(crate) const APPROVAL_REF_PREFIX: &str = "wallet-approval-challenge://";
const CHALLENGE_SCHEMA: &str = "ioi.hypervisor.wallet-approval-challenge.v1";
const CHALLENGE_ID_DOMAIN: &str = "ioi.hypervisor.wallet-approval-challenge.id.v1";
/// The authority control binary (`wallet-network-local-authority`) the daemon runs for `approve`.
pub(crate) const AUTHORITY_BINARY_ENV: &str = "IOI_WALLET_AUTHORITY_BINARY";
/// The deployment authority node's state directory (the directory that IS the node).
pub(crate) const AUTHORITY_STATE_DIR_ENV: &str = "IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR";
/// The one variable the authority binary reads the operator passphrase from. Set on the approve
/// child only; the binary scrubs it from its own environment block at startup.
const OPERATOR_PASS_ENV: &str = "IOI_AUTHORITY_OPERATOR_PASS";
/// A pending challenge stays decidable this long after its latest park.
const CHALLENGE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
/// An isolated stack may SHORTEN the pending window (a verifier drives a challenge's expiry without
/// waiting a day). It narrows only: a value above the default, zero or unparseable leaves the default.
const CHALLENGE_TTL_ENV: &str = "IOI_HYPERVISOR_AUTHORITY_CHALLENGE_TTL_MS";

fn challenge_ttl_from(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(CHALLENGE_TTL_MS))
        .unwrap_or(CHALLENGE_TTL_MS)
}

fn challenge_ttl_ms() -> u64 {
    challenge_ttl_from(std::env::var(CHALLENGE_TTL_ENV).ok().as_deref())
}
/// A claim that never settled (the daemon died mid-consumption) may be re-claimed after this long.
const STALE_CLAIM_MS: u64 = 30 * 60 * 1_000;
const DEFAULT_APPROVE_TIMEOUT_MS: u64 = 1_200_000;
const REASON_MAX_CHARS: usize = 400;
/// Body members a decision may carry. Everything the signature covers is the daemon's own.
const DECISION_FIELDS: &[&str] = &["decision", "reason", "operator_passphrase"];
const DAEMON_OWNED_FIELDS: &[&str] = &[
    "policy_hash",
    "request_hash",
    "target_scope",
    "audience",
    "approval_grant",
    "wallet_approval_grant",
    "grant",
    "expires_in_secs",
    "challenge_id",
    "approval_ref",
];

/// Serializes every read-modify-write of a challenge record. Never held across the approve child
/// or a wallet consumption: those are bounded by the `deciding` set and the `consuming` claim.
static CHALLENGE_LOCK: Mutex<()> = Mutex::new(());
/// Challenges whose approve child is running in this process.
static DECIDING: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn lock_challenges() -> std::sync::MutexGuard<'static, ()> {
    CHALLENGE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The deterministic challenge id for one exact effect's coordinates.
pub(crate) fn challenge_id_for(
    target_scope: &str,
    policy_hash: &str,
    request_hash: &str,
    audience: Option<&str>,
) -> String {
    let material = json!({
        "domain": CHALLENGE_ID_DOMAIN,
        "target_scope": target_scope,
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "audience": audience,
    });
    let bytes = serde_jcs::to_vec(&material).unwrap_or_default();
    format!("wac_{}", &hex::encode(Sha256::digest(bytes))[..32])
}

pub(crate) fn approval_ref_for(challenge_id: &str) -> String {
    format!("{APPROVAL_REF_PREFIX}{challenge_id}")
}

fn challenge_id_from_ref(approval_ref: &str) -> Option<&str> {
    let id = approval_ref.strip_prefix(APPROVAL_REF_PREFIX)?;
    valid_challenge_id(id).then_some(id)
}

fn valid_challenge_id(id: &str) -> bool {
    id.len() == 36
        && id.starts_with("wac_")
        && id[4..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// An approval-ref locator carried where a grant would be: the string `wallet-approval-challenge://…`
/// or the object `{"approval_ref": "…"}`. A locator is never authority; the gate claims the grant the
/// daemon stored for it only when the record's hashes equal the freshly derived ones.
pub(crate) fn approval_ref_locator(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if text.starts_with(APPROVAL_REF_PREFIX) => Some(text.clone()),
        Value::Object(map) if map.len() == 1 => map
            .get("approval_ref")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

/// The approval ref a session-execute retry names: the top-level `approval_ref`, or a locator in
/// `wallet_approval_grant`.
pub(crate) fn approval_ref_in_body(body: &Value) -> Option<String> {
    body.get("approval_ref")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("wallet_approval_grant")
                .and_then(approval_ref_locator)
        })
}

/// Whether this daemon can run the operator's decision itself: the authority binary and the node's
/// state directory are both configured and present.
pub(crate) fn decider_configured() -> bool {
    decider_paths().is_some()
}

fn decider_paths() -> Option<(String, String)> {
    let binary = std::env::var(AUTHORITY_BINARY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let state_dir = std::env::var(AUTHORITY_STATE_DIR_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    (std::path::Path::new(&binary).is_file() && std::path::Path::new(&state_dir).is_dir())
        .then_some((binary, state_dir))
}

fn read_challenge(data_dir: &str, id: &str) -> Result<Option<Value>, String> {
    super::durable_fs::read_record_durable(data_dir, CHALLENGE_FAMILY, id)
}

fn write_challenge(data_dir: &str, id: &str, record: &Value) -> Result<(), String> {
    super::durable_fs::persist_record_durable(data_dir, CHALLENGE_FAMILY, id, record)
        .map_err(|error| format!("challenge {id} was not durably persisted: {error:?}"))
}

fn state_of(record: &Value) -> &str {
    record.get("state").and_then(Value::as_str).unwrap_or("")
}

/// The record as any reader sees it: coordinates, preimage, requester, decision and the grant's
/// public ref. Never the grant bytes.
pub(crate) fn public_view(record: &Value) -> Value {
    let mut view = record.clone();
    if let Some(object) = view.as_object_mut() {
        object.remove("grant");
        let id = object
            .get("challenge_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        object.insert(
            "decision_route".into(),
            json!(format!("/v1/hypervisor/authority/challenges/{id}/decision")),
        );
        object.insert("decidable".into(), json!(decider_configured()));
    }
    view
}

/// What a gate knows when it refuses an effect for want of a grant.
pub(crate) struct ParkRequest<'a> {
    pub(crate) target_scope: &'a str,
    pub(crate) policy_hash: &'a str,
    pub(crate) request_hash: &'a str,
    pub(crate) audience: Option<String>,
    pub(crate) subject_ref: &'a str,
    pub(crate) operation: &'a str,
    /// The exact bytes the hashes commit to, as the gate published them.
    pub(crate) published_preimage: Value,
    pub(crate) requester_ref: Option<&'a str>,
}

/// Park (or re-park) one exact effect's challenge. Returns the members a gate adds to its 403
/// challenge: the challenge id, its state, the decision route and whether this daemon can decide.
/// A persistence failure returns None: the gate's refusal stands without a parked challenge.
pub(crate) fn park_challenge(data_dir: &str, request: ParkRequest<'_>) -> Option<Value> {
    let id = challenge_id_for(
        request.target_scope,
        request.policy_hash,
        request.request_hash,
        request.audience.as_deref(),
    );
    let now = now_ms();
    let _guard = lock_challenges();
    let existing = read_challenge(data_dir, &id).ok()?;
    let record = match existing {
        Some(mut record) => {
            let state = state_of(&record).to_string();
            let expired_pending = state == "pending"
                && record
                    .get("expires_at_ms")
                    .and_then(Value::as_u64)
                    .is_some_and(|expires| expires <= now);
            if state == "denied" || expired_pending {
                // A new ask for the same exact effect after a denial or an expiry.
                let prior = json!({
                    "state": if expired_pending { "expired" } else { "denied" },
                    "decision": record.get("decision").cloned().unwrap_or(Value::Null),
                    "closed_at": iso_now(),
                });
                if let Some(history) = record.get_mut("history").and_then(Value::as_array_mut) {
                    history.push(prior);
                } else {
                    record["history"] = json!([prior]);
                }
                record["state"] = json!("pending");
                record["decision"] = Value::Null;
                record["requester_ref"] = json!(request.requester_ref);
                record["created_at"] = json!(iso_now());
            }
            if state_of(&record) == "pending" {
                record["last_parked_at"] = json!(iso_now());
                record["expires_at_ms"] = json!(now.saturating_add(challenge_ttl_ms()));
                if record.get("requester_ref").is_none_or(Value::is_null) {
                    record["requester_ref"] = json!(request.requester_ref);
                }
                write_challenge(data_dir, &id, &record).ok()?;
            }
            record
        }
        None => {
            let record = json!({
                "schema_version": CHALLENGE_SCHEMA,
                "challenge_id": id,
                "approval_ref": approval_ref_for(&id),
                "state": "pending",
                "target_scope": request.target_scope,
                "policy_hash": request.policy_hash,
                "request_hash": request.request_hash,
                "audience": request.audience,
                "subject_ref": request.subject_ref,
                "operation": request.operation,
                "published_preimage": request.published_preimage,
                "requester_ref": request.requester_ref,
                "created_at": iso_now(),
                "last_parked_at": iso_now(),
                "expires_at_ms": now.saturating_add(challenge_ttl_ms()),
                "decision": Value::Null,
                "grant": Value::Null,
                "grant_ref": Value::Null,
                "grant_expires_at_ms": Value::Null,
                "consumed_at": Value::Null,
                "consumed_by": Value::Null,
                "runtimeTruthSource": "daemon-runtime",
            });
            write_challenge(data_dir, &id, &record).ok()?;
            record
        }
    };
    Some(json!({
        "challenge_id": id,
        "challenge_state": state_of(&record),
        "decision_route": format!("/v1/hypervisor/authority/challenges/{id}/decision"),
        "decidable": decider_configured(),
    }))
}

/// A claimed, approved challenge: the one grant the gate may present, for exactly this effect.
pub(crate) struct ClaimedApproval {
    pub(crate) challenge_id: String,
    pub(crate) grant: Value,
    claim_nonce: String,
}

/// A typed refusal of an approval ref: nothing was presented to wallet.network.
pub(crate) struct ApprovalRefRefusal {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

fn refusal(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> ApprovalRefRefusal {
    ApprovalRefRefusal {
        status,
        code,
        message: message.into(),
    }
}

/// Claim the stored grant behind `approval_ref` for ONE presentation, only when the record's scope
/// and hashes equal the ones the gate derived afresh from the retried request. A consumed, denied,
/// pending or foreign challenge is refused before anything reaches wallet.network.
pub(crate) fn claim_approval_ref(
    data_dir: &str,
    approval_ref: &str,
    target_scope: &str,
    policy_hash: &str,
    request_hash: &str,
) -> Result<ClaimedApproval, ApprovalRefRefusal> {
    let Some(id) = challenge_id_from_ref(approval_ref) else {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "approval_ref_invalid",
            format!("approval_ref must be {APPROVAL_REF_PREFIX}wac_<32 lowercase hex>"),
        ));
    };
    let now = now_ms();
    let _guard = lock_challenges();
    let mut record = match read_challenge(data_dir, id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err(refusal(
                StatusCode::NOT_FOUND,
                "approval_ref_unknown",
                "no parked challenge carries this approval_ref",
            ))
        }
        Err(message) => {
            return Err(refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "approval_ref_unreadable",
                message,
            ))
        }
    };
    let same = |field: &str, value: &str| record.get(field).and_then(Value::as_str) == Some(value);
    if !(same("target_scope", target_scope)
        && same("policy_hash", policy_hash)
        && same("request_hash", request_hash))
    {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "approval_ref_coordinates_mismatch",
            "the approved challenge's scope and hashes are not the ones this request derives; the grant is not presented",
        ));
    }
    let state = state_of(&record).to_string();
    let stale_claim = state == "consuming"
        && record
            .get("claimed_at_ms")
            .and_then(Value::as_u64)
            .is_some_and(|claimed| now.saturating_sub(claimed) > STALE_CLAIM_MS);
    match state.as_str() {
        "approved" => {}
        "consuming" if stale_claim => {}
        "consuming" => {
            return Err(refusal(
                StatusCode::CONFLICT,
                "approval_ref_in_use",
                "this approval is being presented by another request",
            ))
        }
        "consumed" => {
            return Err(refusal(
                StatusCode::CONFLICT,
                "approval_ref_consumed",
                "this approval's one-use grant was already consumed; the exact effect ran once",
            ))
        }
        "denied" => {
            return Err(refusal(
                StatusCode::FORBIDDEN,
                "approval_ref_denied",
                "the operator denied this challenge; nothing may run under it",
            ))
        }
        _ => {
            return Err(refusal(
                StatusCode::CONFLICT,
                "approval_ref_not_approved",
                "the challenge has no operator approval yet",
            ))
        }
    }
    let grant = record.get("grant").cloned().unwrap_or(Value::Null);
    if !grant.is_object() {
        return Err(refusal(
            StatusCode::CONFLICT,
            "approval_ref_grant_absent",
            "the approved challenge holds no grant",
        ));
    }
    if record
        .get("grant_expires_at_ms")
        .and_then(Value::as_u64)
        .is_some_and(|expires| expires <= now)
    {
        return Err(refusal(
            StatusCode::GONE,
            "approval_ref_expired",
            "the approval's one-use grant has expired; the operator must approve again",
        ));
    }
    let claim_nonce = hex::encode(rand::random::<[u8; 16]>());
    record["state"] = json!("consuming");
    record["claimed_at_ms"] = json!(now);
    record["claim_nonce"] = json!(claim_nonce);
    write_challenge(data_dir, id, &record).map_err(|message| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "approval_ref_claim_not_durable",
            message,
        )
    })?;
    Ok(ClaimedApproval {
        challenge_id: id.to_string(),
        grant,
        claim_nonce,
    })
}

fn settle_claim(data_dir: &str, claim: &ClaimedApproval, consumed_by: Option<&str>) {
    let _guard = lock_challenges();
    let Ok(Some(mut record)) = read_challenge(data_dir, &claim.challenge_id) else {
        return;
    };
    if state_of(&record) != "consuming"
        || record.get("claim_nonce").and_then(Value::as_str) != Some(claim.claim_nonce.as_str())
    {
        return;
    }
    match consumed_by {
        Some(admission_ref) => {
            record["state"] = json!("consumed");
            record["consumed_at"] = json!(iso_now());
            record["consumed_by"] = json!(admission_ref);
            // Single use: once consumed, the grant bytes have no further purpose here.
            record["grant"] = Value::Null;
        }
        None => {
            record["state"] = json!("approved");
        }
    }
    if let Some(object) = record.as_object_mut() {
        object.remove("claim_nonce");
        object.remove("claimed_at_ms");
    }
    let _ = write_challenge(data_dir, &claim.challenge_id, &record);
}

/// The gate admitted the effect under the claimed grant: the challenge is consumed for good.
pub(crate) fn mark_consumed(data_dir: &str, claim: &ClaimedApproval, admission_ref: &str) {
    settle_claim(data_dir, claim, Some(admission_ref));
}

/// The gate refused before consumption: the approval stays usable for a corrected retry (the
/// chain's one-use record and the admission slot still bound it to one execution).
pub(crate) fn release_claim(data_dir: &str, claim: &ClaimedApproval) {
    settle_claim(data_dir, claim, None);
}

// ---- routes -------------------------------------------------------------------------------------

fn reply(status: StatusCode, body: Value) -> (StatusCode, Json<Value>) {
    (status, Json(body))
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    reply(
        status,
        json!({
            "ok": false,
            "error": { "code": code, "message": message.into() },
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

/// An authenticated deployment administrator, never an impersonated session.
fn require_operator(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let Some(principal) = super::lifecycle_routes::resolve_principal(data_dir, headers) else {
        return Err(reply(
            StatusCode::UNAUTHORIZED,
            json!({
                "ok": false,
                "code": "hypervisor.authentication_required",
                "message": "an authenticated operator session is required to decide an approval challenge",
            }),
        ));
    };
    if principal["role"].as_str() != Some("admin") {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "approval_decider_not_operator",
            "only the deployment's operator (an administrator) decides approval challenges",
        ));
    }
    if principal["is_impersonated"].as_bool() == Some(true) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "approval_decider_impersonated",
            "an impersonated session cannot decide an approval challenge",
        ));
    }
    let principal_id = principal["principal_id"].as_str().unwrap_or("").to_string();
    Ok(principal["principal_ref"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("user://{principal_id}")))
}

/// GET /v1/hypervisor/authority/challenges — every parked challenge, newest first (public view).
pub(crate) async fn handle_challenge_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if super::lifecycle_routes::resolve_principal(&st.data_dir, &headers).is_none() {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({ "ok": false, "code": "hypervisor.authentication_required", "message": "an authenticated session is required" }),
        );
    }
    let mut challenges: Vec<Value> = read_record_dir(&st.data_dir, CHALLENGE_FAMILY)
        .iter()
        .filter(|record| {
            record.get("schema_version").and_then(Value::as_str) == Some(CHALLENGE_SCHEMA)
        })
        .map(public_view)
        .collect();
    challenges.sort_by(|a, b| {
        let ka = a
            .get("last_parked_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        let kb = b
            .get("last_parked_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        kb.cmp(ka)
    });
    reply(
        StatusCode::OK,
        json!({ "ok": true, "challenges": challenges, "decidable": decider_configured(), "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/authority/challenges/:id — one parked challenge (public view).
pub(crate) async fn handle_challenge_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if super::lifecycle_routes::resolve_principal(&st.data_dir, &headers).is_none() {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({ "ok": false, "code": "hypervisor.authentication_required", "message": "an authenticated session is required" }),
        );
    }
    if !valid_challenge_id(&id) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "challenge_id_invalid",
            "challenge ids are wac_<32 lowercase hex>",
        );
    }
    match read_challenge(&st.data_dir, &id) {
        Ok(Some(record)) => reply(
            StatusCode::OK,
            json!({ "ok": true, "challenge": public_view(&record), "runtimeTruthSource": "daemon-runtime" }),
        ),
        Ok(None) => refuse(
            StatusCode::NOT_FOUND,
            "challenge_not_found",
            "no parked challenge has this id",
        ),
        Err(message) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "challenge_unreadable",
            message,
        ),
    }
}

/// Removes the challenge from the in-process `deciding` set on every exit path.
struct DecidingGuard(String);

impl DecidingGuard {
    fn enter(id: &str) -> Option<Self> {
        let mut deciding = DECIDING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deciding
            .insert(id.to_string())
            .then(|| Self(id.to_string()))
    }
}

impl Drop for DecidingGuard {
    fn drop(&mut self) {
        let mut deciding = DECIDING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deciding.remove(&self.0);
    }
}

/// The parsed decision body. The passphrase lives only in zeroizing memory.
struct DecisionBody {
    decision: String,
    reason: String,
    operator_passphrase: Zeroizing<String>,
}

fn parse_decision_body(raw: &[u8]) -> Result<DecisionBody, (StatusCode, Json<Value>)> {
    let mut value: Value = serde_json::from_slice(raw).map_err(|_| {
        refuse(
            StatusCode::BAD_REQUEST,
            "decision_body_invalid",
            "the decision body must be one JSON object",
        )
    })?;
    let Some(object) = value.as_object_mut() else {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "decision_body_invalid",
            "the decision body must be one JSON object",
        ));
    };
    // Take the passphrase out FIRST, so no refusal below can leave it in a live Value.
    let operator_passphrase = match object.remove("operator_passphrase") {
        Some(Value::String(text)) => Zeroizing::new(text),
        Some(Value::Null) | None => Zeroizing::new(String::new()),
        Some(_) => {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "operator_passphrase_invalid",
                "operator_passphrase must be a string",
            ))
        }
    };
    if let Some(field) = object
        .keys()
        .find(|field| DAEMON_OWNED_FIELDS.contains(&field.as_str()))
    {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "challenge_coordinates_are_daemon_owned",
            format!(
                "a decision may not name `{field}`: the daemon signs only the coordinates in its own challenge record; nothing was signed"
            ),
        ));
    }
    if let Some(field) = object
        .keys()
        .find(|field| !DECISION_FIELDS.contains(&field.as_str()))
    {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "decision_body_field_refused",
            format!(
                "a decision carries only decision, reason and operator_passphrase (got `{field}`)"
            ),
        ));
    }
    let decision = object
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if decision != "approve" && decision != "deny" {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "decision_invalid",
            "decision must be approve or deny",
        ));
    }
    let reason: String = object
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(REASON_MAX_CHARS)
        .collect();
    Ok(DecisionBody {
        decision,
        reason,
        operator_passphrase,
    })
}

/// Replace every occurrence of the passphrase in child output before it is surfaced anywhere.
fn scrub(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "[redacted]")
}

fn tail(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    let count = trimmed.chars().count();
    if count <= max {
        return trimmed.to_string();
    }
    trimmed.chars().skip(count - max).collect()
}

/// POST /v1/hypervisor/authority/challenges/:id/decision — the operator's decision on one parked
/// challenge. `approve` runs the deployment authority's `approve` for the record's exact
/// coordinates with the operator passphrase in the child's environment only, stores the one-use
/// grant in the record and returns `approval_ref`; `deny` records the refusal and mints nothing.
pub(crate) async fn handle_challenge_decision(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    // The raw body carries the passphrase: parse it, then wipe the buffer before anything else.
    let mut raw: Vec<u8> = body.into();
    let parsed = parse_decision_body(&raw);
    raw.zeroize();
    drop(raw);
    // Identity FIRST: an unauthenticated caller learns nothing about the challenge.
    let decided_by = match require_operator(&st.data_dir, &headers) {
        Ok(principal_ref) => principal_ref,
        Err(response) => return response,
    };
    let decision = match parsed {
        Ok(decision) => decision,
        Err(response) => return response,
    };
    if !valid_challenge_id(&id) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "challenge_id_invalid",
            "challenge ids are wac_<32 lowercase hex>",
        );
    }
    let Some(_deciding) = DecidingGuard::enter(&id) else {
        return refuse(
            StatusCode::CONFLICT,
            "challenge_decision_in_progress",
            "a decision on this challenge is already running",
        );
    };
    let record = {
        let _guard = lock_challenges();
        match read_challenge(&st.data_dir, &id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return refuse(
                    StatusCode::NOT_FOUND,
                    "challenge_not_found",
                    "no parked challenge has this id",
                )
            }
            Err(message) => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "challenge_unreadable",
                    message,
                )
            }
        }
    };
    match state_of(&record) {
        "pending" => {}
        "approved" | "consuming" => {
            return reply(
                StatusCode::CONFLICT,
                json!({
                    "ok": false,
                    "error": { "code": "challenge_already_approved", "message": "this challenge is already approved; retry the request with its approval_ref" },
                    "challenge_id": id,
                    "approval_ref": record.get("approval_ref"),
                    "state": state_of(&record),
                    "runtimeTruthSource": "daemon-runtime",
                }),
            )
        }
        "consumed" => {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_consumed",
                "this challenge's one-use grant was already consumed",
            )
        }
        "denied" => {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_denied",
                "this challenge was denied",
            )
        }
        other => {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_state_invalid",
                format!("challenge is {other}"),
            )
        }
    }
    if record
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .is_some_and(|expires| expires <= now_ms())
    {
        return refuse(
            StatusCode::GONE,
            "challenge_expired",
            "this challenge expired; re-run the request to park it again",
        );
    }

    if decision.decision == "deny" {
        let _guard = lock_challenges();
        let Ok(Some(mut current)) = read_challenge(&st.data_dir, &id) else {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_changed",
                "the challenge changed while deciding",
            );
        };
        if state_of(&current) != "pending" {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_changed",
                "the challenge changed while deciding",
            );
        }
        current["state"] = json!("denied");
        current["decision"] = json!({
            "decision": "deny",
            "decided_by": decided_by,
            "decided_at": iso_now(),
            "reason": decision.reason,
        });
        if let Err(message) = write_challenge(&st.data_dir, &id, &current) {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "challenge_not_durable",
                message,
            );
        }
        return reply(
            StatusCode::OK,
            json!({ "ok": true, "challenge_id": id, "state": "denied", "decided_by": decided_by, "runtimeTruthSource": "daemon-runtime" }),
        );
    }

    // ---- approve ----
    if decision.operator_passphrase.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "operator_passphrase_required",
            "approving needs the operator passphrase: it opens the sealed approver key for this one grant",
        );
    }
    let Some((binary, state_dir)) = decider_paths() else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "authority_decider_not_configured",
            format!("this daemon has no deployment authority to decide with ({AUTHORITY_BINARY_ENV} and {AUTHORITY_STATE_DIR_ENV} must name the authority binary and its node's state directory)"),
        );
    };
    let field = |name: &str| {
        record
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (policy_hash, request_hash, target_scope, audience) = (
        field("policy_hash"),
        field("request_hash"),
        field("target_scope"),
        field("audience"),
    );
    if audience.len() != 64 || !audience.chars().all(|c| c.is_ascii_hexdigit()) {
        return refuse(
            StatusCode::CONFLICT,
            "challenge_audience_absent",
            "the parked challenge names no wallet capability audience; a grant without it could never be consumed",
        );
    }
    let timeout_ms = std::env::var("IOI_HYPERVISOR_AUTHORITY_APPROVE_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_APPROVE_TIMEOUT_MS);
    let authority_reason =
        format!("Hypervisor operator approval of the exact effect (challenge {id})");
    let mut command = tokio::process::Command::new(&binary);
    command
        .args([
            "approve",
            "--state-dir",
            &state_dir,
            "--policy-hash",
            &policy_hash,
            "--request-hash",
            &request_hash,
            "--audience",
            &audience,
            "--target-scope",
            &target_scope,
            "--reason",
            &authority_reason,
        ])
        .env_remove(OPERATOR_PASS_ENV)
        // The ONE place the passphrase leaves this process: the approve child's environment. The
        // binary copies it and scrubs its own environment block before any thread starts.
        .env(OPERATOR_PASS_ENV, decision.operator_passphrase.as_str())
        .env("CARGO_TERM_COLOR", "never")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let spawned = command.spawn();
    // The Command's own copy of the environment goes with it, now that the child exists.
    drop(command);
    let child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return refuse(
                StatusCode::BAD_GATEWAY,
                "authority_approve_unavailable",
                format!("the authority binary could not be started: {error}"),
            )
        }
    };
    let output = match tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return refuse(StatusCode::BAD_GATEWAY, "authority_approve_failed", format!("the authority approve did not complete: {error}"))
        }
        Err(_) => {
            return refuse(
                StatusCode::GATEWAY_TIMEOUT,
                "authority_approve_timeout",
                format!("the authority approve did not finish within {timeout_ms} ms; the challenge stays pending"),
            )
        }
    };
    let passphrase = decision.operator_passphrase;
    let stdout = scrub(
        &String::from_utf8_lossy(&output.stdout),
        passphrase.as_str(),
    );
    let stderr = scrub(
        &String::from_utf8_lossy(&output.stderr),
        passphrase.as_str(),
    );
    // Zeroized here: nothing below needs the passphrase.
    drop(passphrase);
    if !output.status.success() {
        let detail = tail(&stderr, 600);
        if detail.contains("operator passphrase") {
            return refuse(
                StatusCode::FORBIDDEN,
                "operator_passphrase_refused",
                "the operator passphrase did not open the sealed approver key; nothing was signed or recorded",
            );
        }
        return refuse(
            StatusCode::BAD_GATEWAY,
            "authority_approve_refused",
            format!("the deployment authority refused to approve: {detail}"),
        );
    }
    let outcome: Value = stdout
        .trim()
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .and_then(|line| serde_json::from_str(line).ok())
        .unwrap_or(Value::Null);
    let grant = outcome
        .get("approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let grant_ref = outcome.get("grant_ref").cloned().unwrap_or(Value::Null);
    let grant_expires_at_ms = outcome.get("expires_at_ms").and_then(Value::as_u64);
    // The grant must be exactly the record's: canonical, bound to the record's hashes, one use,
    // for the record's audience. Anything else is unusable and is not stored.
    let checked = (|| -> Result<(), String> {
        let (typed, canonical) = super::governed_authority::canonicalize_approval_grant(&grant)?;
        ioi_services::agentic::runtime::kernel::approval::verify_wallet_approval_grant_binding(
            &canonical,
            Some(now_ms()),
            Some(&policy_hash),
            Some(&request_hash),
        )?;
        if hex::encode(typed.audience) != audience {
            return Err("the grant's audience is not the challenge's".into());
        }
        if typed.max_usages != Some(1) {
            return Err("the grant is not one-use".into());
        }
        Ok(())
    })();
    if let Err(message) = checked {
        return refuse(
            StatusCode::BAD_GATEWAY,
            "authority_grant_mismatch",
            format!("the authority's grant does not bind this challenge exactly ({message}); it was not stored"),
        );
    }
    let stored = {
        let _guard = lock_challenges();
        match read_challenge(&st.data_dir, &id) {
            Ok(Some(mut current)) if state_of(&current) == "pending" => {
                current["state"] = json!("approved");
                current["grant"] = grant;
                current["grant_ref"] = grant_ref.clone();
                current["grant_expires_at_ms"] = json!(grant_expires_at_ms);
                current["decision"] = json!({
                    "decision": "approve",
                    "decided_by": decided_by,
                    "decided_at": iso_now(),
                    "reason": decision.reason,
                    "recorded_on_authority": outcome.get("recorded").cloned().unwrap_or(Value::Null),
                });
                write_challenge(&st.data_dir, &id, &current)
            }
            _ => Err("the challenge changed while the authority was approving".to_string()),
        }
    };
    if let Err(message) = stored {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "challenge_not_durable",
            message,
        );
    }
    reply(
        StatusCode::OK,
        json!({
            "ok": true,
            "challenge_id": id,
            "approval_ref": approval_ref_for(&id),
            "state": "approved",
            "grant_ref": grant_ref,
            "expires_at_ms": grant_expires_at_ms,
            "decided_by": decided_by,
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

/// The approvals-inbox rows for pending challenges (read projection; decisions run on the route).
pub(crate) fn pending_inbox_items(data_dir: &str) -> (Vec<Value>, usize) {
    let records = read_record_dir(data_dir, CHALLENGE_FAMILY);
    let now = now_ms();
    let items = records
        .iter()
        .filter(|record| {
            record.get("schema_version").and_then(Value::as_str) == Some(CHALLENGE_SCHEMA)
                && state_of(record) == "pending"
                && record
                    .get("expires_at_ms")
                    .and_then(Value::as_u64)
                    .is_none_or(|expires| expires > now)
        })
        .map(|record| {
            let id = record
                .get("challenge_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            json!({
                "source_plane": "wallet_approval_challenge",
                "item_ref": record.get("approval_ref"),
                "challenge_id": id,
                "subject_ref": record.get("subject_ref"),
                "title": record.get("operation"),
                "reason": "the exact effect needs the operator's approval",
                "status": "pending",
                "target_scope": record.get("target_scope"),
                "policy_hash": record.get("policy_hash"),
                "request_hash": record.get("request_hash"),
                "audience": record.get("audience"),
                "requester_ref": record.get("requester_ref"),
                "created_at": record.get("created_at"),
                "updated_at": record.get("last_parked_at"),
                "decide": {
                    "route": format!("/v1/hypervisor/authority/challenges/{id}/decision"),
                    "method": "POST",
                    "transitions": ["approve", "deny"],
                    "approve_requires": ["operator_passphrase"],
                    "decidable": decider_configured(),
                }
            })
        })
        .collect::<Vec<_>>();
    (items, records.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data_dir(label: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "ioi-approval-challenges-{label}-{}",
            hex::encode(rand::random::<[u8; 6]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    const SCOPE: &str = "scope:hypervisor.live-route.session-execute";
    fn hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn park(data_dir: &str, policy: &str, request: &str) -> Value {
        park_challenge(
            data_dir,
            ParkRequest {
                target_scope: SCOPE,
                policy_hash: policy,
                request_hash: request,
                audience: Some("ab".repeat(32)),
                subject_ref: "session:test",
                operation: "session-execute",
                published_preimage: json!({ "intent": "x" }),
                requester_ref: Some("user://operator"),
            },
        )
        .expect("parked")
    }

    fn approve_in_place(data_dir: &str, id: &str) {
        let mut record = read_challenge(data_dir, id).unwrap().unwrap();
        record["state"] = json!("approved");
        record["grant"] = json!({ "stub": true });
        record["grant_expires_at_ms"] = json!(now_ms() + 60_000);
        write_challenge(data_dir, id, &record).unwrap();
    }

    #[test]
    fn a_challenge_id_is_deterministic_in_its_exact_coordinates() {
        let a = challenge_id_for(SCOPE, &hash(1), &hash(2), Some("aa"));
        assert_eq!(a, challenge_id_for(SCOPE, &hash(1), &hash(2), Some("aa")));
        assert_ne!(a, challenge_id_for(SCOPE, &hash(1), &hash(3), Some("aa")));
        assert_ne!(a, challenge_id_for(SCOPE, &hash(1), &hash(2), Some("bb")));
        assert!(valid_challenge_id(&a), "{a}");
        assert_eq!(
            challenge_id_from_ref(&approval_ref_for(&a)),
            Some(a.as_str())
        );
    }

    #[test]
    fn the_pending_window_can_only_be_shortened() {
        assert_eq!(challenge_ttl_from(None), CHALLENGE_TTL_MS, "unset: a day");
        assert_eq!(
            challenge_ttl_from(Some("8000")),
            8_000,
            "an isolated stack shortens it"
        );
        assert_eq!(challenge_ttl_from(Some(" 8000 ")), 8_000);
        assert_eq!(
            challenge_ttl_from(Some(&(CHALLENGE_TTL_MS * 7).to_string())),
            CHALLENGE_TTL_MS,
            "never lengthened past the default"
        );
        for raw in ["0", "-5", "", "a day", "1e9"] {
            assert_eq!(
                challenge_ttl_from(Some(raw)),
                CHALLENGE_TTL_MS,
                "{raw:?} leaves the default"
            );
        }
    }

    #[test]
    fn park_is_idempotent_and_a_denial_reopens_as_a_new_ask() {
        let dir = temp_data_dir("park");
        let first = park(&dir, &hash(1), &hash(2));
        let id = first["challenge_id"].as_str().unwrap().to_string();
        assert_eq!(first["challenge_state"], "pending");
        let again = park(&dir, &hash(1), &hash(2));
        assert_eq!(again["challenge_id"], json!(id));
        let mut record = read_challenge(&dir, &id).unwrap().unwrap();
        record["state"] = json!("denied");
        write_challenge(&dir, &id, &record).unwrap();
        let reopened = park(&dir, &hash(1), &hash(2));
        assert_eq!(reopened["challenge_state"], "pending");
        let record = read_challenge(&dir, &id).unwrap().unwrap();
        assert_eq!(record["history"].as_array().map(Vec::len), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_claim_needs_the_freshly_derived_hashes_and_an_approval() {
        let dir = temp_data_dir("claim");
        let parked = park(&dir, &hash(1), &hash(2));
        let id = parked["challenge_id"].as_str().unwrap().to_string();
        let reference = approval_ref_for(&id);
        let pending = claim_approval_ref(&dir, &reference, SCOPE, &hash(1), &hash(2));
        assert_eq!(
            pending.err().map(|r| r.code),
            Some("approval_ref_not_approved")
        );
        approve_in_place(&dir, &id);
        let foreign = claim_approval_ref(&dir, &reference, SCOPE, &hash(1), &hash(9));
        assert_eq!(
            foreign.err().map(|r| r.code),
            Some("approval_ref_coordinates_mismatch")
        );
        let other_scope = claim_approval_ref(
            &dir,
            &reference,
            "scope:hypervisor.live-route.other",
            &hash(1),
            &hash(2),
        );
        assert_eq!(
            other_scope.err().map(|r| r.code),
            Some("approval_ref_coordinates_mismatch")
        );
        let claim = claim_approval_ref(&dir, &reference, SCOPE, &hash(1), &hash(2))
            .ok()
            .unwrap();
        assert_eq!(claim.grant, json!({ "stub": true }));
        let busy = claim_approval_ref(&dir, &reference, SCOPE, &hash(1), &hash(2));
        assert_eq!(busy.err().map(|r| r.code), Some("approval_ref_in_use"));
        release_claim(&dir, &claim);
        let claim = claim_approval_ref(&dir, &reference, SCOPE, &hash(1), &hash(2))
            .ok()
            .unwrap();
        mark_consumed(&dir, &claim, "authority-admission-intents/test");
        let spent = claim_approval_ref(&dir, &reference, SCOPE, &hash(1), &hash(2));
        assert_eq!(spent.err().map(|r| r.code), Some("approval_ref_consumed"));
        let record = read_challenge(&dir, &id).unwrap().unwrap();
        assert_eq!(
            record["grant"],
            Value::Null,
            "a consumed challenge keeps no grant bytes"
        );
        assert_eq!(record["consumed_by"], "authority-admission-intents/test");
        // A consumed challenge re-parked stays consumed: the exact effect ran once.
        assert_eq!(
            park(&dir, &hash(1), &hash(2))["challenge_state"],
            "consumed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_decision_body_never_names_the_coordinates_and_the_view_never_carries_the_grant() {
        for field in [
            "policy_hash",
            "request_hash",
            "target_scope",
            "audience",
            "wallet_approval_grant",
        ] {
            let mut body = json!({ "decision": "approve", "operator_passphrase": "p" });
            body[field] = json!("x");
            let refused = parse_decision_body(&serde_json::to_vec(&body).unwrap())
                .err()
                .unwrap();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            assert_eq!(
                refused.1 .0["error"]["code"], "challenge_coordinates_are_daemon_owned",
                "{field}"
            );
        }
        let parsed = parse_decision_body(
            br#"{"decision":"approve","reason":"ok","operator_passphrase":"secret-pass"}"#,
        )
        .ok()
        .unwrap();
        assert_eq!(parsed.operator_passphrase.as_str(), "secret-pass");
        assert!(parse_decision_body(br#"{"decision":"maybe"}"#).is_err());
        assert!(parse_decision_body(br#"{"decision":"deny","extra":1}"#).is_err());
        let view =
            public_view(&json!({ "challenge_id": "wac_x", "grant": { "approver_sig": [1] } }));
        assert!(view.get("grant").is_none());
        assert_eq!(
            scrub("wrong secret-pass here", "secret-pass"),
            "wrong [redacted] here"
        );
    }

    #[test]
    fn an_approval_ref_locator_is_a_prefixed_string_or_a_single_member_object() {
        let reference = format!("{APPROVAL_REF_PREFIX}wac_{}", "0".repeat(32));
        assert_eq!(
            approval_ref_locator(&json!(reference)),
            Some(reference.clone())
        );
        assert_eq!(
            approval_ref_locator(&json!({ "approval_ref": reference })),
            Some(reference.clone())
        );
        assert_eq!(approval_ref_locator(&json!("sha256:00")), None);
        assert_eq!(approval_ref_locator(&json!({ "schema_version": 1 })), None);
        assert_eq!(
            approval_ref_in_body(&json!({ "approval_ref": reference })),
            Some(reference.clone())
        );
        assert_eq!(
            approval_ref_in_body(&json!({ "wallet_approval_grant": reference })),
            Some(reference)
        );
    }
}
