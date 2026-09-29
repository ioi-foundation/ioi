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
//! 4. **The decision outlives its request** (R-240, decision route durability). The approve child
//!    takes tens of seconds (the authority unseals the approver key, mints the grant and records it
//!    on chain). It used to run inside the request handler with kill-on-drop, so a client that went
//!    away (a browser navigating off, the serve's fetch giving up at 300 s) dropped the handler,
//!    killed the child, and could leave a grant recorded on chain that the daemon never stored. Now
//!    the decision is marked in flight ON THE RECORD (`deciding`: attempt id, this process's nonce,
//!    who decided, when, the child's pid) before anything runs; the state stays `pending`, since
//!    nothing is decided yet, and every other decision is refused by name while the marker stands
//!    (409 `challenge_decision_in_progress`), so no second child starts. The approve runs on a
//!    tracked task that owns the child and the passphrase and settles the record whether or not
//!    anyone is still listening; the handler waits up to IOI_HYPERVISOR_AUTHORITY_DECISION_WAIT_MS
//!    (default 270 s) and otherwise answers 202 `challenge_decision_still_running`.
//! 5. **Reconciliation, never a blind re-run** (master guide N11). A marker naming ANOTHER process
//!    was left by a daemon that stopped mid-decision. At boot, and before any decision on that
//!    challenge, the daemon reads the authority's own record back (the approval wallet.network
//!    holds for the record's request hash): an approval whose grant binds the record exactly is
//!    stored as the approval; nothing recorded and the old child gone returns the challenge to
//!    `pending` with the interruption in its history, for the operator to decide afresh (a late
//!    landing then conflicts on chain and is adopted from it, never minted twice); anything else is
//!    `outcome_unknown` with a named reason, and approve is refused by name until a later
//!    reconciliation settles it (deny stays open). The daemon never holds the passphrase across a
//!    restart, so it cannot re-run an approve on its own.
//! 6. **An approval whose grant expired unused is asked again, never decided again** (R-240,
//!    challenge states + re-ask; master guide N12: an approval binds the exact arguments, an expiry
//!    and a single-use nonce). The authority keeps one decision per request hash, so an approved
//!    challenge whose grant ran out before any retry ran it can never be approved a second time.
//!    The requester's next retry of the same effect (with or without the stale `approval_ref`)
//!    parks a SUCCESSOR: the same effect under a fresh daemon-minted `ask_nonce`, so a new request
//!    hash (`reask_request_hash`, whose preimage the record publishes) and a new challenge id. The
//!    old record keeps its approval, reads expired, and names its successor (`superseded_by`); the
//!    successor names what it supersedes. A claim re-derives the request hash from the gate's own
//!    fresh hash and the record's nonce, and hands the gate that hash to present, so the grant the
//!    authority mints for the successor binds exactly the effect the retry derives.
//!
//! No second authority plane: wallet.network resolution, grant verification and on-chain
//! consumption are the existing `governed_authority` path; this module only parks, relays the
//! operator's decision to the authority's own `approve`, and hands the one grant back to the gate.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_types::app::wallet_network::WalletApprovalDecisionKind;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{iso_now, read_record_dir, DaemonState};

pub(crate) const CHALLENGE_FAMILY: &str = "wallet-approval-challenges";
pub(crate) const APPROVAL_REF_PREFIX: &str = "wallet-approval-challenge://";
const CHALLENGE_SCHEMA: &str = "ioi.hypervisor.wallet-approval-challenge.v1";
const CHALLENGE_ID_DOMAIN: &str = "ioi.hypervisor.wallet-approval-challenge.id.v1";
/// The domain of a re-ask's request preimage: the effect's own request hash under a fresh nonce.
const REASK_DOMAIN: &str = "ioi.hypervisor.wallet-approval-challenge.reask.v1";
/// How many successive re-asks of one effect a park follows before it gives up (each one is an
/// approval that expired unused; a chain this long is a record fault, not an operator's pattern).
const MAX_REASK_CHAIN: usize = 64;
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

/// How long the decision route waits for a running approve before answering 202: under the
/// serve fetch's 300 s headers deadline, so a slow approve reads "still running", never
/// "unreachable". The decision itself runs to completion either way.
const DECISION_WAIT_ENV: &str = "IOI_HYPERVISOR_AUTHORITY_DECISION_WAIT_MS";
const DEFAULT_DECISION_WAIT_MS: u64 = 270_000;
/// Once nothing is left to re-check, the boot reconciler stops; while something is (the authority
/// not yet readable, an old child still running) it re-checks on this back-off.
const RECONCILE_RETRY_MS: u64 = 60_000;
const RECONCILE_RETRY_MAX_MS: u64 = 600_000;

/// Serializes every read-modify-write of a challenge record. Never held across the approve child,
/// an authority read or a wallet consumption: those are bounded by the record's `deciding` marker
/// and the `consuming` claim.
static CHALLENGE_LOCK: Mutex<()> = Mutex::new(());
/// This process, as an in-flight marker names it. A marker naming any other process was left by a
/// daemon that stopped mid-decision.
static PROCESS_NONCE: OnceLock<String> = OnceLock::new();

pub(crate) fn process_nonce() -> &'static str {
    PROCESS_NONCE.get_or_init(|| format!("dp_{}", hex::encode(rand::random::<[u8; 12]>())))
}

/// The route's bounded wait (an isolated stack may set it; zero or unparseable keeps the default).
pub(crate) fn decision_wait_ms() -> u64 {
    std::env::var(DECISION_WAIT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DECISION_WAIT_MS)
}

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

/// The exact bytes a re-ask's request hash commits to: the effect's own request hash (as the gate
/// derives it) and the ask's single-use nonce.
fn reask_preimage(base_request_hash: &str, ask_nonce: &str) -> Value {
    json!({
        "domain": REASK_DOMAIN,
        "request_hash": base_request_hash,
        "ask_nonce": ask_nonce,
    })
}

/// The request hash of a re-ask of the effect whose own request hash is `base_request_hash`: a new
/// request hash for the same exact effect, so the authority decides it as a new request.
pub(crate) fn reask_request_hash(base_request_hash: &str, ask_nonce: &str) -> String {
    let bytes = serde_jcs::to_vec(&reask_preimage(base_request_hash, ask_nonce)).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// An approval whose one-use grant ran out before any retry presented it. The authority keeps one
/// decision per request hash, so it can never be approved again: the effect is asked again.
fn grant_expired_unused(record: &Value, now: u64) -> bool {
    state_of(record) == "approved"
        && record
            .get("grant_expires_at_ms")
            .and_then(Value::as_u64)
            .is_some_and(|expires| expires <= now)
}

fn superseded_by(record: &Value) -> Option<&str> {
    record
        .get("superseded_by")
        .and_then(Value::as_str)
        .filter(|id| valid_challenge_id(id))
}

fn iso_of_ms(ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
        .ok()
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("{ms} ms since the epoch"))
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

/// The record's in-flight marker, while an approve for it is (or was, if another process wrote
/// it) running.
fn in_flight(record: &Value) -> Option<&Value> {
    record.get("deciding").filter(|marker| marker.is_object())
}

fn marker_is_ours(marker: &Value) -> bool {
    marker.get("process").and_then(Value::as_str) == Some(process_nonce())
}

fn attempt_of(marker: &Value) -> &str {
    marker
        .get("attempt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Why an interrupted decision's outcome is not known yet, if it is not.
fn outcome_unknown(record: &Value) -> Option<&Value> {
    record
        .get("outcome_unknown")
        .filter(|unknown| unknown.is_object())
}

/// A decision another process left in flight, or an outcome still unknown: read the authority's
/// record before anything else is decided.
fn needs_reconciliation(record: &Value) -> bool {
    in_flight(record).is_some_and(|marker| !marker_is_ours(marker))
        || outcome_unknown(record).is_some()
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

/// A fresh challenge record for one exact effect's coordinates.
fn new_challenge_record(
    id: &str,
    request: &ParkRequest<'_>,
    request_hash: &str,
    published_preimage: Value,
    now: u64,
) -> Value {
    json!({
        "schema_version": CHALLENGE_SCHEMA,
        "challenge_id": id,
        "approval_ref": approval_ref_for(id),
        "state": "pending",
        "target_scope": request.target_scope,
        "policy_hash": request.policy_hash,
        "request_hash": request_hash,
        "audience": request.audience,
        "subject_ref": request.subject_ref,
        "operation": request.operation,
        "published_preimage": published_preimage,
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
    })
}

/// Re-park an existing record of this effect: a pending ask is refreshed; one closed by a denial
/// or an expiry (nothing recorded on the authority either way) reopens under the same request
/// hash; anything else stands as it is.
fn repark_existing(
    data_dir: &str,
    id: &str,
    mut record: Value,
    request: &ParkRequest<'_>,
    now: u64,
) -> Option<Value> {
    let state = state_of(&record).to_string();
    // A decision in flight (or one whose outcome is not known yet) is never reopened as a new ask
    // under it: the operator's decision is still settling.
    let expired_pending = state == "pending"
        && in_flight(&record).is_none()
        && outcome_unknown(&record).is_none()
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
        write_challenge(data_dir, id, &record).ok()?;
    }
    Some(record)
}

/// Ask the effect again after `predecessor`'s approval expired unused: a successor challenge for
/// the same exact effect under a fresh single-use nonce, so a new request hash the authority has
/// never decided. The predecessor keeps its approval and names the successor.
fn park_reask(
    data_dir: &str,
    predecessor_id: &str,
    mut predecessor: Value,
    request: &ParkRequest<'_>,
    now: u64,
) -> Option<(String, Value)> {
    let ask_nonce = hex::encode(rand::random::<[u8; 16]>());
    let request_hash = reask_request_hash(request.request_hash, &ask_nonce);
    let id = challenge_id_for(
        request.target_scope,
        request.policy_hash,
        &request_hash,
        request.audience.as_deref(),
    );
    let mut published_preimage = request.published_preimage.clone();
    if let Some(object) = published_preimage.as_object_mut() {
        object.insert(
            "reask_preimage".into(),
            reask_preimage(request.request_hash, &ask_nonce),
        );
    } else {
        published_preimage = json!({
            "effect_preimage": published_preimage,
            "reask_preimage": reask_preimage(request.request_hash, &ask_nonce),
        });
    }
    let mut record = new_challenge_record(&id, request, &request_hash, published_preimage, now);
    record["ask_nonce"] = json!(ask_nonce);
    record["base_request_hash"] = json!(request.request_hash);
    record["supersedes"] = json!(predecessor_id);
    record["supersedes_grant_expired_at_ms"] = predecessor
        .get("grant_expires_at_ms")
        .cloned()
        .unwrap_or(Value::Null);
    // The successor first: a predecessor never names a successor that is not there.
    write_challenge(data_dir, &id, &record).ok()?;
    predecessor["superseded_by"] = json!(id);
    predecessor["superseded_at"] = json!(iso_now());
    write_challenge(data_dir, predecessor_id, &predecessor).ok()?;
    Some((id, record))
}

/// Park (or re-park) one exact effect's challenge. Returns the members a gate adds to its 403
/// challenge: the challenge id, its state, the request hash a grant for it binds, the decision
/// route and whether this daemon can decide. An approval of this effect whose grant expired unused
/// is never reopened: the effect is asked again as its successor (a fresh nonce, a new request
/// hash), and a later park follows that chain to the effect's latest ask.
/// A persistence failure returns None: the gate's refusal stands without a parked challenge.
pub(crate) fn park_challenge(data_dir: &str, request: ParkRequest<'_>) -> Option<Value> {
    let base_id = challenge_id_for(
        request.target_scope,
        request.policy_hash,
        request.request_hash,
        request.audience.as_deref(),
    );
    let now = now_ms();
    let _guard = lock_challenges();
    let mut id = base_id;
    // The ask before `id` in the chain, whose approval expired unused.
    let mut predecessor: Option<(String, Value)> = None;
    let mut hops = 0;
    let (id, record) = loop {
        match read_challenge(data_dir, &id).ok()? {
            Some(record) if grant_expired_unused(&record, now) => {
                match superseded_by(&record).map(str::to_owned) {
                    Some(next) => {
                        // A chain that loops or runs this long is a record fault: no park.
                        hops += 1;
                        if hops > MAX_REASK_CHAIN {
                            return None;
                        }
                        predecessor = Some((id, record));
                        id = next;
                    }
                    None => break park_reask(data_dir, &id, record, &request, now)?,
                }
            }
            Some(record) => {
                let record = repark_existing(data_dir, &id, record, &request, now)?;
                break (id, record);
            }
            None => match predecessor.take() {
                // A successor the chain names is gone: ask again from the one before it.
                Some((predecessor_id, predecessor_record)) => {
                    break park_reask(data_dir, &predecessor_id, predecessor_record, &request, now)?
                }
                None => {
                    let record = new_challenge_record(
                        &id,
                        &request,
                        request.request_hash,
                        request.published_preimage.clone(),
                        now,
                    );
                    write_challenge(data_dir, &id, &record).ok()?;
                    break (id, record);
                }
            },
        }
    };
    let mut members = json!({
        "challenge_id": id,
        "challenge_state": state_of(&record),
        "request_hash": record.get("request_hash").cloned().unwrap_or(Value::Null),
        "decision_route": format!("/v1/hypervisor/authority/challenges/{id}/decision"),
        "decidable": decider_configured(),
    });
    if let Some(supersedes) = record.get("supersedes").filter(|value| value.is_string()) {
        members["supersedes"] = supersedes.clone();
    }
    Some(members)
}

/// A claimed, approved challenge: the one grant the gate may present, for exactly this effect.
pub(crate) struct ClaimedApproval {
    pub(crate) challenge_id: String,
    pub(crate) grant: Value,
    /// The request hash the grant binds and the gate presents: the gate's own, or for a re-ask the
    /// gate's own under the record's single-use nonce (re-derived at the claim, never read back).
    pub(crate) request_hash: String,
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
/// and hashes equal the ones the gate derived afresh from the retried request (for a re-ask: the
/// gate's request hash under the record's nonce). A consumed, denied, pending, expired or foreign
/// challenge is refused before anything reaches wallet.network.
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
    // A re-ask's request hash is the gate's own under the record's single-use nonce: re-derived
    // here from the hash the gate just derived, so a record can never name an effect of its own.
    let presented_request_hash = match record.get("ask_nonce").and_then(Value::as_str) {
        Some(ask_nonce) => reask_request_hash(request_hash, ask_nonce),
        None => request_hash.to_string(),
    };
    let same = |field: &str, value: &str| record.get(field).and_then(Value::as_str) == Some(value);
    if !(same("target_scope", target_scope)
        && same("policy_hash", policy_hash)
        && same("request_hash", &presented_request_hash))
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
        "pending" if in_flight(&record).is_some() => {
            return Err(refusal(
                StatusCode::CONFLICT,
                "approval_ref_deciding",
                "the operator's approval of this challenge is being recorded by the deployment authority now; retry once it settles",
            ))
        }
        "pending" if outcome_unknown(&record).is_some() => {
            return Err(refusal(
                StatusCode::CONFLICT,
                "approval_ref_outcome_unknown",
                "an approval of this challenge was interrupted and its outcome is not known yet; nothing is presented until the daemon reconciles it from the authority's record",
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
    if let Some(expired_at) = record
        .get("grant_expires_at_ms")
        .and_then(Value::as_u64)
        .filter(|expires| *expires <= now)
    {
        // Never "approve again": the authority keeps one decision per request hash, so this
        // approval can never be renewed. The effect is asked again as a new challenge.
        let successor = superseded_by(&record)
            .map(|next| format!("; it was asked again as challenge {next}"))
            .unwrap_or_default();
        return Err(refusal(
            StatusCode::GONE,
            "approval_ref_expired",
            format!(
                "this approval's one-use grant expired unused at {}. It cannot be approved again — the deployment authority keeps one decision per request — so the action must be asked again: retrying it parks a new challenge for the operator (a fresh single-use nonce, so a new request hash){successor}",
                iso_of_ms(expired_at)
            ),
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
        request_hash: presented_request_hash,
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

// ---- the decision: marked in flight, run to completion on its own task, reconciled on restart --

type Reply = (StatusCode, Json<Value>);

/// The exact coordinates the daemon's record names: the only thing the authority is asked to sign.
#[derive(Clone, Debug)]
struct Coordinates {
    target_scope: String,
    policy_hash: String,
    request_hash: String,
    audience: String,
}

impl Coordinates {
    fn of(record: &Value) -> Self {
        let field = |name: &str| {
            record
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        Self {
            target_scope: field("target_scope"),
            policy_hash: field("policy_hash"),
            request_hash: field("request_hash"),
            audience: field("audience"),
        }
    }
}

/// The deployment authority's `approve`, run as a child: the authority binary on its node's state
/// directory, bounded by IOI_HYPERVISOR_AUTHORITY_APPROVE_TIMEOUT_MS.
#[derive(Clone, Debug)]
pub(crate) struct Approver {
    binary: String,
    state_dir: String,
    timeout_ms: u64,
}

impl Approver {
    fn configured() -> Option<Self> {
        let (binary, state_dir) = decider_paths()?;
        let timeout_ms = std::env::var("IOI_HYPERVISOR_AUTHORITY_APPROVE_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_APPROVE_TIMEOUT_MS);
        Some(Self {
            binary,
            state_dir,
            timeout_ms,
        })
    }
}

/// What the deployment authority's chain holds for one request hash.
#[derive(Clone, Debug)]
pub(crate) enum AuthorityRecord {
    /// An approval decision is recorded: the grant it carries, the scope it was recorded under,
    /// and whether it is an operator's approval (what `approve` records).
    Found {
        grant: Value,
        target_label: String,
        approved_by_human: bool,
    },
    /// Nothing is recorded for the request hash.
    Absent,
    /// The record could not be read (the authority unreachable, or no pinned channel to it):
    /// nothing may be concluded.
    Unreadable(String),
}

/// Where the authority's record is read from: wallet.network over the daemon's pinned channel,
/// or (tests only) a fixed answer.
#[derive(Clone)]
pub(crate) enum AuthorityReader {
    Wallet,
    #[cfg(test)]
    Fixed(Arc<Mutex<AuthorityRecord>>),
}

fn hash32(text: &str) -> Option<[u8; 32]> {
    let hex_text = text.strip_prefix("sha256:").unwrap_or(text);
    <[u8; 32]>::try_from(hex::decode(hex_text).ok()?).ok()
}

impl AuthorityReader {
    async fn read(&self, request_hash: &str) -> AuthorityRecord {
        match self {
            Self::Wallet => {
                let Some(hash) = hash32(request_hash) else {
                    return AuthorityRecord::Unreadable(
                        "the challenge's request hash is not 32 bytes of hex".into(),
                    );
                };
                match super::wallet_network_capability_client::read_approval_decision(hash).await {
                    Ok(Some(decision)) => AuthorityRecord::Found {
                        grant: decision
                            .approval_grant
                            .as_ref()
                            .and_then(|grant| serde_json::to_value(grant).ok())
                            .unwrap_or(Value::Null),
                        target_label: decision.interception.target.canonical_label(),
                        approved_by_human: decision.decision
                            == WalletApprovalDecisionKind::ApprovedByHuman,
                    },
                    Ok(None) => AuthorityRecord::Absent,
                    Err(error) => AuthorityRecord::Unreadable(format!("{error:?}")),
                }
            }
            #[cfg(test)]
            Self::Fixed(record) => record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        }
    }
}

/// The grant must be exactly the record's: canonical, bound to the record's hashes, one use, for
/// the record's audience. Anything else is unusable and is never stored. Returns the grant's
/// public ref and its expiry.
fn grant_binds(
    grant: &Value,
    coordinates: &Coordinates,
    now: Option<u64>,
) -> Result<(String, u64), String> {
    let (typed, canonical) = super::governed_authority::canonicalize_approval_grant(grant)?;
    let binding =
        ioi_services::agentic::runtime::kernel::approval::verify_wallet_approval_grant_binding(
            &canonical,
            now,
            Some(&coordinates.policy_hash),
            Some(&coordinates.request_hash),
        )?;
    if hex::encode(typed.audience) != coordinates.audience {
        return Err("the grant's audience is not the challenge's".into());
    }
    if typed.max_usages != Some(1) {
        return Err("the grant is not one-use".into());
    }
    Ok((binding.grant_ref, typed.expires_at))
}

fn in_progress_reply(id: &str, record: &Value, marker: &Value) -> Reply {
    let started_at = marker
        .get("started_at")
        .and_then(Value::as_str)
        .unwrap_or("earlier");
    let decided_by = marker
        .get("decided_by")
        .and_then(Value::as_str)
        .unwrap_or("an operator");
    reply(
        StatusCode::CONFLICT,
        json!({
            "ok": false,
            "error": {
                "code": "challenge_decision_in_progress",
                "message": format!("a decision on this challenge is already running (started {started_at} by {decided_by}); nothing new was started — re-read the challenge for its outcome"),
            },
            "challenge_id": id,
            "state": state_of(record),
            "deciding": { "started_at": started_at, "decided_by": decided_by },
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

fn approved_reply(
    id: &str,
    grant_ref: &str,
    grant_expires_at_ms: u64,
    decided_by: Value,
    reconciled_from: Option<&str>,
) -> Reply {
    let mut body = json!({
        "ok": true,
        "challenge_id": id,
        "approval_ref": approval_ref_for(id),
        "state": "approved",
        "grant_ref": grant_ref,
        "expires_at_ms": grant_expires_at_ms,
        "decided_by": decided_by,
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Some(source) = reconciled_from {
        body["reconciled_from"] = json!(source);
    }
    reply(StatusCode::OK, body)
}

/// Mark the decision in flight, atomically with the checks that allow it: the record is pending,
/// unexpired, not already being decided, and its outcome is not unknown. Returns the attempt id.
fn begin_deciding(
    data_dir: &str,
    id: &str,
    decided_by: &str,
    reason: &str,
) -> Result<String, Reply> {
    let _guard = lock_challenges();
    let mut record = match read_challenge(data_dir, id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err(refuse(
                StatusCode::NOT_FOUND,
                "challenge_not_found",
                "no parked challenge has this id",
            ))
        }
        Err(message) => {
            return Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "challenge_unreadable",
                message,
            ))
        }
    };
    if let Some(marker) = in_flight(&record) {
        return Err(in_progress_reply(id, &record, marker));
    }
    if state_of(&record) != "pending" || outcome_unknown(&record).is_some() {
        return Err(refuse(
            StatusCode::CONFLICT,
            "challenge_changed",
            "the challenge changed while deciding",
        ));
    }
    if record
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .is_some_and(|expires| expires <= now_ms())
    {
        return Err(refuse(
            StatusCode::GONE,
            "challenge_expired",
            "this challenge expired; re-run the request to park it again",
        ));
    }
    let attempt_id = format!("dec_{}", hex::encode(rand::random::<[u8; 12]>()));
    record["deciding"] = json!({
        "attempt_id": attempt_id,
        "process": process_nonce(),
        "decided_by": decided_by,
        "reason": reason,
        "started_at": iso_now(),
        "started_at_ms": now_ms(),
        "child_pid": Value::Null,
    });
    write_challenge(data_dir, id, &record).map_err(|message| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "challenge_not_durable",
            message,
        )
    })?;
    Ok(attempt_id)
}

/// Record the approve child's pid on its attempt's marker, so a later process can tell whether an
/// interrupted approve is still running.
fn note_child_pid(data_dir: &str, id: &str, attempt_id: &str, pid: Option<u32>) {
    let Some(pid) = pid else { return };
    let _guard = lock_challenges();
    let Ok(Some(mut record)) = read_challenge(data_dir, id) else {
        return;
    };
    if !in_flight(&record).is_some_and(|marker| attempt_of(marker) == attempt_id) {
        return;
    }
    record["deciding"]["child_pid"] = json!(pid);
    let _ = write_challenge(data_dir, id, &record);
}

/// What a finished approve leaves on the record.
enum Settle {
    /// Nothing was decided: the marker goes and the record is exactly what it was before.
    Clear,
    /// The authority's grant binds the record exactly: it is the approval.
    Approved {
        grant: Value,
        grant_ref: String,
        grant_expires_at_ms: u64,
        recorded_on_authority: Value,
        reconciled_from: Option<&'static str>,
    },
}

/// Apply a finished approve's outcome, only to the attempt that ran it.
fn settle_decision(
    data_dir: &str,
    id: &str,
    attempt_id: &str,
    settle: Settle,
) -> Result<Value, String> {
    let _guard = lock_challenges();
    let mut record = read_challenge(data_dir, id)?
        .ok_or_else(|| "the challenge vanished while the authority was approving".to_string())?;
    let Some(marker) = in_flight(&record)
        .filter(|marker| attempt_of(marker) == attempt_id)
        .cloned()
    else {
        return Err("the challenge changed while the authority was approving".to_string());
    };
    if let Some(object) = record.as_object_mut() {
        object.remove("deciding");
    }
    if let Settle::Approved {
        grant,
        grant_ref,
        grant_expires_at_ms,
        recorded_on_authority,
        reconciled_from,
    } = settle
    {
        record["state"] = json!("approved");
        record["grant"] = grant;
        record["grant_ref"] = json!(grant_ref);
        record["grant_expires_at_ms"] = json!(grant_expires_at_ms);
        record["decision"] = json!({
            "decision": "approve",
            "decided_by": marker.get("decided_by"),
            "decided_at": iso_now(),
            "reason": marker.get("reason"),
            "recorded_on_authority": recorded_on_authority,
        });
        if let Some(source) = reconciled_from {
            record["decision"]["reconciled_from"] = json!(source);
        }
    }
    write_challenge(data_dir, id, &record)?;
    Ok(record)
}

/// A task dropped before it settled its attempt (the runtime shutting down, a panic) leaves the
/// outcome unknown — never a marker that reads as still running in a process that is not running
/// it. Reconciliation reads what the authority recorded.
struct SettleGuard {
    data_dir: String,
    id: String,
    attempt_id: String,
}

impl Drop for SettleGuard {
    fn drop(&mut self) {
        let _guard = lock_challenges();
        let Ok(Some(mut record)) = read_challenge(&self.data_dir, &self.id) else {
            return;
        };
        let Some(marker) = in_flight(&record)
            .filter(|marker| attempt_of(marker) == self.attempt_id)
            .cloned()
        else {
            // Settled (or superseded): nothing to do.
            return;
        };
        if let Some(object) = record.as_object_mut() {
            object.remove("deciding");
        }
        record["outcome_unknown"] = json!({
            "reason": "decision_task_aborted",
            "message": "the daemon stopped running this approve before it settled; the authority may have recorded the grant",
            "since": iso_now(),
            "attempt": marker,
        });
        let _ = write_challenge(&self.data_dir, &self.id, &record);
    }
}

/// One approve, owned by its task: the passphrase lives here and nowhere else.
struct ApproveJob {
    data_dir: String,
    id: String,
    attempt_id: String,
    decided_by: String,
    coordinates: Coordinates,
    passphrase: Zeroizing<String>,
    approver: Approver,
    reader: AuthorityReader,
}

async fn run_approve_job(job: ApproveJob) -> Reply {
    let ApproveJob {
        data_dir,
        id,
        attempt_id,
        decided_by,
        coordinates,
        passphrase,
        approver,
        reader,
    } = job;
    let _settled = SettleGuard {
        data_dir: data_dir.clone(),
        id: id.clone(),
        attempt_id: attempt_id.clone(),
    };
    approve_to_completion(
        &data_dir,
        &id,
        &attempt_id,
        &decided_by,
        &coordinates,
        passphrase,
        &approver,
        &reader,
    )
    .await
}

/// The approve ended without a grant this daemon can store (it failed, timed out or was refused),
/// yet it may have recorded one first, or an earlier interrupted approve did. Read the authority's
/// record: an approval that binds the record exactly is adopted (a grant is never minted twice for
/// one request hash); otherwise the marker goes and the refusal stands.
async fn settle_unconfirmed(
    data_dir: &str,
    id: &str,
    attempt_id: &str,
    coordinates: &Coordinates,
    reader: &AuthorityReader,
    refusal: Reply,
) -> Reply {
    if let AuthorityRecord::Found {
        grant,
        target_label,
        approved_by_human,
    } = reader.read(&coordinates.request_hash).await
    {
        if approved_by_human && target_label == coordinates.target_scope {
            if let Ok((grant_ref, grant_expires_at_ms)) =
                grant_binds(&grant, coordinates, Some(now_ms()))
            {
                if let Ok(record) = settle_decision(
                    data_dir,
                    id,
                    attempt_id,
                    Settle::Approved {
                        grant,
                        grant_ref: grant_ref.clone(),
                        grant_expires_at_ms,
                        recorded_on_authority: json!("existing"),
                        reconciled_from: Some("authority_record"),
                    },
                ) {
                    let decided_by = record
                        .pointer("/decision/decided_by")
                        .cloned()
                        .unwrap_or(Value::Null);
                    return approved_reply(
                        id,
                        &grant_ref,
                        grant_expires_at_ms,
                        decided_by,
                        Some("authority_record"),
                    );
                }
            }
        }
    }
    let _ = settle_decision(data_dir, id, attempt_id, Settle::Clear);
    refusal
}

#[allow(clippy::too_many_arguments)]
async fn approve_to_completion(
    data_dir: &str,
    id: &str,
    attempt_id: &str,
    decided_by: &str,
    coordinates: &Coordinates,
    passphrase: Zeroizing<String>,
    approver: &Approver,
    reader: &AuthorityReader,
) -> Reply {
    let authority_reason =
        format!("Hypervisor operator approval of the exact effect (challenge {id})");
    let mut command = tokio::process::Command::new(&approver.binary);
    command
        .args([
            "approve",
            "--state-dir",
            &approver.state_dir,
            "--policy-hash",
            &coordinates.policy_hash,
            "--request-hash",
            &coordinates.request_hash,
            "--audience",
            &coordinates.audience,
            "--target-scope",
            &coordinates.target_scope,
            "--reason",
            &authority_reason,
        ])
        .env_remove(OPERATOR_PASS_ENV)
        // The ONE place the passphrase leaves this process: the approve child's environment. The
        // binary copies it and scrubs its own environment block before any thread starts.
        .env(OPERATOR_PASS_ENV, passphrase.as_str())
        .env("CARGO_TERM_COLOR", "never")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // This task owns the child, so a departing client cannot kill it. Only the task ending
        // early (the runtime shutting down) does, and reconciliation reads what it left.
        .kill_on_drop(true);
    let spawned = command.spawn();
    // The Command's own copy of the environment goes with it, now that the child exists.
    drop(command);
    let child = match spawned {
        Ok(child) => child,
        Err(error) => {
            drop(passphrase);
            let _ = settle_decision(data_dir, id, attempt_id, Settle::Clear);
            return refuse(
                StatusCode::BAD_GATEWAY,
                "authority_approve_unavailable",
                format!("the authority binary could not be started: {error}"),
            );
        }
    };
    note_child_pid(data_dir, id, attempt_id, child.id());
    let waited = tokio::time::timeout(
        Duration::from_millis(approver.timeout_ms),
        child.wait_with_output(),
    )
    .await;
    let output = match waited {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            drop(passphrase);
            return settle_unconfirmed(
                data_dir,
                id,
                attempt_id,
                coordinates,
                reader,
                refuse(
                    StatusCode::BAD_GATEWAY,
                    "authority_approve_failed",
                    format!("the authority approve did not complete: {error}"),
                ),
            )
            .await;
        }
        Err(_) => {
            // The timed-out wait dropped the child, which kill-on-drop ended; it may have
            // recorded the grant first.
            drop(passphrase);
            return settle_unconfirmed(
                data_dir,
                id,
                attempt_id,
                coordinates,
                reader,
                refuse(
                    StatusCode::GATEWAY_TIMEOUT,
                    "authority_approve_timeout",
                    format!(
                        "the authority approve did not finish within {} ms; the challenge stays pending",
                        approver.timeout_ms
                    ),
                ),
            )
            .await;
        }
    };
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
            // A refused passphrase records nothing: the record goes back exactly as it was.
            let _ = settle_decision(data_dir, id, attempt_id, Settle::Clear);
            return refuse(
                StatusCode::FORBIDDEN,
                "operator_passphrase_refused",
                "the operator passphrase did not open the sealed approver key; nothing was signed or recorded",
            );
        }
        return settle_unconfirmed(
            data_dir,
            id,
            attempt_id,
            coordinates,
            reader,
            refuse(
                StatusCode::BAD_GATEWAY,
                "authority_approve_refused",
                format!("the deployment authority refused to approve: {detail}"),
            ),
        )
        .await;
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
    let (grant_ref, grant_expires_at_ms) = match grant_binds(&grant, coordinates, Some(now_ms())) {
        Ok(bound) => bound,
        Err(message) => {
            let _ = settle_decision(data_dir, id, attempt_id, Settle::Clear);
            return refuse(
                StatusCode::BAD_GATEWAY,
                "authority_grant_mismatch",
                format!("the authority's grant does not bind this challenge exactly ({message}); it was not stored"),
            );
        }
    };
    match settle_decision(
        data_dir,
        id,
        attempt_id,
        Settle::Approved {
            grant,
            grant_ref: grant_ref.clone(),
            grant_expires_at_ms,
            recorded_on_authority: outcome.get("recorded").cloned().unwrap_or(Value::Null),
            reconciled_from: None,
        },
    ) {
        Ok(_) => approved_reply(id, &grant_ref, grant_expires_at_ms, json!(decided_by), None),
        Err(message) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "challenge_not_durable",
            message,
        ),
    }
}

// ---- reconciliation (N11: an unknown outcome is reconciled, never blindly re-run) -------------

/// How a read of the authority's record settled one interrupted decision.
enum Resolution {
    Approved {
        grant: Value,
        grant_ref: String,
        grant_expires_at_ms: u64,
    },
    /// Nothing is recorded and the earlier approve is gone: the operator decides afresh.
    Interrupted,
    Unknown {
        reason: &'static str,
        message: String,
    },
}

/// Unknown outcomes a later read can change; the boot reconciler keeps re-checking these.
fn retryable_unknown(unknown: &Value) -> bool {
    matches!(
        unknown.get("reason").and_then(Value::as_str),
        Some("authority_record_unreadable" | "authority_approve_still_running")
    )
}

/// The pid of the approve an earlier process started for this record, when it is still running:
/// alive, and that exact act (the authority binary's `approve` for this request hash).
fn approve_child_running(attempt: &Value, request_hash: &str) -> Option<u32> {
    let pid = u32::try_from(attempt.get("child_pid").and_then(Value::as_u64)?).ok()?;
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
    (args.iter().any(|arg| *arg == b"approve")
        && args.iter().any(|arg| *arg == request_hash.as_bytes()))
    .then_some(pid)
}

/// The attempt an interrupted record is about: its foreign in-flight marker, or the attempt an
/// unknown outcome names.
fn interrupted_attempt(record: &Value) -> Value {
    in_flight(record)
        .cloned()
        .or_else(|| outcome_unknown(record).and_then(|unknown| unknown.get("attempt").cloned()))
        .unwrap_or(Value::Null)
}

/// Reconcile one challenge whose in-flight marker names another process, or whose outcome is
/// unknown, from the authority's own record. Returns the record as it stands afterwards.
pub(crate) async fn reconcile_challenge(
    data_dir: &str,
    id: &str,
    reader: &AuthorityReader,
) -> Result<Value, String> {
    let record = {
        let _guard = lock_challenges();
        read_challenge(data_dir, id)?
    }
    .ok_or_else(|| format!("challenge {id} is absent"))?;
    if !needs_reconciliation(&record) {
        return Ok(record);
    }
    let attempt = interrupted_attempt(&record);
    let attempt_id = attempt_of(&attempt).to_string();
    let coordinates = Coordinates::of(&record);
    let resolution = match reader.read(&coordinates.request_hash).await {
        AuthorityRecord::Found {
            grant,
            target_label,
            approved_by_human,
        } => {
            if !approved_by_human || target_label != coordinates.target_scope {
                Resolution::Unknown {
                    reason: "authority_record_mismatch",
                    message: format!(
                        "the authority records a decision for this request hash that is not an operator's approval under {} (it names {target_label}); it is not adopted",
                        coordinates.target_scope
                    ),
                }
            } else {
                match grant_binds(&grant, &coordinates, None) {
                    Ok((grant_ref, grant_expires_at_ms)) => Resolution::Approved {
                        grant,
                        grant_ref,
                        grant_expires_at_ms,
                    },
                    Err(message) => Resolution::Unknown {
                        reason: "authority_record_mismatch",
                        message: format!(
                            "the authority's recorded grant does not bind this challenge exactly ({message}); it is not adopted"
                        ),
                    },
                }
            }
        }
        AuthorityRecord::Absent => match approve_child_running(&attempt, &coordinates.request_hash)
        {
            Some(pid) => Resolution::Unknown {
                reason: "authority_approve_still_running",
                message: format!(
                    "the approve an earlier daemon started (pid {pid}) is still running and the authority records nothing yet; it is re-read, never re-run"
                ),
            },
            None => Resolution::Interrupted,
        },
        AuthorityRecord::Unreadable(detail) => Resolution::Unknown {
            reason: "authority_record_unreadable",
            message: format!(
                "the authority's record for this request hash could not be read ({detail}); nothing is concluded until it can be"
            ),
        },
    };

    let _guard = lock_challenges();
    let mut current =
        read_challenge(data_dir, id)?.ok_or_else(|| format!("challenge {id} is absent"))?;
    // Only the attempt that was read about is settled: anything that moved meanwhile stands.
    if !needs_reconciliation(&current) || attempt_of(&interrupted_attempt(&current)) != attempt_id {
        return Ok(current);
    }
    if let Resolution::Unknown { reason, message } = &resolution {
        let unchanged = in_flight(&current).is_none()
            && outcome_unknown(&current).is_some_and(|unknown| {
                unknown.get("reason").and_then(Value::as_str) == Some(*reason)
                    && unknown.get("message").and_then(Value::as_str) == Some(message.as_str())
            });
        if unchanged {
            return Ok(current);
        }
    }
    let prior_unknown = current.as_object_mut().and_then(|object| {
        object.remove("deciding");
        object.remove("outcome_unknown")
    });
    match resolution {
        Resolution::Approved {
            grant,
            grant_ref,
            grant_expires_at_ms,
        } => {
            current["state"] = json!("approved");
            current["grant"] = grant;
            current["grant_ref"] = json!(grant_ref);
            current["grant_expires_at_ms"] = json!(grant_expires_at_ms);
            current["decision"] = json!({
                "decision": "approve",
                "decided_by": attempt.get("decided_by"),
                "decided_at": iso_now(),
                "reason": attempt.get("reason"),
                "recorded_on_authority": "existing",
                "reconciled_from": "authority_record",
            });
        }
        Resolution::Interrupted => {
            let entry = json!({
                "state": "interrupted",
                "decision": Value::Null,
                "closed_at": iso_now(),
                "reconciliation": {
                    "authority_record": "absent",
                    "note": "the daemon stopped mid-approve and the authority recorded nothing for this request hash; the operator decides afresh",
                    "attempt": attempt,
                },
            });
            if let Some(history) = current.get_mut("history").and_then(Value::as_array_mut) {
                history.push(entry);
            } else {
                current["history"] = json!([entry]);
            }
        }
        Resolution::Unknown { reason, message } => {
            let since = prior_unknown
                .as_ref()
                .and_then(|unknown| unknown.get("since").cloned())
                .unwrap_or_else(|| json!(iso_now()));
            current["outcome_unknown"] = json!({
                "reason": reason,
                "message": message,
                "since": since,
                "checked_at": iso_now(),
                "attempt": attempt,
            });
        }
    }
    write_challenge(data_dir, id, &current)?;
    Ok(current)
}

/// Reconcile every challenge a stopped daemon left mid-decision. Returns how many are still
/// unsettled for a reason a later read can change (the authority unreadable, an old child running).
pub(crate) async fn reconcile_pass(data_dir: &str, reader: &AuthorityReader) -> usize {
    let interrupted: Vec<String> = read_record_dir(data_dir, CHALLENGE_FAMILY)
        .iter()
        .filter(|record| {
            record.get("schema_version").and_then(Value::as_str) == Some(CHALLENGE_SCHEMA)
                && needs_reconciliation(record)
        })
        .filter_map(|record| {
            record
                .get("challenge_id")
                .and_then(Value::as_str)
                .filter(|id| valid_challenge_id(id))
                .map(str::to_owned)
        })
        .collect();
    let mut unsettled = 0;
    for id in interrupted {
        match reconcile_challenge(data_dir, &id, reader).await {
            Ok(record) => match outcome_unknown(&record) {
                Some(unknown) => {
                    if retryable_unknown(unknown) {
                        unsettled += 1;
                    }
                    let reason = unknown
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    tracing::warn!(
                        challenge = %id,
                        %reason,
                        "an interrupted approval decision's outcome is not known yet"
                    );
                }
                None => tracing::info!(
                    challenge = %id,
                    state = state_of(&record),
                    "an interrupted approval decision was reconciled from the authority's record"
                ),
            },
            Err(message) => tracing::warn!(
                challenge = %id,
                %message,
                "an interrupted approval decision could not be reconciled"
            ),
        }
    }
    unsettled
}

/// Boot: reconcile what a stopped daemon left mid-decision, and keep re-checking whatever a later
/// read can still settle until nothing is left.
pub(crate) async fn reconcile_interrupted_decisions(data_dir: String) {
    let reader = AuthorityReader::Wallet;
    let mut wait_ms = RECONCILE_RETRY_MS;
    loop {
        if reconcile_pass(&data_dir, &reader).await == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        wait_ms = wait_ms.saturating_mul(2).min(RECONCILE_RETRY_MAX_MS);
    }
}

/// POST /v1/hypervisor/authority/challenges/:id/decision — the operator's decision on one parked
/// challenge. `approve` runs the deployment authority's `approve` for the record's exact
/// coordinates with the operator passphrase in the child's environment only, on a task that
/// settles the record whether or not the caller is still there, stores the one-use grant and
/// returns `approval_ref`; `deny` records the refusal and mints nothing.
pub(crate) async fn handle_challenge_decision(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Reply {
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
    decide_challenge(
        st.data_dir.clone(),
        id,
        decided_by,
        decision,
        Approver::configured(),
        AuthorityReader::Wallet,
        decision_wait_ms(),
    )
    .await
}

/// The decision itself, for an authenticated operator. The approve is spawned onto its own task;
/// this waits for it up to `wait_ms` and otherwise answers 202 (the task settles the record).
async fn decide_challenge(
    data_dir: String,
    id: String,
    decided_by: String,
    decision: DecisionBody,
    approver: Option<Approver>,
    reader: AuthorityReader,
    wait_ms: u64,
) -> Reply {
    let record = {
        let _guard = lock_challenges();
        match read_challenge(&data_dir, &id) {
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
    // A decision a stopped daemon left in flight, or an outcome not known yet, is reconciled from
    // the authority's record before anything else is decided.
    let record = if needs_reconciliation(&record) {
        match reconcile_challenge(&data_dir, &id, &reader).await {
            Ok(record) => record,
            Err(message) => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "challenge_unreadable",
                    message,
                )
            }
        }
    } else {
        record
    };
    if let Some(marker) = in_flight(&record) {
        return in_progress_reply(&id, &record, marker);
    }
    match state_of(&record) {
        "pending" => {}
        "approved" if grant_expired_unused(&record, now_ms()) => {
            // Never decided twice: the authority already holds this request hash's decision.
            let expired_at = record
                .get("grant_expires_at_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let successor = superseded_by(&record);
            return reply(
                StatusCode::GONE,
                json!({
                    "ok": false,
                    "error": {
                        "code": "challenge_grant_expired",
                        "message": format!(
                            "this challenge was approved, but its one-use grant expired unused at {}. The deployment authority keeps one decision per request, so it is never decided again; the action must be asked again — the requester's retry parks a new challenge{}. Nothing was started.",
                            iso_of_ms(expired_at),
                            successor.map(|next| format!(" (it was asked again as challenge {next})")).unwrap_or_default()
                        ),
                    },
                    "challenge_id": id,
                    "state": state_of(&record),
                    "superseded_by": successor,
                    "runtimeTruthSource": "daemon-runtime",
                }),
            );
        }
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
        let Ok(Some(mut current)) = read_challenge(&data_dir, &id) else {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_changed",
                "the challenge changed while deciding",
            );
        };
        if let Some(marker) = in_flight(&current) {
            return in_progress_reply(&id, &current, marker);
        }
        if state_of(&current) != "pending" {
            return refuse(
                StatusCode::CONFLICT,
                "challenge_changed",
                "the challenge changed while deciding",
            );
        }
        // Denying an interrupted approval is always open: whatever the authority recorded, the
        // daemon never presents it.
        let unknown = current
            .as_object_mut()
            .and_then(|object| object.remove("outcome_unknown"));
        current["state"] = json!("denied");
        current["decision"] = json!({
            "decision": "deny",
            "decided_by": decided_by,
            "decided_at": iso_now(),
            "reason": decision.reason,
        });
        if let Some(unknown) = unknown {
            current["decision"]["outcome_unknown_at_denial"] = unknown;
        }
        if let Err(message) = write_challenge(&data_dir, &id, &current) {
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
    if let Some(unknown) = outcome_unknown(&record) {
        let reason = unknown.get("reason").and_then(Value::as_str).unwrap_or("");
        let detail = unknown.get("message").and_then(Value::as_str).unwrap_or("");
        return reply(
            StatusCode::CONFLICT,
            json!({
                "ok": false,
                "error": {
                    "code": "challenge_outcome_unknown",
                    "message": format!("an earlier approval of this challenge was interrupted and its outcome is not known ({reason}: {detail}). The daemon re-reads the authority's record before any new approve and runs nothing on a guess; nothing was started. Deny stays available."),
                },
                "challenge_id": id,
                "outcome_unknown": unknown,
                "runtimeTruthSource": "daemon-runtime",
            }),
        );
    }
    if decision.operator_passphrase.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "operator_passphrase_required",
            "approving needs the operator passphrase: it opens the sealed approver key for this one grant",
        );
    }
    let Some(approver) = approver else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "authority_decider_not_configured",
            format!("this daemon has no deployment authority to decide with ({AUTHORITY_BINARY_ENV} and {AUTHORITY_STATE_DIR_ENV} must name the authority binary and its node's state directory)"),
        );
    };
    let coordinates = Coordinates::of(&record);
    if coordinates.audience.len() != 64
        || !coordinates.audience.chars().all(|c| c.is_ascii_hexdigit())
    {
        return refuse(
            StatusCode::CONFLICT,
            "challenge_audience_absent",
            "the parked challenge names no wallet capability audience; a grant without it could never be consumed",
        );
    }
    let attempt_id = match begin_deciding(&data_dir, &id, &decided_by, &decision.reason) {
        Ok(attempt_id) => attempt_id,
        Err(response) => return response,
    };
    let job = ApproveJob {
        data_dir,
        id: id.clone(),
        attempt_id,
        decided_by,
        coordinates,
        passphrase: decision.operator_passphrase,
        approver,
        reader,
    };
    // The approve runs on its OWN task: a client that goes away drops only this wait, never the
    // child, and the task settles the record either way.
    let task = tokio::spawn(run_approve_job(job));
    match tokio::time::timeout(Duration::from_millis(wait_ms), task).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "challenge_decision_task_failed",
            format!("the approve task ended without an answer ({error}); the challenge's outcome is reconciled from the authority's record"),
        ),
        Err(_) => reply(
            StatusCode::ACCEPTED,
            json!({
                "ok": false,
                "state": "pending",
                "deciding": true,
                "challenge_id": id,
                "approval_ref": approval_ref_for(&id),
                "error": {
                    "code": "challenge_decision_still_running",
                    "message": format!("the deployment authority is still approving after {wait_ms} ms; the decision continues in the daemon and settles the challenge on its own — re-read it for the outcome"),
                },
                "runtimeTruthSource": "daemon-runtime",
            }),
        ),
    }
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
                },
                // An approve being recorded now, or one a stopped daemon left whose outcome is
                // not known yet (approve is refused by name until it is reconciled).
                "deciding": in_flight(record).is_some(),
                "outcome_unknown": outcome_unknown(record)
                    .and_then(|unknown| unknown.get("reason").cloned())
                    .unwrap_or(Value::Null),
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

    // ---- R-240, decision route durability -----------------------------------------------------

    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
    use ioi_types::app::action::ApprovalGrant;
    use ioi_types::app::{account_id_from_key_material, SignatureSuite};

    const PASS: &str = "decision-durability-operator-pass";
    const OPERATOR: &str = "user://operator";

    /// A one-use grant for exactly these coordinates, signed by a test approver key.
    fn grant_for(policy: &str, request: &str) -> Value {
        let private = Ed25519PrivateKey::from_bytes(&[9u8; 32]).unwrap();
        let keypair = Ed25519KeyPair::from_private_key(&private).unwrap();
        let public_key = keypair.public_key().to_bytes();
        let mut grant = ApprovalGrant {
            schema_version: 1,
            authority_id: account_id_from_key_material(SignatureSuite::ED25519, &public_key)
                .unwrap(),
            request_hash: hash32(request).unwrap(),
            policy_hash: hash32(policy).unwrap(),
            audience: hash32(&"ab".repeat(32)).unwrap(),
            nonce: rand::random(),
            counter: 1,
            expires_at: now_ms() + 900_000,
            max_usages: Some(1),
            window_id: None,
            pii_action: None,
            scoped_exception: None,
            review_request_hash: None,
            approver_public_key: public_key,
            approver_sig: Vec::new(),
            approver_suite: SignatureSuite::ED25519,
        };
        grant.approver_sig = keypair
            .sign(&grant.signing_bytes().unwrap())
            .unwrap()
            .to_bytes()
            .to_vec();
        serde_json::to_value(&grant).unwrap()
    }

    /// A stand-in for the authority binary: a script that logs each invocation, refuses a wrong
    /// passphrase the way the binary does, takes a while, then prints the recording outcome.
    struct StubAuthority {
        dir: std::path::PathBuf,
    }

    impl StubAuthority {
        fn new(label: &str, grant: &Value, seconds: &str) -> Self {
            let dir = std::path::PathBuf::from(temp_data_dir(&format!("stub-{label}")));
            let outcome = json!({
                "ok": true,
                "recorded": "committed",
                "grant_ref": "wallet.network://grant/approval/stub",
                "expires_at_ms": grant["expires_at"],
                "approval_grant": grant,
            });
            std::fs::write(
                dir.join("outcome.json"),
                serde_json::to_string(&outcome).unwrap(),
            )
            .unwrap();
            let script = format!(
                "#!/bin/sh\necho \"$$ $*\" >> '{dir}/invocations'\nif [ \"$IOI_AUTHORITY_OPERATOR_PASS\" != '{PASS}' ]; then echo 'Error: the operator passphrase did not open the sealed approver key' >&2; exit 1; fi\nsleep {seconds}\ncat '{dir}/outcome.json'\n",
                dir = dir.display()
            );
            let path = dir.join("authority");
            std::fs::write(&path, script).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }

        fn approver(&self) -> Approver {
            Approver {
                binary: self.dir.join("authority").to_string_lossy().into_owned(),
                state_dir: self.dir.to_string_lossy().into_owned(),
                timeout_ms: 60_000,
            }
        }

        fn invocations(&self) -> usize {
            std::fs::read_to_string(self.dir.join("invocations"))
                .map(|text| text.lines().count())
                .unwrap_or(0)
        }

        /// The request hash each invocation asked the authority to decide, in order.
        fn decided_request_hashes(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("invocations"))
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let words: Vec<&str> = line.split_whitespace().collect();
                    words
                        .iter()
                        .position(|word| *word == "--request-hash")
                        .and_then(|at| words.get(at + 1))
                        .map(|hash| hash.to_string())
                })
                .collect()
        }
    }

    impl Drop for StubAuthority {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn body(decision: &str, passphrase: &str) -> DecisionBody {
        parse_decision_body(
            &serde_json::to_vec(&json!({
                "decision": decision,
                "reason": "decision durability",
                "operator_passphrase": passphrase,
            }))
            .unwrap(),
        )
        .ok()
        .unwrap()
    }

    fn reader(record: AuthorityRecord) -> AuthorityReader {
        AuthorityReader::Fixed(Arc::new(Mutex::new(record)))
    }

    fn record_of(dir: &str, id: &str) -> Value {
        read_challenge(dir, id).unwrap().unwrap()
    }

    /// Poll until no decision is in flight on the record.
    async fn settled(dir: &str, id: &str) -> Value {
        for _ in 0..300 {
            let record = record_of(dir, id);
            if in_flight(&record).is_none() {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the decision never settled: {}", record_of(dir, id));
    }

    fn park_id(dir: &str, policy: &str, request: &str) -> String {
        park(dir, policy, request)["challenge_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn a_decision_whose_client_goes_away_still_settles_the_record() {
        let dir = temp_data_dir("client-gone");
        let (policy, request) = (hash(21), hash(22));
        let id = park_id(&dir, &policy, &request);
        let stub = StubAuthority::new("client-gone", &grant_for(&policy, &request), "1.5");
        let decision = decide_challenge(
            dir.clone(),
            id.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        );
        // The client goes away mid-approve: the request future is dropped.
        assert!(
            tokio::time::timeout(Duration::from_millis(500), decision)
                .await
                .is_err(),
            "the approve was still running when the client left"
        );
        let mid = record_of(&dir, &id);
        assert_eq!(mid["state"], "pending", "nothing is decided mid-approve");
        let marker = in_flight(&mid).expect("the decision is marked in flight on the record");
        assert!(marker_is_ours(marker));
        assert_eq!(marker["decided_by"], OPERATOR);
        // The approve runs to completion on its own task and settles the record.
        let record = settled(&dir, &id).await;
        assert_eq!(record["state"], "approved", "{record}");
        assert!(record["grant"].is_object());
        assert!(record["grant_ref"]
            .as_str()
            .unwrap()
            .starts_with("wallet.network://grant/approval/"));
        assert_eq!(record["decision"]["decided_by"], OPERATOR);
        assert_eq!(record["decision"]["recorded_on_authority"], "committed");
        assert!(outcome_unknown(&record).is_none());
        assert!(!serde_json::to_string(&record).unwrap().contains(PASS));
        assert_eq!(stub.invocations(), 1, "exactly one approve ran");
        // The requester's retry claims the stored grant, as before.
        assert!(claim_approval_ref(&dir, &approval_ref_for(&id), SCOPE, &policy, &request).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_second_decision_while_one_is_in_flight_is_refused_and_starts_no_child() {
        let dir = temp_data_dir("in-flight");
        let (policy, request) = (hash(23), hash(24));
        let id = park_id(&dir, &policy, &request);
        let stub = StubAuthority::new("in-flight", &grant_for(&policy, &request), "1.5");
        // A refused passphrase first: the authority records nothing and the record is exactly
        // what it was.
        let before = record_of(&dir, &id);
        let wrong = decide_challenge(
            dir.clone(),
            id.clone(),
            OPERATOR.into(),
            body("approve", "not-the-operator-passphrase"),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(wrong.0, StatusCode::FORBIDDEN);
        assert_eq!(wrong.1 .0["error"]["code"], "operator_passphrase_refused");
        assert_eq!(record_of(&dir, &id), before, "the record is untouched");
        assert_eq!(stub.invocations(), 1);

        let first = tokio::spawn(decide_challenge(
            dir.clone(),
            id.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        ));
        for _ in 0..200 {
            if in_flight(&record_of(&dir, &id)).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(in_flight(&record_of(&dir, &id)).is_some());
        let second = decide_challenge(
            dir.clone(),
            id.clone(),
            "user://another-operator".into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(second.0, StatusCode::CONFLICT);
        assert_eq!(
            second.1 .0["error"]["code"], "challenge_decision_in_progress",
            "{}",
            second.1 .0
        );
        assert_eq!(second.1 .0["deciding"]["decided_by"], OPERATOR);
        let deny = decide_challenge(
            dir.clone(),
            id.clone(),
            OPERATOR.into(),
            body("deny", ""),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(deny.0, StatusCode::CONFLICT);
        assert_eq!(deny.1 .0["error"]["code"], "challenge_decision_in_progress");
        assert_eq!(
            claim_approval_ref(&dir, &approval_ref_for(&id), SCOPE, &policy, &request)
                .err()
                .map(|refusal| refusal.code),
            Some("approval_ref_deciding")
        );
        let done = first.await.unwrap();
        assert_eq!(done.0, StatusCode::OK, "{}", done.1 .0);
        assert_eq!(done.1 .0["state"], "approved");
        assert_eq!(
            stub.invocations(),
            2,
            "the refused attempt and ONE approve: the refused decisions started no child"
        );
        let again = decide_challenge(
            dir.clone(),
            id.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(again.1 .0["error"]["code"], "challenge_already_approved");
        assert_eq!(stub.invocations(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_slow_approve_answers_202_and_settles_on_its_own() {
        let dir = temp_data_dir("slow");
        let (policy, request) = (hash(25), hash(26));
        let id = park_id(&dir, &policy, &request);
        let stub = StubAuthority::new("slow", &grant_for(&policy, &request), "1");
        let answered = decide_challenge(
            dir.clone(),
            id.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            200,
        )
        .await;
        assert_eq!(answered.0, StatusCode::ACCEPTED);
        assert_eq!(
            answered.1 .0["error"]["code"],
            "challenge_decision_still_running"
        );
        assert_eq!(answered.1 .0["challenge_id"], json!(id));
        let record = settled(&dir, &id).await;
        assert_eq!(record["state"], "approved", "{record}");
        assert_eq!(stub.invocations(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a daemon that stopped mid-approve leaves: a marker naming a process that is gone.
    fn leave_in_flight(dir: &str, id: &str, child_pid: Option<u32>) {
        let mut record = record_of(dir, id);
        record["deciding"] = json!({
            "attempt_id": "dec_previous",
            "process": "dp_previous_daemon",
            "decided_by": OPERATOR,
            "reason": "before the restart",
            "started_at": iso_now(),
            "started_at_ms": now_ms(),
            "child_pid": child_pid,
        });
        write_challenge(dir, id, &record).unwrap();
    }

    #[tokio::test]
    async fn a_decision_left_in_flight_by_a_stopped_daemon_is_reconciled_from_the_authority_never_rerun(
    ) {
        let dir = temp_data_dir("restart");

        // (a) The authority recorded the grant before the daemon stopped: it is adopted.
        let (pa, ra) = (hash(31), hash(32));
        let a = park_id(&dir, &pa, &ra);
        leave_in_flight(&dir, &a, None);
        let recorded = grant_for(&pa, &ra);
        let found = reader(AuthorityRecord::Found {
            grant: recorded.clone(),
            target_label: SCOPE.into(),
            approved_by_human: true,
        });
        assert_eq!(reconcile_pass(&dir, &found).await, 0);
        let record = record_of(&dir, &a);
        assert_eq!(record["state"], "approved", "{record}");
        assert_eq!(record["grant"], recorded);
        assert_eq!(record["decision"]["reconciled_from"], "authority_record");
        assert_eq!(record["decision"]["decided_by"], OPERATOR);
        assert!(in_flight(&record).is_none() && outcome_unknown(&record).is_none());

        // (b) Nothing recorded and the old child is gone: pending again with the interruption in
        // its history, and the operator's fresh decision runs.
        let (pb, rb) = (hash(33), hash(34));
        let b = park_id(&dir, &pb, &rb);
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let gone_pid = gone.id();
        gone.wait().unwrap();
        leave_in_flight(&dir, &b, Some(gone_pid));
        assert_eq!(
            reconcile_pass(&dir, &reader(AuthorityRecord::Absent)).await,
            0
        );
        let record = record_of(&dir, &b);
        assert_eq!(record["state"], "pending");
        assert!(in_flight(&record).is_none() && outcome_unknown(&record).is_none());
        let last = record["history"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(last["state"], "interrupted");
        assert_eq!(last["reconciliation"]["authority_record"], "absent");
        let stub_b = StubAuthority::new("restart-b", &grant_for(&pb, &rb), "0.1");
        let fresh = decide_challenge(
            dir.clone(),
            b.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub_b.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(fresh.0, StatusCode::OK, "{}", fresh.1 .0);
        assert_eq!(stub_b.invocations(), 1);

        // (c) The authority unreadable: the outcome is unknown by name, approve is refused and
        // starts nothing, and once the authority reads back the grant it is adopted, not re-run.
        let (pc, rc) = (hash(35), hash(36));
        let c = park_id(&dir, &pc, &rc);
        leave_in_flight(&dir, &c, None);
        let unreadable = reader(AuthorityRecord::Unreadable("authority offline".into()));
        assert_eq!(
            reconcile_pass(&dir, &unreadable).await,
            1,
            "a later read can settle it"
        );
        let record = record_of(&dir, &c);
        assert_eq!(record["state"], "pending");
        assert_eq!(
            record["outcome_unknown"]["reason"],
            "authority_record_unreadable"
        );
        assert_eq!(
            record["outcome_unknown"]["attempt"]["attempt_id"],
            "dec_previous"
        );
        let stub_c = StubAuthority::new("restart-c", &grant_for(&pc, &rc), "0.1");
        let refused = decide_challenge(
            dir.clone(),
            c.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub_c.approver()),
            unreadable.clone(),
            60_000,
        )
        .await;
        assert_eq!(refused.0, StatusCode::CONFLICT);
        assert_eq!(refused.1 .0["error"]["code"], "challenge_outcome_unknown");
        assert_eq!(
            stub_c.invocations(),
            0,
            "an unknown outcome is never re-run"
        );
        assert_eq!(
            claim_approval_ref(&dir, &approval_ref_for(&c), SCOPE, &pc, &rc)
                .err()
                .map(|refusal| refusal.code),
            Some("approval_ref_outcome_unknown")
        );
        let late = grant_for(&pc, &rc);
        let readable = reader(AuthorityRecord::Found {
            grant: late.clone(),
            target_label: SCOPE.into(),
            approved_by_human: true,
        });
        let adopted = decide_challenge(
            dir.clone(),
            c.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub_c.approver()),
            readable,
            60_000,
        )
        .await;
        assert_eq!(adopted.1 .0["error"]["code"], "challenge_already_approved");
        assert_eq!(stub_c.invocations(), 0);
        let record = record_of(&dir, &c);
        assert_eq!(record["state"], "approved");
        assert_eq!(record["grant"], late);
        assert!(outcome_unknown(&record).is_none());

        // (d) The old approve still running with nothing recorded yet: unknown, re-read and never
        // re-run; deny stays open.
        let (pd, rd) = (hash(37), hash(38));
        let d = park_id(&dir, &pd, &rd);
        let mut running = std::process::Command::new("sh")
            .args(["-c", "sleep 30; true", "approve", rd.as_str()])
            .spawn()
            .unwrap();
        leave_in_flight(&dir, &d, Some(running.id()));
        assert_eq!(
            reconcile_pass(&dir, &reader(AuthorityRecord::Absent)).await,
            1
        );
        assert_eq!(
            record_of(&dir, &d)["outcome_unknown"]["reason"],
            "authority_approve_still_running"
        );
        let denied = decide_challenge(
            dir.clone(),
            d.clone(),
            OPERATOR.into(),
            body("deny", ""),
            None,
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(denied.0, StatusCode::OK, "{}", denied.1 .0);
        let record = record_of(&dir, &d);
        assert_eq!(record["state"], "denied");
        assert_eq!(
            record["decision"]["outcome_unknown_at_denial"]["reason"],
            "authority_approve_still_running"
        );
        let _ = running.kill();
        let _ = running.wait();

        // (e) A foreign grant recorded for the request hash is never adopted.
        let (pe, re) = (hash(39), hash(40));
        let e = park_id(&dir, &pe, &re);
        leave_in_flight(&dir, &e, None);
        let foreign = reader(AuthorityRecord::Found {
            grant: grant_for(&pe, &hash(41)),
            target_label: SCOPE.into(),
            approved_by_human: true,
        });
        assert_eq!(
            reconcile_pass(&dir, &foreign).await,
            0,
            "not retried: it cannot change"
        );
        let record = record_of(&dir, &e);
        assert_eq!(record["state"], "pending");
        assert_eq!(
            record["outcome_unknown"]["reason"],
            "authority_record_mismatch"
        );
        assert_eq!(record["grant"], Value::Null);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- R-240, challenge states + re-ask ----------------------------------------------------

    /// What time does to an approval nobody ran: its one-use grant's expiry passes.
    fn let_grant_expire(dir: &str, id: &str) {
        let mut record = record_of(dir, id);
        record["grant_expires_at_ms"] = json!(now_ms().saturating_sub(1));
        write_challenge(dir, id, &record).unwrap();
    }

    #[tokio::test]
    async fn an_approval_that_expired_unused_is_asked_again_as_a_new_challenge_never_decided_twice()
    {
        let dir = temp_data_dir("reask");
        let (policy, request) = (hash(51), hash(52));
        let old = park_id(&dir, &policy, &request);
        // The operator approves; the authority records ONE decision for this request hash.
        let stub = StubAuthority::new("reask-old", &grant_for(&policy, &request), "0.1");
        let approved = decide_challenge(
            dir.clone(),
            old.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(approved.0, StatusCode::OK, "{}", approved.1 .0);
        // Nobody retries in time: the grant expires unused.
        let_grant_expire(&dir, &old);

        // The stale approval_ref is refused, and its words are true: never "approve again".
        let stale = claim_approval_ref(&dir, &approval_ref_for(&old), SCOPE, &policy, &request)
            .err()
            .expect("an expired grant is never presented");
        assert_eq!(stale.code, "approval_ref_expired");
        assert_eq!(stale.status, StatusCode::GONE);
        assert!(!stale.message.contains("approve again"), "{}", stale.message);
        assert!(
            stale.message.contains("cannot be approved again")
                && stale.message.contains("asked again"),
            "{}",
            stale.message
        );

        // The requester's retry of the same effect parks a SUCCESSOR: a fresh nonce, so a new
        // request hash and a new challenge id, pending for the operator.
        let parked = park(&dir, &policy, &request);
        let new = parked["challenge_id"].as_str().unwrap().to_string();
        assert_ne!(new, old, "the old challenge is never reopened");
        assert_eq!(parked["challenge_state"], "pending");
        assert_eq!(parked["supersedes"], json!(old));
        let successor = record_of(&dir, &new);
        let nonce = successor["ask_nonce"].as_str().unwrap().to_string();
        let new_request = successor["request_hash"].as_str().unwrap().to_string();
        assert_ne!(new_request, request, "a new request hash");
        assert_eq!(new_request, reask_request_hash(&request, &nonce));
        assert_eq!(successor["base_request_hash"], json!(request));
        assert_eq!(successor["policy_hash"], json!(policy), "the same exact effect");
        assert_eq!(successor["supersedes"], json!(old));
        assert_eq!(
            successor["published_preimage"]["reask_preimage"],
            reask_preimage(&request, &nonce),
            "the bytes the new request hash commits to are published"
        );
        assert_eq!(
            new,
            challenge_id_for(SCOPE, &policy, &new_request, Some(&"ab".repeat(32)))
        );
        // The old challenge keeps its approval, reads expired, and names its successor.
        let predecessor = record_of(&dir, &old);
        assert_eq!(predecessor["state"], "approved");
        assert!(grant_expired_unused(&predecessor, now_ms()));
        assert_eq!(predecessor["superseded_by"], json!(new));
        assert_eq!(predecessor["request_hash"], json!(request), "untouched");
        // A re-park is the same successor (idempotent), and the stale ref now names it.
        assert_eq!(park(&dir, &policy, &request)["challenge_id"], json!(new));
        let replay = claim_approval_ref(&dir, &approval_ref_for(&old), SCOPE, &policy, &request)
            .err()
            .expect("a replay of the old approval_ref is refused");
        assert_eq!(replay.code, "approval_ref_expired");
        assert!(replay.message.contains(&new), "{}", replay.message);

        // The authority is never asked to decide the old request hash again.
        let again = decide_challenge(
            dir.clone(),
            old.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(again.0, StatusCode::GONE, "{}", again.1 .0);
        assert_eq!(again.1 .0["error"]["code"], "challenge_grant_expired");
        assert_eq!(again.1 .0["superseded_by"], json!(new));
        assert_eq!(stub.invocations(), 1, "no second approve of the old request hash");

        // The operator approves the successor: the authority decides the NEW request hash.
        let stub_new = StubAuthority::new("reask-new", &grant_for(&policy, &new_request), "0.1");
        let fresh = decide_challenge(
            dir.clone(),
            new.clone(),
            OPERATOR.into(),
            body("approve", PASS),
            Some(stub_new.approver()),
            reader(AuthorityRecord::Absent),
            60_000,
        )
        .await;
        assert_eq!(fresh.0, StatusCode::OK, "{}", fresh.1 .0);
        let asked: Vec<String> = stub
            .decided_request_hashes()
            .into_iter()
            .chain(stub_new.decided_request_hashes())
            .collect();
        assert_eq!(
            asked,
            vec![request.clone(), new_request.clone()],
            "each request hash decided exactly once"
        );

        // The retry claims the successor with the hash the gate derives afresh, and presents the
        // re-ask's request hash; a foreign effect cannot borrow the nonce.
        let foreign = claim_approval_ref(&dir, &approval_ref_for(&new), SCOPE, &policy, &hash(53));
        assert_eq!(
            foreign.err().map(|refusal| refusal.code),
            Some("approval_ref_coordinates_mismatch")
        );
        let claim = claim_approval_ref(&dir, &approval_ref_for(&new), SCOPE, &policy, &request)
            .ok()
            .expect("the successor's approval is claimed by the same effect");
        assert_eq!(claim.request_hash, new_request);
        mark_consumed(&dir, &claim, "authority-admission-intents/reask");
        // Ran once: a re-park of the effect reads consumed, and both refs are refused.
        assert_eq!(park(&dir, &policy, &request)["challenge_state"], "consumed");
        assert_eq!(
            claim_approval_ref(&dir, &approval_ref_for(&new), SCOPE, &policy, &request)
                .err()
                .map(|refusal| refusal.code),
            Some("approval_ref_consumed")
        );
        assert_eq!(
            claim_approval_ref(&dir, &approval_ref_for(&old), SCOPE, &policy, &request)
                .err()
                .map(|refusal| refusal.code),
            Some("approval_ref_expired")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reask_chain_follows_to_the_latest_ask_and_a_lost_successor_is_asked_again() {
        let dir = temp_data_dir("reask-chain");
        let (policy, request) = (hash(54), hash(55));
        let first = park_id(&dir, &policy, &request);
        approve_in_place(&dir, &first);
        let_grant_expire(&dir, &first);
        let second = park_id(&dir, &policy, &request);
        assert_ne!(second, first);
        // The second ask is approved and also expires unused: the third follows the chain.
        approve_in_place(&dir, &second);
        let_grant_expire(&dir, &second);
        let third = park_id(&dir, &policy, &request);
        assert!(third != first && third != second, "{first} {second} {third}");
        assert_eq!(record_of(&dir, &second)["superseded_by"], json!(third));
        assert_eq!(record_of(&dir, &third)["supersedes"], json!(second));
        assert_eq!(
            record_of(&dir, &third)["base_request_hash"],
            json!(request),
            "every re-ask is of the effect's own request hash"
        );
        assert_eq!(park_id(&dir, &policy, &request), third);
        // A denied successor reopens under ITS request hash (the authority recorded nothing).
        let mut record = record_of(&dir, &third);
        record["state"] = json!("denied");
        write_challenge(&dir, &third, &record).unwrap();
        assert_eq!(park_id(&dir, &policy, &request), third);
        assert_eq!(record_of(&dir, &third)["state"], "pending");
        // A successor whose record is gone is asked again from the ask before it.
        std::fs::remove_file(
            std::path::Path::new(&dir)
                .join(CHALLENGE_FAMILY)
                .join(format!("{third}.json")),
        )
        .unwrap();
        assert!(read_challenge(&dir, &third).unwrap().is_none());
        let fourth = park_id(&dir, &policy, &request);
        assert!(fourth != third && fourth != second, "{fourth}");
        assert_eq!(record_of(&dir, &second)["superseded_by"], json!(fourth));
        assert_eq!(record_of(&dir, &fourth)["state"], "pending");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
