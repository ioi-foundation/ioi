//! Master guide G5 follow-on — the STANDING envelope is decided through the daemon, and the UI
//! server holds no signing key (§0.5.2, N9).
//!
//! A standing envelope (M13.3, `schema://ioi/components/hypervisor/session-standing-envelope/v1`)
//! lets the sessions that name one connection draw silently within usages, budget and expiry. It is
//! bound by a StandingApprovalGrant the deployment's approver signs. Until commit f3b869df2 the
//! served App minted that grant with a local approver seed; since the approver and control-root
//! keys are SEALED under the operator passphrase, the App cannot sign it, and "Set limits" refused
//! in deployment mode. This module is the daemon's standing decision, built on the exact-effect
//! relay's pattern (`authority_challenge_routes`):
//!
//! 1. **`POST /v1/hypervisor/authority/standing-envelopes`** takes ONLY the envelope's bounds —
//!    the connection it binds, the operations and tools it covers, usages, budget, expiry — and the
//!    operator passphrase, from an authenticated administrator. Every coordinate a signature
//!    covers is the daemon's own: a body naming an envelope, grant, hash, audience, principal, nonce
//!    or window is refused before anything runs. The daemon reads the authority node's committed
//!    chain clock (ADR 0052 §7: a deployment that mints standing envelopes runs its authority on
//!    the wall clock, and one that does not is refused typed), derives the registered envelope, the
//!    review and policy-decision commitments, the single-use approval ceremony context and the v2
//!    `deployment_local_operator` factor receipt (custody evidence: the host, the hash of the sealed
//!    key's path, its 0600 mode), and runs the sealed authority's `record-standing-approval` in MINT
//!    mode with the passphrase in THAT CHILD's environment only. The authority opens the approver
//!    key, signs the one grant those coordinates determine, and the control root records it. The
//!    daemon checks the returned grant against its own derivation, binds it to the connection's
//!    `standing_lease` (the unchanged M13.3 validator) and keeps the envelope's public record here.
//!    A refused passphrase records nothing. The passphrase is never logged, persisted or echoed, and
//!    the daemon's copy is zeroized once the child exits.
//! 2. **`POST /v1/hypervisor/authority/standing-envelopes/:id/revoke`** takes a reason and the
//!    passphrase: the authority's `revoke-standing-approval` revokes the grant on chain, then the
//!    connection's lease and this record are fenced, so the next draw refuses before any wallet
//!    call. A refused passphrase revokes nothing (the passphrase-free local fence stays the
//!    `DELETE /v1/hypervisor/connectors/:id/standing-lease` route, which this record follows).
//! 3. **Drawdown.** Each admitted draw against a daemon-issued envelope is counted here (uses,
//!    spend, deposit), and a draw the count says is outside the bounds is refused before the wallet
//!    is asked. The wallet's own ledger stays the authority; this is the daemon's pre-check and the
//!    public "remaining" projection, never a second allowance.
//!
//! No second authority plane: resolution, grant verification and on-chain consumption are the
//! existing `governed_authority` path, the lease on the connector is the one the execute gate and
//! the connector gateway already draw from, and minting happens only inside the authority binary.

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

pub(crate) const STANDING_ENVELOPE_FAMILY: &str = "standing-envelopes";
const RECORD_SCHEMA: &str = "ioi.hypervisor.standing-envelope-record.v1";
const ENVELOPE_SCHEMA: &str = "ioi.hypervisor.session-standing-envelope.v1";
const ENVELOPE_BODY_DOMAIN: &str = "ioi.session-standing-envelope-jcs-sha256.v1";
const APPROVAL_CONTEXT_CONTRACT: &str = "schema://ioi/foundations/approval-ceremony-context/v1";
const AUTH_FACTOR_RECEIPT_CONTRACT_V2: &str =
    "schema://ioi/components/hypervisor/auth-factor-receipt/v2";
const APPROVAL_CONTEXT_DOMAIN: &[u8] = b"IOI-APPROVAL-CEREMONY-CONTEXT-V1\0";
/// The one variable the authority binary reads the operator passphrase from.
const OPERATOR_PASS_ENV: &str = "IOI_AUTHORITY_OPERATOR_PASS";
const DEFAULT_AUTHORITY_TIMEOUT_MS: u64 = 1_200_000;
/// ADR 0052 §7: the envelope's expiry is a real-time promise the daemon checks against the host
/// clock. An authority whose committed chain clock is further than this from the host clock is not
/// on the wall clock, and cannot record one.
const WALL_CLOCK_TOLERANCE_MS: u64 = 5 * 60 * 1_000;
/// The wallet refuses a ceremony whose window exceeds five minutes.
const CEREMONY_WINDOW_MS: u64 = 5 * 60 * 1_000;
const MAX_USAGES: u64 = 1_000_000;
const MAX_EXPIRES_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
const DEFAULT_EXPIRES_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REASON_MAX_CHARS: usize = 400;
const DRAW_REFS_KEPT: usize = 64;
const SESSION_EXECUTE: &str = "session_execute";
const CONNECTOR_INVOKE: &str = "connector_invoke";

const CREATE_FIELDS: &[&str] = &[
    "connector_id",
    "operations",
    "tools",
    "max_usages",
    "budget_usd",
    "budget_microusd",
    "per_operation_usd",
    "per_operation_microusd",
    "expires_hours",
    "expires_in_secs",
    "reason",
    "operator_passphrase",
];
const REVOKE_FIELDS: &[&str] = &["reason", "operator_passphrase"];
/// Everything a signature or a record covers is the daemon's own; naming any of it is refused.
const DAEMON_OWNED_FIELDS: &[&str] = &[
    "envelope",
    "standing_envelope",
    "standing_authority_envelope",
    "grant",
    "standing_approval_grant",
    "wallet_approval_grant",
    "standing_envelope_ref",
    "standing_envelope_id",
    "standing_envelope_hash",
    "envelope_hash",
    "body_hash",
    "policy_hash",
    "trajectory_policy_hash",
    "trajectory_policy_ref",
    "audience",
    "audience_ref",
    "principal_ref",
    "owner_ref",
    "bounded_system_ref",
    "facet_template",
    "aggregate_bounds",
    "nonce",
    "counter",
    "issued_at_ms",
    "not_before_ms",
    "expires_at_ms",
    "revocation_epoch",
    "review_receipt_hash",
    "approval_ceremony_context",
    "approval_ceremony_context_hash",
    "context",
    "auth_factor_receipt",
    "auth_factor_receipt_hash",
    "factor",
    "grant_hash",
    "standing_grant_hash",
    "authority_id",
    "approver_public_key",
    "approver_sig",
];

/// Serializes every read-modify-write of an envelope record (drawdown, fence, revoke). Never held
/// across an authority child.
static RECORD_LOCK: Mutex<()> = Mutex::new(());
/// Connections whose standing decision (or envelope revocation) is running in this process.
static DECIDING: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn lock_records() -> std::sync::MutexGuard<'static, ()> {
    RECORD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Removes a key from the in-process `deciding` set on every exit path.
struct DecidingGuard(String);

impl DecidingGuard {
    fn enter(key: &str) -> Option<Self> {
        let mut deciding = DECIDING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deciding
            .insert(key.to_string())
            .then(|| Self(key.to_string()))
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

type Reply = (StatusCode, Json<Value>);

fn reply(status: StatusCode, body: Value) -> Reply {
    (status, Json(body))
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    reply(
        status,
        json!({
            "ok": false,
            "error": { "code": code, "message": message.into() },
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn sha256_ref(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha256_bytes(bytes)))
}

fn jcs(value: &Value) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| format!("not canonical JSON: {error}"))
}

fn hash_of(value: &Value) -> Result<String, String> {
    Ok(sha256_ref(&jcs(value)?))
}

fn ref_bytes(text: &str) -> Option<[u8; 32]> {
    let decoded = hex::decode(text.strip_prefix("sha256:")?).ok()?;
    <[u8; 32]>::try_from(decoded).ok()
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`: the one timestamp form this module writes (and the authority
/// binary parses back).
pub(crate) fn rfc3339_ms(ms: u64) -> String {
    let at = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.millisecond()
    )
}

// ---- the request: bounds only ------------------------------------------------------------------

/// What a caller may decide about an envelope. Nothing here is signed as given: the daemon derives
/// every coordinate from it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StandingBounds {
    pub(crate) connector_id: String,
    pub(crate) operations: Vec<String>,
    pub(crate) tools: Option<Vec<String>>,
    pub(crate) max_usages: u32,
    pub(crate) budget_microusd: u64,
    pub(crate) per_operation_microusd: u64,
    pub(crate) expires_in_ms: u64,
    pub(crate) reason: String,
}

struct CreateBody {
    bounds: StandingBounds,
    operator_passphrase: Zeroizing<String>,
}

struct RevokeBody {
    reason: String,
    operator_passphrase: Zeroizing<String>,
}

/// A JSON number, or a numeric string (an HTML form sends every field as a string).
fn number_of(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) if !text.trim().is_empty() => text.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|number| number.is_finite())
}

fn list_of(value: Option<&Value>) -> Option<Vec<String>> {
    let items: Vec<String> = match value? {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
        Value::String(text) => text
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    (!items.is_empty()).then_some(items)
}

fn clean_reason(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(REASON_MAX_CHARS)
        .collect()
}

/// Parse the body: the passphrase is taken out FIRST (so no refusal below leaves it in a live
/// Value), daemon-owned coordinates are refused by name, unknown members are refused, and the
/// bounds are checked.
fn take_passphrase(
    object: &mut serde_json::Map<String, Value>,
) -> Result<Zeroizing<String>, Reply> {
    match object.remove("operator_passphrase") {
        Some(Value::String(text)) => Ok(Zeroizing::new(text)),
        Some(Value::Null) | None => Ok(Zeroizing::new(String::new())),
        Some(_) => Err(refuse(
            StatusCode::BAD_REQUEST,
            "operator_passphrase_invalid",
            "operator_passphrase must be a string",
        )),
    }
}

fn refuse_foreign_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), Reply> {
    if let Some(field) = object
        .keys()
        .find(|field| DAEMON_OWNED_FIELDS.contains(&field.as_str()))
    {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "standing_envelope_coordinates_are_daemon_owned",
            format!(
                "a standing envelope request may not name `{field}`: the daemon derives every coordinate the grant commits to; nothing was signed or recorded"
            ),
        ));
    }
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "standing_envelope_body_field_refused",
            format!(
                "this request carries only {} (got `{field}`)",
                allowed.join(", ")
            ),
        ));
    }
    Ok(())
}

fn parse_object(raw: &[u8]) -> Result<serde_json::Map<String, Value>, Reply> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| {
        refuse(
            StatusCode::BAD_REQUEST,
            "standing_envelope_body_invalid",
            "the body must be one JSON object",
        )
    })?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(refuse(
            StatusCode::BAD_REQUEST,
            "standing_envelope_body_invalid",
            "the body must be one JSON object",
        )),
    }
}

fn bounds_refusal(message: impl Into<String>) -> Reply {
    refuse(
        StatusCode::BAD_REQUEST,
        "standing_envelope_bounds_invalid",
        message,
    )
}

/// The bounds a caller asked for, checked (the same arithmetic the attach form always used: a
/// metered unit per operation, an aggregate budget, a usage count and a window).
pub(crate) fn parse_bounds(
    object: &serde_json::Map<String, Value>,
) -> Result<StandingBounds, Reply> {
    let connector_id = object
        .get("connector_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty() && id.len() <= 128)
        .ok_or_else(|| bounds_refusal("connector_id names the connection the envelope binds"))?
        .to_string();
    let max_usages = number_of(object.get("max_usages"))
        .filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n <= MAX_USAGES as f64)
        .ok_or_else(|| bounds_refusal("max_usages must be an integer between 1 and 1000000"))?
        as u32;
    let micro = |usd_key: &str, micro_key: &str| -> Result<u64, Reply> {
        if let Some(value) = object.get(micro_key).filter(|v| !v.is_null()) {
            return number_of(Some(value))
                .filter(|n| n.fract() == 0.0 && *n >= 0.0 && *n <= MAX_SAFE_INTEGER as f64)
                .map(|n| n as u64)
                .ok_or_else(|| {
                    bounds_refusal(format!("{micro_key} must be a non-negative integer"))
                });
        }
        match object.get(usd_key) {
            None | Some(Value::Null) => Ok(0),
            Some(Value::String(text)) if text.trim().is_empty() => Ok(0),
            Some(value) => number_of(Some(value))
                .filter(|n| *n >= 0.0 && *n * 1_000_000.0 <= MAX_SAFE_INTEGER as f64)
                .map(|n| (n * 1_000_000.0).round() as u64)
                .ok_or_else(|| bounds_refusal(format!("{usd_key} must be a non-negative amount"))),
        }
    };
    let budget = micro("budget_usd", "budget_microusd")?;
    let per_operation = micro("per_operation_usd", "per_operation_microusd")?;
    let per_operation_microusd = if per_operation > 0 {
        per_operation
    } else if budget > 0 {
        ((budget as f64) / f64::from(max_usages)).round().max(1.0) as u64
    } else {
        1_000
    }
    .max(1);
    let budget_microusd = if budget > 0 {
        budget
    } else {
        per_operation_microusd.saturating_mul(u64::from(max_usages))
    };
    if budget_microusd > MAX_SAFE_INTEGER {
        return Err(bounds_refusal(
            "the budget exceeds the largest amount a record carries",
        ));
    }
    if per_operation_microusd > budget_microusd {
        return Err(bounds_refusal(
            "the metered unit per operation exceeds the whole budget",
        ));
    }
    let expires_in_ms = if let Some(value) = object.get("expires_in_secs").filter(|v| !v.is_null())
    {
        number_of(Some(value))
            .filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n * 1_000.0 <= MAX_EXPIRES_MS as f64)
            .map(|n| (n * 1_000.0) as u64)
            .ok_or_else(|| {
                bounds_refusal("expires_in_secs must be an integer between 1 and 7776000")
            })?
    } else {
        match number_of(object.get("expires_hours")) {
            None => DEFAULT_EXPIRES_MS,
            Some(hours) if hours > 0.0 && hours * 3_600_000.0 <= MAX_EXPIRES_MS as f64 => {
                (hours * 3_600_000.0).round() as u64
            }
            Some(_) => return Err(bounds_refusal("expires_hours must be between 0 and 2160")),
        }
    };
    let operations = list_of(object.get("operations"))
        .unwrap_or_else(|| vec![SESSION_EXECUTE.to_string(), CONNECTOR_INVOKE.to_string()]);
    let unique: BTreeSet<&str> = operations.iter().map(String::as_str).collect();
    if unique.len() != operations.len()
        || operations.len() > 2
        || operations
            .iter()
            .any(|op| op != SESSION_EXECUTE && op != CONNECTOR_INVOKE)
    {
        return Err(bounds_refusal(
            "operations is a set drawn from session_execute and connector_invoke",
        ));
    }
    let tools = list_of(object.get("tools"));
    if tools.as_ref().is_some_and(|tools| {
        tools.len() > 64
            || tools.iter().any(|tool| tool.len() > 128)
            || tools.iter().collect::<BTreeSet<_>>().len() != tools.len()
    }) {
        return Err(bounds_refusal("tools is a set of at most 64 names"));
    }
    Ok(StandingBounds {
        connector_id,
        operations,
        tools,
        max_usages,
        budget_microusd,
        per_operation_microusd,
        expires_in_ms,
        reason: clean_reason(object.get("reason")),
    })
}

fn parse_create_body(raw: &[u8]) -> Result<CreateBody, Reply> {
    let mut object = parse_object(raw)?;
    let operator_passphrase = take_passphrase(&mut object)?;
    refuse_foreign_fields(&object, CREATE_FIELDS)?;
    let bounds = parse_bounds(&object)?;
    Ok(CreateBody {
        bounds,
        operator_passphrase,
    })
}

fn parse_revoke_body(raw: &[u8]) -> Result<RevokeBody, Reply> {
    let mut object = if raw.iter().all(u8::is_ascii_whitespace) {
        serde_json::Map::new()
    } else {
        parse_object(raw)?
    };
    let operator_passphrase = take_passphrase(&mut object)?;
    refuse_foreign_fields(&object, REVOKE_FIELDS)?;
    Ok(RevokeBody {
        reason: clean_reason(object.get("reason")),
        operator_passphrase,
    })
}

// ---- identity -----------------------------------------------------------------------------------

/// An authenticated deployment administrator, never an impersonated session. Returns
/// `(principal_ref, principal_id)`.
fn require_operator(data_dir: &str, headers: &HeaderMap) -> Result<(String, String), Reply> {
    let Some(principal) = super::lifecycle_routes::resolve_principal(data_dir, headers) else {
        return Err(reply(
            StatusCode::UNAUTHORIZED,
            json!({
                "ok": false,
                "code": "hypervisor.authentication_required",
                "message": "an authenticated operator session is required to decide a standing envelope",
            }),
        ));
    };
    if principal["role"].as_str() != Some("admin") {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "standing_envelope_decider_not_operator",
            "only the deployment's operator (an administrator) decides standing envelopes",
        ));
    }
    if principal["is_impersonated"].as_bool() == Some(true) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "standing_envelope_decider_impersonated",
            "an impersonated session cannot decide a standing envelope",
        ));
    }
    let principal_id = principal["principal_id"].as_str().unwrap_or("").to_string();
    let principal_ref = principal["principal_ref"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("user://{principal_id}"));
    Ok((principal_ref, principal_id))
}

// ---- the authority node -------------------------------------------------------------------------

/// Why an authority act did not complete. Nothing a `PassphraseRefused` act touched was recorded.
#[derive(Debug)]
pub(crate) enum AuthorityFailure {
    PassphraseRefused,
    Refused(String),
    Unavailable(String),
    Timeout(u64),
}

/// What the custody tier can honestly attest about the sealed approver key.
#[derive(Debug, Clone)]
pub(crate) struct CustodyEvidence {
    pub(crate) key_path_hash: String,
    pub(crate) credential_id_hash: String,
}

/// The deployment authority the daemon runs acts against: the authority binary on its state dir,
/// or (tests only) an in-process stand-in that signs with a test key.
pub(crate) enum StandingAuthority {
    Binary {
        binary: String,
        state_dir: String,
        timeout_ms: u64,
    },
    #[cfg(test)]
    Fake(Arc<tests::FakeAuthority>),
}

impl StandingAuthority {
    fn configured() -> Option<Self> {
        let binary = std::env::var(super::authority_challenge_routes::AUTHORITY_BINARY_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let state_dir = std::env::var(super::authority_challenge_routes::AUTHORITY_STATE_DIR_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        if !(std::path::Path::new(&binary).is_file() && std::path::Path::new(&state_dir).is_dir()) {
            return None;
        }
        let timeout_ms = std::env::var("IOI_HYPERVISOR_AUTHORITY_APPROVE_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_AUTHORITY_TIMEOUT_MS);
        Some(Self::Binary {
            binary,
            state_dir,
            timeout_ms,
        })
    }

    /// The sealed approver key's custody, read from the state dir: the key must exist sealed and
    /// be readable by its owner alone (0600). Only public material is read.
    fn custody_evidence(&self) -> Result<CustodyEvidence, String> {
        match self {
            Self::Binary { state_dir, .. } => {
                use std::os::unix::fs::PermissionsExt;
                let keys = std::path::Path::new(state_dir).join("keys");
                let sealed = keys.join("approver.seed.sealed");
                let mode = std::fs::metadata(&sealed)
                    .map_err(|_| format!("{} is absent: a standing grant is minted only by a SEALED approver key", sealed.display()))?
                    .permissions()
                    .mode()
                    & 0o777;
                if mode != 0o600 {
                    return Err(format!(
                        "{} is mode {mode:o}; the custody tier attests an owner-only (0600) key",
                        sealed.display()
                    ));
                }
                let public_hex = std::fs::read_to_string(keys.join("approver.pub"))
                    .map_err(|_| "keys/approver.pub is absent".to_string())?;
                let public = hex::decode(public_hex.trim())
                    .map_err(|_| "keys/approver.pub is not hex".to_string())?;
                Ok(CustodyEvidence {
                    key_path_hash: sha256_ref(sealed.to_string_lossy().as_bytes()),
                    credential_id_hash: sha256_ref(&public),
                })
            }
            #[cfg(test)]
            Self::Fake(fake) => Ok(fake.custody()),
        }
    }

    async fn run_act(
        &self,
        args: &[String],
        passphrase: Option<&str>,
    ) -> Result<Value, AuthorityFailure> {
        match self {
            Self::Binary {
                binary,
                state_dir,
                timeout_ms,
            } => {
                let mut command = tokio::process::Command::new(binary);
                command
                    .arg(&args[0])
                    .args(["--state-dir", state_dir.as_str()])
                    .args(&args[1..])
                    .env_remove(OPERATOR_PASS_ENV)
                    .env("CARGO_TERM_COLOR", "never")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .kill_on_drop(true);
                if let Some(passphrase) = passphrase {
                    // The ONE place the passphrase leaves this process: this child's environment.
                    // The binary copies it and scrubs its own environment block before any thread.
                    command.env(OPERATOR_PASS_ENV, passphrase);
                }
                let spawned = command.spawn();
                // The Command's own copy of the environment goes with it, now that the child exists.
                drop(command);
                let child = spawned.map_err(|error| {
                    AuthorityFailure::Unavailable(format!(
                        "the authority binary could not be started: {error}"
                    ))
                })?;
                let output = match tokio::time::timeout(
                    Duration::from_millis(*timeout_ms),
                    child.wait_with_output(),
                )
                .await
                {
                    Ok(Ok(output)) => output,
                    Ok(Err(error)) => {
                        return Err(AuthorityFailure::Unavailable(format!(
                            "the authority act did not complete: {error}"
                        )))
                    }
                    Err(_) => return Err(AuthorityFailure::Timeout(*timeout_ms)),
                };
                let secret = passphrase.unwrap_or("");
                let stdout = scrub(&String::from_utf8_lossy(&output.stdout), secret);
                let stderr = scrub(&String::from_utf8_lossy(&output.stderr), secret);
                if !output.status.success() {
                    let detail = tail(&stderr, 600);
                    if detail.contains("operator passphrase") {
                        return Err(AuthorityFailure::PassphraseRefused);
                    }
                    return Err(AuthorityFailure::Refused(detail));
                }
                Ok(stdout
                    .trim()
                    .lines()
                    .rev()
                    .find(|line| line.trim_start().starts_with('{'))
                    .and_then(|line| serde_json::from_str(line).ok())
                    .unwrap_or(Value::Null))
            }
            #[cfg(test)]
            Self::Fake(fake) => fake.act(args, passphrase),
        }
    }

    async fn chain_timestamp_ms(&self) -> Result<u64, AuthorityFailure> {
        let outcome = self.run_act(&["chain-timestamp".to_string()], None).await?;
        outcome
            .get("chain_timestamp_ms")
            .and_then(Value::as_u64)
            .filter(|ms| *ms > 0)
            .ok_or_else(|| {
                AuthorityFailure::Refused(
                    "the authority reported no committed chain timestamp".into(),
                )
            })
    }

    /// `record-standing-approval` in MINT mode. The evidence (public) is written to a private
    /// temporary directory for the child and removed when it exits.
    async fn record(
        &self,
        envelope: &Value,
        context: &Value,
        factor: &Value,
        passphrase: &str,
    ) -> Result<Value, AuthorityFailure> {
        let dir = std::env::temp_dir().join(format!(
            "ioi-standing-evidence-{}",
            hex::encode(rand::random::<[u8; 12]>())
        ));
        let written = (|| -> std::io::Result<Vec<String>> {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            let mut paths = Vec::new();
            for (name, value) in [
                ("envelope.json", envelope),
                ("context.json", context),
                ("factor.json", factor),
            ] {
                use std::io::Write;
                let path = dir.join(name);
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(&serde_json::to_vec(value).unwrap_or_default())?;
                paths.push(path.to_string_lossy().into_owned());
            }
            Ok(paths)
        })();
        let paths = match written {
            Ok(paths) => paths,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(AuthorityFailure::Unavailable(format!(
                    "the standing evidence could not be handed to the authority: {error}"
                )));
            }
        };
        let args = vec![
            "record-standing-approval".to_string(),
            "--envelope-file".to_string(),
            paths[0].clone(),
            "--context-file".to_string(),
            paths[1].clone(),
            "--factor-file".to_string(),
            paths[2].clone(),
        ];
        let outcome = self.run_act(&args, Some(passphrase)).await;
        let _ = std::fs::remove_dir_all(&dir);
        outcome
    }

    async fn revoke(
        &self,
        grant_hash_hex: &str,
        passphrase: &str,
    ) -> Result<Value, AuthorityFailure> {
        let args = vec![
            "revoke-standing-approval".to_string(),
            "--grant-hash".to_string(),
            grant_hash_hex.to_string(),
        ];
        self.run_act(&args, Some(passphrase)).await
    }
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

fn authority_refusal(failure: AuthorityFailure, what: &str) -> Reply {
    match failure {
        AuthorityFailure::PassphraseRefused => refuse(
            StatusCode::FORBIDDEN,
            "operator_passphrase_refused",
            format!("the operator passphrase did not open the sealed keys; nothing was signed or recorded ({what})"),
        ),
        AuthorityFailure::Refused(detail) => refuse(
            StatusCode::BAD_GATEWAY,
            "authority_standing_act_refused",
            format!("the deployment authority refused to {what}: {detail}"),
        ),
        AuthorityFailure::Unavailable(detail) => refuse(
            StatusCode::BAD_GATEWAY,
            "authority_standing_act_unavailable",
            detail,
        ),
        AuthorityFailure::Timeout(ms) => refuse(
            StatusCode::GATEWAY_TIMEOUT,
            "authority_standing_act_timeout",
            format!("the deployment authority did not {what} within {ms} ms"),
        ),
    }
}

// ---- derivation -------------------------------------------------------------------------------

/// The grant coordinates the daemon derived; the authority's grant must carry exactly these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedGrant {
    pub(crate) standing_envelope_hash: [u8; 32],
    pub(crate) policy_hash: [u8; 32],
    pub(crate) audience: [u8; 32],
    pub(crate) issued_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) max_usages: u32,
    pub(crate) max_cumulative_deposit_microusd: u64,
    pub(crate) max_cumulative_spend_microusd: u64,
    pub(crate) review_receipt_hash: [u8; 32],
    pub(crate) approval_ceremony_context_hash: [u8; 32],
    pub(crate) auth_factor_receipt_hash: [u8; 32],
}

pub(crate) struct DerivedEvidence {
    pub(crate) envelope: Value,
    pub(crate) context: Value,
    pub(crate) factor: Value,
    pub(crate) review: Value,
    pub(crate) expected: ExpectedGrant,
}

pub(crate) struct DerivationInputs<'a> {
    pub(crate) connector: &'a Value,
    pub(crate) bounds: &'a StandingBounds,
    pub(crate) principal_ref: &'a str,
    pub(crate) audience_hex: &'a str,
    pub(crate) decided_by: &'a str,
    pub(crate) now_ms: u64,
    pub(crate) custody: &'a CustodyEvidence,
    pub(crate) marker: &'a str,
}

fn host_ref_for(principal_ref: &str) -> String {
    let tail = principal_ref
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(principal_ref);
    format!("deployment-host://{tail}")
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Derive the registered envelope, the review, the single-use ceremony context and the v2 factor
/// receipt for one standing decision, and the grant coordinates they determine. Pure: the clock,
/// the marker and the custody evidence are inputs. Each artefact is validated against its
/// registered contract before anything is handed to the authority.
pub(crate) fn derive_standing_evidence(
    inputs: &DerivationInputs<'_>,
) -> Result<DerivedEvidence, String> {
    let bounds = inputs.bounds;
    let connector = inputs.connector;
    let connector_id = connector["connector_id"].as_str().unwrap_or("");
    let audience = <[u8; 32]>::try_from(
        hex::decode(inputs.audience_hex)
            .map_err(|_| "the capability audience is not hex".to_string())?,
    )
    .map_err(|_| "the capability audience is not 32 bytes".to_string())?;
    let declared_tools: Vec<String> = connector["allowed_tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let allowed_tools = bounds.tools.clone().unwrap_or(declared_tools);
    let issued_ms = inputs.now_ms.saturating_sub(1_000);
    let expires_at_ms = inputs.now_ms.saturating_add(bounds.expires_in_ms);
    let envelope_ref = format!(
        "standing-envelope://hypervisor/connections/{connector_id}/{}",
        inputs.marker
    );
    let facet_template = json!({
        "connector_id": connector_id,
        "service": connector["service"],
        "base_url": connector["base_url"],
        "operations": bounds.operations,
        "allowed_tools": allowed_tools,
        "per_operation_spend_microusd": bounds.per_operation_microusd,
        "per_operation_deposit_microusd": bounds.per_operation_microusd,
    });
    let aggregate_bounds = json!({
        "max_cumulative_deposit_microusd": bounds.budget_microusd,
        "max_cumulative_spend_microusd": bounds.budget_microusd,
        "max_usages": bounds.max_usages,
    });
    // The trajectory policy is a daemon-derived commitment to exactly what the envelope admits.
    let trajectory_policy_hash = hash_of(&json!({
        "domain": "ioi.hypervisor.session-standing-envelope.trajectory-policy.v1",
        "principal_ref": inputs.principal_ref,
        "audience": inputs.audience_hex,
        "facet_template": facet_template,
        "aggregate_bounds": aggregate_bounds,
    }))?;
    let mut envelope = json!({
        "schema_version": ENVELOPE_SCHEMA,
        "standing_envelope_ref": envelope_ref,
        "owner_ref": "org://local",
        "bounded_system_ref": "system://hypervisor/local",
        "principal_ref": inputs.principal_ref,
        "audience_ref": "wallet-client://hypervisor/daemon",
        "authority_scope": "scope:hypervisor.session-standing-envelope",
        "facet_template": facet_template,
        "aggregate_bounds": aggregate_bounds,
        "not_before_ms": issued_ms.saturating_sub(60_000),
        "expires_at_ms": expires_at_ms,
        "revocation_epoch": 0,
        "trajectory_policy_ref": "policy://hypervisor/session-standing-envelope/trajectory/v1",
        "trajectory_policy_hash": trajectory_policy_hash,
        "approval_mode": "standing_envelope",
        "recovery_posture": "recovery_never_widens_or_resets_drawdown",
    });
    let mut body_material = envelope.clone();
    body_material["domain"] = json!(ENVELOPE_BODY_DOMAIN);
    let body_hash = hash_of(&body_material)?;
    envelope["body_hash"] = json!(body_hash);
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        super::lifecycle_routes::SESSION_STANDING_ENVELOPE_CONTRACT,
        &envelope,
    )
    .map_err(|error| format!("the derived envelope violates its registered contract: {error}"))?;

    // The request, the operator's review of it, and the policy decision that admits it: each a
    // daemon-derived commitment the ceremony names.
    let request = json!({
        "domain": "ioi.hypervisor.standing-envelope.request.v1",
        "standing_envelope_ref": envelope_ref,
        "connector_id": connector_id,
        "operations": bounds.operations,
        "allowed_tools": envelope["facet_template"]["allowed_tools"],
        "max_usages": bounds.max_usages,
        "budget_microusd": bounds.budget_microusd,
        "per_operation_microusd": bounds.per_operation_microusd,
        "expires_in_ms": bounds.expires_in_ms,
        "requested_by": inputs.decided_by,
        "reason": bounds.reason,
    });
    let request_hash = hash_of(&request)?;
    let review = json!({
        "domain": "ioi.hypervisor.standing-envelope.review.v1",
        "authority_request_body_hash": request_hash,
        "standing_envelope_hash": body_hash,
        "trajectory_policy_hash": trajectory_policy_hash,
        "reviewed_by": inputs.decided_by,
        "reviewed_at": rfc3339_ms(issued_ms),
        "decision": "record_standing_envelope",
    });
    let review_hash = hash_of(&review)?;
    let policy_decision_receipt_hash = hash_of(&json!({
        "domain": "ioi.hypervisor.standing-envelope.policy-decision-receipt.v1",
        "authority_review_body_hash": review_hash,
        "trajectory_policy_hash": trajectory_policy_hash,
        "decided_by": inputs.decided_by,
        "admits": "standing_envelope",
    }))?;
    let reviewed_representation_hash = hash_of(&json!({
        "domain": "ioi.hypervisor.standing-envelope.reviewed-representation.v1",
        "standing_envelope_hash": body_hash,
        "facet_template": envelope["facet_template"],
        "aggregate_bounds": envelope["aggregate_bounds"],
        "expires_at_ms": expires_at_ms,
    }))?;
    let host_ref = host_ref_for(inputs.principal_ref);
    let posture_ref = format!(
        "auth_factor://deployment-local-operator/{}",
        percent_encode(&host_ref)
    );
    let authorization_subject = json!({
        "kind": "standing_envelope",
        "subject_ref": envelope_ref,
        "subject_hash": body_hash,
        "validation_profile_ref": super::lifecycle_routes::SESSION_STANDING_ENVELOPE_CONTRACT,
    });
    let marker = inputs.marker;
    let acting_subject_ref =
        if inputs.decided_by.contains("://") && !inputs.decided_by.contains(char::is_whitespace) {
            inputs.decided_by.to_string()
        } else {
            "runtime://hypervisor/operator".to_string()
        };
    let context = json!({
        "schema_version": "ioi.foundations.approval-ceremony-context.v1",
        "approval_ceremony_context_ref": format!("approval-ceremony-context://hypervisor/standing-envelope/{marker}"),
        "authority_request_ref": format!("authority-request://hypervisor/standing-envelope/{marker}"),
        "authority_request_body_hash": request_hash,
        "authority_review_ref": format!("review://hypervisor/standing-envelope/{marker}"),
        "authority_review_body_hash": review_hash,
        "predecessor_authority_review_ref": null,
        "predecessor_authority_review_body_hash": null,
        "predecessor_authority_request_ref": null,
        "predecessor_authority_request_body_hash": null,
        "predecessor_authority_review_receipt_ref": null,
        "predecessor_authority_review_receipt_hash": null,
        "reviewed_representation_hash": reviewed_representation_hash,
        "principal_ref": inputs.principal_ref,
        "acting_subject_ref": acting_subject_ref,
        "product_session_ref": format!("session://hypervisor/standing-envelope/{marker}"),
        "origin_binding_ref": "origin://hypervisor/local",
        "authorization_subject": authorization_subject,
        "presentation_surface_ref": "wallet-client://hypervisor/daemon",
        "presentation_evidence_profile_ref": "policy://presentation/deployment-local-operator/v1",
        "principal_authority_resolution_ref": null,
        "principal_authority_resolution_hash": null,
        "required_auth_factor_posture_refs": [posture_ref],
        "required_guardian_surface_refs": [],
        "posture_satisfaction_profile_ref": "policy://auth-posture/step-up/v1",
        "interaction_mode": "interactive",
        "authentication_posture": "step_up",
        "receipt_timing": "before_effect",
        "policy_decision_receipt_ref": format!("receipt://hypervisor/standing-envelope/review/{marker}"),
        "policy_decision_receipt_hash": policy_decision_receipt_hash,
        "policy_hash": trajectory_policy_hash,
        "risk_classes": ["external_spend", "standing_authority"],
        "revocation_epoch": 0,
        "nonce_b64url": hex::encode(rand::random::<[u8; 32]>()),
        "issued_at": rfc3339_ms(issued_ms),
        "expires_at": rfc3339_ms(issued_ms.saturating_add(CEREMONY_WINDOW_MS)),
        "single_use": true,
    });
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        APPROVAL_CONTEXT_CONTRACT,
        &context,
    )
    .map_err(|error| {
        format!("the derived ceremony context violates its registered contract: {error}")
    })?;
    let mut context_material = APPROVAL_CONTEXT_DOMAIN.to_vec();
    context_material.extend_from_slice(&jcs(&context)?);
    let context_hash = sha256_bytes(&context_material);
    let mut factor = json!({
        "schema_version": "ioi.hypervisor.auth-factor-receipt.v2",
        "receipt_id": format!("afr_{marker}"),
        "ceremony_id": format!("pkc_{marker}"),
        "principal_id": "deployment-local-operator",
        "principal_ref": inputs.principal_ref,
        "factor_kind": "deployment_local_operator",
        "credential_id_hash": inputs.custody.credential_id_hash,
        "user_verification": "deployment_local_key_custody",
        "purpose": "standing_effect_authority",
        "approval_ceremony_context_ref": context["approval_ceremony_context_ref"],
        "approval_ceremony_context_hash": format!("sha256:{}", hex::encode(context_hash)),
        "authorization_subject": context["authorization_subject"],
        "policy_hash": trajectory_policy_hash,
        "effect_authority_created": false,
        "created_at": rfc3339_ms(issued_ms),
        "custody_tier_evidence": {
            "host_ref": host_ref,
            "key_path_hash": inputs.custody.key_path_hash,
            "key_mode_octal": "600",
            "operator_acknowledged_at": rfc3339_ms(issued_ms),
        },
    });
    let factor_hash = sha256_bytes(&jcs(&factor)?);
    factor["receipt_hash"] = json!(format!("sha256:{}", hex::encode(factor_hash)));
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        AUTH_FACTOR_RECEIPT_CONTRACT_V2,
        &factor,
    )
    .map_err(|error| {
        format!("the derived factor receipt violates its registered contract: {error}")
    })?;
    let expected = ExpectedGrant {
        standing_envelope_hash: ref_bytes(&body_hash).ok_or("body hash")?,
        policy_hash: ref_bytes(&trajectory_policy_hash).ok_or("policy hash")?,
        audience,
        issued_at_ms: issued_ms,
        expires_at_ms,
        max_usages: bounds.max_usages,
        max_cumulative_deposit_microusd: bounds.budget_microusd,
        max_cumulative_spend_microusd: bounds.budget_microusd,
        review_receipt_hash: ref_bytes(&policy_decision_receipt_hash).ok_or("receipt hash")?,
        approval_ceremony_context_hash: context_hash,
        auth_factor_receipt_hash: factor_hash,
    };
    Ok(DerivedEvidence {
        envelope,
        context,
        factor,
        review: json!({ "request": request, "review": review, "policy_decision_receipt_hash": policy_decision_receipt_hash }),
        expected,
    })
}

/// The authority's grant must be exactly the one the daemon's derivation determines.
pub(crate) fn check_minted_grant(
    grant_value: &Value,
    expected: &ExpectedGrant,
) -> Result<Value, String> {
    let (grant, canonical) =
        super::governed_authority::canonicalize_standing_approval_grant(grant_value)?;
    let mismatch = [
        (
            "standing_envelope_hash",
            grant.standing_envelope_hash == expected.standing_envelope_hash,
        ),
        ("policy_hash", grant.policy_hash == expected.policy_hash),
        ("audience", grant.audience == expected.audience),
        ("issued_at_ms", grant.issued_at_ms == expected.issued_at_ms),
        (
            "expires_at_ms",
            grant.expires_at_ms == expected.expires_at_ms,
        ),
        ("max_usages", grant.max_usages == expected.max_usages),
        (
            "max_cumulative_deposit_microusd",
            grant.max_cumulative_deposit_microusd == expected.max_cumulative_deposit_microusd,
        ),
        (
            "max_cumulative_spend_microusd",
            grant.max_cumulative_spend_microusd == expected.max_cumulative_spend_microusd,
        ),
        (
            "review_receipt_hash",
            grant.review_receipt_hash == expected.review_receipt_hash,
        ),
        (
            "approval_ceremony_context_hash",
            grant.approval_ceremony_context_hash == expected.approval_ceremony_context_hash,
        ),
        (
            "auth_factor_receipt_hash",
            grant.auth_factor_receipt_hash == expected.auth_factor_receipt_hash,
        ),
    ]
    .into_iter()
    .filter(|(_, same)| !same)
    .map(|(field, _)| field)
    .collect::<Vec<_>>();
    if !mismatch.is_empty() {
        return Err(format!(
            "the grant differs from the derivation in {}",
            mismatch.join(", ")
        ));
    }
    Ok(canonical)
}

// ---- records ----------------------------------------------------------------------------------

fn valid_envelope_id(id: &str) -> bool {
    id.len() == 36
        && id.starts_with("sse_")
        && id[4..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn read_envelope_record(data_dir: &str, id: &str) -> Result<Option<Value>, String> {
    super::durable_fs::read_record_durable(data_dir, STANDING_ENVELOPE_FAMILY, id)
}

fn write_envelope_record(data_dir: &str, id: &str, record: &Value) -> Result<(), String> {
    super::durable_fs::persist_record_durable(data_dir, STANDING_ENVELOPE_FAMILY, id, record)
        .map_err(|error| format!("standing envelope {id} was not durably persisted: {error:?}"))
}

fn record_u64(record: &Value, pointer: &str) -> u64 {
    record.pointer(pointer).and_then(Value::as_u64).unwrap_or(0)
}

/// The record as any reader sees it, with what remains of the bounds.
pub(crate) fn public_view(record: &Value) -> Value {
    let mut view = record.clone();
    let max_usages = record_u64(record, "/bounds/max_usages");
    let max_spend = record_u64(record, "/bounds/max_cumulative_spend_microusd");
    let max_deposit = record_u64(record, "/bounds/max_cumulative_deposit_microusd");
    let uses = record_u64(record, "/drawn/uses");
    let spend = record_u64(record, "/drawn/spend_microusd");
    let deposit = record_u64(record, "/drawn/deposit_microusd");
    if let Some(object) = view.as_object_mut() {
        let id = object
            .get("standing_envelope_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        object.insert(
            "remaining".into(),
            json!({
                "usages": max_usages.saturating_sub(uses),
                "spend_microusd": max_spend.saturating_sub(spend),
                "deposit_microusd": max_deposit.saturating_sub(deposit),
            }),
        );
        object.insert(
            "revoke_route".into(),
            json!(format!(
                "/v1/hypervisor/authority/standing-envelopes/{id}/revoke"
            )),
        );
    }
    view
}

/// Why a draw against a daemon-issued envelope is outside its bounds, judged from the record
/// before the wallet is asked. Leases this module did not issue (no `standing_envelope_id`) are
/// the wallet's alone and pass through.
pub(crate) fn precheck_draw(
    data_dir: &str,
    lease: &Value,
    now: u64,
) -> Result<(), (&'static str, &'static str)> {
    let Some(id) = lease.get("standing_envelope_id").and_then(Value::as_str) else {
        return Ok(());
    };
    let record = match read_envelope_record(data_dir, id) {
        Ok(Some(record)) => record,
        // The lease names a record this daemon cannot read: fail closed.
        _ => return Err(("standing_lease_invalid", "record")),
    };
    if record.get("status").and_then(Value::as_str) != Some("active") {
        return Err(("standing_lease_revoked", "status"));
    }
    if now > record_u64(&record, "/bounds/expires_at_ms") {
        return Err(("standing_envelope_exceeded", "expired"));
    }
    if record_u64(&record, "/drawn/uses").saturating_add(1)
        > record_u64(&record, "/bounds/max_usages")
    {
        return Err(("standing_envelope_exceeded", "max_usages"));
    }
    if record_u64(&record, "/drawn/spend_microusd")
        .saturating_add(record_u64(&record, "/bounds/per_operation_spend_microusd"))
        > record_u64(&record, "/bounds/max_cumulative_spend_microusd")
    {
        return Err((
            "standing_envelope_exceeded",
            "max_cumulative_spend_microusd",
        ));
    }
    if record_u64(&record, "/drawn/deposit_microusd").saturating_add(record_u64(
        &record,
        "/bounds/per_operation_deposit_microusd",
    )) > record_u64(&record, "/bounds/max_cumulative_deposit_microusd")
    {
        return Err((
            "standing_envelope_exceeded",
            "max_cumulative_deposit_microusd",
        ));
    }
    Ok(())
}

/// Count one ADMITTED draw (the wallet consumed it) against a daemon-issued envelope.
pub(crate) fn note_draw(data_dir: &str, lease: &Value, admission_ref: &str) {
    let Some(id) = lease.get("standing_envelope_id").and_then(Value::as_str) else {
        return;
    };
    let _guard = lock_records();
    let Ok(Some(mut record)) = read_envelope_record(data_dir, id) else {
        return;
    };
    let spend = record_u64(&record, "/bounds/per_operation_spend_microusd");
    let deposit = record_u64(&record, "/bounds/per_operation_deposit_microusd");
    let uses = record_u64(&record, "/drawn/uses").saturating_add(1);
    let total_spend = record_u64(&record, "/drawn/spend_microusd").saturating_add(spend);
    let total_deposit = record_u64(&record, "/drawn/deposit_microusd").saturating_add(deposit);
    let mut refs: Vec<Value> = record
        .pointer("/drawn/draw_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    refs.push(json!(admission_ref));
    if refs.len() > DRAW_REFS_KEPT {
        let excess = refs.len() - DRAW_REFS_KEPT;
        refs.drain(..excess);
    }
    record["drawn"] = json!({
        "uses": uses,
        "spend_microusd": total_spend,
        "deposit_microusd": total_deposit,
        "draw_refs": refs,
        "last_drawn_at": iso_now(),
    });
    let _ = write_envelope_record(data_dir, id, &record);
}

/// The passphrase-free local fence (`DELETE /connectors/:id/standing-lease`) revoked a lease this
/// module issued: the record follows it, and says the chain grant was not revoked by that act.
pub(crate) fn note_local_fence(data_dir: &str, lease: &Value) {
    let Some(id) = lease.get("standing_envelope_id").and_then(Value::as_str) else {
        return;
    };
    let _guard = lock_records();
    let Ok(Some(mut record)) = read_envelope_record(data_dir, id) else {
        return;
    };
    if record.get("status").and_then(Value::as_str) != Some("active") {
        return;
    }
    record["status"] = json!("revoked");
    record["revoked_at"] = json!(iso_now());
    record["revocation"] = json!({
        "kind": "local_fence",
        "chain_revocation": "not_run",
        "note": "fenced on the connection without the operator passphrase; the recorded grant stays on the authority node until revoked there",
    });
    let _ = write_envelope_record(data_dir, id, &record);
}

// ---- the decision ------------------------------------------------------------------------------

/// Who decides, and the deployment coordinates the decision is made against.
pub(crate) struct DecisionContext<'a> {
    pub(crate) data_dir: &'a str,
    pub(crate) decided_by: &'a str,
    pub(crate) principal_id: &'a str,
    pub(crate) principal_ref: &'a str,
    pub(crate) audience_hex: &'a str,
}

fn connector_in_scope(data_dir: &str, principal_id: &str, connector_id: &str) -> Option<Value> {
    let connector = read_record_dir(data_dir, "connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(connector_id))?;
    // The same scope the bind/revoke routes read: a principal-scoped connection is decided only by
    // a caller holding a lease grant for it, and the refusal is the unknown-connector answer.
    if connector["org_policy"]["principal_scoped"]
        .as_bool()
        .unwrap_or(false)
        && !super::lifecycle_routes::principal_has_connector_grant(
            data_dir,
            principal_id,
            connector_id,
        )
    {
        return None;
    }
    Some(connector)
}

fn unknown_connector() -> Reply {
    reply(
        StatusCode::NOT_FOUND,
        json!({ "ok": false, "reason": "unknown connector_id" }),
    )
}

async fn create_standing_envelope(
    ctx: &DecisionContext<'_>,
    body: CreateBody,
    authority: &StandingAuthority,
) -> Reply {
    let CreateBody {
        bounds,
        operator_passphrase,
    } = body;
    let Some(mut connector) =
        connector_in_scope(ctx.data_dir, ctx.principal_id, &bounds.connector_id)
    else {
        return unknown_connector();
    };
    if connector
        .get("standing_lease")
        .is_some_and(|lease| lease["status"].as_str() == Some("active"))
    {
        return refuse(
            StatusCode::CONFLICT,
            "standing_lease_already_bound",
            "this connection already carries an active standing envelope; revoke it and decide a successor rather than editing it in place",
        );
    }
    if connector["kind"].as_str() != Some("mcp") {
        if let Some(tools) = bounds.tools.as_ref() {
            let declared: BTreeSet<&str> = connector["allowed_tools"]
                .as_array()
                .map(|tools| tools.iter().filter_map(|t| t["name"].as_str()).collect())
                .unwrap_or_default();
            if let Some(tool) = tools.iter().find(|tool| !declared.contains(tool.as_str())) {
                return refuse(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "standing_lease_tool_outside_connector",
                    format!(
                        "the envelope names tool '{tool}', which the connection does not declare"
                    ),
                );
            }
        }
    }
    if operator_passphrase.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "operator_passphrase_required",
            "setting limits needs the operator passphrase: the deployment authority opens the sealed approver key with it to sign this one standing grant",
        );
    }
    let Some(_deciding) = DecidingGuard::enter(&format!(
        "{}::connector:{}",
        ctx.data_dir, bounds.connector_id
    )) else {
        return refuse(
            StatusCode::CONFLICT,
            "standing_envelope_decision_in_progress",
            "a standing decision for this connection is already running",
        );
    };
    let custody = match authority.custody_evidence() {
        Ok(custody) => custody,
        Err(message) => {
            return refuse(
                StatusCode::CONFLICT,
                "standing_envelope_custody_unverifiable",
                message,
            )
        }
    };
    // ADR 0052 §7: the envelope's window is judged on the authority's committed chain clock by the
    // wallet and on the host clock by this daemon, so the two must agree.
    let chain_ms = match authority.chain_timestamp_ms().await {
        Ok(ms) => ms,
        Err(failure) => return authority_refusal(failure, "report its chain clock"),
    };
    let wall_ms = now_ms();
    if chain_ms.abs_diff(wall_ms) > WALL_CLOCK_TOLERANCE_MS {
        return refuse(
            StatusCode::CONFLICT,
            "standing_envelope_requires_wall_clock_authority",
            format!(
                "the authority's committed chain clock is {} s from the host clock; a standing envelope promises real time, so its authority must run on the wall clock (ADR 0052 §7: `serve --wall-clock`). Nothing was signed or recorded.",
                chain_ms.abs_diff(wall_ms) / 1_000
            ),
        );
    }
    let marker = hex::encode(rand::random::<[u8; 8]>());
    let derived = match derive_standing_evidence(&DerivationInputs {
        connector: &connector,
        bounds: &bounds,
        principal_ref: ctx.principal_ref,
        audience_hex: ctx.audience_hex,
        decided_by: ctx.decided_by,
        now_ms: chain_ms.min(wall_ms),
        custody: &custody,
        marker: &marker,
    }) {
        Ok(derived) => derived,
        Err(message) => {
            return refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                "standing_envelope_evidence_invalid",
                message,
            )
        }
    };
    let outcome = authority
        .record(
            &derived.envelope,
            &derived.context,
            &derived.factor,
            operator_passphrase.as_str(),
        )
        .await;
    // Zeroized here: nothing below needs the passphrase.
    drop(operator_passphrase);
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(failure) => return authority_refusal(failure, "record the standing grant"),
    };
    let grant_value = outcome
        .get("standing_approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let canonical_grant = match check_minted_grant(&grant_value, &derived.expected) {
        Ok(canonical) => canonical,
        Err(message) => {
            return refuse(
                StatusCode::BAD_GATEWAY,
                "authority_grant_mismatch",
                format!("the authority's standing grant does not bind this decision exactly ({message}); it was not bound"),
            )
        }
    };
    let lease_body = json!({ "grant": canonical_grant, "envelope": derived.envelope });
    let mut lease = match super::lifecycle_routes::validate_connector_standing_lease(
        &connector,
        &lease_body,
        now_ms(),
    ) {
        Ok(lease) => lease,
        Err((status, Json(body))) => return (status, Json(body)),
    };
    let id = format!("sse_{}", hex::encode(rand::random::<[u8; 16]>()));
    let envelope_ref = derived.envelope["standing_envelope_ref"].clone();
    lease["standing_envelope_id"] = json!(id);
    lease["standing_envelope_ref"] = envelope_ref.clone();
    lease["issued_by"] = json!("daemon_standing_decision");
    let record = json!({
        "schema_version": RECORD_SCHEMA,
        "standing_envelope_id": id,
        "standing_envelope_ref": envelope_ref,
        "connector_id": bounds.connector_id,
        "connection_ref": format!("connector:{}", bounds.connector_id),
        "status": "active",
        "decided_by": ctx.decided_by,
        "reason": bounds.reason,
        "created_at": iso_now(),
        "bounds": lease["bounds"],
        "envelope": derived.envelope,
        "approval_ceremony_context": derived.context,
        "auth_factor_receipt": derived.factor,
        "review": derived.review,
        "grant": canonical_grant,
        "envelope_hash_ref": lease["envelope_hash_ref"],
        "policy_hash_ref": lease["policy_hash_ref"],
        "grant_hash_ref": lease["grant_hash_ref"],
        "recorded_on_authority": {
            "recorded": outcome.get("recorded").cloned().unwrap_or(Value::Null),
            "standing_grant_hash": outcome.get("standing_grant_hash").cloned().unwrap_or(Value::Null),
            "custody_tier": outcome.get("custody_tier").cloned().unwrap_or(Value::Null),
            "chain_clock_ms": chain_ms,
        },
        "drawn": { "uses": 0, "spend_microusd": 0, "deposit_microusd": 0, "draw_refs": [] },
        "revoked_at": null,
        "revocation": null,
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Err(message) = write_envelope_record(ctx.data_dir, &id, &record) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_envelope_not_durable",
            format!("{message}; the grant is recorded on the authority node but NOT bound here"),
        );
    }
    connector["standing_lease"] = lease.clone();
    if super::persist_record(ctx.data_dir, "connectors", &bounds.connector_id, &connector).is_err()
    {
        let _guard = lock_records();
        let mut unbound = record.clone();
        unbound["status"] = json!("unbound");
        let _ = write_envelope_record(ctx.data_dir, &id, &unbound);
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_lease_persistence_failed",
            "the standing lease could not be durably bound to the connection; the envelope is NOT in force",
        );
    }
    reply(
        StatusCode::OK,
        json!({
            "ok": true,
            "standing_envelope_id": id,
            "standing_envelope_ref": record["standing_envelope_ref"],
            "connector_id": bounds.connector_id,
            "status": "active",
            "bounds": lease["bounds"],
            "envelope_hash_ref": lease["envelope_hash_ref"],
            "grant_hash_ref": lease["grant_hash_ref"],
            "recorded_on_authority": record["recorded_on_authority"]["recorded"],
            "decided_by": ctx.decided_by,
            "standing_lease": { "status": "active", "bounds": lease["bounds"], "envelope_hash_ref": lease["envelope_hash_ref"], "grant_hash_ref": lease["grant_hash_ref"], "standing_envelope_id": id, "declared_at": lease["declared_at"] },
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

async fn revoke_standing_envelope(
    ctx: &DecisionContext<'_>,
    id: &str,
    body: RevokeBody,
    authority: &StandingAuthority,
) -> Reply {
    let RevokeBody {
        reason,
        operator_passphrase,
    } = body;
    let record = match read_envelope_record(ctx.data_dir, id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "standing_envelope_not_found",
                "no standing envelope has this id",
            )
        }
        Err(message) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "standing_envelope_unreadable",
                message,
            )
        }
    };
    let connector_id = record["connector_id"].as_str().unwrap_or("").to_string();
    if connector_in_scope(ctx.data_dir, ctx.principal_id, &connector_id).is_none() {
        return unknown_connector();
    }
    if record
        .pointer("/revocation/chain_revocation")
        .and_then(Value::as_str)
        == Some("committed")
    {
        return refuse(
            StatusCode::CONFLICT,
            "standing_envelope_already_revoked",
            "this standing envelope is already revoked, on the connection and on the authority node",
        );
    }
    if operator_passphrase.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "operator_passphrase_required",
            "revoking on the authority node needs the operator passphrase (the control root signs the revocation); the passphrase-free local fence is DELETE /v1/hypervisor/connectors/:id/standing-lease",
        );
    }
    let grant_hash_hex = record["grant_hash_ref"]
        .as_str()
        .and_then(|text| text.strip_prefix("sha256:"))
        .unwrap_or("")
        .to_string();
    if grant_hash_hex.len() != 64 {
        return refuse(
            StatusCode::CONFLICT,
            "standing_envelope_record_invalid",
            "the record names no grant hash to revoke",
        );
    }
    let Some(_deciding) = DecidingGuard::enter(&format!("{}::envelope:{id}", ctx.data_dir)) else {
        return refuse(
            StatusCode::CONFLICT,
            "standing_envelope_decision_in_progress",
            "a revocation of this envelope is already running",
        );
    };
    let outcome = authority
        .revoke(&grant_hash_hex, operator_passphrase.as_str())
        .await;
    drop(operator_passphrase);
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(failure) => return authority_refusal(failure, "revoke the standing grant"),
    };
    // On chain first, then the local fence: the next draw refuses here before any wallet call.
    let fenced_lease = {
        let connectors = read_record_dir(ctx.data_dir, "connectors");
        connectors
            .into_iter()
            .find(|c| c["connector_id"].as_str() == Some(connector_id.as_str()))
            .and_then(|mut connector| {
                let lease = connector.get_mut("standing_lease")?;
                if lease.get("standing_envelope_id").and_then(Value::as_str) != Some(id) {
                    return None;
                }
                lease["status"] = json!("revoked");
                lease["revoked_at"] = json!(iso_now());
                let lease_copy = lease.clone();
                super::persist_record(ctx.data_dir, "connectors", &connector_id, &connector)
                    .ok()
                    .map(|_| lease_copy)
            })
    };
    let revocation = json!({
        "kind": "authority_revocation",
        "chain_revocation": "committed",
        "standing_grant_status": outcome.get("standing_grant_status").cloned().unwrap_or(Value::Null),
        "revoked_by": ctx.decided_by,
        "reason": reason,
        "connection_fenced": fenced_lease.is_some(),
    });
    let stored = {
        let _guard = lock_records();
        match read_envelope_record(ctx.data_dir, id) {
            Ok(Some(mut current)) => {
                current["status"] = json!("revoked");
                if current.get("revoked_at").is_none_or(Value::is_null) {
                    current["revoked_at"] = json!(iso_now());
                }
                current["revocation"] = revocation.clone();
                write_envelope_record(ctx.data_dir, id, &current)
            }
            _ => Err("the record vanished while revoking".to_string()),
        }
    };
    if let Err(message) = stored {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_envelope_not_durable",
            format!("{message}; the grant IS revoked on the authority node"),
        );
    }
    reply(
        StatusCode::OK,
        json!({
            "ok": true,
            "standing_envelope_id": id,
            "connector_id": connector_id,
            "status": "revoked",
            "revocation": revocation,
            "standing_lease": { "status": "revoked" },
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

// ---- routes -----------------------------------------------------------------------------------

/// The deployment coordinates a decision needs, or the typed reason this daemon cannot decide.
fn deployment_coordinates() -> Result<(String, String, StandingAuthority), Reply> {
    let Some(authority) = StandingAuthority::configured() else {
        return Err(refuse(
            StatusCode::NOT_IMPLEMENTED,
            "authority_decider_not_configured",
            format!(
                "this daemon has no deployment authority to decide with ({} and {} must name the authority binary and its node's state directory)",
                super::authority_challenge_routes::AUTHORITY_BINARY_ENV,
                super::authority_challenge_routes::AUTHORITY_STATE_DIR_ENV
            ),
        ));
    };
    let principal_ref = std::env::var("IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            refuse(
                StatusCode::NOT_IMPLEMENTED,
                "authority_principal_not_configured",
                "IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF is required: a standing envelope names the deployment principal it draws for",
            )
        })?;
    let audience = super::wallet_network_capability_client::capability_account_id_hex()
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_GATEWAY,
                "capability_audience_unavailable",
                "the daemon has no wallet capability account; a grant without the audience can never be drawn",
            )
        })?;
    Ok((principal_ref, audience, authority))
}

/// POST /v1/hypervisor/authority/standing-envelopes — the operator's standing decision for one
/// connection: bounds in, the sealed authority mints and records, the daemon binds.
pub(crate) async fn handle_standing_envelope_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    // The raw body carries the passphrase: parse it, then wipe the buffer before anything else.
    let mut raw: Vec<u8> = body.into();
    let parsed = parse_create_body(&raw);
    raw.zeroize();
    drop(raw);
    // Identity FIRST: an unauthenticated caller learns nothing.
    let (decided_by, principal_id) = match require_operator(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let body = match parsed {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (principal_ref, audience, authority) = match deployment_coordinates() {
        Ok(coordinates) => coordinates,
        Err(response) => return response,
    };
    let ctx = DecisionContext {
        data_dir: &st.data_dir,
        decided_by: &decided_by,
        principal_id: &principal_id,
        principal_ref: &principal_ref,
        audience_hex: &audience,
    };
    create_standing_envelope(&ctx, body, &authority).await
}

/// POST /v1/hypervisor/authority/standing-envelopes/:id/revoke — revoke on the authority node with
/// the passphrase, then fence the connection.
pub(crate) async fn handle_standing_envelope_revoke(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Reply {
    let mut raw: Vec<u8> = body.into();
    let parsed = parse_revoke_body(&raw);
    raw.zeroize();
    drop(raw);
    let (decided_by, principal_id) = match require_operator(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let body = match parsed {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !valid_envelope_id(&id) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "standing_envelope_id_invalid",
            "standing envelope ids are sse_<32 lowercase hex>",
        );
    }
    let Some(authority) = StandingAuthority::configured() else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "authority_decider_not_configured",
            "this daemon has no deployment authority to revoke with; the passphrase-free local fence is DELETE /v1/hypervisor/connectors/:id/standing-lease",
        );
    };
    let ctx = DecisionContext {
        data_dir: &st.data_dir,
        decided_by: &decided_by,
        principal_id: &principal_id,
        principal_ref: "",
        audience_hex: "",
    };
    revoke_standing_envelope(&ctx, &id, body, &authority).await
}

/// GET /v1/hypervisor/authority/standing-envelopes — every envelope this daemon decided (public
/// view), newest first, and whether this daemon can decide one.
pub(crate) async fn handle_standing_envelope_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    if super::lifecycle_routes::resolve_principal(&st.data_dir, &headers).is_none() {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({ "ok": false, "code": "hypervisor.authentication_required", "message": "an authenticated session is required" }),
        );
    }
    let mut envelopes: Vec<Value> = read_record_dir(&st.data_dir, STANDING_ENVELOPE_FAMILY)
        .iter()
        .filter(|record| {
            record.get("schema_version").and_then(Value::as_str) == Some(RECORD_SCHEMA)
        })
        .map(public_view)
        .collect();
    envelopes.sort_by(|a, b| {
        let key = |v: &Value| {
            v.get("created_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        key(b).cmp(&key(a))
    });
    reply(
        StatusCode::OK,
        json!({
            "ok": true,
            "standing_envelopes": envelopes,
            "decidable": StandingAuthority::configured().is_some(),
            "create_route": "/v1/hypervisor/authority/standing-envelopes",
            "create_requires": ["operator_passphrase"],
            "runtimeTruthSource": "daemon-runtime",
        }),
    )
}

/// GET /v1/hypervisor/authority/standing-envelopes/:id — one envelope (public view).
pub(crate) async fn handle_standing_envelope_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    if super::lifecycle_routes::resolve_principal(&st.data_dir, &headers).is_none() {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({ "ok": false, "code": "hypervisor.authentication_required", "message": "an authenticated session is required" }),
        );
    }
    if !valid_envelope_id(&id) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "standing_envelope_id_invalid",
            "standing envelope ids are sse_<32 lowercase hex>",
        );
    }
    match read_envelope_record(&st.data_dir, &id) {
        Ok(Some(record)) => reply(
            StatusCode::OK,
            json!({ "ok": true, "standing_envelope": public_view(&record), "runtimeTruthSource": "daemon-runtime" }),
        ),
        Ok(None) => refuse(
            StatusCode::NOT_FOUND,
            "standing_envelope_not_found",
            "no standing envelope has this id",
        ),
        Err(message) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_envelope_unreadable",
            message,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
    use ioi_types::app::action::StandingApprovalGrant;
    use ioi_types::app::{account_id_from_key_material, SignatureSuite};

    const PASS: &str = "standing-operator-passphrase";
    const PRINCIPAL: &str = "domain://standing-test";

    /// An in-process stand-in for the sealed authority: it holds a test approver key, opens it
    /// only with the right passphrase, mints exactly what the evidence determines, and keeps a log
    /// of every act it RECORDED, so a test can prove a refused act recorded nothing.
    pub(crate) struct FakeAuthority {
        approver_seed: [u8; 32],
        pub(crate) audience: [u8; 32],
        pub(crate) chain_offset_ms: i64,
        pub(crate) recorded: Mutex<Vec<Value>>,
        pub(crate) revoked: Mutex<Vec<String>>,
    }

    impl FakeAuthority {
        fn new() -> Self {
            Self {
                approver_seed: [7u8; 32],
                audience: [0xab; 32],
                chain_offset_ms: -2_000,
                recorded: Mutex::new(Vec::new()),
                revoked: Mutex::new(Vec::new()),
            }
        }

        fn keypair(&self) -> Ed25519KeyPair {
            let private = Ed25519PrivateKey::from_bytes(&self.approver_seed).unwrap();
            Ed25519KeyPair::from_private_key(&private).unwrap()
        }

        pub(crate) fn custody(&self) -> CustodyEvidence {
            CustodyEvidence {
                key_path_hash: sha256_ref(b"/state/keys/approver.seed.sealed"),
                credential_id_hash: sha256_ref(&self.keypair().public_key().to_bytes()),
            }
        }

        fn read(path: &str) -> Value {
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        }

        pub(crate) fn act(
            &self,
            args: &[String],
            passphrase: Option<&str>,
        ) -> Result<Value, AuthorityFailure> {
            let flag = |name: &str| {
                args.iter()
                    .position(|arg| arg == name)
                    .and_then(|index| args.get(index + 1))
                    .cloned()
                    .unwrap_or_default()
            };
            match args[0].as_str() {
                "chain-timestamp" => Ok(json!({
                    "ok": true,
                    "chain_timestamp_ms": (now_ms() as i64 + self.chain_offset_ms).max(1) as u64,
                })),
                "record-standing-approval" => {
                    if passphrase != Some(PASS) {
                        return Err(AuthorityFailure::PassphraseRefused);
                    }
                    let envelope = Self::read(&flag("--envelope-file"));
                    let context = Self::read(&flag("--context-file"));
                    let factor = Self::read(&flag("--factor-file"));
                    let mut context_material = APPROVAL_CONTEXT_DOMAIN.to_vec();
                    context_material.extend_from_slice(&jcs(&context).unwrap());
                    let hash = |value: &Value| ref_bytes(value.as_str().unwrap()).unwrap();
                    let issued = context["issued_at"].as_str().unwrap();
                    let issued_at_ms = time::OffsetDateTime::parse(
                        issued,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map(|at| (at.unix_timestamp_nanos() / 1_000_000) as u64)
                    .unwrap();
                    let keypair = self.keypair();
                    let public_key = keypair.public_key().to_bytes();
                    let mut grant = StandingApprovalGrant {
                        schema_version: 1,
                        authority_id: account_id_from_key_material(
                            SignatureSuite::ED25519,
                            &public_key,
                        )
                        .unwrap(),
                        standing_envelope_hash: hash(&envelope["body_hash"]),
                        policy_hash: hash(&envelope["trajectory_policy_hash"]),
                        audience: self.audience,
                        nonce: rand::random(),
                        counter: 1,
                        issued_at_ms,
                        expires_at_ms: envelope["expires_at_ms"].as_u64().unwrap(),
                        max_usages: envelope["aggregate_bounds"]["max_usages"].as_u64().unwrap()
                            as u32,
                        max_cumulative_deposit_microusd: envelope["aggregate_bounds"]
                            ["max_cumulative_deposit_microusd"]
                            .as_u64()
                            .unwrap(),
                        max_cumulative_spend_microusd: envelope["aggregate_bounds"]
                            ["max_cumulative_spend_microusd"]
                            .as_u64()
                            .unwrap(),
                        review_receipt_hash: hash(&context["policy_decision_receipt_hash"]),
                        approval_ceremony_context_hash: sha256_bytes(&context_material),
                        auth_factor_receipt_hash: hash(&factor["receipt_hash"]),
                        approver_public_key: public_key,
                        approver_sig: Vec::new(),
                        approver_suite: SignatureSuite::ED25519,
                    };
                    grant.approver_sig = keypair
                        .sign(&grant.signing_bytes().unwrap())
                        .unwrap()
                        .to_bytes()
                        .to_vec();
                    let grant_hash = hex::encode(grant.artifact_hash().unwrap());
                    let grant_value = serde_json::to_value(&grant).unwrap();
                    self.recorded.lock().unwrap().push(grant_value.clone());
                    Ok(
                        json!({ "ok": true, "recorded": "committed", "minted": true, "standing_grant_hash": grant_hash, "custody_tier": "deployment_local_operator", "standing_approval_grant": grant_value }),
                    )
                }
                "revoke-standing-approval" => {
                    if passphrase != Some(PASS) {
                        return Err(AuthorityFailure::PassphraseRefused);
                    }
                    let grant_hash = flag("--grant-hash");
                    self.revoked.lock().unwrap().push(grant_hash.clone());
                    Ok(
                        json!({ "ok": true, "standing_grant_hash": grant_hash, "standing_grant_status": "revoked" }),
                    )
                }
                other => Err(AuthorityFailure::Refused(format!("unknown act {other}"))),
            }
        }
    }

    fn temp_data_dir(label: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "ioi-standing-envelopes-{label}-{}",
            hex::encode(rand::random::<[u8; 6]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    const CONNECTOR: &str = "conn_0123456789abcdef";

    fn seed_connector(data_dir: &str) {
        let connector = json!({
            "connector_id": CONNECTOR,
            "service": "ping-service",
            "name": "ping",
            "kind": "bearer",
            "base_url": "http://127.0.0.1:9/api",
            "allowed_tools": [{ "name": "ping", "method": "GET", "path": "/ping" }],
        });
        crate::persist_record(data_dir, "connectors", CONNECTOR, &connector).unwrap();
    }

    fn connector_lease(data_dir: &str) -> Value {
        read_record_dir(data_dir, "connectors")
            .into_iter()
            .find(|c| c["connector_id"].as_str() == Some(CONNECTOR))
            .map(|c| c["standing_lease"].clone())
            .unwrap_or(Value::Null)
    }

    fn body(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    fn create_body(passphrase: &str, max_usages: u64, budget_usd: f64) -> CreateBody {
        parse_create_body(&body(json!({
            "connector_id": CONNECTOR,
            "max_usages": max_usages,
            "budget_usd": budget_usd,
            "expires_hours": 2,
            "operator_passphrase": passphrase,
        })))
        .ok()
        .unwrap()
    }

    fn context<'a>(data_dir: &'a str, audience: &'a str) -> DecisionContext<'a> {
        DecisionContext {
            data_dir,
            decided_by: "user://operator",
            principal_id: "operator",
            principal_ref: PRINCIPAL,
            audience_hex: audience,
        }
    }

    fn envelope_records(data_dir: &str) -> Vec<Value> {
        read_record_dir(data_dir, STANDING_ENVELOPE_FAMILY)
    }

    #[test]
    fn a_request_carries_bounds_only_and_every_coordinate_is_refused() {
        for field in [
            "envelope",
            "grant",
            "policy_hash",
            "trajectory_policy_hash",
            "audience",
            "principal_ref",
            "expires_at_ms",
            "nonce",
            "approval_ceremony_context",
            "auth_factor_receipt",
            "standing_envelope_ref",
        ] {
            let mut request =
                json!({ "connector_id": CONNECTOR, "max_usages": 2, "operator_passphrase": PASS });
            request[field] = json!("x");
            let refused = parse_create_body(&body(request)).err().expect(field);
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{field}");
            assert_eq!(
                refused.1 .0["error"]["code"], "standing_envelope_coordinates_are_daemon_owned",
                "{field}"
            );
            assert!(
                !serde_json::to_string(&refused.1 .0).unwrap().contains(PASS),
                "a refusal never echoes the passphrase"
            );
        }
        let unknown = parse_create_body(&body(
            json!({ "connector_id": CONNECTOR, "max_usages": 2, "colour": "red" }),
        ))
        .err()
        .unwrap();
        assert_eq!(
            unknown.1 .0["error"]["code"],
            "standing_envelope_body_field_refused"
        );
        for bad in [json!(0), json!(1.5), json!(2_000_000), json!("many")] {
            let refused = parse_create_body(&body(
                json!({ "connector_id": CONNECTOR, "max_usages": bad }),
            ))
            .err()
            .unwrap();
            assert_eq!(
                refused.1 .0["error"]["code"],
                "standing_envelope_bounds_invalid"
            );
        }
        let over = parse_create_body(&body(json!({ "connector_id": CONNECTOR, "max_usages": 2, "operations": ["session_execute", "wipe"] })))
            .err()
            .unwrap();
        assert_eq!(
            over.1 .0["error"]["code"],
            "standing_envelope_bounds_invalid"
        );
        // A form's strings parse, and the bounds are the attach form's arithmetic.
        let parsed = parse_create_body(&body(json!({ "connector_id": CONNECTOR, "max_usages": "4", "budget_usd": "0.02", "expires_hours": "3", "operator_passphrase": PASS })))
            .ok()
            .unwrap();
        assert_eq!(parsed.operator_passphrase.as_str(), PASS);
        assert_eq!(parsed.bounds.max_usages, 4);
        assert_eq!(parsed.bounds.budget_microusd, 20_000);
        assert_eq!(parsed.bounds.per_operation_microusd, 5_000);
        assert_eq!(parsed.bounds.expires_in_ms, 3 * 3_600_000);
        assert_eq!(
            parsed.bounds.operations,
            vec!["session_execute", "connector_invoke"]
        );
        let revoke = parse_revoke_body(br#"{"reason":"done","grant_hash":"ab"}"#)
            .err()
            .unwrap();
        assert_eq!(
            revoke.1 .0["error"]["code"],
            "standing_envelope_coordinates_are_daemon_owned"
        );
        assert!(parse_revoke_body(b"").is_ok());
    }

    #[tokio::test]
    async fn a_wrong_passphrase_records_nothing_and_the_right_one_binds_exactly_the_derivation() {
        let dir = temp_data_dir("create");
        seed_connector(&dir);
        let fake = Arc::new(FakeAuthority::new());
        let audience = hex::encode(fake.audience);
        let authority = StandingAuthority::Fake(fake.clone());
        let ctx = context(&dir, &audience);

        let missing = create_standing_envelope(&ctx, create_body("", 2, 0.02), &authority).await;
        assert_eq!(missing.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            missing.1 .0["error"]["code"],
            "operator_passphrase_required"
        );
        let wrong =
            create_standing_envelope(&ctx, create_body("not-the-operator", 2, 0.02), &authority)
                .await;
        assert_eq!(wrong.0, StatusCode::FORBIDDEN);
        assert_eq!(wrong.1 .0["error"]["code"], "operator_passphrase_refused");
        assert!(
            fake.recorded.lock().unwrap().is_empty(),
            "the authority recorded nothing"
        );
        assert!(
            envelope_records(&dir).is_empty(),
            "the daemon stored no envelope"
        );
        assert_eq!(
            connector_lease(&dir),
            Value::Null,
            "the connection stays unbounded"
        );

        let made = create_standing_envelope(&ctx, create_body(PASS, 2, 0.02), &authority).await;
        assert_eq!(made.0, StatusCode::OK, "{}", made.1 .0);
        let id = made.1 .0["standing_envelope_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(valid_envelope_id(&id));
        assert_eq!(fake.recorded.lock().unwrap().len(), 1);
        let lease = connector_lease(&dir);
        assert_eq!(lease["status"], "active");
        assert_eq!(lease["standing_envelope_id"], json!(id));
        assert_eq!(lease["bounds"]["max_usages"], 2);
        assert_eq!(lease["bounds"]["max_cumulative_spend_microusd"], 20_000);
        assert_eq!(lease["bounds"]["per_operation_spend_microusd"], 10_000);
        assert_eq!(lease["bounds"]["allowed_tools"], json!(["ping"]));
        // The lease the execute gate draws from is the unchanged M13.3 shape.
        assert!(
            super::super::lifecycle_routes::connector_active_standing_lease(
                &read_record_dir(&dir, "connectors")[0],
                now_ms()
            )
            .is_ok()
        );
        assert!(
            super::super::lifecycle_routes::standing_draw_from_connector_lease(&lease).is_some()
        );
        let record = read_envelope_record(&dir, &id).unwrap().unwrap();
        assert_eq!(record["status"], "active");
        assert_eq!(
            record["auth_factor_receipt"]["factor_kind"],
            "deployment_local_operator"
        );
        assert_eq!(record["envelope"]["principal_ref"], PRINCIPAL);
        assert_eq!(record["grant"], fake.recorded.lock().unwrap()[0]);
        assert!(!serde_json::to_string(&record).unwrap().contains(PASS));
        assert!(!serde_json::to_string(&made.1 .0).unwrap().contains(PASS));

        let twice = create_standing_envelope(&ctx, create_body(PASS, 2, 0.02), &authority).await;
        assert_eq!(twice.0, StatusCode::CONFLICT);
        assert_eq!(twice.1 .0["error"]["code"], "standing_lease_already_bound");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_authority_off_the_wall_clock_or_a_foreign_grant_binds_nothing() {
        let dir = temp_data_dir("clock");
        seed_connector(&dir);
        let mut deterministic = FakeAuthority::new();
        deterministic.chain_offset_ms = -(now_ms() as i64) + 1_000_000;
        let fake = Arc::new(deterministic);
        let audience = hex::encode(fake.audience);
        let authority = StandingAuthority::Fake(fake.clone());
        let refused = create_standing_envelope(
            &context(&dir, &audience),
            create_body(PASS, 2, 0.0),
            &authority,
        )
        .await;
        assert_eq!(refused.0, StatusCode::CONFLICT);
        assert_eq!(
            refused.1 .0["error"]["code"],
            "standing_envelope_requires_wall_clock_authority"
        );
        assert!(fake.recorded.lock().unwrap().is_empty());

        // A grant for another audience than the daemon derived is not bound.
        let fake = Arc::new(FakeAuthority::new());
        let authority = StandingAuthority::Fake(fake.clone());
        let other_audience = hex::encode([0xcd; 32]);
        let mismatch = create_standing_envelope(
            &context(&dir, &other_audience),
            create_body(PASS, 2, 0.0),
            &authority,
        )
        .await;
        assert_eq!(mismatch.0, StatusCode::BAD_GATEWAY);
        assert_eq!(mismatch.1 .0["error"]["code"], "authority_grant_mismatch");
        assert_eq!(connector_lease(&dir), Value::Null);
        assert!(envelope_records(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn draws_count_down_and_an_exhausted_expired_or_revoked_envelope_refuses() {
        let dir = temp_data_dir("draws");
        seed_connector(&dir);
        let fake = Arc::new(FakeAuthority::new());
        let audience = hex::encode(fake.audience);
        let authority = StandingAuthority::Fake(fake.clone());
        let ctx = context(&dir, &audience);
        // Two usages, a budget of three metered units: usages bind first.
        let made = create_standing_envelope(&ctx, create_body(PASS, 2, 0.03), &authority).await;
        assert_eq!(made.0, StatusCode::OK, "{}", made.1 .0);
        let id = made.1 .0["standing_envelope_id"]
            .as_str()
            .unwrap()
            .to_string();
        let lease = connector_lease(&dir);
        let view = |dir: &str| public_view(&read_envelope_record(dir, &id).unwrap().unwrap());
        assert_eq!(view(&dir)["remaining"]["usages"], 2);
        assert_eq!(precheck_draw(&dir, &lease, now_ms()), Ok(()));
        note_draw(&dir, &lease, "authority-admission-intents/a");
        assert_eq!(view(&dir)["remaining"]["usages"], 1);
        assert_eq!(view(&dir)["remaining"]["spend_microusd"], 15_000);
        assert_eq!(precheck_draw(&dir, &lease, now_ms()), Ok(()));
        note_draw(&dir, &lease, "authority-admission-intents/b");
        assert_eq!(view(&dir)["remaining"]["usages"], 0);
        assert_eq!(
            view(&dir)["drawn"]["draw_refs"],
            json!([
                "authority-admission-intents/a",
                "authority-admission-intents/b"
            ])
        );
        assert_eq!(
            precheck_draw(&dir, &lease, now_ms()),
            Err(("standing_envelope_exceeded", "max_usages"))
        );
        // Budget: raise the usage bound in the record to show the spend bound refuses on its own.
        {
            let mut record = read_envelope_record(&dir, &id).unwrap().unwrap();
            record["bounds"]["max_usages"] = json!(10);
            record["drawn"]["spend_microusd"] = json!(25_000);
            write_envelope_record(&dir, &id, &record).unwrap();
        }
        assert_eq!(
            precheck_draw(&dir, &lease, now_ms()),
            Err((
                "standing_envelope_exceeded",
                "max_cumulative_spend_microusd"
            ))
        );
        let expiry = read_envelope_record(&dir, &id).unwrap().unwrap()["bounds"]["expires_at_ms"]
            .as_u64()
            .unwrap();
        assert_eq!(
            precheck_draw(&dir, &lease, expiry + 1),
            Err(("standing_envelope_exceeded", "expired"))
        );
        assert!(
            super::super::lifecycle_routes::connector_active_standing_lease(
                &read_record_dir(&dir, "connectors")[0],
                expiry + 1
            )
            .is_err(),
            "the connection's lease is expired to the execute gate too"
        );
        // A lease this module never issued is the wallet's alone.
        assert_eq!(
            precheck_draw(&dir, &json!({ "status": "active" }), now_ms()),
            Ok(())
        );

        // Revoke: a wrong passphrase revokes nothing, the right one revokes on chain and fences.
        let revoke = |passphrase: &str| {
            parse_revoke_body(&body(
                json!({ "reason": "test", "operator_passphrase": passphrase }),
            ))
            .ok()
            .unwrap()
        };
        let wrong =
            revoke_standing_envelope(&ctx, &id, revoke("wrong-passphrase"), &authority).await;
        assert_eq!(wrong.0, StatusCode::FORBIDDEN);
        assert!(fake.revoked.lock().unwrap().is_empty());
        assert_eq!(connector_lease(&dir)["status"], "active");
        let done = revoke_standing_envelope(&ctx, &id, revoke(PASS), &authority).await;
        assert_eq!(done.0, StatusCode::OK, "{}", done.1 .0);
        assert_eq!(fake.revoked.lock().unwrap().len(), 1);
        assert_eq!(
            format!("sha256:{}", fake.revoked.lock().unwrap()[0]),
            lease["grant_hash_ref"].as_str().unwrap()
        );
        assert_eq!(connector_lease(&dir)["status"], "revoked");
        assert_eq!(
            super::super::lifecycle_routes::connector_active_standing_lease(
                &read_record_dir(&dir, "connectors")[0],
                now_ms()
            )
            .err(),
            Some("standing_lease_revoked")
        );
        assert_eq!(
            precheck_draw(&dir, &lease, now_ms()),
            Err(("standing_lease_revoked", "status"))
        );
        let record = read_envelope_record(&dir, &id).unwrap().unwrap();
        assert_eq!(record["status"], "revoked");
        assert_eq!(record["revocation"]["chain_revocation"], "committed");
        let again = revoke_standing_envelope(&ctx, &id, revoke(PASS), &authority).await;
        assert_eq!(again.0, StatusCode::CONFLICT);
        // A successor may now be decided on the same connection.
        let successor = create_standing_envelope(&ctx, create_body(PASS, 1, 0.0), &authority).await;
        assert_eq!(successor.0, StatusCode::OK, "{}", successor.1 .0);
        assert_ne!(successor.1 .0["standing_envelope_id"], json!(id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_derivation_is_contract_valid_and_self_consistent() {
        let fake = FakeAuthority::new();
        let connector = json!({
            "connector_id": CONNECTOR, "service": "ping-service", "kind": "bearer",
            "base_url": "http://127.0.0.1:9/api", "allowed_tools": [{ "name": "ping" }],
        });
        let bounds = parse_bounds(
            json!({ "connector_id": CONNECTOR, "max_usages": 3, "budget_usd": 0.03, "tools": "ping" })
                .as_object()
                .unwrap(),
        )
        .ok()
        .unwrap();
        let now = 1_790_000_000_000;
        let derived = derive_standing_evidence(&DerivationInputs {
            connector: &connector,
            bounds: &bounds,
            principal_ref: PRINCIPAL,
            audience_hex: &hex::encode(fake.audience),
            decided_by: "user://operator",
            now_ms: now,
            custody: &fake.custody(),
            marker: "0011223344556677",
        })
        .unwrap();
        assert_eq!(derived.context["issued_at"], "2026-09-21T14:13:19.000Z");
        assert_eq!(derived.context["expires_at"], "2026-09-21T14:18:19.000Z");
        assert_eq!(derived.factor["created_at"], derived.context["issued_at"]);
        assert_eq!(derived.expected.issued_at_ms, now - 1_000);
        assert_eq!(derived.envelope["expires_at_ms"], now + DEFAULT_EXPIRES_MS);
        assert_eq!(
            derived.context["authorization_subject"]["subject_hash"],
            derived.envelope["body_hash"]
        );
        assert_eq!(
            derived.context["policy_hash"],
            derived.envelope["trajectory_policy_hash"]
        );
        assert_eq!(
            derived.context["required_auth_factor_posture_refs"][0],
            "auth_factor://deployment-local-operator/deployment-host%3A%2F%2Fstanding-test"
        );
        let mut unhashed = derived.factor.clone();
        unhashed.as_object_mut().unwrap().remove("receipt_hash");
        assert_eq!(
            format!(
                "sha256:{}",
                hex::encode(sha256_bytes(&jcs(&unhashed).unwrap()))
            ),
            derived.factor["receipt_hash"].as_str().unwrap()
        );
        assert!(
            derived.envelope["not_before_ms"].as_u64().unwrap() <= derived.expected.issued_at_ms
        );
    }
}
