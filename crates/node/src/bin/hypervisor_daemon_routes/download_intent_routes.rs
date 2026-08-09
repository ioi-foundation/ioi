//! DownloadIntent plane (W1.3) — short-lived, rights-bound authorization to fetch one exact
//! artifact payload. Canonical contract: `schema://ioi/foundations/download-intent/v1`
//! (docs/architecture/foundations/objects/evidence-and-delivery.md §DownloadIntent).
//!
//! Hard boundaries (enforced, not decorative):
//!   * The intent id is NOT a bearer token. Every read and every delivery re-resolves request
//!     identity and re-checks the principal binding, owner scope, expiry, and revocation.
//!   * The intent commits to the exact `payload_sha256`; delivery re-hashes the bytes against
//!     that commitment before serving. A mismatch is a typed conflict, never a substitution.
//!   * Every content delivery is admitted to the intent's owner-scoped stream BEFORE bytes are
//!     served, so the audit trail cannot claim less than what was delivered.
//!   * The admitted payload carries the expiry DURATION only, never a clock — a clock in the
//!     payload makes every idempotent retry byte-different, silently defeating replay. The
//!     deadline is stamped once at first projection, and a replayed mint returns the stored
//!     record rather than recomputing it, so a retry can never extend access.
//!   * `managed_backup_export` is the one artifact kind today. An unlisted kind is refused at
//!     mint, not interpreted. The legacy one-off `/v1/hypervisor/backup-exports/:token` lane
//!     keeps serving untouched; it retires at the Environments/Operations surface cutover.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::{persist_record, DaemonState};

const INTENT_NAMESPACE: &str = "hypervisor-download-intents";
const KIND_INTENT: &str = "download-intents";
const SCHEMA_VERSION: &str = "ioi.foundations.download_intent.v1";
const CONTRACT_ID: &str = "schema://ioi/foundations/download-intent/v1";
/// The one artifact kind this plane delivers today (owner ruling in evidence-and-delivery.md).
const ARTIFACT_KINDS: &[&str] = &["managed_backup_export"];
/// Mint expiry bounds — the same ceiling the backup-export precedent enforces.
const MAX_EXPIRES_IN_SECONDS: u64 = 3600;

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

fn load(data_dir: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(KIND_INTENT)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{:x}", sha2::Sha256::digest(bytes))
}

/// Strip projection-only facts before admitting. A payload carrying the clock or its own
/// stream head is byte-different on every retry, so the idempotency key stops matching.
fn without_projection_facts(record: &Value) -> Value {
    let mut copy = record.clone();
    if let Some(map) = copy.as_object_mut() {
        map.remove("created_at");
        map.remove("updated_at");
        map.remove("admitted_head");
        map.remove("expires_at_ms");
    }
    copy
}

fn project_admission(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    // Projection-time stamp, never part of the admitted payload. The shared write path admits
    // with `recorded_at_ms: 0` (a clock in the admitted bytes would break replay), so the
    // admitted stamp is not a usable wall time here; replays short-circuit to the stored
    // record before reaching any projection, so this clock read never rewrites history.
    record["updated_at"] = json!(super::iso_now());
}

/// Persist a projection whose transition is already admitted. A discarded write here is the
/// both-tests defect: success over state no later read would find.
fn project_or_fail(data_dir: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, KIND_INTENT, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "download_intent_persistence_failed",
            "the transition is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

fn intent_resource_ref(id: &str) -> String {
    format!("download-intent://{id}")
}

/// The caller-facing view: the record plus the derived effective state. Expiry is judged
/// against the live clock at read time — a stored "expired" status would go stale.
fn effective_state(record: &Value) -> &'static str {
    if record["status"].as_str() == Some("revoked") {
        return "revoked";
    }
    if record["expires_at_ms"].as_u64().unwrap_or(0) <= now_ms() {
        return "expired";
    }
    "active"
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
}

/// POST /v1/hypervisor/download-intents — mint a rights-bound intent over an admitted backup
/// export payload. Identity first; the rights check is the SAME admission scope the backup
/// family itself enforces, re-run here, not inherited from the caller's claim.
pub(crate) async fn handle_download_intent_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    mint_download_intent(&st.data_dir, &caller, &body)
}

/// The mint, with identity already resolved (the `capture_environment_backup` split pattern:
/// testable against a real tempdir and the real admission chain, byte-identical behavior).
fn mint_download_intent(data_dir: &str, caller: &WriteCaller, body: &Value) -> Reply {
    let artifact_kind = str_field(body, "artifact_kind");
    if !ARTIFACT_KINDS.contains(&artifact_kind) {
        return bad(
            StatusCode::BAD_REQUEST,
            "download_intent_artifact_kind_unsupported",
            format!("artifact_kind must be one of {ARTIFACT_KINDS:?}; an unlisted kind is refused, not interpreted"),
        );
    }
    let backup_id = str_field(body, "backup_ref");
    if backup_id.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "download_intent_artifact_required",
            "backup_ref must name the admitted backup the intent delivers from",
        );
    }
    let expires_in_seconds = body
        .get("expires_in_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if expires_in_seconds == 0 || expires_in_seconds > MAX_EXPIRES_IN_SECONDS {
        return bad(
            StatusCode::BAD_REQUEST,
            "download_intent_expiry_invalid",
            format!("expires_in_seconds must be between 1 and {MAX_EXPIRES_IN_SECONDS}"),
        );
    }
    // Rights admission: resolve the backup through the caller's OWN authorized scope set and
    // byte-verify the payload commitment before any intent exists.
    let (backup, _scope) = match super::managed_runtime_routes::authorized_backup_by_id(
        data_dir,
        &caller.identity,
        backup_id,
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let verification = match super::managed_runtime_routes::verify_backup(data_dir, &backup) {
        Ok(verification) => verification,
        Err(reply) => return reply,
    };
    let Some(state_root) = verification["state_root"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "download_intent_payload_unresolved",
            "backup verification did not resolve an exact payload state root",
        );
    };
    let Some(backup_ref) = backup["backup_ref"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "download_intent_artifact_unresolved",
            "the admitted backup record carries no backup_ref",
        );
    };
    let id = replay_stable_id("dlint", &caller.owner_ref, &caller.idempotency_key);
    let record = json!({
        "schema_version": SCHEMA_VERSION,
        "intent_id": intent_resource_ref(&id),
        "artifact": {
            "artifact_kind": artifact_kind,
            "artifact_ref": backup_ref,
            "payload_sha256": state_root,
            "media_type": "application/x-tar",
        },
        "principal_ref": caller.identity.principal_ref,
        "owner_ref": caller.owner_ref,
        "rights": {
            "scope_kind": super::managed_runtime_routes::BACKUP_SCOPE_KIND,
            "resource_ref": backup_ref,
        },
        "status": "active",
        "revocation": null,
        "delivery": { "supports_ranges": true, "delivery_admissions": 0 },
        // The admitted payload carries the DURATION only — replay-stable bytes. The deadline
        // is stamped once, at first projection; a replayed mint returns the stored record and
        // never recomputes it (the shared write path admits with recorded_at_ms 0, so there is
        // no admitted wall time to derive from).
        "expires_in_seconds": expires_in_seconds,
    });
    let commit = match admit_owner_scoped_write(
        data_dir,
        caller,
        INTENT_NAMESPACE,
        KIND_INTENT,
        &intent_resource_ref(&id),
        "download_intent.create",
        None,
        &without_projection_facts(&record),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if commit.replayed {
        // The mint already projected: the stored record — with its ORIGINAL deadline — is the
        // one truth. Recomputing expiry on replay would quietly extend access on every retry.
        if let Some(existing) = load(data_dir, &id) {
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "intent": existing,
                    "effective_state": effective_state(&existing),
                    "content_path": format!("/v1/hypervisor/download-intents/{id}/content"),
                })),
            );
        }
        // Admitted but never projected (crash between admit and persist): fall through and
        // reconcile the projection now, stamping from this clock — the documented recovery.
    }
    let mut record = record;
    if let Some(map) = record.as_object_mut() {
        map.remove("expires_in_seconds");
    }
    record["expires_at_ms"] =
        json!(now_ms().saturating_add(expires_in_seconds.saturating_mul(1000)));
    record["created_at"] = json!(super::iso_now());
    project_admission(&mut record, &commit);
    // Close the loop against the registered contract: a projection this plane cannot validate
    // is refused, not persisted.
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            CONTRACT_ID,
            &record,
        )
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "download_intent_contract_invalid",
            error,
        );
    }
    if let Err(response) = project_or_fail(data_dir, &id, &record) {
        return response;
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "intent": record,
            "effective_state": effective_state(&record),
            "content_path": format!("/v1/hypervisor/download-intents/{id}/content"),
        })),
    )
}

/// Authorize a non-mint access to an existing intent: the intent is principal-bound AND
/// owner-scoped — both must hold, and a mismatch answers the same scope refusal the rest of
/// the estate uses (no existence oracle for another principal's intent id).
fn authorize_intent_access(
    identity: &super::substrate_store::RequestIdentity,
    record: &Value,
) -> Result<(), Reply> {
    let principal_matches =
        record["principal_ref"].as_str() == Some(identity.principal_ref.as_str());
    let tenant_authorized = record["owner_ref"]
        .as_str()
        .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref));
    if !principal_matches || !tenant_authorized {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    Ok(())
}

/// GET /v1/hypervisor/download-intents/:id
pub(crate) async fn handle_download_intent_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    // Identity FIRST: an unauthenticated caller is owed 401, never a 404 existence oracle.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(record) = load(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "download_intent_not_found",
            "no download intent exists at this id",
        );
    };
    if let Err(reply) = authorize_intent_access(&identity, &record) {
        return reply;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "intent": record, "effective_state": effective_state(&record) })),
    )
}

/// POST /v1/hypervisor/download-intents/:id/revoke — revocation stops all future deliveries.
/// Idempotent: revoking a revoked intent replays the admitted revocation rather than failing.
/// The revoking principal is resolved server-side (INV-37) — any principal with tenant
/// authority over the intent's owner scope may revoke; the bound principal is not the only
/// one who can close the tap.
pub(crate) async fn handle_download_intent_revoke(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // INV-37: the revoker identity is resolved server-side; a body carrying a WHO field is
    // refused before any state is read.
    let revoked_by = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor_ref) => actor_ref,
        Err((status, value)) => return (status, Json(value)),
    };
    revoke_download_intent(&st.data_dir, &caller, &revoked_by, &id)
}

/// The revocation, with identity already resolved (same split pattern as the mint).
fn revoke_download_intent(
    data_dir: &str,
    caller: &WriteCaller,
    revoked_by: &str,
    id: &str,
) -> Reply {
    let Some(record) = load(data_dir, id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "download_intent_not_found",
            "no download intent exists at this id",
        );
    };
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if record["status"].as_str() == Some("revoked") {
        return (
            StatusCode::OK,
            Json(
                json!({ "ok": true, "replayed": true, "intent": record, "effective_state": "revoked" }),
            ),
        );
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "download_intent_expected_head_required",
            "this record predates admitted mutation; it cannot be advanced without a head",
        );
    };
    let mut successor = record.clone();
    successor["status"] = json!("revoked");
    successor["revocation"] = json!({ "revoked_by": revoked_by });
    let commit = match admit_owner_scoped_write(
        data_dir,
        caller,
        INTENT_NAMESPACE,
        KIND_INTENT,
        &intent_resource_ref(id),
        "download_intent.revoke",
        Some(&expected_head),
        &without_projection_facts(&json!({
            "intent_id": successor["intent_id"],
            "status": "revoked",
            "revocation": { "revoked_by": revoked_by },
        })),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    successor["revocation"]["revoked_at"] = json!(super::iso_now());
    project_admission(&mut successor, &commit);
    if let Err(response) = project_or_fail(data_dir, id, &successor) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "intent": successor,
            "effective_state": effective_state(&successor),
        })),
    )
}

/// One admissible byte range. Only the single-range form `bytes=a-b` / `bytes=a-` is
/// supported; multipart ranges are refused typed rather than half-implemented.
fn parse_range(header: &str, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let header = header.trim();
    if header.is_empty() {
        return Ok(None);
    }
    let Some(spec) = header.strip_prefix("bytes=") else {
        return Err(());
    };
    if spec.contains(',') {
        return Err(());
    }
    let (start_raw, end_raw) = spec.split_once('-').ok_or(())?;
    let start_raw = start_raw.trim();
    let end_raw = end_raw.trim();
    if start_raw.is_empty() {
        // suffix form bytes=-N: last N bytes
        let n: u64 = end_raw.parse().map_err(|_| ())?;
        if n == 0 || len == 0 {
            return Err(());
        }
        let start = len.saturating_sub(n);
        return Ok(Some((start, len - 1)));
    }
    let start: u64 = start_raw.parse().map_err(|_| ())?;
    let end: u64 = if end_raw.is_empty() {
        len.saturating_sub(1)
    } else {
        end_raw.parse().map_err(|_| ())?
    };
    if start > end || end >= len {
        return Err(());
    }
    Ok(Some((start, end)))
}

/// GET /v1/hypervisor/download-intents/:id/content — hash-verified, range-capable delivery.
/// The delivery admission is written to the intent's stream BEFORE bytes leave the process.
pub(crate) async fn handle_download_intent_content(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    // Identity FIRST: an unauthenticated caller is owed 401, never a 404 existence oracle,
    // and no record byte is read before the caller is resolved.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error).into_response(),
    };
    let range_header = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    deliver_download_intent_content(&st.data_dir, &identity, &id, &range_header)
}

/// The delivery, with identity already resolved (same split pattern as the mint).
fn deliver_download_intent_content(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    id: &str,
    range_header: &str,
) -> Response {
    let Some(record) = load(data_dir, id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "download_intent_not_found",
            "no download intent exists at this id",
        )
        .into_response();
    };
    if let Err(reply) = authorize_intent_access(identity, &record) {
        return reply.into_response();
    }
    // Re-check the recorded rights basis against the caller's live scope set — rights may
    // have been revoked since mint, and the intent must not outlive them.
    if let Err(reply) = super::managed_runtime_routes::authorize_scope(
        data_dir,
        identity,
        record["rights"]["scope_kind"].as_str().unwrap_or(""),
        record["rights"]["resource_ref"].as_str().unwrap_or(""),
        None,
    ) {
        return reply.into_response();
    }
    match effective_state(&record) {
        "revoked" => {
            return bad(
                StatusCode::FORBIDDEN,
                "download_intent_revoked",
                "this intent is revoked; revocation stops all future deliveries",
            )
            .into_response()
        }
        "expired" => {
            return bad(
                StatusCode::GONE,
                "download_intent_expired",
                "this intent has expired; mint a fresh one",
            )
            .into_response()
        }
        _ => {}
    }
    let payload_sha256 = record["artifact"]["payload_sha256"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let bytes = match std::fs::read(super::managed_runtime_routes::material_path(
        data_dir,
        &payload_sha256,
    )) {
        Ok(bytes) if digest(&bytes) == payload_sha256 => bytes,
        Ok(_) => {
            return bad(
                StatusCode::CONFLICT,
                "download_intent_payload_digest_mismatch",
                "payload bytes do not match the intent's exact commitment; nothing is served",
            )
            .into_response()
        }
        Err(error) => {
            return bad(
                StatusCode::CONFLICT,
                "download_intent_payload_unavailable",
                error.to_string(),
            )
            .into_response()
        }
    };
    let total_len = bytes.len() as u64;
    let range = match parse_range(range_header, total_len) {
        Ok(range) => range,
        Err(()) => {
            return bad(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "download_intent_range_invalid",
                "only a single satisfiable bytes=a-b range is served",
            )
            .into_response()
        }
    };
    // Admit the delivery BEFORE serving. The admission key is content-derived (sequence +
    // exact range), so an identical concurrent fetch replays one admission instead of
    // double-counting, and a conflicting concurrent advance answers a typed 409.
    let sequence = record["delivery"]["delivery_admissions"]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(1);
    let range_label = range
        .map(|(start, end)| format!("{start}-{end}"))
        .unwrap_or_else(|| "full".to_string());
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "download_intent_expected_head_required",
            "this record predates admitted mutation; it cannot deliver without a head",
        )
        .into_response();
    };
    let caller = WriteCaller {
        identity: identity.clone(),
        owner_ref: record["owner_ref"].as_str().unwrap_or("").to_string(),
        idempotency_key: format!("delivery:{sequence}:{range_label}"),
    };
    let commit = match admit_owner_scoped_write(
        data_dir,
        &caller,
        INTENT_NAMESPACE,
        KIND_INTENT,
        &intent_resource_ref(id),
        "download_intent.delivery",
        Some(&expected_head),
        &json!({
            "intent_id": record["intent_id"],
            "delivery": { "sequence": sequence, "range": range_label },
        }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response.into_response(),
    };
    let mut successor = record;
    successor["delivery"]["delivery_admissions"] = json!(sequence);
    project_admission(&mut successor, &commit);
    if let Err(response) = project_or_fail(data_dir, id, &successor) {
        return response.into_response();
    }
    let filename = format!(
        "{}.tar",
        safe(
            successor["artifact"]["artifact_ref"]
                .as_str()
                .and_then(|r| r.rsplit('/').next())
                .unwrap_or("download")
        )
    );
    let media_type = successor["artifact"]["media_type"]
        .as_str()
        .unwrap_or("application/octet-stream")
        .to_string();
    let (status, body, content_range) = match range {
        Some((start, end)) => (
            StatusCode::PARTIAL_CONTENT,
            bytes[start as usize..=(end as usize)].to_vec(),
            Some(format!("bytes {start}-{end}/{total_len}")),
        ),
        None => (StatusCode::OK, bytes, None),
    };
    let mut response = (status, body).into_response();
    let headers_out = response.headers_mut();
    let set = |headers_out: &mut axum::http::HeaderMap, name: &'static str, value: String| {
        if let Ok(value) = axum::http::HeaderValue::from_str(&value) {
            headers_out.insert(name, value);
        }
    };
    set(headers_out, "content-type", media_type);
    set(headers_out, "accept-ranges", "bytes".to_string());
    set(headers_out, "etag", format!("\"{payload_sha256}\""));
    set(headers_out, "cache-control", "no-store".to_string());
    set(
        headers_out,
        "content-disposition",
        format!("attachment; filename=\"{filename}\""),
    );
    set(
        headers_out,
        "x-ioi-download-intent",
        successor["intent_id"].as_str().unwrap_or("").to_string(),
    );
    if let Some(content_range) = content_range {
        set(headers_out, "content-range", content_range);
    }
    response
}

#[cfg(test)]
mod download_intent_tests {
    use super::*;

    /// Every handler in this plane resolves identity BEFORE reading any record byte, and no
    /// production span carries a hardcoded principal or a client-suppliable identity header.
    #[test]
    fn every_download_intent_handler_resolves_identity_first() {
        let source = include_str!("download_intent_routes.rs");
        for handler in [
            "handle_download_intent_create",
            "handle_download_intent_get",
            "handle_download_intent_revoke",
            "handle_download_intent_content",
        ] {
            let marker = format!("pub(crate) async fn {handler}");
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("missing {handler}"));
            let remainder = &source[start..];
            let end = remainder[marker.len()..]
                .find("pub(crate) async fn ")
                .map(|offset| marker.len() + offset)
                .unwrap_or(remainder.len());
            let block = &remainder[..end];
            assert!(
                block.contains("headers: HeaderMap"),
                "{handler} must extract request headers"
            );
            assert!(
                block.contains("require_write_caller(")
                    || block.contains("resolve_request_identity("),
                "{handler} must resolve a real request principal"
            );
            let identity_at = block
                .find("require_write_caller(")
                .or_else(|| block.find("resolve_request_identity("))
                .unwrap();
            if let Some(load_at) = block.find("load(data_dir") {
                assert!(
                    identity_at < load_at,
                    "{handler} must resolve identity before reading the record"
                );
            }
        }
        let production = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];
        assert!(!production.contains("user://local-operator"));
        assert!(!production.contains("x-ioi-principal"));
    }

    #[test]
    fn range_parsing_serves_single_satisfiable_ranges_only() {
        // full fetch: no header
        assert_eq!(parse_range("", 100), Ok(None));
        // exact range
        assert_eq!(parse_range("bytes=0-9", 100), Ok(Some((0, 9))));
        // open end
        assert_eq!(parse_range("bytes=90-", 100), Ok(Some((90, 99))));
        // suffix
        assert_eq!(parse_range("bytes=-10", 100), Ok(Some((90, 99))));
        // out of bounds / inverted / multipart / non-bytes: typed refusals
        assert_eq!(parse_range("bytes=0-100", 100), Err(()));
        assert_eq!(parse_range("bytes=50-10", 100), Err(()));
        assert_eq!(parse_range("bytes=0-1,5-9", 100), Err(()));
        assert_eq!(parse_range("items=0-1", 100), Err(()));
        assert_eq!(parse_range("bytes=-0", 100), Err(()));
    }

    #[test]
    fn effective_state_derives_expiry_from_the_live_clock() {
        let mut record = serde_json::json!({
            "status": "active",
            "expires_at_ms": now_ms() + 60_000,
        });
        assert_eq!(effective_state(&record), "active");
        record["expires_at_ms"] = serde_json::json!(1u64);
        assert_eq!(effective_state(&record), "expired");
        // revocation wins over expiry: a revoked intent never reads as merely expired
        record["status"] = serde_json::json!("revoked");
        assert_eq!(effective_state(&record), "revoked");
    }

    #[test]
    fn admitted_payload_carries_no_projection_facts() {
        let record = serde_json::json!({
            "intent_id": "download-intent://dlint_x",
            "created_at": "2026-08-08T00:00:00Z",
            "updated_at": "2026-08-08T00:00:00Z",
            "admitted_head": "sha256:aa",
            "expires_at_ms": 123,
            "status": "active",
        });
        let admitted = without_projection_facts(&record);
        for clock_fact in ["created_at", "updated_at", "admitted_head", "expires_at_ms"] {
            assert!(
                admitted.get(clock_fact).is_none(),
                "{clock_fact} must not enter the admitted payload — it makes every retry byte-different"
            );
        }
        assert_eq!(admitted["status"], "active");
    }

    // ---------------- integration: the real admitted-backup fixture, the real admission chain --

    use super::super::managed_runtime_routes::backup_fixture::{
        admitted_backup_fixture, FIXTURE_PRINCIPAL, FIXTURE_TENANT,
    };
    use super::super::substrate_store::{request_identity_for_test, reset_handle_for_test};

    fn caller_for(principal: &str, key: &str) -> WriteCaller {
        WriteCaller {
            identity: request_identity_for_test(principal, [FIXTURE_TENANT.to_string()]),
            owner_ref: FIXTURE_TENANT.to_string(),
            idempotency_key: key.to_string(),
        }
    }

    fn mint_body(backup_id: &str, expires_in_seconds: u64) -> Value {
        serde_json::json!({
            "artifact_kind": "managed_backup_export",
            "backup_ref": backup_id,
            "expires_in_seconds": expires_in_seconds,
        })
    }

    fn intent_tail(minted: &Value) -> String {
        minted["intent"]["intent_id"]
            .as_str()
            .unwrap()
            .trim_start_matches("download-intent://")
            .to_owned()
    }

    fn body_bytes(response: Response) -> Vec<u8> {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec()
        })
    }

    fn body_json(response: Response) -> Value {
        serde_json::from_slice(&body_bytes(response)).unwrap()
    }

    #[test]
    fn mint_is_idempotent_and_expiry_derives_from_the_admitted_transition() {
        let fx = admitted_backup_fixture();
        let caller = caller_for(FIXTURE_PRINCIPAL, "mint-1");
        let (status, Json(minted)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 600));
        assert_eq!(status, StatusCode::CREATED, "{minted}");
        assert_eq!(
            minted["intent"]["artifact"]["payload_sha256"],
            serde_json::json!(fx.state_root),
            "the intent commits to the backup's exact verified payload"
        );
        assert_eq!(
            minted["intent"]["rights"]["scope_kind"],
            serde_json::json!(super::super::managed_runtime_routes::BACKUP_SCOPE_KIND)
        );
        let intent_id = minted["intent"]["intent_id"].as_str().unwrap().to_owned();
        let expires_at_ms = minted["intent"]["expires_at_ms"].as_u64().unwrap();

        // Exact replay resolves to the SAME intent and the SAME deadline — the expiry is a
        // projection of the admitted transition, not a fresh clock read.
        let (status, Json(replayed)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 600));
        assert_eq!(status, StatusCode::OK, "{replayed}");
        assert_eq!(replayed["replayed"], serde_json::json!(true));
        assert_eq!(replayed["intent"]["intent_id"].as_str().unwrap(), intent_id);
        assert_eq!(
            replayed["intent"]["expires_at_ms"].as_u64().unwrap(),
            expires_at_ms
        );
        reset_handle_for_test();
    }

    #[test]
    fn delivery_verifies_bytes_serves_ranges_and_audits_before_serving() {
        let fx = admitted_backup_fixture();
        let caller = caller_for(FIXTURE_PRINCIPAL, "mint-d");
        let (_, Json(minted)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 600));
        let id = intent_tail(&minted);

        let response = deliver_download_intent_content(&fx.data_dir, &fx.identity, &id, "");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("etag").unwrap().to_str().unwrap(),
            format!("\"{}\"", fx.state_root)
        );
        let bytes = body_bytes(response);
        assert_eq!(
            digest(&bytes),
            fx.state_root,
            "served bytes match the exact commitment"
        );
        let record = load(&fx.data_dir, &id).unwrap();
        assert_eq!(
            record["delivery"]["delivery_admissions"],
            serde_json::json!(1)
        );

        let response =
            deliver_download_intent_content(&fx.data_dir, &fx.identity, &id, "bytes=0-4");
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let content_range = response
            .headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(content_range.starts_with("bytes 0-4/"), "{content_range}");
        let slice = body_bytes(response);
        assert_eq!(slice.len(), 5);
        assert_eq!(
            slice,
            bytes[0..5],
            "a range serves the same verified payload"
        );
        let record = load(&fx.data_dir, &id).unwrap();
        assert_eq!(
            record["delivery"]["delivery_admissions"],
            serde_json::json!(2),
            "each delivery is admitted to the stream before bytes are served"
        );

        // An unsatisfiable range is a typed 416, and it admits nothing.
        let response =
            deliver_download_intent_content(&fx.data_dir, &fx.identity, &id, "bytes=0-999999999");
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        let record = load(&fx.data_dir, &id).unwrap();
        assert_eq!(
            record["delivery"]["delivery_admissions"],
            serde_json::json!(2)
        );
        reset_handle_for_test();
    }

    #[test]
    fn the_intent_id_is_not_a_bearer_token() {
        let fx = admitted_backup_fixture();
        let caller = caller_for(FIXTURE_PRINCIPAL, "mint-b");
        let (_, Json(minted)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 600));
        let id = intent_tail(&minted);

        // Another principal in the SAME tenant holds the id — delivery still refuses: the
        // intent is principal-bound, not tenant-bearer.
        let intruder = request_identity_for_test("user://intruder", [FIXTURE_TENANT.to_string()]);
        let response = deliver_download_intent_content(&fx.data_dir, &intruder, &id, "");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let record = load(&fx.data_dir, &id).unwrap();
        assert_eq!(
            record["delivery"]["delivery_admissions"],
            serde_json::json!(0),
            "a refused delivery admits nothing"
        );
        reset_handle_for_test();
    }

    #[test]
    fn revocation_stops_future_deliveries_and_replays_idempotently() {
        let fx = admitted_backup_fixture();
        let caller = caller_for(FIXTURE_PRINCIPAL, "mint-r");
        let (_, Json(minted)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 600));
        let id = intent_tail(&minted);

        let (status, Json(revoked)) = revoke_download_intent(
            &fx.data_dir,
            &caller_for(FIXTURE_PRINCIPAL, "rev-1"),
            FIXTURE_PRINCIPAL,
            &id,
        );
        assert_eq!(status, StatusCode::OK, "{revoked}");
        assert_eq!(revoked["effective_state"], serde_json::json!("revoked"));
        assert_eq!(
            revoked["intent"]["revocation"]["revoked_by"],
            serde_json::json!(FIXTURE_PRINCIPAL)
        );

        let response = deliver_download_intent_content(&fx.data_dir, &fx.identity, &id, "");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let refusal = body_json(response);
        assert_eq!(
            refusal["error"]["code"],
            serde_json::json!("download_intent_revoked")
        );

        // Re-revoking an already-revoked intent replays rather than failing.
        let (status, Json(again)) = revoke_download_intent(
            &fx.data_dir,
            &caller_for(FIXTURE_PRINCIPAL, "rev-2"),
            FIXTURE_PRINCIPAL,
            &id,
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["replayed"], serde_json::json!(true));
        reset_handle_for_test();
    }

    #[test]
    fn expiry_and_substituted_payloads_refuse_typed() {
        let fx = admitted_backup_fixture();
        let caller = caller_for(FIXTURE_PRINCIPAL, "mint-e");
        let (_, Json(minted)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 1));
        let id = intent_tail(&minted);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let response = deliver_download_intent_content(&fx.data_dir, &fx.identity, &id, "");
        assert_eq!(response.status(), StatusCode::GONE);
        let refusal = body_json(response);
        assert_eq!(
            refusal["error"]["code"],
            serde_json::json!("download_intent_expired")
        );

        // A fresh intent over material that no longer matches its commitment: typed conflict,
        // zero bytes served.
        let caller = caller_for(FIXTURE_PRINCIPAL, "mint-e2");
        let (_, Json(minted)) =
            mint_download_intent(&fx.data_dir, &caller, &mint_body(&fx.backup_id, 600));
        let id = intent_tail(&minted);
        std::fs::write(
            super::super::managed_runtime_routes::material_path(&fx.data_dir, &fx.state_root),
            b"substituted payload",
        )
        .unwrap();
        let response = deliver_download_intent_content(&fx.data_dir, &fx.identity, &id, "");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let refusal = body_json(response);
        assert_eq!(
            refusal["error"]["code"],
            serde_json::json!("download_intent_payload_digest_mismatch")
        );
        reset_handle_for_test();
    }
}
