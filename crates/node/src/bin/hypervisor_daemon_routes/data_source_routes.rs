//! Data-source REGISTRY — daemon-owned truth for declared external data sources. A DRAFT plane
//! (contract-first, per the estate doctrine): a registration is a validated, receipted DECLARATION
//! of an external source the estate may later ingest from. It is admission-only — nothing here
//! connects, extracts, or moves data; effectful ingestion is a NAMED GAP that requires a future
//! wallet/authority crossing bound to admitted substrate.
//!
//! Doctrine enforced here:
//! - Registration is FAIL-CLOSED: the source kind must be a known kind, a network kind must carry an
//!   endpoint, and a credential is NEVER accepted as a plaintext secret — only a declared
//!   credential posture (the secret stays in the daemon's own credential planes, referenced by
//!   posture). A plaintext `secret`/`password`/`api_key` in the body is rejected outright.
//! - Input is TYPED and BOUNDED (operational wave #69, the #63 discipline): a present-but-non-string
//!   field is REJECTED with a typed code, never silently defaulted — a malformed
//!   `credential_posture` can never fall through to `no_credentials_required`. Omitted/null
//!   optional fields stay consistently absent (`endpoint`/`project_ref` persist as null,
//!   `credential_binding` as null).
//! - Persistence is ATOMIC-WITH-ROLLBACK (#62 proof discipline): the receipt is built PURELY, the
//!   source record persists FIRST (a receipt must never describe an unpersisted record), the
//!   receipt persists SECOND, and a receipt-persist failure removes the record with a CHECKED
//!   rollback. Every failure lane returns a typed 5xx; no partial success, no orphan record, no
//!   orphan receipt. The receipt is returned explicitly alongside the record.
//! - Records persist under `data-source-registry` (a fresh plane; no existing family is touched).
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const SOURCE_SCHEMA: &str = "ioi.hypervisor.data-source.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.data-source-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.data-sources-overview.v1";
pub(crate) const RECORD_DIR: &str = "data-source-registry";
const RECEIPT_DIR: &str = "data-source-registry-receipts";

/// Known source kinds. `network` kinds require an endpoint; `local` kinds (file/object drop) do not.
const SOURCE_KINDS: &[(&str, bool)] = &[
    ("postgres", true),
    ("mysql", true),
    ("rest_api", true),
    ("graphql_api", true),
    ("s3", true),
    ("object_store", true),
    ("http_feed", true),
    ("kafka", true),
    ("file_drop", false),
    ("local_folder", false),
];
/// Declared credential postures (the secret itself never enters this plane).
const CREDENTIAL_POSTURES: &[&str] = &[
    "no_credentials_required",
    "wallet_credential_lease",
    "provider_vault_token",
    "customer_boundary",
];
/// Query keys in an endpoint URL that would smuggle a credential into declared truth.
const SENSITIVE_ENDPOINT_QUERY_KEYS: &[&str] = &[
    "api_key", "apikey", "token", "secret", "password", "key", "access_token", "credential",
];

/// Bounded lengths for accepted text fields (#69 hardening — every accepted field is bounded).
const NAME_MAX: usize = 120;
const ENDPOINT_MAX: usize = 2000;
const REF_MAX: usize = 200;
const KIND_MAX: usize = 60;
const POSTURE_MAX: usize = 60;

/// An endpoint that embeds credentials (userinfo or a sensitive query param) is rejected — the
/// credential planes hold secrets; declared truth never does.
fn endpoint_carries_credentials(endpoint: &str) -> bool {
    if let Some((_, rest)) = endpoint.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return true;
        }
    }
    if let Some((_, query)) = endpoint.split_once('?') {
        for pair in query.split('&') {
            let k = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
            if SENSITIVE_ENDPOINT_QUERY_KEYS.contains(&k.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Body keys that would be a plaintext secret — rejected outright (no secret ever enters the plane).
const PLAINTEXT_SECRET_KEYS: &[&str] = &["secret", "password", "api_key", "apikey", "token", "credential"];

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}

/// Typed, bounded optional-string reader (#63 discipline): omitted/null → None; a present
/// non-string is REJECTED (`data_source_field_type_invalid`), an oversized value is REJECTED
/// (`data_source_field_too_long`) — never silently defaulted or truncated into a different value.
fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, (String, String)> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            if raw.chars().count() > max {
                return Err((
                    "data_source_field_too_long".into(),
                    format!("`{key}` exceeds the bounded length ({max} chars)"),
                ));
            }
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            Ok(Some(trimmed.to_string()))
        }
        Some(_) => Err((
            "data_source_field_type_invalid".into(),
            format!("`{key}` must be a string when present — a non-string value is never defaulted"),
        )),
    }
}

fn kind_requires_endpoint(kind: &str) -> Option<bool> {
    SOURCE_KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, net)| *net)
}

fn load_source(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("source_id").and_then(|v| v.as_str()) == Some(id))
}

/// Build a data-source receipt (PURE — nothing persists here; #62 proof discipline). The receipt
/// carries only record-derived fields + the op/outcome — never request material.
fn build_data_source_receipt(source_ref: &str, op: &str, outcome: &str, now: &str) -> (String, Value) {
    let id = format!("dsr_{:x}", nanos());
    let receipt_ref = format!("agentgres://data-source-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "source_ref": source_ref, "op": op, "outcome": outcome, "at": now
    });
    (id, rec)
}

/// Atomic-with-rollback finalization (#62 discipline): the SOURCE record persists first (a receipt
/// must never describe an unpersisted record); the receipt follows; if the receipt write fails the
/// created record is REMOVED with a CHECKED rollback so a persisted declaration never lacks its
/// receipt. Every failure lane reports a distinct typed code; no partial success survives.
fn finalize_data_source_persist(
    data_dir: &str,
    source_id: &str,
    record: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), (String, String)> {
    if let Err(e) = persist_record(data_dir, RECORD_DIR, source_id, record) {
        return Err((
            "data_source_record_persist_failed".into(),
            format!("data-source record persist failed ({e}) — nothing changed"),
        ));
    }
    match persist_record(data_dir, RECEIPT_DIR, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => {
            if remove_record(data_dir, RECORD_DIR, source_id) {
                Err((
                    "data_source_receipt_persist_failed".into(),
                    format!("data-source receipt persist failed ({e}); the created record was rolled back — nothing changed"),
                ))
            } else {
                Err((
                    "data_source_rollback_failed".into(),
                    format!("data-source receipt persist failed ({e}) AND the created record rollback failed — manual repair required for data source '{source_id}'"),
                ))
            }
        }
    }
}

fn sorted_sources(data_dir: &str) -> Vec<Value> {
    let mut sources = read_record_dir(data_dir, RECORD_DIR);
    sources.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    sources
}

/// GET /v1/hypervisor/data-sources — the declared data-source registry (newest first).
pub(crate) async fn handle_data_sources_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({
        "schema_version": SOURCE_SCHEMA,
        "data_sources": sorted_sources(&st.data_dir),
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/data-sources/overview — posture + counts + governance gaps (named honestly).
/// `source_kinds` is the DECLARATION VOCABULARY projection (#69): each known kind with whether it
/// requires an endpoint — a declaring surface derives its kind picker and endpoint requirement
/// from THIS, never from a hardcoded copy. `known_kinds` is retained for compatibility.
pub(crate) async fn handle_data_sources_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let sources = read_record_dir(&st.data_dir, RECORD_DIR);
    let by_kind = |kind: &str| sources.iter().filter(|r| s(r, "kind", "") == kind).count();
    let kinds: Value = SOURCE_KINDS
        .iter()
        .filter(|(k, _)| by_kind(k) > 0)
        .map(|(k, _)| json!({ "kind": k, "count": by_kind(k) }))
        .collect();
    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "data_sources": sources.len(),
        "kinds": kinds,
        "source_kinds": SOURCE_KINDS.iter().map(|(k, req)| json!({ "kind": k, "requires_endpoint": req })).collect::<Vec<_>>(),
        "known_kinds": SOURCE_KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        "credential_postures": CREDENTIAL_POSTURES,
        "governance_gaps": [
            "this is a DRAFT registry — a registration is a validated declaration only; nothing here connects, extracts, or moves data",
            "ingestion/extraction is not wired: an effectful pull requires a future wallet/authority crossing bound to admitted substrate (named, not built)",
            "credentials never enter this plane — only a declared credential posture is stored; the secret lives in the daemon credential planes and is referenced by posture"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/data-sources/:id — one declared source.
pub(crate) async fn handle_data_source_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_source(&st.data_dir, &id) {
        Some(record) => (StatusCode::OK, Json(json!({ "data_source": record }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "data_source": id } })),
        ),
    }
}

/// POST /v1/hypervisor/data-sources — register a declared source. FAIL-CLOSED: known kind, name
/// required, endpoint required for network kinds, valid credential posture, NO plaintext secret,
/// every accepted text field typed + bounded. Persistence is atomic-with-rollback; the response
/// returns the durable receipt explicitly alongside the record.
pub(crate) async fn handle_data_source_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err = |code: &str, msg: &str| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
    // Reject plaintext secrets outright — the plane never accepts a raw credential.
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": {
                    "code": "data_source_plaintext_secret_rejected",
                    "message": "Plaintext credentials are never accepted. Declare credential_posture; the secret stays in the daemon credential planes."
                } })),
            );
        }
    }
    // Typed + bounded field intake (#69): a present-but-non-string or oversized value refuses
    // typed — it is NEVER silently defaulted (a malformed credential_posture must not become
    // no_credentials_required) and NEVER truncated into a different declared identity.
    let name = match str_opt_bounded(&body, "name", NAME_MAX) {
        Ok(Some(n)) => n,
        Ok(None) => return err("data_source_name_required", "A data source requires a name."),
        Err((code, msg)) => return err(&code, &msg),
    };
    let kind = match str_opt_bounded(&body, "kind", KIND_MAX) {
        Ok(v) => v.unwrap_or_default(),
        Err((code, msg)) => return err(&code, &msg),
    };
    let requires_endpoint = match kind_requires_endpoint(&kind) {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": {
                    "code": "data_source_kind_invalid",
                    "message": "Unknown data source kind.",
                    "known_kinds": SOURCE_KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>()
                } })),
            );
        }
    };
    let endpoint = match str_opt_bounded(&body, "endpoint", ENDPOINT_MAX) {
        Ok(v) => v,
        Err((code, msg)) => return err(&code, &msg),
    };
    if requires_endpoint && endpoint.is_none() {
        return err(
            "data_source_endpoint_required",
            "A network data source kind requires an endpoint.",
        );
    }
    if let Some(e) = &endpoint {
        if endpoint_carries_credentials(e) {
            return err(
                "data_source_endpoint_credentialed",
                "The endpoint embeds credential material (userinfo or a sensitive query param) — declare credential_posture instead; secrets never enter declared truth.",
            );
        }
    }
    // credential_posture: omitted/null keeps the consistent default; a present value must be a
    // STRING member of the declared postures — a wrong-typed value refuses typed, never defaults.
    let credential_posture = match str_opt_bounded(&body, "credential_posture", POSTURE_MAX) {
        Ok(v) => v.unwrap_or_else(|| "no_credentials_required".to_string()),
        Err((code, msg)) => return err(&code, &msg),
    };
    if !CREDENTIAL_POSTURES.contains(&credential_posture.as_str()) {
        return err(
            "data_source_credential_posture_invalid",
            "credential_posture must be a declared posture (never a plaintext secret).",
        );
    }
    let credential_lease_ref = match str_opt_bounded(&body, "credential_lease_ref", REF_MAX) {
        Ok(v) => v,
        Err((code, msg)) => return err(&code, &msg),
    };
    let project_ref = match str_opt_bounded(&body, "project_ref", REF_MAX) {
        Ok(v) => v,
        Err((code, msg)) => return err(&code, &msg),
    };
    let source_id = format!("ds_{:x}", nanos());
    let source_ref = format!("data-source:{source_id}");
    let now = iso_now();
    // #62 proof discipline: build record + receipt PURE, then finalize atomically-with-rollback.
    let (receipt_id, receipt) = build_data_source_receipt(&source_ref, "registered", "ok", &now);
    let receipt_ref = s(&receipt, "receipt_ref", "");
    let record = json!({
        "schema_version": SOURCE_SCHEMA,
        "source_id": source_id,
        "source_ref": source_ref,
        "name": name,
        "kind": kind,
        "endpoint": endpoint,
        "credential_posture": credential_posture,
        "credential_binding": credential_lease_ref.map(|r| json!({ "kind": "lease_ref", "credential_lease_ref": r })).unwrap_or(Value::Null),
        "project_ref": project_ref,
        "lifecycle": { "status": "declared" },
        "ingestion": { "wired": false, "note": "declaration only — extraction requires a future authority crossing (named gap)" },
        "receipt_refs": [receipt_ref],
        "created_at": now,
        "updated_at": now,
        "runtimeTruthSource": "daemon-runtime"
    });
    if let Err((code, msg)) = finalize_data_source_persist(&st.data_dir, &source_id, &record, &receipt_id, &receipt) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": code, "message": msg } })),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({ "data_source": record, "data_source_receipt": receipt })),
    )
}

#[cfg(test)]
mod data_source_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-ds-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn load(data_dir: &str, record_dir: &str, id: &str) -> Option<Value> {
        read_record_dir(data_dir, record_dir)
            .into_iter()
            .find(|r| {
                r.get("source_id").and_then(|v| v.as_str()) == Some(id)
                    || r.get("receipt_id").and_then(|v| v.as_str()) == Some(id)
            })
    }

    #[test]
    fn network_kind_requires_endpoint() {
        assert_eq!(kind_requires_endpoint("postgres"), Some(true));
        assert_eq!(kind_requires_endpoint("local_folder"), Some(false));
        assert_eq!(kind_requires_endpoint("nonsense"), None);
    }

    #[test]
    fn credentialed_endpoints_are_detected() {
        assert!(endpoint_carries_credentials("https://user:pass@host/rows"));
        assert!(endpoint_carries_credentials("https://host/rows?api_key=x"));
        assert!(endpoint_carries_credentials("https://host/rows?limit=5&TOKEN=x"));
        assert!(!endpoint_carries_credentials("https://host/rows"));
        assert!(!endpoint_carries_credentials("https://host/rows?limit=5&cursor=abc"));
        assert!(!endpoint_carries_credentials("postgres://host:5432/db"));
    }

    #[test]
    fn plaintext_secret_keys_are_named() {
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"password"));
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"api_key"));
    }

    #[test]
    fn typed_bounded_fields_refuse_wrong_types_and_oversize() {
        // Omitted / null / blank → consistently absent.
        assert_eq!(str_opt_bounded(&json!({}), "name", NAME_MAX).unwrap(), None);
        assert_eq!(str_opt_bounded(&json!({ "name": null }), "name", NAME_MAX).unwrap(), None);
        assert_eq!(str_opt_bounded(&json!({ "name": "  " }), "name", NAME_MAX).unwrap(), None);
        // Present string → trimmed value.
        assert_eq!(str_opt_bounded(&json!({ "name": " s " }), "name", NAME_MAX).unwrap(), Some("s".into()));
        // Present-but-non-string → typed refusal, NEVER a silent default.
        assert_eq!(str_opt_bounded(&json!({ "credential_posture": 7 }), "credential_posture", POSTURE_MAX).unwrap_err().0, "data_source_field_type_invalid");
        assert_eq!(str_opt_bounded(&json!({ "kind": ["postgres"] }), "kind", KIND_MAX).unwrap_err().0, "data_source_field_type_invalid");
        assert_eq!(str_opt_bounded(&json!({ "endpoint": { "url": "x" } }), "endpoint", ENDPOINT_MAX).unwrap_err().0, "data_source_field_type_invalid");
        // Oversized → typed refusal, never truncated into a different declared identity.
        assert_eq!(str_opt_bounded(&json!({ "name": "x".repeat(NAME_MAX + 1) }), "name", NAME_MAX).unwrap_err().0, "data_source_field_too_long");
        assert_eq!(str_opt_bounded(&json!({ "project_ref": "p".repeat(REF_MAX + 1) }), "project_ref", REF_MAX).unwrap_err().0, "data_source_field_too_long");
    }

    #[test]
    fn receipt_builder_is_pure_and_record_shaped() {
        let dir = temp_dir("pure");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt("data-source:ds_x", "registered", "ok", "2026-01-01T00:00:00Z");
        assert!(rid.starts_with("dsr_"));
        assert_eq!(receipt["schema_version"], json!(RECEIPT_SCHEMA));
        assert_eq!(receipt["source_ref"], json!("data-source:ds_x"));
        assert_eq!(receipt["receipt_ref"], json!(format!("agentgres://data-source-receipt/{rid}")));
        // PURE: building the receipt persisted NOTHING.
        assert!(read_record_dir(data_dir, RECORD_DIR).is_empty());
        assert!(read_record_dir(data_dir, RECEIPT_DIR).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_rolls_back_record_on_receipt_failure_no_orphans() {
        let dir = temp_dir("rollback");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt("data-source:ds_x", "registered", "ok", "2026-01-01T00:00:00Z");
        let record = json!({ "source_id": "ds_x", "source_ref": "data-source:ds_x", "receipt_refs": [receipt["receipt_ref"]] });
        // FAILURE INJECTION: block the receipts dir with a plain file → receipt persist fails.
        std::fs::write(dir.join(RECEIPT_DIR), b"blocker").unwrap();
        let (code, msg) = finalize_data_source_persist(data_dir, "ds_x", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code, "data_source_receipt_persist_failed");
        assert!(msg.contains("rolled back"), "{msg}");
        // NO ORPHAN RECORD: the created record did not survive its missing receipt.
        assert!(load(data_dir, RECORD_DIR, "ds_x").is_none(), "no unproven declaration survives");
        // Happy path once unblocked: record + receipt both persist.
        std::fs::remove_file(dir.join(RECEIPT_DIR)).unwrap();
        finalize_data_source_persist(data_dir, "ds_x", &record, &rid, &receipt).unwrap();
        assert_eq!(load(data_dir, RECORD_DIR, "ds_x").unwrap()["source_ref"], json!("data-source:ds_x"));
        assert_eq!(load(data_dir, RECEIPT_DIR, &rid).unwrap()["op"], json!("registered"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_record_persist_failure_writes_no_orphan_receipt() {
        let dir = temp_dir("recfail");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt("data-source:ds_y", "registered", "ok", "2026-01-01T00:00:00Z");
        let record = json!({ "source_id": "ds_y" });
        // FAILURE INJECTION: block the RECORD dir with a plain file → record persist fails FIRST.
        std::fs::write(dir.join(RECORD_DIR), b"blocker").unwrap();
        let (code, msg) = finalize_data_source_persist(data_dir, "ds_y", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code, "data_source_record_persist_failed");
        assert!(msg.contains("nothing changed"), "{msg}");
        // NO ORPHAN RECEIPT: the receipt was never attempted for an unpersisted record.
        assert!(read_record_dir(data_dir, RECEIPT_DIR).is_empty(), "no receipt without its record");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn finalize_reports_rollback_failure_as_its_own_typed_lane() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("rbfail");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt("data-source:ds_z", "registered", "ok", "2026-01-01T00:00:00Z");
        let record = json!({ "source_id": "ds_z" });
        // FAILURE INJECTION: receipts dir blocked AND the record file pre-created inside a
        // read-only record dir — overwrite of the existing file succeeds (file perms allow it)
        // but the rollback's remove_file needs dir-write and FAILS.
        persist_record(data_dir, RECORD_DIR, "ds_z", &record).unwrap();
        std::fs::write(dir.join(RECEIPT_DIR), b"blocker").unwrap();
        let record_dir = dir.join(RECORD_DIR);
        std::fs::set_permissions(&record_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = finalize_data_source_persist(data_dir, "ds_z", &record, &rid, &receipt);
        std::fs::set_permissions(&record_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Root bypasses directory permissions (some CI containers): the injection can't fire
        // there — the lane then reports the checked rollback instead; assert the typed pair.
        let (code, msg) = out.unwrap_err();
        if code == "data_source_rollback_failed" {
            assert!(msg.contains("manual repair required"), "{msg}");
            assert!(load(data_dir, RECORD_DIR, "ds_z").is_some(), "the stranded record is reported, not hidden");
        } else {
            assert_eq!(code, "data_source_receipt_persist_failed");
            assert!(load(data_dir, RECORD_DIR, "ds_z").is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
