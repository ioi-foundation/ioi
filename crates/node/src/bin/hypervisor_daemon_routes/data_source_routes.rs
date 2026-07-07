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
//! - Every registration writes a receipt; the record is honest about its lifecycle (`declared`) and
//!   names that ingestion is not wired.
//! - Records persist under `data-source-registry` (a fresh plane; no existing family is touched).
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

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
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
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

fn source_receipt(data_dir: &str, source_ref: &str, op: &str, outcome: &str) -> String {
    let id = format!("dsr_{:x}", nanos());
    let receipt_ref = format!("agentgres://data-source-receipt/{id}");
    let _ = persist_record(
        data_dir,
        RECEIPT_DIR,
        &id,
        &json!({
            "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
            "source_ref": source_ref, "op": op, "outcome": outcome, "at": iso_now()
        }),
    );
    receipt_ref
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
/// required, endpoint required for network kinds, valid credential posture, and NO plaintext secret.
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
    let name = match opt_s(&body, "name") {
        Some(n) => n,
        None => return err("data_source_name_required", "A data source requires a name."),
    };
    let kind = s(&body, "kind", "");
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
    let endpoint = opt_s(&body, "endpoint");
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
    let credential_posture = s(&body, "credential_posture", "no_credentials_required");
    if !CREDENTIAL_POSTURES.contains(&credential_posture.as_str()) {
        return err(
            "data_source_credential_posture_invalid",
            "credential_posture must be a declared posture (never a plaintext secret).",
        );
    }
    let source_id = format!("ds_{:x}", nanos());
    let source_ref = format!("data-source:{source_id}");
    let receipt = source_receipt(&st.data_dir, &source_ref, "registered", "ok");
    let record = json!({
        "schema_version": SOURCE_SCHEMA,
        "source_id": source_id,
        "source_ref": source_ref,
        "name": name,
        "kind": kind,
        "endpoint": endpoint,
        "credential_posture": credential_posture,
        "credential_binding": opt_s(&body, "credential_lease_ref").map(|r| json!({ "kind": "lease_ref", "credential_lease_ref": r })).unwrap_or(Value::Null),
        "project_ref": opt_s(&body, "project_ref"),
        "lifecycle": { "status": "declared" },
        "ingestion": { "wired": false, "note": "declaration only — extraction requires a future authority crossing (named gap)" },
        "receipt_refs": [receipt],
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime"
    });
    let _ = persist_record(&st.data_dir, RECORD_DIR, &source_id, &record);
    (StatusCode::CREATED, Json(json!({ "data_source": record })))
}

#[cfg(test)]
mod data_source_tests {
    use super::*;

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
}
