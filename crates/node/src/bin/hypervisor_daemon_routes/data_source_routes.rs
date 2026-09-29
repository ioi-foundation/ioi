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
use axum::http::{HeaderMap, StatusCode};
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
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "key",
    "access_token",
    "credential",
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
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];

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
fn str_opt_bounded(
    body: &Value,
    key: &str,
    max: usize,
) -> Result<Option<String>, (String, String)> {
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
            format!(
                "`{key}` must be a string when present — a non-string value is never defaulted"
            ),
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
fn build_data_source_receipt(
    source_ref: &str,
    op: &str,
    outcome: &str,
    now: &str,
) -> (String, Value) {
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

// ---- WHO MAY READ A DECLARED SOURCE -------------------------------------------------------------
//
// The three reads below handed every declared source, with its endpoint, credential posture and
// declarer, to any caller that reached the daemon; the adopted Data Connection hid other principals'
// sources client-side. The daemon now answers only for sources the caller may see, and an
// anonymous caller is owed the same typed refusal the ODK reads and this plane's own writes give
// (`odk_scope_refusal`). Daemon-internal readers (lease plans, mappings, sessions, runs) read the
// record dir directly and keep full access; only the HTTP answers are scoped.

/// The project a ref names, as the slug a `project://<slug>` membership carries. A project record's
/// id is `project:<slug>` and its membership tenant is `project://<slug>` (the membership admission
/// resolves one to the other), while a source filed through the adopted Data Connection names it
/// `project://project:<slug>`. All three spellings name the same project record, so they compare
/// by slug.
fn project_slug(project_ref: &str) -> Option<&str> {
    let tail = project_ref
        .strip_prefix("project://")
        .or_else(|| project_ref.strip_prefix("project:"))?;
    let slug = tail.strip_prefix("project:").unwrap_or(tail);
    (!slug.is_empty()).then_some(slug)
}

/// A caller may see a source it declared, or one filed in a project it is a member of. Project
/// membership is the principal's live `project://` tenant membership (revocation takes effect on
/// the next request); the project registry itself names no members, so being listed there grants
/// nothing. A source with no declarer and no project (written before declarations were identity
/// first) is answered to no one over HTTP.
pub(crate) fn source_visible_to(
    record: &Value,
    identity: &super::substrate_store::RequestIdentity,
) -> bool {
    if record
        .get("declared_by_principal_ref")
        .and_then(Value::as_str)
        == Some(identity.principal_ref.as_str())
    {
        return true;
    }
    let Some(slug) = record
        .get("project_ref")
        .and_then(Value::as_str)
        .and_then(project_slug)
    else {
        return false;
    };
    identity
        .tenant_refs
        .iter()
        .filter(|tenant| tenant.starts_with("project://"))
        .any(|tenant| project_slug(tenant) == Some(slug))
}

/// Whether a declared source answers to `source_ref` (`data-source:<id>`) AND the caller may see it
/// (`source_visible_to`). An absent and a hidden source both answer false, so a plane that lets a
/// record NAME a source (the System-record seam's data attachments) discloses neither.
pub(crate) fn source_ref_visible_to(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    source_ref: &str,
) -> bool {
    read_record_dir(data_dir, RECORD_DIR).iter().any(|record| {
        record.get("source_ref").and_then(Value::as_str) == Some(source_ref)
            && source_visible_to(record, identity)
    })
}

fn visible_sources(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
) -> Vec<Value> {
    let mut sources: Vec<Value> = read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .filter(|record| source_visible_to(record, identity))
        .collect();
    sources.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    sources
}

fn caller(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<super::substrate_store::RequestIdentity, (StatusCode, Json<Value>)> {
    super::substrate_store::resolve_request_identity(data_dir, headers)
        .map_err(super::odk_routes::odk_scope_refusal)
}

/// GET /v1/hypervisor/data-sources — the caller's declared data sources (newest first): those it
/// declared and those filed in a project it is a member of.
pub(crate) async fn handle_data_sources_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    match caller(&st.data_dir, &headers) {
        Ok(identity) => (
            StatusCode::OK,
            Json(list_data_sources(&st.data_dir, &identity)),
        ),
        Err(refusal) => refusal,
    }
}

pub(crate) fn list_data_sources(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
) -> Value {
    json!({
        "schema_version": SOURCE_SCHEMA,
        "data_sources": visible_sources(data_dir, identity),
        "runtimeTruthSource": "daemon-runtime"
    })
}

/// GET /v1/hypervisor/data-sources/overview — posture + counts + governance gaps (named honestly).
/// `source_kinds` is the DECLARATION VOCABULARY projection (#69): each known kind with whether it
/// requires an endpoint — a declaring surface derives its kind picker and endpoint requirement
/// from THIS, never from a hardcoded copy. `known_kinds` is retained for compatibility. The counts
/// are over the caller's sources only: a registry-wide total would tell any caller when another
/// principal declared one.
pub(crate) async fn handle_data_sources_overview(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    match caller(&st.data_dir, &headers) {
        Ok(identity) => (
            StatusCode::OK,
            Json(data_sources_overview(&st.data_dir, &identity)),
        ),
        Err(refusal) => refusal,
    }
}

pub(crate) fn data_sources_overview(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
) -> Value {
    let sources = visible_sources(data_dir, identity);
    let by_kind = |kind: &str| sources.iter().filter(|r| s(r, "kind", "") == kind).count();
    let kinds: Value = SOURCE_KINDS
        .iter()
        .filter(|(k, _)| by_kind(k) > 0)
        .map(|(k, _)| json!({ "kind": k, "count": by_kind(k) }))
        .collect();
    json!({
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
    })
}

/// GET /v1/hypervisor/data-sources/:id — one declared source the caller may see. Identity comes
/// first, so an anonymous caller gets no existence oracle; a source the caller may not see answers
/// exactly as an absent one does.
pub(crate) async fn handle_data_source_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match caller(&st.data_dir, &headers) {
        Ok(identity) => get_data_source(&st.data_dir, &identity, &id),
        Err(refusal) => refusal,
    }
}

pub(crate) fn get_data_source(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    id: &str,
) -> (StatusCode, Json<Value>) {
    match load_source(data_dir, id).filter(|record| source_visible_to(record, identity)) {
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
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // IDENTITY FIRST (R-240, measured): this route took no headers at all, so any caller that could
    // reach the daemon — including through a sign-in-required serve, whose /v1/* pass-through relies
    // on the daemon to refuse — appended a durable, unowned record to the registry. Two verifier
    // fixtures landed in an owner's registry that way before this was found. A declaration is an
    // authored mutation: an anonymous caller is owed the typed refusal before any field is judged,
    // exactly as the ODK writes answer it (#236), and the record names who declared it.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    create_data_source(&st.data_dir, &identity.principal_ref, &body)
}

/// The declaration itself, once the caller is known: every check below runs as it always did, and
/// the record carries `declared_by_principal_ref`.
pub(crate) fn create_data_source(
    data_dir: &str,
    declared_by_principal_ref: &str,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    let body = body.clone();
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
        Ok(None) => {
            return err(
                "data_source_name_required",
                "A data source requires a name.",
            )
        }
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
    // `draft: true` declares a network source before its endpoint is known (the reference creates a
    // source at "Name and location", before its connection details). A draft is not usable: no lease
    // plan may bind it, and it becomes `declared` once an update gives it an endpoint.
    let draft =
        match body.get("draft") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return err(
                "data_source_field_type_invalid",
                "`draft` must be a boolean when present — a non-boolean value is never defaulted",
            ),
        };
    if requires_endpoint && endpoint.is_none() && !draft {
        return err(
            "data_source_endpoint_required",
            "A network data source kind requires an endpoint.",
        );
    }
    let lifecycle_status = if requires_endpoint && endpoint.is_none() {
        "draft"
    } else {
        "declared"
    };
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
        "declared_by_principal_ref": declared_by_principal_ref,
        "lifecycle": { "status": lifecycle_status },
        "ingestion": { "wired": false, "note": "declaration only — extraction requires a future authority crossing (named gap)" },
        "receipt_refs": [receipt_ref],
        "created_at": now,
        "updated_at": now,
        "runtimeTruthSource": "daemon-runtime"
    });
    if let Err((code, msg)) =
        finalize_data_source_persist(data_dir, &source_id, &record, &receipt_id, &receipt)
    {
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

/// Fields an update may change. Everything else (kind, project, declarer, lifecycle, receipts) is
/// fixed at declaration.
const UPDATABLE_FIELDS: &[&str] = &[
    "name",
    "endpoint",
    "credential_posture",
    "credential_lease_ref",
];
/// Fields that decide what a source reaches and with which credential: once a lease plan or a
/// connector mapping binds the source, changing one would move what an approved lease authorizes.
const BINDING_FIELDS: &[&str] = &["endpoint", "credential_posture", "credential_lease_ref"];

/// PATCH /v1/hypervisor/data-sources/:id — change a declared source's name, endpoint or credential
/// posture. Only its declarer may, every field is judged exactly as at declaration, and the change
/// is receipted (op `updated`, naming the fields that changed — never their values).
pub(crate) async fn handle_data_source_update(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    update_data_source(&st.data_dir, &identity.principal_ref, &id, &body)
}

fn source_is_bound(data_dir: &str, source_id: &str) -> bool {
    [
        crate::capability_lease_plan_routes::RECORD_DIR,
        crate::connector_mapping_routes::RECORD_DIR,
    ]
    .iter()
    .any(|dir| {
        read_record_dir(data_dir, dir)
            .iter()
            .any(|r| r.get("data_source_id").and_then(|v| v.as_str()) == Some(source_id))
    })
}

pub(crate) fn update_data_source(
    data_dir: &str,
    principal_ref: &str,
    id: &str,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    let refuse = |status: StatusCode, code: &str, msg: String| {
        (
            status,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
    let Some(obj) = body.as_object() else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "data_source_update_invalid",
            "An update is a JSON object of the fields to change.".into(),
        );
    };
    if PLAINTEXT_SECRET_KEYS
        .iter()
        .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
    {
        return refuse(StatusCode::BAD_REQUEST, "data_source_plaintext_secret_rejected",
            "Plaintext credentials are never accepted. Declare credential_posture; the secret stays in the daemon credential planes.".into());
    }
    if let Some(k) = obj.keys().find(|k| !UPDATABLE_FIELDS.contains(&k.as_str())) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "data_source_field_immutable",
            format!(
                "`{k}` is fixed at declaration; an update may change only {}",
                UPDATABLE_FIELDS.join(", ")
            ),
        );
    }
    let Some(prior) = load_source(data_dir, id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("no data source '{id}'"),
        );
    };
    if s(&prior, "declared_by_principal_ref", "") != principal_ref {
        return refuse(
            StatusCode::FORBIDDEN,
            "data_source_not_declarer",
            "Only the principal that declared a data source may change it.".into(),
        );
    }
    let mut next = prior.clone();
    let mut changed: Vec<&str> = Vec::new();
    for key in UPDATABLE_FIELDS {
        if !obj.contains_key(*key) {
            continue;
        }
        let max = match *key {
            "name" => NAME_MAX,
            "endpoint" => ENDPOINT_MAX,
            "credential_posture" => POSTURE_MAX,
            _ => REF_MAX,
        };
        let value = match str_opt_bounded(body, key, max) {
            Ok(v) => v,
            Err((code, msg)) => return refuse(StatusCode::BAD_REQUEST, &code, msg),
        };
        let stored = match *key {
            "name" => match value {
                Some(n) => json!(n),
                None => {
                    return refuse(
                        StatusCode::BAD_REQUEST,
                        "data_source_name_required",
                        "A data source requires a name.".into(),
                    )
                }
            },
            "endpoint" => {
                if let Some(e) = &value {
                    if endpoint_carries_credentials(e) {
                        return refuse(StatusCode::BAD_REQUEST, "data_source_endpoint_credentialed",
                            "The endpoint embeds credential material (userinfo or a sensitive query param) — declare credential_posture instead; secrets never enter declared truth.".into());
                    }
                } else if kind_requires_endpoint(&s(&prior, "kind", "")) == Some(true) {
                    return refuse(
                        StatusCode::BAD_REQUEST,
                        "data_source_endpoint_required",
                        "A network data source kind requires an endpoint.".into(),
                    );
                }
                value.map(Value::String).unwrap_or(Value::Null)
            }
            "credential_posture" => {
                let posture = value.unwrap_or_else(|| "no_credentials_required".to_string());
                if !CREDENTIAL_POSTURES.contains(&posture.as_str()) {
                    return refuse(
                        StatusCode::BAD_REQUEST,
                        "data_source_credential_posture_invalid",
                        "credential_posture must be a declared posture (never a plaintext secret)."
                            .into(),
                    );
                }
                json!(posture)
            }
            _ => value
                .map(|r| json!({ "kind": "lease_ref", "credential_lease_ref": r }))
                .unwrap_or(Value::Null),
        };
        let field = if *key == "credential_lease_ref" {
            "credential_binding"
        } else {
            *key
        };
        if prior.get(field) != Some(&stored) {
            next[field] = stored;
            changed.push(key);
        }
    }
    if changed.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({ "data_source": prior, "changed": [] })),
        );
    }
    if changed.iter().any(|k| BINDING_FIELDS.contains(k)) && source_is_bound(data_dir, id) {
        return refuse(StatusCode::CONFLICT, "data_source_bound",
            format!("A lease plan or connector mapping binds this source, so its {} cannot change — it would move what an approved lease reaches.", changed.join(", ")));
    }
    let now = iso_now();
    if s(
        &prior.get("lifecycle").cloned().unwrap_or(Value::Null),
        "status",
        "",
    ) == "draft"
        && next.get("endpoint").is_some_and(|e| e.is_string())
    {
        next["lifecycle"] = json!({ "status": "declared" });
    }
    let source_ref = s(&prior, "source_ref", "");
    let (receipt_id, mut receipt) = build_data_source_receipt(&source_ref, "updated", "ok", &now);
    receipt["changed"] = json!(changed);
    let receipt_ref = s(&receipt, "receipt_ref", "");
    if let Some(refs) = next.get_mut("receipt_refs").and_then(|v| v.as_array_mut()) {
        refs.push(json!(receipt_ref));
    } else {
        next["receipt_refs"] = json!([receipt_ref]);
    }
    next["updated_at"] = json!(now);
    // The record persists first; if its receipt cannot, the prior record is restored (checked) so a
    // change never stands without its receipt.
    if let Err(e) = persist_record(data_dir, RECORD_DIR, id, &next) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "data_source_record_persist_failed",
            format!("data-source record persist failed ({e}) — nothing changed"),
        );
    }
    if let Err(e) = persist_record(data_dir, RECEIPT_DIR, &receipt_id, &receipt) {
        return match persist_record(data_dir, RECORD_DIR, id, &prior) {
            Ok(()) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "data_source_receipt_persist_failed", format!("data-source receipt persist failed ({e}); the prior record was restored — nothing changed")),
            Err(re) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "data_source_rollback_failed", format!("data-source receipt persist failed ({e}) AND restoring the prior record failed ({re}) — manual repair required for data source '{id}'")),
        };
    }
    (
        StatusCode::OK,
        Json(json!({ "data_source": next, "changed": changed, "data_source_receipt": receipt })),
    )
}

#[cfg(test)]
mod data_source_tests {
    use super::*;

    #[test]
    fn a_declaration_names_its_declarer_and_still_judges_every_field() {
        let dir = temp_dir("declarer");
        let data_dir = dir.to_str().unwrap();
        let (status, Json(reply)) = create_data_source(
            data_dir,
            "user://alpha",
            &json!({ "name": "orders", "kind": "rest_api", "endpoint": "https://api.example.test/orders" }),
        );
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        assert_eq!(
            reply["data_source"]["declared_by_principal_ref"],
            json!("user://alpha")
        );
        let id = reply["data_source"]["source_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            load(data_dir, "data-source-registry", &id).unwrap()["declared_by_principal_ref"],
            json!("user://alpha"),
            "the persisted record carries the declarer, not only the reply"
        );
        let (status, Json(reply)) =
            create_data_source(data_dir, "user://alpha", &json!({ "kind": "rest_api" }));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(reply["error"]["code"], json!("data_source_name_required"));
        let (status, _) = create_data_source(
            data_dir,
            "user://alpha",
            &json!({ "name": "x", "kind": "rest_api", "endpoint": "https://e.test", "password": "hunter2" }),
        );
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a plaintext secret is still refused"
        );
    }

    #[test]
    fn a_draft_is_declared_without_an_endpoint_and_becomes_declared_when_its_declarer_gives_one() {
        let dir = temp_dir("draft");
        let data_dir = dir.to_str().unwrap();
        let (status, Json(reply)) = create_data_source(
            data_dir,
            "user://alpha",
            &json!({ "name": "orders", "kind": "rest_api" }),
        );
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "without draft, a network kind still requires an endpoint"
        );
        assert_eq!(
            reply["error"]["code"],
            json!("data_source_endpoint_required")
        );
        let (status, _) = create_data_source(
            data_dir,
            "user://alpha",
            &json!({ "name": "orders", "kind": "rest_api", "draft": "yes" }),
        );
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-boolean draft refuses typed"
        );
        let (status, Json(reply)) = create_data_source(
            data_dir,
            "user://alpha",
            &json!({ "name": "orders", "kind": "rest_api", "draft": true }),
        );
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        assert_eq!(reply["data_source"]["lifecycle"]["status"], json!("draft"));
        let id = reply["data_source"]["source_id"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, Json(reply)) = update_data_source(
            data_dir,
            "user://mallory",
            &id,
            &json!({ "endpoint": "https://api.example.test" }),
        );
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "only the declarer may change a source"
        );
        assert_eq!(reply["error"]["code"], json!("data_source_not_declarer"));
        for (body, code) in [
            (json!({ "kind": "s3" }), "data_source_field_immutable"),
            (
                json!({ "endpoint": "https://u:p@api.example.test" }),
                "data_source_endpoint_credentialed",
            ),
            (json!({ "endpoint": null }), "data_source_endpoint_required"),
            (
                json!({ "password": "hunter2" }),
                "data_source_plaintext_secret_rejected",
            ),
            (
                json!({ "credential_posture": "plaintext" }),
                "data_source_credential_posture_invalid",
            ),
            (json!({ "name": 7 }), "data_source_field_type_invalid"),
        ] {
            let (status, Json(reply)) = update_data_source(data_dir, "user://alpha", &id, &body);
            assert_eq!(
                (status, reply["error"]["code"].clone()),
                (StatusCode::BAD_REQUEST, json!(code)),
                "{body}"
            );
        }
        let untouched = load(data_dir, "data-source-registry", &id).unwrap();
        assert_eq!(
            untouched["lifecycle"]["status"],
            json!("draft"),
            "a refused update changes nothing"
        );

        let (status, Json(reply)) = update_data_source(
            data_dir,
            "user://alpha",
            &id,
            &json!({ "endpoint": "https://api.example.test/orders", "name": "orders" }),
        );
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(
            reply["changed"],
            json!(["endpoint"]),
            "an unchanged name is not a change"
        );
        assert_eq!(
            reply["data_source"]["lifecycle"]["status"],
            json!("declared")
        );
        let receipt_id = reply["data_source_receipt"]["receipt_id"]
            .as_str()
            .unwrap()
            .to_string();
        let receipt = load(data_dir, "data-source-registry-receipts", &receipt_id).unwrap();
        assert_eq!(
            (receipt["op"].clone(), receipt["changed"].clone()),
            (json!("updated"), json!(["endpoint"]))
        );
        assert!(
            !receipt.to_string().contains("api.example.test"),
            "a receipt names the fields that changed, never their values"
        );
        let persisted = load(data_dir, "data-source-registry", &id).unwrap();
        assert_eq!(
            persisted["endpoint"],
            json!("https://api.example.test/orders")
        );
        assert_eq!(persisted["receipt_refs"].as_array().unwrap().len(), 2);

        let (status, Json(reply)) = update_data_source(
            data_dir,
            "user://alpha",
            &id,
            &json!({ "endpoint": "https://api.example.test/orders" }),
        );
        assert_eq!(
            (status, reply["changed"].clone()),
            (StatusCode::OK, json!([])),
            "no change, no receipt"
        );
        assert!(reply.get("data_source_receipt").is_none());
    }

    #[test]
    fn a_source_a_lease_plan_binds_keeps_its_endpoint_and_credential() {
        let dir = temp_dir("bound");
        let data_dir = dir.to_str().unwrap();
        let (_, Json(reply)) = create_data_source(
            data_dir,
            "user://alpha",
            &json!({ "name": "orders", "kind": "rest_api", "endpoint": "https://a.example.test" }),
        );
        let id = reply["data_source"]["source_id"]
            .as_str()
            .unwrap()
            .to_string();
        persist_record(
            data_dir,
            crate::capability_lease_plan_routes::RECORD_DIR,
            "plan_1",
            &json!({ "id": "plan_1", "data_source_id": id }),
        )
        .unwrap();
        let (status, Json(reply)) = update_data_source(
            data_dir,
            "user://alpha",
            &id,
            &json!({ "endpoint": "https://b.example.test" }),
        );
        assert_eq!(
            (status, reply["error"]["code"].clone()),
            (StatusCode::CONFLICT, json!("data_source_bound"))
        );
        let (status, Json(reply)) = update_data_source(
            data_dir,
            "user://alpha",
            &id,
            &json!({ "name": "orders v2" }),
        );
        assert_eq!(
            (status, reply["changed"].clone()),
            (StatusCode::OK, json!(["name"])),
            "a name is not what a lease reaches"
        );
    }

    fn who(
        principal_ref: &str,
        tenants: &[&str],
    ) -> super::super::substrate_store::RequestIdentity {
        super::super::substrate_store::request_identity_for_test(
            principal_ref,
            tenants.iter().map(|t| t.to_string()),
        )
    }
    fn declare(data_dir: &str, principal_ref: &str, body: Value) -> String {
        let (status, Json(reply)) = create_data_source(data_dir, principal_ref, &body);
        assert_eq!(status, StatusCode::CREATED, "{reply}");
        reply["data_source"]["source_id"]
            .as_str()
            .unwrap()
            .to_string()
    }
    fn listed(
        data_dir: &str,
        identity: &super::super::substrate_store::RequestIdentity,
    ) -> Vec<String> {
        list_data_sources(data_dir, identity)["data_sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["source_id"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn each_principal_lists_reads_and_counts_only_the_sources_it_declared() {
        let dir = temp_dir("scoped");
        let data_dir = dir.to_str().unwrap();
        let alpha_src = declare(
            data_dir,
            "user://alpha",
            json!({ "name": "alpha orders", "kind": "rest_api", "endpoint": "https://alpha.example.test/orders" }),
        );
        let beta_src = declare(
            data_dir,
            "user://beta",
            json!({ "name": "beta drop", "kind": "file_drop" }),
        );
        let (alpha, beta) = (
            who("user://alpha", &["org://local"]),
            who("user://beta", &["org://local"]),
        );

        assert_eq!(listed(data_dir, &alpha), vec![alpha_src.clone()]);
        assert_eq!(listed(data_dir, &beta), vec![beta_src.clone()]);
        assert!(
            listed(data_dir, &who("user://gamma", &["org://local"])).is_empty(),
            "a principal that declared nothing and is in no project sees nothing, though it shares the organization"
        );

        let (status, Json(reply)) = get_data_source(data_dir, &alpha, &alpha_src);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply["data_source"]["name"], json!("alpha orders"));
        let (status, Json(theirs)) = get_data_source(data_dir, &alpha, &beta_src);
        let (_, Json(absent)) = get_data_source(data_dir, &alpha, "ds_absent");
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "another principal's source is not answered"
        );
        assert_eq!(
            theirs["error"]["code"], absent["error"]["code"],
            "and answers exactly as an absent one does"
        );
        assert!(!theirs.to_string().contains("beta drop"));

        let overview = data_sources_overview(data_dir, &alpha);
        assert_eq!(
            overview["data_sources"],
            json!(1),
            "the overview counts the caller's sources only"
        );
        assert_eq!(
            overview["kinds"],
            json!([{ "kind": "rest_api", "count": 1 }])
        );
        assert_eq!(
            overview["source_kinds"].as_array().unwrap().len(),
            SOURCE_KINDS.len(),
            "the declaration vocabulary is not scoped"
        );
        assert_eq!(
            read_record_dir(data_dir, RECORD_DIR).len(),
            2,
            "the record dir still holds both, for daemon-internal readers"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_project_member_sees_a_source_filed_in_that_project_and_a_non_member_does_not() {
        let dir = temp_dir("project");
        let data_dir = dir.to_str().unwrap();
        // the adopted Data Connection files a source as `project://<project_id>`, i.e.
        // `project://project:<slug>`; a membership names `project://<slug>`
        let filed = declare(
            data_dir,
            "user://alpha",
            json!({ "name": "payments", "kind": "file_drop", "project_ref": "project://project:payments" }),
        );
        let canonical = declare(
            data_dir,
            "user://alpha",
            json!({ "name": "ledger", "kind": "file_drop", "project_ref": "project://payments" }),
        );
        let elsewhere = declare(
            data_dir,
            "user://alpha",
            json!({ "name": "hr", "kind": "file_drop", "project_ref": "project://hr" }),
        );
        let member = who("user://beta", &["org://local", "project://payments"]);
        let mut seen = listed(data_dir, &member);
        seen.sort();
        let mut want = vec![filed.clone(), canonical.clone()];
        want.sort();
        assert_eq!(
            seen, want,
            "a member of project://payments sees both of its sources, and not project://hr's"
        );
        assert_eq!(get_data_source(data_dir, &member, &filed).0, StatusCode::OK);
        assert_eq!(
            get_data_source(data_dir, &member, &elsewhere).0,
            StatusCode::NOT_FOUND
        );

        let outsider = who("user://gamma", &["org://local", "project://pay"]);
        assert!(
            listed(data_dir, &outsider).is_empty(),
            "a different project, or a prefix of the slug, grants nothing"
        );
        assert_eq!(
            get_data_source(data_dir, &outsider, &filed).0,
            StatusCode::NOT_FOUND
        );
        let not_a_project = who("user://gamma", &["org://payments"]);
        assert!(
            listed(data_dir, &not_a_project).is_empty(),
            "an organization tenant is not a project membership"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_anonymous_read_is_the_typed_refusal_the_odk_reads_give() {
        let dir = temp_dir("anon");
        let data_dir = dir.to_str().unwrap();
        declare(
            data_dir,
            "user://alpha",
            json!({ "name": "x", "kind": "file_drop" }),
        );
        let (status, Json(reply)) = caller(data_dir, &HeaderMap::new()).unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply["code"], json!("request_principal_required"));
        assert!(!reply.to_string().contains("\"x\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_refs_compare_by_the_project_they_name() {
        assert_eq!(project_slug("project://payments"), Some("payments"));
        assert_eq!(project_slug("project://project:payments"), Some("payments"));
        assert_eq!(project_slug("project:payments"), Some("payments"));
        assert_eq!(project_slug("project://"), None);
        assert_eq!(project_slug("org://payments"), None);
        let legacy = json!({ "source_id": "ds_old", "project_ref": null });
        assert!(
            !source_visible_to(&legacy, &who("user://alpha", &["project://payments"])),
            "a source with no declarer and no project is answered to no one"
        );
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-ds-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn load(data_dir: &str, record_dir: &str, id: &str) -> Option<Value> {
        read_record_dir(data_dir, record_dir).into_iter().find(|r| {
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
        assert!(endpoint_carries_credentials(
            "https://host/rows?limit=5&TOKEN=x"
        ));
        assert!(!endpoint_carries_credentials("https://host/rows"));
        assert!(!endpoint_carries_credentials(
            "https://host/rows?limit=5&cursor=abc"
        ));
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
        assert_eq!(
            str_opt_bounded(&json!({ "name": null }), "name", NAME_MAX).unwrap(),
            None
        );
        assert_eq!(
            str_opt_bounded(&json!({ "name": "  " }), "name", NAME_MAX).unwrap(),
            None
        );
        // Present string → trimmed value.
        assert_eq!(
            str_opt_bounded(&json!({ "name": " s " }), "name", NAME_MAX).unwrap(),
            Some("s".into())
        );
        // Present-but-non-string → typed refusal, NEVER a silent default.
        assert_eq!(
            str_opt_bounded(
                &json!({ "credential_posture": 7 }),
                "credential_posture",
                POSTURE_MAX
            )
            .unwrap_err()
            .0,
            "data_source_field_type_invalid"
        );
        assert_eq!(
            str_opt_bounded(&json!({ "kind": ["postgres"] }), "kind", KIND_MAX)
                .unwrap_err()
                .0,
            "data_source_field_type_invalid"
        );
        assert_eq!(
            str_opt_bounded(
                &json!({ "endpoint": { "url": "x" } }),
                "endpoint",
                ENDPOINT_MAX
            )
            .unwrap_err()
            .0,
            "data_source_field_type_invalid"
        );
        // Oversized → typed refusal, never truncated into a different declared identity.
        assert_eq!(
            str_opt_bounded(
                &json!({ "name": "x".repeat(NAME_MAX + 1) }),
                "name",
                NAME_MAX
            )
            .unwrap_err()
            .0,
            "data_source_field_too_long"
        );
        assert_eq!(
            str_opt_bounded(
                &json!({ "project_ref": "p".repeat(REF_MAX + 1) }),
                "project_ref",
                REF_MAX
            )
            .unwrap_err()
            .0,
            "data_source_field_too_long"
        );
    }

    #[test]
    fn receipt_builder_is_pure_and_record_shaped() {
        let dir = temp_dir("pure");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt(
            "data-source:ds_x",
            "registered",
            "ok",
            "2026-01-01T00:00:00Z",
        );
        assert!(rid.starts_with("dsr_"));
        assert_eq!(receipt["schema_version"], json!(RECEIPT_SCHEMA));
        assert_eq!(receipt["source_ref"], json!("data-source:ds_x"));
        assert_eq!(
            receipt["receipt_ref"],
            json!(format!("agentgres://data-source-receipt/{rid}"))
        );
        // PURE: building the receipt persisted NOTHING.
        assert!(read_record_dir(data_dir, RECORD_DIR).is_empty());
        assert!(read_record_dir(data_dir, RECEIPT_DIR).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_rolls_back_record_on_receipt_failure_no_orphans() {
        let dir = temp_dir("rollback");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt(
            "data-source:ds_x",
            "registered",
            "ok",
            "2026-01-01T00:00:00Z",
        );
        let record = json!({ "source_id": "ds_x", "source_ref": "data-source:ds_x", "receipt_refs": [receipt["receipt_ref"]] });
        // FAILURE INJECTION: block the receipts dir with a plain file → receipt persist fails.
        std::fs::write(dir.join(RECEIPT_DIR), b"blocker").unwrap();
        let (code, msg) =
            finalize_data_source_persist(data_dir, "ds_x", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code, "data_source_receipt_persist_failed");
        assert!(msg.contains("rolled back"), "{msg}");
        // NO ORPHAN RECORD: the created record did not survive its missing receipt.
        assert!(
            load(data_dir, RECORD_DIR, "ds_x").is_none(),
            "no unproven declaration survives"
        );
        // Happy path once unblocked: record + receipt both persist.
        std::fs::remove_file(dir.join(RECEIPT_DIR)).unwrap();
        finalize_data_source_persist(data_dir, "ds_x", &record, &rid, &receipt).unwrap();
        assert_eq!(
            load(data_dir, RECORD_DIR, "ds_x").unwrap()["source_ref"],
            json!("data-source:ds_x")
        );
        assert_eq!(
            load(data_dir, RECEIPT_DIR, &rid).unwrap()["op"],
            json!("registered")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_record_persist_failure_writes_no_orphan_receipt() {
        let dir = temp_dir("recfail");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt(
            "data-source:ds_y",
            "registered",
            "ok",
            "2026-01-01T00:00:00Z",
        );
        let record = json!({ "source_id": "ds_y" });
        // FAILURE INJECTION: block the RECORD dir with a plain file → record persist fails FIRST.
        std::fs::write(dir.join(RECORD_DIR), b"blocker").unwrap();
        let (code, msg) =
            finalize_data_source_persist(data_dir, "ds_y", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code, "data_source_record_persist_failed");
        assert!(msg.contains("nothing changed"), "{msg}");
        // NO ORPHAN RECEIPT: the receipt was never attempted for an unpersisted record.
        assert!(
            read_record_dir(data_dir, RECEIPT_DIR).is_empty(),
            "no receipt without its record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn finalize_reports_rollback_failure_as_its_own_typed_lane() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("rbfail");
        let data_dir = dir.to_str().unwrap();
        let (rid, receipt) = build_data_source_receipt(
            "data-source:ds_z",
            "registered",
            "ok",
            "2026-01-01T00:00:00Z",
        );
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
            assert!(
                load(data_dir, RECORD_DIR, "ds_z").is_some(),
                "the stranded record is reported, not hidden"
            );
        } else {
            assert_eq!(code, "data_source_receipt_persist_failed");
            assert!(load(data_dir, RECORD_DIR, "ds_z").is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
