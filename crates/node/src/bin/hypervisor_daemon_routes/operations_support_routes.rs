//! Operations support plane (W1.5) — SupportIncidentLink projections and the paginated
//! audit-trail read. Canon: `SupportIncidentLink` is Operations-owned and PROJECTION-ONLY
//! (docs/architecture/components/daemon-runtime/platform-operability.md §SupportIncidentLink):
//! an incident link correlates affected product/tenant/objects/event-range with severity and
//! redacted diagnostics; it grants nothing, gates nothing, and never becomes authority.
//!
//! The audit trail is a READ over the durable evidence families the daemon already writes —
//! authority receipts, credential-grant audit, retention dispositions, support incidents. It
//! fabricates nothing: every row is a stored record, typed by source, paginated with the same
//! deterministic limit/after mechanic the shared read client negotiates.

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

const SUPPORT_NAMESPACE: &str = "hypervisor-operations-support";
const KIND_INCIDENT: &str = "support-incidents";
const SCHEMA_VERSION: &str = "ioi.hypervisor.support_incident_link.v1";
const SEVERITIES: &[&str] = &["informational", "minor", "major", "critical"];
const STATUSES: &[&str] = &["open", "mitigated", "resolved", "closed"];

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
                .join(KIND_INCIDENT)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

fn project_admission(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(super::iso_now());
}

fn project_or_fail(data_dir: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, KIND_INCIDENT, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "support_incident_persistence_failed",
            "the transition is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
}

/// POST /v1/hypervisor/support-incidents — link an incident to what it affects.
pub(crate) async fn handle_incident_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let reported_by = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor_ref) => actor_ref,
        Err((status, value)) => return (status, Json(value)),
    };
    let severity = str_field(&body, "severity");
    if !SEVERITIES.contains(&severity) {
        return bad(
            StatusCode::BAD_REQUEST,
            "support_incident_severity_invalid",
            format!("severity must be one of {SEVERITIES:?}"),
        );
    }
    let title = str_field(&body, "title");
    if title.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "support_incident_title_required",
            "title is required",
        );
    }
    let affected_object_refs: Vec<String> = body
        .get("affected_object_refs")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if affected_object_refs.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "support_incident_affected_required",
            "affected_object_refs must name at least one affected object — an incident that affects nothing links nothing",
        );
    }
    let id = replay_stable_id("sil", &caller.owner_ref, &caller.idempotency_key);
    let incident_ref = format!("support-incident://{id}");
    let admitted = json!({
        "incident_id": incident_ref,
        "title": title,
        "severity": severity,
        "affected_object_refs": affected_object_refs,
    });
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        SUPPORT_NAMESPACE,
        KIND_INCIDENT,
        &incident_ref,
        "support.incident.link",
        None,
        &admitted,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if commit.replayed {
        if let Some(existing) = load(&st.data_dir, &id) {
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "replayed": true, "incident": existing })),
            );
        }
    }
    let mut record = json!({
        "schema_version": SCHEMA_VERSION,
        "incident_id": incident_ref,
        "title": title,
        "severity": severity,
        "status": "open",
        "affected": {
            "product": str_field(&body, "product"),
            "tenant_ref": caller.owner_ref,
            "object_refs": affected_object_refs,
            "event_range": body.get("event_range").cloned().unwrap_or(Value::Null),
        },
        // Diagnostics are DECLARED redacted by the reporter; this plane stores what it is
        // given and never unseals anything — secrets have no path into an incident body.
        "redacted_diagnostics": str_field(&body, "redacted_diagnostics"),
        "reported_by": reported_by,
        "assigned_owner_ref": str_field(&body, "assigned_owner_ref"),
        "owner_ref": caller.owner_ref,
        "created_at": super::iso_now(),
    });
    project_admission(&mut record, &commit);
    if let Err(response) = project_or_fail(&st.data_dir, &id, &record) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "replayed": false, "incident": record })),
    )
}

/// POST /v1/hypervisor/support-incidents/:id/status {status} — advance the incident.
pub(crate) async fn handle_incident_status(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let to_status = str_field(&body, "status");
    if !STATUSES.contains(&to_status) {
        return bad(
            StatusCode::BAD_REQUEST,
            "support_incident_status_invalid",
            format!("status must be one of {STATUSES:?}"),
        );
    }
    let Some(record) = load(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "support_incident_not_found",
            "no incident exists at this id",
        );
    };
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if record["status"].as_str() == Some(to_status) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "incident": record })),
        );
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "support_incident_expected_head_required",
            "this record predates admitted mutation; it cannot be advanced without a head",
        );
    };
    let incident_ref = format!("support-incident://{id}");
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        SUPPORT_NAMESPACE,
        KIND_INCIDENT,
        &incident_ref,
        "support.incident.status",
        Some(&expected_head),
        &json!({ "incident_id": incident_ref, "status": to_status }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut successor = record;
    successor["status"] = json!(to_status);
    project_admission(&mut successor, &commit);
    if let Err(response) = project_or_fail(&st.data_dir, &id, &successor) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "replayed": commit.replayed, "incident": successor })),
    )
}

/// GET /v1/hypervisor/support-incidents/:id
pub(crate) async fn handle_incident_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(record) = load(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "support_incident_not_found",
            "no incident exists at this id",
        );
    };
    if !record["owner_ref"]
        .as_str()
        .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref))
    {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "incident": record })),
    )
}

// ================================ audit trail ==================================================

#[derive(serde::Deserialize)]
pub(crate) struct AuditTrailQuery {
    limit: Option<u64>,
    after: Option<String>,
}

fn audit_row(kind: &str, at: &str, id: &str, record: Value) -> Value {
    json!({ "kind": kind, "at": at, "id": id, "record": record })
}

/// GET /v1/hypervisor/audit/trail — one typed, paginated read over the durable evidence
/// families. Order is (at, kind, id) descending; `after` is the previous page's last
/// composite token. Every row is a stored record — nothing is synthesized.
pub(crate) async fn handle_audit_trail(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(page): Query<AuditTrailQuery>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let mut rows: Vec<Value> = Vec::new();
    for receipt in read_record_dir(&st.data_dir, "authority-receipts") {
        let at = receipt["at"].as_str().unwrap_or("").to_string();
        let id = receipt["receipt_id"].as_str().unwrap_or("").to_string();
        rows.push(audit_row("authority_receipt", &at, &id, receipt));
    }
    for audit in read_record_dir(&st.data_dir, "principal-lease-grant-audit") {
        let at = audit["at"].as_str().unwrap_or("").to_string();
        let id = audit["grant"]["grant_id"]
            .as_str()
            .unwrap_or("")
            .to_string();
        rows.push(audit_row("credential_grant_audit", &at, &id, audit));
    }
    for disposition in read_record_dir(&st.data_dir, "retention-dispositions") {
        if !disposition["owner_ref"]
            .as_str()
            .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref))
        {
            continue;
        }
        let at = disposition["updated_at"].as_str().unwrap_or("").to_string();
        let id = disposition["disposition_id"]
            .as_str()
            .unwrap_or("")
            .to_string();
        rows.push(audit_row("retention_disposition", &at, &id, disposition));
    }
    for incident in read_record_dir(&st.data_dir, KIND_INCIDENT) {
        if !incident["owner_ref"]
            .as_str()
            .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref))
        {
            continue;
        }
        let at = incident["updated_at"].as_str().unwrap_or("").to_string();
        let id = incident["incident_id"].as_str().unwrap_or("").to_string();
        rows.push(audit_row("support_incident", &at, &id, incident));
    }
    rows.sort_by(|a, b| {
        let key = |r: &Value| {
            format!(
                "{}|{}|{}",
                r["at"].as_str().unwrap_or(""),
                r["kind"].as_str().unwrap_or(""),
                r["id"].as_str().unwrap_or("")
            )
        };
        key(b).cmp(&key(a))
    });
    let total = rows.len();
    if let Some(after) = page
        .after
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        rows.retain(|r| {
            let key = format!(
                "{}|{}|{}",
                r["at"].as_str().unwrap_or(""),
                r["kind"].as_str().unwrap_or(""),
                r["id"].as_str().unwrap_or("")
            );
            key.as_str() < after
        });
    }
    let mut body = json!({
        "schema_version": "ioi.hypervisor.audit-trail.v1",
        "at": super::iso_now(),
        "sources": ["authority_receipt", "credential_grant_audit", "retention_disposition", "support_incident"],
    });
    if let Some(limit) = page.limit {
        let limit = limit.clamp(1, 500) as usize;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_after = if has_more {
            rows.last().map(|r| {
                format!(
                    "{}|{}|{}",
                    r["at"].as_str().unwrap_or(""),
                    r["kind"].as_str().unwrap_or(""),
                    r["id"].as_str().unwrap_or("")
                )
            })
        } else {
            None
        };
        body["page"] = json!({
            "limit": limit,
            "after": page.after,
            "next_after": next_after,
            "has_more": has_more,
            "total": total,
        });
    }
    body["entries"] = json!(rows);
    (StatusCode::OK, Json(body))
}
