//! ADR 0056 P1 — THE NOTIFICATION INBOX, as canon shapes it (core-clients-surfaces.md): notifications are
//! PROJECTIONS of their owner's records — WorkRun, AutomationRun, Session, lease, approval, operation or an
//! owner event — and introduce no notification-event truth plane. So this module stores nothing and
//! caches nothing: every read re-derives each item from the owner record that changed, through that
//! owner's own published reader, and every item carries ONE deep link back to the object (work happens at
//! the owner, never in the inbox).
//!
//! WHAT AN ITEM IS. One `HypervisorNotificationProjection` (registered): the owner-event family, the
//! owner's own dotted transition (`approval.requested`, `run.failed`, `incident.opened`), the owner ref
//! and the revision at which it happened, a title read from the owner record, and the detail route. It
//! carries no read state and no delivery state — those are not event truth (the durable object is the
//! principal's `HypervisorNotificationSubscription`, a separate plane).
//!
//! POLICY BEFORE COUNTS. Sessions, automation runs and support incidents come through their owners'
//! policy-filtered readers, so there is no unfiltered set here to count. Governance approval requests are
//! read under the governance plane's own read policy (its list route answers any caller today); the inbox
//! adds identity: an anonymous caller gets the owners' refusal, never an inbox.
//!
//! WHAT IS NOT HERE YET, SAID OUT LOUD. Lease events (the capability-lease list is not filtered by
//! principal, so it cannot feed a per-person inbox honestly), provider-operation events, and health-check
//! events (P2) are TYPED ABSENCES in every answer, never an empty list pretending to be knowledge.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::DaemonState;

type Reply = (StatusCode, Json<Value>);

const INBOX_SCHEMA: &str = "ioi.hypervisor.notification-inbox.v1";
const ITEM_SCHEMA: &str = "ioi.hypervisor.notification-projection.v1";
const ITEM_CONTRACT_ID: &str = "schema://ioi/components/hypervisor/notification-projection/v1";
/// The reference's inbox window (and canon's "recent" lane): owner events of the last 30 days.
const WINDOW_DAYS: i64 = 30;
const DEFAULT_LIMIT: usize = 25;
const MAX_LIMIT: usize = 50;
const FAMILIES: [&str; 7] = [
    "owner_event",
    "work_run",
    "automation_run",
    "session",
    "lease",
    "approval",
    "operation",
];

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn text<'a>(record: &'a Value, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

fn tail_of(r: &str) -> &str {
    r.split_once("://")
        .map(|(_, tail)| tail)
        .or_else(|| r.strip_prefix("session:"))
        .unwrap_or(r)
}

/// One owner event, before the contract judges it.
struct Event {
    family: &'static str,
    kind: String,
    owner_ref: String,
    revision: String,
    occurred_at: String,
    title: String,
    body: Option<String>,
    route: String,
    source: &'static str,
}

impl Event {
    fn item(&self) -> Value {
        let id = format!(
            "projection://hypervisor/notification/{}/{}/{}",
            self.family,
            tail_of(&self.owner_ref),
            self.kind
        );
        let mut item = json!({
            "schema_version": ITEM_SCHEMA,
            "notification_projection_id": id,
            "owner_event_family": self.family,
            "event_kind": self.kind,
            "owner_ref": self.owner_ref,
            "owner_revision": self.revision,
            "occurred_at": self.occurred_at,
            "title": self.title.chars().take(300).collect::<String>(),
            "canonical_detail_route": self.route,
            "source_projection_ref": self.source,
            "policy_decision_refs": [],
            "read_model_only": true,
        });
        if let Some(body) = self.body.as_deref().filter(|b| !b.is_empty()) {
            item["body"] = json!(body.chars().take(2000).collect::<String>());
        }
        item
    }
}

/// The owner's revision marker for an event: its own operation ref when it records one, else the
/// timestamp the owner stamped on the transition — never a value this module invents.
fn revision_of(record: &Value, at: &str) -> String {
    for key in ["agentgres_operation_ref", "operation_ref", "revision"] {
        if let Some(v) = record.get(key) {
            if let Some(s) = v.as_str().filter(|s| !s.is_empty()) {
                return s.to_string();
            }
            if let Some(n) = v.as_u64() {
                return n.to_string();
            }
        }
    }
    format!("at:{at}")
}

/// An approval request's event: `approval.requested` while pending, `approval.<decision>` once decided.
fn approval_event(record: &Value) -> Option<Event> {
    let owner_ref = text(record, "ref");
    if !owner_ref.starts_with("approval-request://") {
        return None;
    }
    let status = text(record, "status");
    let (kind, at) = match status {
        "pending" => ("approval.requested".to_string(), text(record, "created_at")),
        "approved" | "rejected" | "withdrawn" | "expired" => (
            format!("approval.{status}"),
            if text(record, "decided_at").is_empty() {
                text(record, "updated_at")
            } else {
                text(record, "decided_at")
            },
        ),
        _ => return None,
    };
    if at.is_empty() {
        return None;
    }
    let subject = text(record, "subject_ref");
    let title = match (status, text(record, "request_kind")) {
        ("pending", k) if !k.is_empty() => format!("Approval requested: {k}"),
        ("pending", _) => "Approval requested".to_string(),
        (s, _) => format!("Approval {s}"),
    };
    Some(Event {
        family: "approval",
        kind,
        owner_ref: owner_ref.to_string(),
        revision: revision_of(record, at),
        occurred_at: at.to_string(),
        title,
        body: (!subject.is_empty()).then(|| format!("Subject: {subject}")),
        route: format!("/governance/approvals?req={}", tail_of(owner_ref)),
        source: "governance_routes::approval_requests (governance read policy)",
    })
}

/// A finished automation run's event: `run.failed` / `run.succeeded` / `run.cancelled`. A run still in
/// flight is not an event yet — the inbox reports transitions, not state.
fn automation_run_event(record: &Value) -> Option<Event> {
    let owner_ref = text(record, "automation_run_ref");
    if owner_ref.is_empty() {
        return None;
    }
    let status = record
        .get("status")
        .or_else(|| record.pointer("/resolution_receipt/material/status"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let kind = match status {
        "failed" | "error" => "run.failed",
        "succeeded" | "completed" | "success" => "run.succeeded",
        "cancelled" | "canceled" => "run.cancelled",
        _ => return None,
    };
    let at = if text(record, "updated_at").is_empty() {
        text(record, "admitted_at")
    } else {
        text(record, "updated_at")
    };
    if at.is_empty() {
        return None;
    }
    let name = text(record, "automation_ref");
    Some(Event {
        family: "automation_run",
        kind: kind.to_string(),
        owner_ref: owner_ref.to_string(),
        revision: revision_of(record, at),
        occurred_at: at.to_string(),
        title: match kind {
            "run.failed" => "Automation run failed".to_string(),
            "run.succeeded" => "Automation run succeeded".to_string(),
            _ => "Automation run cancelled".to_string(),
        },
        body: (!name.is_empty()).then(|| format!("Automation: {name}")),
        route: format!("/automations?run={}", tail_of(owner_ref)),
        source: "automation_contract_routes::automation_runs_for_request",
    })
}

/// A session's terminal event: `session.failed` / `session.completed` / `session.stopped`.
fn session_event(record: &Value) -> Option<Event> {
    let owner_ref = text(record, "session_ref");
    if owner_ref.is_empty() {
        return None;
    }
    let kind = match text(record, "lifecycle_state") {
        "failed" | "error" => "session.failed",
        "completed" | "succeeded" => "session.completed",
        "stopped" | "cancelled" | "canceled" => "session.stopped",
        _ => return None,
    };
    let at = if text(record, "updated_at").is_empty() {
        text(record, "created_at")
    } else {
        text(record, "updated_at")
    };
    if at.is_empty() {
        return None;
    }
    let title = text(record, "title");
    Some(Event {
        family: "session",
        kind: kind.to_string(),
        owner_ref: owner_ref.to_string(),
        revision: revision_of(record, at),
        occurred_at: at.to_string(),
        title: if title.is_empty() {
            match kind {
                "session.failed" => "Session failed",
                "session.completed" => "Session completed",
                _ => "Session stopped",
            }
            .to_string()
        } else {
            title.to_string()
        },
        body: None,
        route: format!("/work/sessions/{}", tail_of(owner_ref)),
        source: "lifecycle_routes::sessions_for_request",
    })
}

/// A support incident's event (an Operations owner event): `incident.opened` while open,
/// `incident.<status>` once it moves.
fn incident_event(record: &Value) -> Option<Event> {
    let owner_ref = text(record, "incident_id");
    if !owner_ref.starts_with("support-incident://") {
        return None;
    }
    let status = text(record, "status");
    let kind = match status {
        "" | "open" | "new" => "incident.opened".to_string(),
        s if s.chars().all(|c| c.is_ascii_lowercase() || c == '_') => format!("incident.{s}"),
        _ => return None,
    };
    let at = if kind == "incident.opened" || text(record, "updated_at").is_empty() {
        text(record, "created_at")
    } else {
        text(record, "updated_at")
    };
    if at.is_empty() {
        return None;
    }
    let title = text(record, "title");
    Some(Event {
        family: "owner_event",
        kind,
        owner_ref: owner_ref.to_string(),
        revision: revision_of(record, at),
        occurred_at: at.to_string(),
        title: if title.is_empty() {
            "Issue filed".to_string()
        } else {
            format!("Issue: {title}")
        },
        body: None,
        route: format!("/operations/issues?issue={}", tail_of(owner_ref)),
        source: "operations_support_routes::incidents_for_request",
    })
}

fn within_window(at: &str, now: OffsetDateTime) -> bool {
    OffsetDateTime::parse(at, &Rfc3339)
        .map(|t| now - t <= time::Duration::days(WINDOW_DAYS))
        .unwrap_or(false)
}

fn validate(item: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(ITEM_CONTRACT_ID, item).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "notification_item_contract_invalid",
            format!("an inbox item violates its registered contract and the inbox is NOT served: {error}"),
        )
    })
}

/// Assemble the inbox from owner events: window, family filter, newest first, a named cap, and every
/// item judged by its registered contract (a malformed item fails the whole read closed — a finding,
/// not a dropped row).
fn assemble(
    events: Vec<Event>,
    family: Option<&str>,
    limit: usize,
    now: OffsetDateTime,
    readers: Vec<Value>,
) -> Result<Value, Reply> {
    let mut kept: Vec<Event> = events
        .into_iter()
        .filter(|e| within_window(&e.occurred_at, now))
        .filter(|e| family.map_or(true, |f| e.family == f))
        .collect();
    kept.sort_by(|a, b| {
        b.occurred_at
            .cmp(&a.occurred_at)
            .then_with(|| a.owner_ref.cmp(&b.owner_ref))
    });
    let mut by_family: HashMap<&str, usize> = HashMap::new();
    for e in &kept {
        *by_family.entry(e.family).or_default() += 1;
    }
    let total = kept.len();
    let mut items = Vec::new();
    for e in kept.iter().take(limit) {
        let item = e.item();
        validate(&item)?;
        items.push(item);
    }
    Ok(json!({
        "ok": true,
        "schema_version": INBOX_SCHEMA,
        "window_days": WINDOW_DAYS,
        "items": items,
        "counts": { "total": total, "shown": items.len(), "by_family": by_family },
        "limit": limit,
        "policy_filtered_before_counts": true,
        "readers": readers,
        "typed_absences": [
            { "family": "lease", "code": "lease_events_need_a_principal_filtered_reader", "message": "The capability-lease list is not filtered by principal, so lease expiry cannot feed a per-person inbox honestly." },
            { "family": "operation", "code": "provider_operation_events_not_projected", "message": "Provider-operation events have no policy-filtered owner reader yet." },
            { "family": "owner_event", "code": "health_check_events_await_p2", "message": "Health-check events arrive with the health-check plane (ADR 0056 P2)." }
        ],
        "delivery": { "in_platform": "this read", "email": null, "email_absence": "no delivery-channel plane exists; subscriptions record channels, nothing sends mail" },
        "stores_nothing": true
    }))
}

/// GET /v1/hypervisor/notifications — the caller's inbox, re-derived on every read.
pub(crate) async fn handle_notifications(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Reply {
    let family = params
        .get("family")
        .map(String::as_str)
        .filter(|f| !f.is_empty());
    if let Some(f) = family {
        if !FAMILIES.contains(&f) {
            return bad(
                StatusCode::BAD_REQUEST,
                "notification_family_unknown",
                format!("family must be one of {FAMILIES:?}"),
            );
        }
    }
    let limit = match params.get("limit").map(|l| l.parse::<usize>()) {
        None => DEFAULT_LIMIT,
        Some(Ok(n)) if (1..=MAX_LIMIT).contains(&n) => n,
        Some(_) => {
            return bad(
                StatusCode::BAD_REQUEST,
                "hypervisor.page_size_out_of_bounds",
                format!("limit must be 1..={MAX_LIMIT}"),
            )
        }
    };
    // EVERY FAMILY THROUGH ITS OWNER'S READER — identity-first; an anonymous caller is refused there.
    let sessions = match super::lifecycle_routes::sessions_for_request(&st, &headers) {
        Ok(records) => records,
        Err(reply) => return reply,
    };
    let runs = match super::automation_contract_routes::automation_runs_for_request(&st, &headers) {
        Ok(records) => records,
        Err(reply) => return reply,
    };
    let incidents = match super::operations_support_routes::incidents_for_request(&st, &headers) {
        Ok(records) => records,
        Err(reply) => return reply,
    };
    let approvals = super::governance_routes::approval_requests_all(&st.data_dir);
    let mut events: Vec<Event> = Vec::new();
    events.extend(sessions.iter().filter_map(session_event));
    events.extend(runs.iter().filter_map(automation_run_event));
    events.extend(incidents.iter().filter_map(incident_event));
    events.extend(approvals.iter().filter_map(approval_event));
    let readers = vec![
        json!({ "family": "session", "reader": "lifecycle_routes::sessions_for_request", "records": sessions.len() }),
        json!({ "family": "automation_run", "reader": "automation_contract_routes::automation_runs_for_request", "records": runs.len() }),
        json!({ "family": "owner_event", "owner": "support_incident", "reader": "operations_support_routes::incidents_for_request", "records": incidents.len() }),
        json!({ "family": "approval", "reader": "governance_routes::approval_requests_all", "records": approvals.len(), "read_policy": "the governance plane's own (its list route answers any caller)" }),
    ];
    match assemble(events, family, limit, OffsetDateTime::now_utc(), readers) {
        Ok(inbox) => (StatusCode::OK, Json(inbox)),
        Err(reply) => reply,
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-09-25T12:00:00Z", &Rfc3339).unwrap()
    }

    #[test]
    fn every_owner_event_projects_a_registered_item_with_one_link_back() {
        let events = vec![
            approval_event(&json!({ "ref": "approval-request://appr_1", "status": "pending", "request_kind": "publish", "subject_ref": "improvement-proposal://imp_1", "created_at": "2026-09-25T10:00:00Z" })).unwrap(),
            automation_run_event(&json!({ "automation_run_ref": "automation-run://ar_1", "status": "failed", "updated_at": "2026-09-24T09:00:00Z", "automation_ref": "automation://nightly" })).unwrap(),
            session_event(&json!({ "session_ref": "session://acme/s1", "lifecycle_state": "completed", "updated_at": "2026-09-23T08:00:00Z" })).unwrap(),
            incident_event(&json!({ "incident_id": "support-incident://sil_1", "status": "open", "title": "Orders feed stopped", "created_at": "2026-09-22T07:00:00Z" })).unwrap(),
        ];
        let inbox =
            assemble(events, None, 25, now(), vec![]).expect("every item is registered-valid");
        let items = inbox["items"].as_array().unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0]["event_kind"], "approval.requested", "newest first");
        assert_eq!(
            items[0]["canonical_detail_route"],
            "/governance/approvals?req=appr_1"
        );
        assert_eq!(items[1]["canonical_detail_route"], "/automations?run=ar_1");
        assert_eq!(items[3]["owner_event_family"], "owner_event");
        assert_eq!(
            items[3]["canonical_detail_route"],
            "/operations/issues?issue=sil_1"
        );
        for item in items {
            assert!(
                item.get("read").is_none() && item.get("delivered").is_none(),
                "no read or delivery state on an item"
            );
            assert_eq!(item["read_model_only"], true);
        }
        assert_eq!(inbox["stores_nothing"], true);
        assert_eq!(
            inbox["typed_absences"].as_array().unwrap().len(),
            3,
            "lease, operation and health events are named absences"
        );
    }

    #[test]
    fn the_inbox_reports_transitions_inside_its_window_and_names_its_cap() {
        assert!(automation_run_event(&json!({ "automation_run_ref": "automation-run://ar_2", "status": "running", "updated_at": "2026-09-25T09:00:00Z" })).is_none(), "a run in flight is not an event");
        assert!(session_event(&json!({ "session_ref": "session://acme/s2", "lifecycle_state": "running", "updated_at": "2026-09-25T09:00:00Z" })).is_none());
        let old = approval_event(&json!({ "ref": "approval-request://appr_old", "status": "approved", "decided_at": "2026-07-01T00:00:00Z" })).unwrap();
        let fresh = approval_event(&json!({ "ref": "approval-request://appr_new", "status": "rejected", "decided_at": "2026-09-25T00:00:00Z" })).unwrap();
        let inbox = assemble(vec![old, fresh], None, 25, now(), vec![]).unwrap();
        assert_eq!(
            inbox["items"].as_array().unwrap().len(),
            1,
            "older than 30 days is outside the window"
        );
        assert_eq!(inbox["items"][0]["event_kind"], "approval.rejected");
        let many: Vec<Event> = (0..30)
            .map(|i| incident_event(&json!({ "incident_id": format!("support-incident://sil_{i}"), "status": "open", "created_at": format!("2026-09-2{}T0{}:00:00Z", i % 5, i % 9) })).unwrap())
            .collect();
        let capped = assemble(many, Some("owner_event"), 25, now(), vec![]).unwrap();
        assert_eq!(capped["counts"]["total"], 30);
        assert_eq!(
            capped["counts"]["shown"], 25,
            "the cap is named, never silent"
        );
        let other = assemble(vec![], Some("approval"), 25, now(), vec![]).unwrap();
        assert_eq!(other["counts"]["total"], 0);
    }

    #[test]
    fn a_malformed_item_fails_the_inbox_closed() {
        let mut e = session_event(&json!({ "session_ref": "session://acme/s3", "lifecycle_state": "failed", "updated_at": "2026-09-25T09:00:00Z" })).unwrap();
        e.route = "https://evil.example/x".to_string();
        let refused = assemble(vec![e], None, 25, now(), vec![]).unwrap_err();
        assert_eq!(refused.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(refused
            .1
             .0
            .to_string()
            .contains("notification_item_contract_invalid"));
    }
}
