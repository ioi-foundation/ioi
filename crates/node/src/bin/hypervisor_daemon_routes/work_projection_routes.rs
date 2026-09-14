//! M08.9 — THE WORK READ MODEL, as canon shapes it (core-clients-surfaces.md § Hypervisor Work):
//! a policy-filtered projection of heterogeneous work into typed rows, never a canonical `Work`
//! object and never one universal lifecycle.
//!
//! WHAT A ROW IS. Every row is one `HypervisorWorkSubjectProjection` (registered): a typed
//! `subject_kind`, the owner's canonical `subject_ref` carried verbatim, the deep link to the
//! type-specific owner, and two DISPLAY facets derived from the owner's own state without writing
//! a common status back over it. Reviews are `HypervisorWorkFacetProjection` pointers at the
//! governance plane's approval requests — a pointer, never a converted Review object.
//!
//! WHERE ROWS COME FROM. Hypervisor core Work enumerates ONLY the families the substrate owns, in
//! session vocabulary (canon's Work subject registry, ruled 2026-09-14): Sessions through
//! `lifecycle_routes::sessions_for_request` and automation runs through
//! `automation_contract_routes::automation_runs_for_request`. Each reader applies its owner's
//! policy (identity, tenant) BEFORE this module sees a record, so policy precedes search, counts,
//! recents and aggregation by construction: there is no unfiltered set anywhere here to count.
//!
//! WHAT IS CONTRIBUTED, NOT ENUMERATED. Goal runs and rooms are the ioi.ai orchestration
//! application's domain (ADR 0022 Decision 1: "goal runs and rooms are not Hypervisor surfaces";
//! term-boundaries.md: the substrate's own surfaces speak session vocabulary). They reach Work
//! through exactly two seams — a Session's typed `subject_attachments[]` row pointing at the owner
//! object, or a Work view the owner application registers through the product-surface
//! registration family — and this module publishes no reader for them and mints no route for
//! them. Their kinds stay in the registered enum because a contributed row must still be typed.
//!
//! WHAT IT DOES NOT DO. It caches nothing and persists nothing — every read re-derives, which is
//! what makes `rebuild` a property rather than a procedure. It does not enumerate the
//! work-lifecycle log's queues, items and runs: that log is object-scoped and its owner publishes
//! no enumeration yet, so those subject kinds are a TYPED ABSENCE in every answer, never an empty
//! list pretending to be knowledge. A row that fails its registered contract fails the whole read
//! closed and names the family — a malformed owner record is a finding, not a dropped row.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::DaemonState;

type Reply = (StatusCode, Json<Value>);

const PROJECTION_SCHEMA: &str = "ioi.hypervisor.work-projection.v1";
const SUBJECT_SCHEMA: &str = "ioi.hypervisor.work-subject-projection.v1";
const SUBJECT_CONTRACT_ID: &str = "schema://ioi/components/hypervisor/work-subject-projection/v1";
const FACET_SCHEMA: &str = "ioi.hypervisor.work-facet-projection.v1";
const FACET_CONTRACT_ID: &str = "schema://ioi/components/hypervisor/work-facet-projection/v1";
/// The typed views canon routes (`/work` → active, then one per view). Closed: an unknown view
/// refuses rather than answering the nearest one.
const VIEWS: &[&str] = &[
    "active",
    "sessions",
    "queues",
    "reviews",
    "incidents",
    "history",
];
/// The registered subject kinds and the ref schemes their owners mint — the CONTRACT's vocabulary,
/// wider than what core enumerates (see `CONTRIBUTED_FAMILIES`). `session:` is the Session
/// plane's admitted identity today (canon names `session://` as the target form; the row carries
/// the owner's identity verbatim either way).
const SUBJECT_KINDS: &[&str] = &[
    "goal_run",
    "outcome_room",
    "automation_run",
    "session",
    "work_queue",
    "work_item",
    "work_run",
];
/// Kinds this build cannot project, each with the reason — typed absence, said on every answer.
const FAMILIES_NOT_PROJECTED: &[(&str, &str)] = &[
    ("work_queue", "the work-lifecycle log is object-scoped and its owner publishes no enumeration yet (M04.6 owns it)"),
    ("work_item", "the work-lifecycle log is object-scoped and its owner publishes no enumeration yet (M04.6 owns it)"),
    ("work_run", "the work-lifecycle log is object-scoped and its owner publishes no enumeration yet (M04.6 owns it)"),
];
/// Kinds core Work never enumerates: contributed families, each with its owner and the only seams
/// it may arrive through. Said on every answer so an empty Goals column is never read as "none".
const CONTRIBUTED_FAMILIES: &[(&str, &str)] = &[
    ("goal_run", "ioi.ai orchestration application (goal-pursuit.md § Work / Goals surface): reaches Work only through a Session's typed subject attachment or the application-contributed Work / Goals view; core publishes no reader and mints no route"),
    ("outcome_room", "ioi.ai orchestration application (collaborative-outcome-pattern.md § The application-contributed Rooms view): reaches Work only through a Session's typed subject attachment or the application-contributed Work / Rooms view; core publishes no reader and mints no route"),
];
const RECENTS: usize = 10;

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

/// The subject kind a canonical ref belongs to, from its scheme alone. `None` for a ref outside
/// the registered vocabulary; the mapping is one-to-one, so no ref is ambiguous by itself.
pub(crate) fn subject_kind_for_ref(subject_ref: &str) -> Option<&'static str> {
    if subject_ref.starts_with("session:") {
        return Some("session");
    }
    let scheme = subject_ref.split_once("://")?.0;
    match scheme {
        "goal" | "goal-run" => Some("goal_run"),
        "outcome-room" => Some("outcome_room"),
        "automation-run" => Some("automation_run"),
        "session" => Some("session"),
        "work_queue" => Some("work_queue"),
        "work_item" => Some("work_item"),
        "work_run" => Some("work_run"),
        _ => None,
    }
}

/// The activity facet, DERIVED from the owner's own status vocabulary and never written back. An
/// owner status this table does not know reads as `waiting` — the facet claims the least, and the
/// owner's verbatim status travels beside it in the row's source note.
pub(crate) fn activity_facet(subject_kind: &str, owner_status: &str) -> &'static str {
    match (subject_kind, owner_status) {
        (_, "completed" | "settled" | "closed" | "resolved") => "completed",
        (_, "archived" | "dissolved" | "retired") => "archived",
        (_, s) if s.starts_with("failed") || s.starts_with("aborted") || s == "error" => "failed",
        (_, "review" | "awaiting_review" | "in_review" | "reviewing") => "review",
        (_, "blocked" | "waiting_on_conductor" | "reconciling" | "paused") => "blocked",
        ("session", "launched" | "running" | "active") => "active",
        ("automation_run", "running" | "executing" | "active") => "active",
        _ => "waiting",
    }
}

/// How the subject executes, by kind: a Session is interactive, an automation run is headless.
/// Fixed by kind, not guessed from state; a contributed kind is never derived here, so it has no
/// mode from core (`not_applicable`) — its owner's view says how it executes.
pub(crate) fn execution_mode(subject_kind: &str) -> &'static str {
    match subject_kind {
        "session" => "interactive",
        "automation_run" => "headless",
        _ => "not_applicable",
    }
}

/// The canonical deep link for a CORE subject: the typed Work view for sessions and the
/// Automations owner for automation runs. Core mints no `/work/goals` or `/work/rooms` route —
/// those belong to the application that contributes the view (ADR 0052 Decision 4).
fn detail_route(subject_kind: &str, subject_ref: &str) -> String {
    let tail = subject_ref
        .split_once("://")
        .map(|(_, tail)| tail)
        .or_else(|| subject_ref.strip_prefix("session:"))
        .unwrap_or(subject_ref);
    match subject_kind {
        "session" => format!("/work/sessions/{tail}"),
        "automation_run" => format!("/automations?run={tail}"),
        _ => format!("/work/queues/{tail}"),
    }
}

fn text<'a>(record: &'a Value, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

fn scoped_ref(record: &Value, key: &str, scheme: &str) -> Value {
    match record.get(key).and_then(Value::as_str) {
        Some(value) if value.starts_with(scheme) => json!(value),
        _ => Value::Null,
    }
}

/// One family's admitted record becomes one typed row plus the ordering key the recents view
/// needs. The row carries no owner-specific payload — the deep link is where the payload lives.
struct Derived {
    row: Value,
    updated_at: String,
    owner_status: String,
}

fn derive_row(
    subject_kind: &str,
    subject_ref: &str,
    record: &Value,
    owner_status: &str,
    updated_at: &str,
    source: &str,
) -> Derived {
    let row = json!({
        "schema_version": SUBJECT_SCHEMA,
        "projection_row_id": format!("hypervisor_work_subject_projection:{subject_ref}"),
        "subject_kind": subject_kind,
        "subject_ref": subject_ref,
        "org_ref": scoped_ref(record, "owner_ref", "org://"),
        "project_ref": scoped_ref(record, "project_ref", "project://"),
        "system_ref": scoped_ref(record, "system_ref", "system://"),
        "canonical_detail_route": detail_route(subject_kind, subject_ref),
        "display_facets": {
            "activity": activity_facet(subject_kind, owner_status),
            "execution_mode": execution_mode(subject_kind),
        },
        "review_facet_projection_refs": [],
        "incident_facet_projection_refs": [],
        "source_projection_refs": [source],
        "policy_decision_refs": [],
        "read_model_only": true,
    });
    Derived {
        row,
        updated_at: updated_at.to_owned(),
        owner_status: owner_status.to_owned(),
    }
}

fn validate(contract_id: &str, family: &str, value: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(contract_id, value)
        .map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "work_projection_row_contract_invalid",
                format!("a {family} row violates its registered contract and the projection is NOT served: {error}"),
            )
        })
}

/// The view a row belongs to by its activity facet alone: live work is `active`, finished work is
/// `history`; `sessions` is a kind, and `reviews`/`incidents` are facet views.
fn activity_view(activity: &str) -> &'static str {
    match activity {
        "completed" | "failed" | "archived" => "history",
        _ => "active",
    }
}

fn parse_subject_filter(
    params: &HashMap<String, String>,
) -> Result<Option<(String, &'static str)>, Reply> {
    let Some(subject_ref) = params
        .get("subject_ref")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        if let Some(kind) = params.get("subject_kind") {
            if !SUBJECT_KINDS.contains(&kind.as_str()) {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "work_projection_subject_kind_unknown",
                    format!("subject_kind must be one of {SUBJECT_KINDS:?}"),
                ));
            }
        }
        return Ok(None);
    };
    let Some(kind) = subject_kind_for_ref(subject_ref) else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_projection_subject_ref_invalid",
            format!("{subject_ref} is not a canonical typed Work subject ref; the registered schemes are goal://, outcome-room://, automation-run://, session: and work_queue|work_item|work_run://"),
        ));
    };
    if let Some(asserted) = params.get("subject_kind") {
        if asserted != kind {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "work_projection_subject_kind_ambiguous",
                format!("{subject_ref} is a {kind} by its scheme but the request asserts subject_kind {asserted}; a subject has exactly one kind and the projection refuses to pick"),
            ));
        }
    }
    Ok(Some((subject_ref.to_owned(), kind)))
}

/// The projection's pure half: rows the owners' readers have ALREADY policy-filtered become the
/// answer for one view, with counts and recents computed over that same filtered set (never over
/// anything wider) and search applied last.
fn assemble(
    view: &str,
    params: &HashMap<String, String>,
    derived: Vec<Derived>,
    facets: Vec<Value>,
    readers: Vec<Value>,
) -> Result<Value, Reply> {
    if !VIEWS.contains(&view) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "work_projection_view_unknown",
            format!("view must be one of {VIEWS:?}"),
        ));
    }
    let subject_filter = parse_subject_filter(params)?;
    let query = params
        .get("q")
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());
    let kind_filter = params.get("subject_kind").cloned();

    // Counts per view over the policy-filtered set — before search, before the subject filter.
    let mut counts: HashMap<&str, usize> = VIEWS.iter().map(|view| (*view, 0)).collect();
    for item in &derived {
        let activity = item.row["display_facets"]["activity"]
            .as_str()
            .unwrap_or("waiting");
        *counts.get_mut(activity_view(activity)).unwrap() += 1;
        if item.row["subject_kind"] == "session" {
            *counts.get_mut("sessions").unwrap() += 1;
        }
        if !item.row["review_facet_projection_refs"]
            .as_array()
            .map(Vec::is_empty)
            .unwrap_or(true)
        {
            *counts.get_mut("reviews").unwrap() += 1;
        }
    }
    // Recents over the same set, newest first, before search.
    let mut by_recency: Vec<&Derived> = derived.iter().collect();
    by_recency.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    let recents: Vec<Value> = by_recency
        .iter()
        .take(RECENTS)
        .map(|item| json!({ "subject_kind": item.row["subject_kind"], "subject_ref": item.row["subject_ref"], "canonical_detail_route": item.row["canonical_detail_route"], "updated_at": item.updated_at }))
        .collect();

    let matches_view = |item: &Derived| -> bool {
        let activity = item.row["display_facets"]["activity"]
            .as_str()
            .unwrap_or("waiting");
        match view {
            "active" | "history" => activity_view(activity) == view,
            "sessions" => item.row["subject_kind"] == "session",
            "queues" => matches!(
                item.row["subject_kind"].as_str(),
                Some("work_queue" | "work_item" | "work_run")
            ),
            "reviews" => !item.row["review_facet_projection_refs"]
                .as_array()
                .map(Vec::is_empty)
                .unwrap_or(true),
            "incidents" => !item.row["incident_facet_projection_refs"]
                .as_array()
                .map(Vec::is_empty)
                .unwrap_or(true),
            _ => false,
        }
    };
    let mut rows: Vec<Value> = derived
        .iter()
        .filter(|item| matches_view(item))
        .filter(|item| {
            kind_filter
                .as_deref()
                .is_none_or(|kind| item.row["subject_kind"] == kind)
        })
        .filter(|item| {
            subject_filter
                .as_ref()
                .is_none_or(|(subject_ref, _)| item.row["subject_ref"] == *subject_ref)
        })
        .filter(|item| {
            query.as_deref().is_none_or(|needle| {
                item.row["subject_ref"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(needle)
                    || item.row["canonical_detail_route"]
                        .as_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(needle)
                    || item.owner_status.to_lowercase().contains(needle)
            })
        })
        .map(|item| item.row.clone())
        .collect();
    rows.sort_by(|left, right| {
        left["subject_ref"]
            .as_str()
            .cmp(&right["subject_ref"].as_str())
    });
    let facets_for_view: Vec<Value> = match view {
        "reviews" => facets
            .iter()
            .filter(|facet| facet["facet_kind"] == "review")
            .cloned()
            .collect(),
        "incidents" => facets
            .iter()
            .filter(|facet| facet["facet_kind"] == "incident")
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    Ok(json!({
        "ok": true,
        "schema_version": PROJECTION_SCHEMA,
        "row_contract_id": SUBJECT_CONTRACT_ID,
        "facet_contract_id": FACET_CONTRACT_ID,
        "view": view,
        "rows": rows,
        "facets": facets_for_view,
        "counts": VIEWS.iter().map(|view| (view.to_string(), json!(counts[view]))).collect::<serde_json::Map<String, Value>>(),
        "recents": recents,
        "policy": {
            "applied_before": ["search", "counts", "recents", "aggregation", "caching"],
            "readers": readers,
            "note": "every family is read through its owner's published reader, which applies that owner's identity, tenant or principal rule before this projection sees a record; there is no unfiltered set here to count"
        },
        "families": {
            "projected": ["session", "automation_run"],
            "not_projected": FAMILIES_NOT_PROJECTED.iter().map(|(kind, reason)| json!({ "subject_kind": kind, "reason": reason })).collect::<Vec<_>>(),
            "contributed": CONTRIBUTED_FAMILIES.iter().map(|(kind, seam)| json!({ "subject_kind": kind, "seam": seam })).collect::<Vec<_>>(),
            "registry": "core Work enumerates only substrate-owned families in session vocabulary; a contributed family arrives through a Session's typed subject attachment or a registered application-contributed view, never through a core reader (core-clients-surfaces.md § Hypervisor Work, Work subject registry)",
            "incident_facets": { "state": "absent", "reason": "no incident owner publishes a reader this projection can point at yet; a Work incident is a typed pointer, never a minted incident" }
        },
        "migration": {
            "from": ["/__ioi/sessions (the Sessions root)", "/__ioi/missions/incidents (issue/blocker aggregates)", "/__ioi/work-ledger"],
            "to": "typed HypervisorWorkSubjectProjection rows under /work, /work/sessions, /work/queues, /work/reviews, /work/incidents and /work/history",
            "not_core": "/__ioi/missions renders the room graph, which is the ioi.ai contribution seam's to replace, not core's to migrate",
            "rule": "legacy readouts are migration inputs, not proof; a legacy row that is not one of the two core families is not carried over as a generic mission"
        },
        "rebuild": "every read re-derives the rows from the owners' readers; nothing is cached or persisted, so a restart changes nothing this projection answers",
        "nonclaim": "a policy-filtered read model over typed subjects: it mints no Work object, writes no common status back to any owner, and grants nothing"
    }))
}

/// GET /v1/hypervisor/work-projection?view=active|sessions|queues|reviews|incidents|history
///     [&q=…][&subject_ref=…][&subject_kind=…]
pub(crate) async fn handle_work_projection(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Reply {
    let view = params.get("view").map(String::as_str).unwrap_or("active");
    if !VIEWS.contains(&view) {
        return bad(
            StatusCode::BAD_REQUEST,
            "work_projection_view_unknown",
            format!("view must be one of {VIEWS:?}"),
        );
    }
    if let Err(reply) = parse_subject_filter(&params) {
        return reply;
    }
    // EVERY CORE FAMILY THROUGH ITS OWNER'S READER — each applies its own policy first. Nothing
    // else is read: a contributed family (goal runs, rooms) has no reader here by ruling.
    let sessions = match super::lifecycle_routes::sessions_for_request(&st, &headers) {
        Ok(records) => records,
        Err(reply) => return reply,
    };
    let automation_runs =
        match super::automation_contract_routes::automation_runs_for_request(&st, &headers) {
            Ok(records) => records,
            Err(reply) => return reply,
        };
    let mut derived: Vec<Derived> = Vec::new();
    for record in &sessions {
        let subject_ref = text(record, "session_ref");
        if subject_ref.is_empty() {
            continue;
        }
        derived.push(derive_row(
            "session",
            subject_ref,
            record,
            text(record, "lifecycle_state"),
            text(record, "created_at"),
            "lifecycle_routes::sessions_for_request",
        ));
    }
    for record in &automation_runs {
        let subject_ref = text(record, "automation_run_ref");
        if subject_ref.is_empty() {
            continue;
        }
        let status = record
            .get("status")
            .or_else(|| record.pointer("/resolution_receipt/material/status"))
            .and_then(Value::as_str)
            .unwrap_or("queued");
        let updated = if text(record, "updated_at").is_empty() {
            text(record, "admitted_at")
        } else {
            text(record, "updated_at")
        };
        derived.push(derive_row(
            "automation_run",
            subject_ref,
            record,
            status,
            updated,
            "automation_contract_routes::automation_runs_for_request",
        ));
    }
    // REVIEW FACETS — pointers at the governance plane's approval requests over these subjects.
    let subject_refs: Vec<String> = derived
        .iter()
        .filter_map(|item| item.row["subject_ref"].as_str().map(str::to_owned))
        .collect();
    let mut facets: Vec<Value> = Vec::new();
    for approval in
        super::governance_routes::approval_requests_for_subjects(&st.data_dir, &subject_refs)
    {
        let (Some(approval_ref), Some(subject_ref)) = (
            approval.get("ref").and_then(Value::as_str),
            approval.get("subject_ref").and_then(Value::as_str),
        ) else {
            continue;
        };
        let Some(subject_kind) = subject_kind_for_ref(subject_ref) else {
            continue;
        };
        let tail = approval_ref
            .split_once("://")
            .map(|(_, tail)| tail)
            .unwrap_or(approval_ref);
        let facet_id = format!("projection://hypervisor/work-facet/review/{tail}");
        let facet = json!({
            "schema_version": FACET_SCHEMA,
            "facet_projection_id": facet_id,
            "facet_kind": "review",
            "facet_type": "approval_request",
            "facet_ref": approval_ref,
            "owner_ref": "surface://hypervisor/governance",
            "subject_kind": subject_kind,
            "subject_ref": subject_ref,
            "canonical_detail_route": format!("/work/reviews/review/{tail}"),
            "source_projection_ref": "governance_routes::approval_requests_for_subjects",
            "policy_decision_refs": [],
            "read_model_only": true,
        });
        if let Err(reply) = validate(FACET_CONTRACT_ID, "review facet", &facet) {
            return reply;
        }
        for item in derived.iter_mut() {
            if item.row["subject_ref"] == subject_ref {
                if let Some(refs) = item.row["review_facet_projection_refs"].as_array_mut() {
                    refs.push(json!(facet_id));
                }
            }
        }
        facets.push(facet);
    }
    for item in &derived {
        if let Err(reply) = validate(
            SUBJECT_CONTRACT_ID,
            item.row["subject_kind"].as_str().unwrap_or("?"),
            &item.row,
        ) {
            return reply;
        }
    }
    let readers = vec![
        json!({ "family": "session", "reader": "lifecycle_routes::sessions_for_request", "rows": sessions.len() }),
        json!({ "family": "automation_run", "reader": "automation_contract_routes::automation_runs_for_request", "rows": automation_runs.len() }),
    ];
    match assemble(view, &params, derived, facets, readers) {
        Ok(projection) => (StatusCode::OK, Json(projection)),
        Err(reply) => reply,
    }
}

#[cfg(test)]
mod work_projection_tests {
    use super::*;

    fn refusal_code(reply: &Reply) -> String {
        reply.1 .0.to_string()
    }

    #[test]
    fn a_subject_ref_has_exactly_one_kind_and_an_unknown_scheme_has_none() {
        assert_eq!(subject_kind_for_ref("goal://acme/g1"), Some("goal_run"));
        assert_eq!(subject_kind_for_ref("goal-run://acme/g1"), Some("goal_run"));
        assert_eq!(
            subject_kind_for_ref("outcome-room://acme/r1"),
            Some("outcome_room")
        );
        assert_eq!(
            subject_kind_for_ref("automation-run://acme/a1"),
            Some("automation_run")
        );
        assert_eq!(subject_kind_for_ref("session:goalrun-1-2"), Some("session"));
        assert_eq!(subject_kind_for_ref("session://acme/s1"), Some("session"));
        assert_eq!(
            subject_kind_for_ref("work_queue://acme/q1"),
            Some("work_queue")
        );
        assert_eq!(subject_kind_for_ref("mission://old"), None);
        assert_eq!(subject_kind_for_ref("not a ref"), None);
    }

    #[test]
    fn the_activity_facet_is_derived_from_the_owners_status_and_claims_the_least() {
        assert_eq!(activity_facet("session", "launched"), "active");
        assert_eq!(activity_facet("session", "provisioned"), "waiting");
        assert_eq!(activity_facet("automation_run", "executing"), "active");
        assert_eq!(activity_facet("automation_run", "completed"), "completed");
        assert_eq!(
            activity_facet("automation_run", "failed_partial_commit"),
            "failed"
        );
        assert_eq!(
            activity_facet("automation_run", "aborted_before_output_admission"),
            "failed"
        );
        assert_eq!(activity_facet("automation_run", "paused"), "blocked");
        assert_eq!(activity_facet("automation_run", "queued"), "waiting");
        assert_eq!(activity_facet("automation_run", "something-new"), "waiting");
        assert_eq!(execution_mode("session"), "interactive");
        assert_eq!(execution_mode("automation_run"), "headless");
        // a contributed kind is never derived by core, so core assigns it no mode
        assert_eq!(execution_mode("goal_run"), "not_applicable");
        assert_eq!(execution_mode("outcome_room"), "not_applicable");
        assert_eq!(execution_mode("work_item"), "not_applicable");
        assert_eq!(activity_view("completed"), "history");
        assert_eq!(activity_view("blocked"), "active");
    }

    #[test]
    fn derived_rows_validate_against_the_registered_contract_and_deep_link_to_their_owner() {
        let session = json!({ "session_ref": "session:goalrun-7-plan", "owner_ref": "org://acme", "project_ref": "project://acme/p1", "lifecycle_state": "launched", "created_at": "2026-09-14T10:00:00Z" });
        let row = derive_row(
            "session",
            "session:goalrun-7-plan",
            &session,
            "launched",
            "2026-09-14T10:00:00Z",
            "test",
        )
        .row;
        validate(SUBJECT_CONTRACT_ID, "session", &row).unwrap();
        assert_eq!(
            row["canonical_detail_route"],
            json!("/work/sessions/goalrun-7-plan")
        );
        assert_eq!(row["org_ref"], json!("org://acme"));
        assert_eq!(row["project_ref"], json!("project://acme/p1"));
        assert_eq!(row["system_ref"], Value::Null);
        assert_eq!(row["display_facets"]["activity"], json!("active"));
        assert_eq!(row["read_model_only"], json!(true));
        let run = json!({ "automation_run_ref": "automation-run://acme/a1", "owner_ref": "user://someone", "status": "completed" });
        let row = derive_row(
            "automation_run",
            "automation-run://acme/a1",
            &run,
            "completed",
            "",
            "test",
        )
        .row;
        validate(SUBJECT_CONTRACT_ID, "automation_run", &row).unwrap();
        assert_eq!(
            row["canonical_detail_route"],
            json!("/automations?run=acme/a1")
        );
        // an owner ref that is not an org is not promoted into one
        assert_eq!(row["org_ref"], Value::Null);
        // a forged row with a status written onto it fails the closed contract
        let mut forged = row.clone();
        forged["status"] = json!("done");
        assert!(refusal_code(
            &validate(SUBJECT_CONTRACT_ID, "automation_run", &forged).unwrap_err()
        )
        .contains("work_projection_row_contract_invalid"));
    }

    #[test]
    fn counts_and_recents_are_over_the_policy_filtered_set_search_narrows_only_the_rows_and_the_registry_is_said(
    ) {
        let derived = vec![
            derive_row(
                "session",
                "session:a",
                &json!({}),
                "launched",
                "2026-09-14T10:00:00Z",
                "t",
            ),
            derive_row(
                "session",
                "session:b",
                &json!({}),
                "provisioned",
                "2026-09-14T12:00:00Z",
                "t",
            ),
            derive_row(
                "automation_run",
                "automation-run://acme/a2",
                &json!({}),
                "completed",
                "2026-09-14T11:00:00Z",
                "t",
            ),
            derive_row(
                "automation_run",
                "automation-run://acme/a1",
                &json!({}),
                "failed",
                "2026-09-13T09:00:00Z",
                "t",
            ),
        ];
        let mut params = HashMap::new();
        params.insert("q".to_string(), "session:a".to_string());
        let answer = assemble("active", &params, derived, Vec::new(), Vec::new()).unwrap();
        assert_eq!(answer["rows"].as_array().unwrap().len(), 1);
        assert_eq!(answer["rows"][0]["subject_ref"], json!("session:a"));
        // counts ignore the search: two live rows, two sessions, two finished
        assert_eq!(answer["counts"]["active"], json!(2));
        assert_eq!(answer["counts"]["sessions"], json!(2));
        assert_eq!(answer["counts"]["history"], json!(2));
        assert_eq!(answer["counts"]["queues"], json!(0));
        // recents are newest-first over the whole filtered set
        assert_eq!(answer["recents"][0]["subject_ref"], json!("session:b"));
        assert_eq!(
            answer["recents"][1]["subject_ref"],
            json!("automation-run://acme/a2")
        );
        assert_eq!(
            answer["families"]["not_projected"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        // the registry, said on every answer: core enumerates exactly the two substrate families,
        // and the two contributed families are named with their seams — never an empty column
        assert_eq!(
            answer["families"]["projected"],
            json!(["session", "automation_run"])
        );
        let contributed: Vec<&str> = answer["families"]["contributed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["subject_kind"].as_str().unwrap())
            .collect();
        assert_eq!(contributed, vec!["goal_run", "outcome_room"]);
        assert!(answer["families"]["contributed"][0]["seam"]
            .as_str()
            .unwrap()
            .contains("subject attachment"));
        assert_eq!(answer["policy"]["applied_before"][0], json!("search"));
    }

    #[test]
    fn malformed_and_ambiguous_subject_filters_refuse_by_name_and_so_does_an_unknown_view() {
        let mut params = HashMap::new();
        params.insert("subject_ref".to_string(), "mission://old-1".to_string());
        assert!(refusal_code(
            &assemble("active", &params, Vec::new(), Vec::new(), Vec::new()).unwrap_err()
        )
        .contains("work_projection_subject_ref_invalid"));
        params.insert("subject_ref".to_string(), "goal://acme/g1".to_string());
        params.insert("subject_kind".to_string(), "session".to_string());
        assert!(refusal_code(
            &assemble("active", &params, Vec::new(), Vec::new(), Vec::new()).unwrap_err()
        )
        .contains("work_projection_subject_kind_ambiguous"));
        params.remove("subject_ref");
        params.insert("subject_kind".to_string(), "mission".to_string());
        assert!(refusal_code(
            &assemble("active", &params, Vec::new(), Vec::new(), Vec::new()).unwrap_err()
        )
        .contains("work_projection_subject_kind_unknown"));
        assert!(refusal_code(
            &assemble(
                "everything",
                &HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new()
            )
            .unwrap_err()
        )
        .contains("work_projection_view_unknown"));
    }
}
