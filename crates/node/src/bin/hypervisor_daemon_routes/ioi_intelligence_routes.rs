//! IOI Agent intelligence plane — portable memory, skills, automation affinities, and
//! connector-derived context that SURVIVES harness/model swaps.
//!
//! Product decision realized here: persistent IOI Agent intelligence belongs to workspace/
//! project/domain state (daemon truth), never to any one harness. Harness-local memory is
//! cache (the existing /v1/memory thread-store lane). Harnesses receive SCOPED PROJECTIONS —
//! a rendered summary + refs — never raw private MemoryEntry records by default.
//!
//! Records (durable JSON, one file per record):
//!   MemorySpace          memory-space://<id>          the portable container (scoped)
//!   MemoryEntry          memory-entry://<id>          preferences/facts/concepts/entities/…
//!   SkillEntry           skill-entry://<id>           reusable capability/procedure records
//!   AutomationAffinity   automation-affinity://<id>   goal-pattern → policy/automation/harness
//!   MemoryProjection     memory-projection://<id>     the scoped, receipted projection an
//!                                                     invocation actually receives
//!
//! The projection planner is pure + deterministic: include compatible ACTIVE records, exclude
//! archived/revoked/expired and harness/model-incompatible records, redact sensitive entries
//! unless the launch policy allows, enforce private-local (connector-derived context needs a
//! live connector lease), and give EVERY exclusion a reason code. Projections mint receipts;
//! the Work Ledger indexes them. Connectors stay owned by Developer & Integrations — this
//! plane only records connector REFS and derived context, never sealed credentials.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use super::goalrun_routes::{fact_from_profile, live_profiles, route_fact};
use super::{iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, DaemonState};
use ioi_services::agentic::runtime::RuntimeOwnerServices;

pub(crate) const SPACE_KIND: &str = "memory-spaces";
pub(crate) const ENTRY_KIND: &str = "memory-entries";
pub(crate) const SKILL_KIND: &str = "skill-entries";
pub(crate) const AFFINITY_KIND: &str = "automation-affinities";
pub(crate) const PROJECTION_KIND: &str = "memory-projections";

const ENTRY_KINDS: &[&str] = &[
    "preference",
    "instruction",
    "fact",
    "concept",
    "entity",
    "workstream",
    "note",
    "correction",
    "tool_affordance",
    "blocker",
    "connector_derived",
];
const SENSITIVITIES: &[&str] = &["normal", "private", "secret"];
const STATUSES: &[&str] = &["active", "archived", "revoked"];

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn bad(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

fn refs(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The default portable workspace space — created on first read, never a fixture.
pub(crate) fn ensure_default_space(st: &DaemonState) -> Value {
    let spaces = read_record_dir(&st.data_dir, SPACE_KIND);
    if let Some(space) = spaces
        .iter()
        .find(|s| text(s, "space_id") == "ms_workspace_default")
    {
        return space.clone();
    }
    let record = json!({
        "schema_version": "ioi.hypervisor.memory-space.v1",
        "space_id": "ms_workspace_default",
        "space_ref": "memory-space://ms_workspace_default",
        "scope": "workspace",
        "owner_ref": "workspace:hypervisor",
        "display_name": "Workspace intelligence",
        "privacy_posture": "standard",
        "default_projection_policy_ref": null,
        "status": "active",
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, SPACE_KIND, "ms_workspace_default", &record);
    record
}

fn load(st: &DaemonState, kind: &str, id_key: &str, id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, kind)
        .into_iter()
        .find(|r| text(r, id_key) == id || text(r, &id_key.replace("_id", "_ref")) == id)
}

// ---------------------------------------------------------------------------
// generic record validation (per family)
// ---------------------------------------------------------------------------

fn validate_entry(body: &Value, record: &mut Value) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(kind) = body.get("entry_kind").and_then(Value::as_str) {
        if !ENTRY_KINDS.contains(&kind) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "memory_entry_kind_invalid",
                &format!("entry_kind must be one of {ENTRY_KINDS:?}"),
            ));
        }
        record["entry_kind"] = json!(kind);
    }
    if let Some(sens) = body.get("sensitivity").and_then(Value::as_str) {
        if !SENSITIVITIES.contains(&sens) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "memory_entry_sensitivity_invalid",
                "sensitivity must be normal|private|secret",
            ));
        }
        record["sensitivity"] = json!(sens);
    }
    // connector_derived entries carry connector refs, NEVER credentials — reject anything that
    // smells like a sealed secret in the payload (defense in depth; the vault never leaves D&I).
    let blob = serde_json::to_string(body).unwrap_or_default();
    if blob.contains("sealed_client_secret") || blob.contains("IOI_WALLET_SECRET") {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "memory_entry_credential_material_forbidden",
            "Memory entries must not contain credential material.",
        ));
    }
    if text(record, "entry_kind") == "connector_derived"
        && refs(body.get("connector_refs").or(record.get("connector_refs"))).is_empty()
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "memory_entry_connector_refs_required",
            "connector_derived entries must name their connector refs.",
        ));
    }
    for key in ["title", "body"] {
        if let Some(v) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(v.trim());
        }
    }
    for key in [
        "tags",
        "source_refs",
        "connector_refs",
        "compatible_harness_refs",
        "compatible_model_route_refs",
    ] {
        if let Some(v) = body.get(key) {
            record[key] = v.clone();
        }
    }
    if let Some(v) = body.get("structured_payload") {
        record["structured_payload"] = v.clone();
    }
    if let Some(v) = body.get("confidence").and_then(Value::as_f64) {
        record["confidence"] = json!(v.clamp(0.0, 1.0));
    }
    if let Some(v) = body.get("expires_at").and_then(Value::as_str) {
        record["expires_at"] = json!(v);
    }
    if let Some(state) = body.get("quality_state").and_then(Value::as_str) {
        if !QUALITY_STATES.contains(&state) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "memory_quality_state_invalid",
                "quality_state must be candidate|accepted|stale|disputed|superseded",
            ));
        }
        record["quality_state"] = json!(state);
    }
    // Self-describing records: the vault format serializes these explicitly, so defaults are
    // stored rather than implied. Operator-authored entries are ACCEPTED; model/run claims
    // arrive as proposals and become candidates.
    if record
        .get("entry_kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        record["entry_kind"] = json!("note");
    }
    if record
        .get("sensitivity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        record["sensitivity"] = json!("normal");
    }
    if record
        .get("quality_state")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        record["quality_state"] = json!("accepted");
    }
    Ok(())
}

fn validate_skill(body: &Value, record: &mut Value) -> Result<(), (StatusCode, Json<Value>)> {
    for key in ["title", "description", "body", "procedure_ref"] {
        if let Some(v) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(v.trim());
        }
    }
    for key in [
        "trigger_conditions",
        "tool_requirements",
        "connector_requirements",
        "compatible_harness_refs",
        "compatible_model_route_refs",
        "source_refs",
        "memory_refs",
    ] {
        if let Some(v) = body.get(key) {
            record[key] = v.clone();
        }
    }
    if let Some(state) = body.get("quality_state").and_then(Value::as_str) {
        if !QUALITY_STATES.contains(&state) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "memory_quality_state_invalid",
                "quality_state must be candidate|accepted|stale|disputed|superseded",
            ));
        }
        record["quality_state"] = json!(state);
    }
    if record
        .get("quality_state")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        record["quality_state"] = json!("accepted");
    }
    if let Some(v) = body.get("confidence").and_then(Value::as_f64) {
        record["confidence"] = json!(v.clamp(0.0, 1.0));
    }
    Ok(())
}

fn validate_affinity(body: &Value, record: &mut Value) -> Result<(), (StatusCode, Json<Value>)> {
    for key in [
        "title",
        "goal_pattern",
        "preferred_policy_ref",
        "failure_policy",
    ] {
        if let Some(v) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(v.trim());
        }
    }
    if let Some(policy) = record.get("preferred_policy_ref").and_then(Value::as_str) {
        if !policy.is_empty() && !policy.starts_with("ioi-agent-policy://") {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "automation_affinity_policy_ref_invalid",
                "preferred_policy_ref must be an ioi-agent-policy:// ref",
            ));
        }
    }
    for key in [
        "preferred_automation_refs",
        "preferred_harness_refs",
        "preferred_model_route_refs",
        "required_connector_refs",
    ] {
        if let Some(v) = body.get(key) {
            record[key] = v.clone();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CRUD — one macro-shaped set of handlers per family (list/create/get/patch)
// ---------------------------------------------------------------------------

struct Family {
    kind: &'static str,
    id_prefix: &'static str,
    id_key: &'static str,
    ref_key: &'static str,
    ref_scheme: &'static str,
    schema: &'static str,
    plural: &'static str,
}

const ENTRY_FAMILY: Family = Family {
    kind: ENTRY_KIND,
    id_prefix: "mem",
    id_key: "entry_id",
    ref_key: "entry_ref",
    ref_scheme: "memory-entry://",
    schema: "ioi.hypervisor.memory-entry.v1",
    plural: "entries",
};
const SKILL_FAMILY: Family = Family {
    kind: SKILL_KIND,
    id_prefix: "skl",
    id_key: "skill_id",
    ref_key: "skill_ref",
    ref_scheme: "skill-entry://",
    schema: "ioi.hypervisor.skill-entry.v1",
    plural: "skills",
};
const AFFINITY_FAMILY: Family = Family {
    kind: AFFINITY_KIND,
    id_prefix: "aff",
    id_key: "affinity_id",
    ref_key: "affinity_ref",
    ref_scheme: "automation-affinity://",
    schema: "ioi.hypervisor.automation-affinity.v1",
    plural: "affinities",
};

fn family_list(st: &DaemonState, family: &Family, query: &HashMap<String, String>) -> Value {
    ensure_default_space(st);
    let mut records = read_record_dir(&st.data_dir, family.kind);
    if let Some(status) = query.get("status") {
        records.retain(|r| text(r, "status") == status);
    }
    if let Some(kind) = query.get("entry_kind") {
        records.retain(|r| text(r, "entry_kind") == kind);
    }
    if let Some(q) = query.get("q") {
        let needle = q.to_lowercase();
        records.retain(|r| {
            serde_json::to_string(r)
                .unwrap_or_default()
                .to_lowercase()
                .contains(&needle)
        });
    }
    records.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    json!({ "ok": true, family.plural: records })
}

fn family_create(
    st: &DaemonState,
    family: &Family,
    body: &Value,
    validate: fn(&Value, &mut Value) -> Result<(), (StatusCode, Json<Value>)>,
) -> (StatusCode, Json<Value>) {
    let space = ensure_default_space(st);
    if text(body, "title").trim().is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "intelligence_title_required",
            "A title is required.",
        );
    }
    let space_ref = {
        let requested = text(body, "memory_space_ref");
        if requested.is_empty() {
            text(&space, "space_ref").to_string()
        } else {
            if load(
                st,
                SPACE_KIND,
                "space_id",
                requested.trim_start_matches("memory-space://"),
            )
            .is_none()
            {
                return bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "memory_space_unresolved",
                    "Unknown memory space.",
                );
            }
            requested.to_string()
        }
    };
    let id = format!("{}_{:x}", family.id_prefix, nanos());
    let mut record = json!({
        "schema_version": family.schema,
        family.id_key: id,
        family.ref_key: format!("{}{}", family.ref_scheme, id),
        "memory_space_ref": space_ref,
        "status": "active",
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Err(rejection) = validate(body, &mut record) {
        return rejection;
    }
    let _ = persist_record(&st.data_dir, family.kind, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "record": record })),
    )
}

fn family_patch(
    st: &DaemonState,
    family: &Family,
    id: &str,
    body: &Value,
    validate: fn(&Value, &mut Value) -> Result<(), (StatusCode, Json<Value>)>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load(st, family.kind, family.id_key, id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "intelligence_record_not_found",
            "Unknown record.",
        );
    };
    if let Err(rejection) = validate(body, &mut record) {
        return rejection;
    }
    if let Some(status) = body.get("status").and_then(Value::as_str) {
        if !STATUSES.contains(&status) {
            return bad(
                StatusCode::BAD_REQUEST,
                "intelligence_status_invalid",
                "status must be active|archived|revoked",
            );
        }
        record["status"] = json!(status);
    }
    record["updated_at"] = json!(iso_now());
    let rid = text(&record, family.id_key).to_string();
    let _ = persist_record(&st.data_dir, family.kind, &rid, &record);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "record": record })),
    )
}

macro_rules! family_handlers {
    ($list:ident, $create:ident, $get:ident, $patch:ident, $family:expr, $validate:expr) => {
        pub(crate) async fn $list(State(st): State<Arc<DaemonState>>, Query(q): Query<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
            (StatusCode::OK, Json(family_list(&st, &$family, &q)))
        }
        pub(crate) async fn $create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
            family_create(&st, &$family, &body, $validate)
        }
        pub(crate) async fn $get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
            match load(&st, $family.kind, $family.id_key, &id) {
                Some(record) => (StatusCode::OK, Json(json!({ "ok": true, "record": record }))),
                None => bad(StatusCode::NOT_FOUND, "intelligence_record_not_found", "Unknown record."),
            }
        }
        pub(crate) async fn $patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
            family_patch(&st, &$family, &id, &body, $validate)
        }
    };
}

family_handlers!(
    handle_entries_list,
    handle_entries_create,
    handle_entries_get,
    handle_entries_patch,
    ENTRY_FAMILY,
    validate_entry
);
family_handlers!(
    handle_skills_list,
    handle_skills_create,
    handle_skills_get,
    handle_skills_patch,
    SKILL_FAMILY,
    validate_skill
);
family_handlers!(
    handle_affinities_list,
    handle_affinities_create,
    handle_affinities_get,
    handle_affinities_patch,
    AFFINITY_FAMILY,
    validate_affinity
);

pub(crate) async fn handle_spaces_list(
    State(st): State<Arc<DaemonState>>,
    Query(_q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let spaces = read_record_dir(&st.data_dir, SPACE_KIND);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "spaces": spaces })),
    )
}

pub(crate) async fn handle_spaces_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    if text(&body, "display_name").trim().is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "memory_space_name_required",
            "display_name required",
        );
    }
    let scope = text(&body, "scope");
    if !["personal", "project", "workspace", "domain"].contains(&scope) {
        return bad(
            StatusCode::BAD_REQUEST,
            "memory_space_scope_invalid",
            "scope must be personal|project|workspace|domain",
        );
    }
    let id = format!("ms_{:x}", nanos());
    let record = json!({
        "schema_version": "ioi.hypervisor.memory-space.v1",
        "space_id": id,
        "space_ref": format!("memory-space://{id}"),
        "scope": scope,
        "owner_ref": text(&body, "owner_ref"),
        "display_name": text(&body, "display_name").trim(),
        "privacy_posture": if text(&body, "privacy_posture").is_empty() { "standard" } else { text(&body, "privacy_posture") },
        "status": "active",
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, SPACE_KIND, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "space": record })),
    )
}

// ---------------------------------------------------------------------------
// projection planner — pure, deterministic, reason-coded
// ---------------------------------------------------------------------------

pub(crate) struct ProjectionContext {
    pub harness_profile_ref: String,
    pub model_route_ref: String,
    pub privacy_posture: String,         // standard | private_local
    pub allow_sensitive: bool,           // launch policy permits private-sensitivity inclusion
    pub live_connector_ids: Vec<String>, // connectors with a usable auth posture (lease-backed)
    pub goal: String,
    // Memory quality posture (policy-bound; private mode is stricter by default; no
    // harness/model can widen these — they arrive only via the launch policy).
    pub allow_candidate: bool,
    pub include_disputed: bool,
    pub max_stale_age_days: u64,
    pub require_accepted_for_private: bool,
}

/// Why a record is excluded (None = include). Secret entries are ALWAYS redacted.
fn exclusion_reason(record: &Value, ctx: &ProjectionContext, now: &str) -> Option<&'static str> {
    match text(record, "status") {
        "archived" => return Some("archived"),
        "revoked" => return Some("revoked"),
        _ => {}
    }
    let expires = text(record, "expires_at");
    if !expires.is_empty() && expires < now {
        return Some("expired");
    }
    // Quality lifecycle gates (deterministic, policy-bound).
    match quality_of(record) {
        "superseded" => return Some("superseded"),
        "disputed" if !ctx.include_disputed => return Some("disputed_excluded_by_policy"),
        "stale" if ctx.max_stale_age_days == 0 => return Some("stale"),
        "stale" => {
            // Coarse deterministic tolerance: a policy max_stale_age_days > 0 admits stale
            // records marked within that window (lexicographic ISO date-prefix compare).
            let marked = text(record, "marked_stale_at");
            let stale_days = ctx.max_stale_age_days.min(28) as u32;
            let mut bound = now.to_string();
            if let Some(day) = now.get(8..10).and_then(|d| d.parse::<u32>().ok()) {
                let floor = day.saturating_sub(stale_days).max(1);
                bound.replace_range(8..10, &format!("{floor:02}"));
            }
            if marked.is_empty() || marked < bound.as_str() {
                return Some("stale_beyond_policy_age");
            }
        }
        "candidate" if !ctx.allow_candidate => return Some("candidate_excluded_by_policy"),
        _ => {}
    }
    let harness_compat = refs(record.get("compatible_harness_refs"));
    if !harness_compat.is_empty() && !harness_compat.contains(&ctx.harness_profile_ref) {
        return Some("incompatible_harness");
    }
    let route_compat = refs(record.get("compatible_model_route_refs"));
    if !route_compat.is_empty() && !route_compat.contains(&ctx.model_route_ref) {
        return Some("incompatible_model_route");
    }
    if text(record, "entry_kind") == "connector_derived" {
        if ctx.privacy_posture == "private_local" {
            return Some("private_local_excludes_connector_context");
        }
        let connectors = refs(record.get("connector_refs"));
        let allowed = connectors.iter().any(|c| {
            ctx.live_connector_ids
                .iter()
                .any(|live| c.contains(live.as_str()))
        });
        if !allowed {
            return Some("connector_lease_unavailable");
        }
    }
    None
}

pub(crate) fn plan_projection(
    entries: &[Value],
    skills: &[Value],
    affinities: &[Value],
    ctx: &ProjectionContext,
) -> Value {
    let now = iso_now();
    let mut included_entries: Vec<&Value> = Vec::new();
    let mut redacted: Vec<Value> = Vec::new();
    let mut excluded: Vec<Value> = Vec::new();
    for entry in entries {
        match exclusion_reason(entry, ctx, &now) {
            Some(reason) => {
                excluded.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": reason }))
            }
            None => {
                let sensitivity = text(entry, "sensitivity");
                // secret NEVER projects; private projects only when the policy allows —
                // and, when the policy demands it, only ACCEPTED private memory projects.
                if sensitivity == "secret" {
                    redacted.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": "sensitivity_secret_always_redacted" }));
                } else if sensitivity == "private" && !ctx.allow_sensitive {
                    redacted.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": "sensitivity_private_policy_disallows" }));
                } else if sensitivity == "private"
                    && ctx.require_accepted_for_private
                    && quality_of(entry) != "accepted"
                {
                    redacted.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": "private_requires_accepted_memory" }));
                } else {
                    included_entries.push(entry);
                }
            }
        }
    }
    let mut included_skills: Vec<&Value> = Vec::new();
    for skill in skills {
        match exclusion_reason(skill, ctx, &now) {
            Some(reason) => {
                excluded.push(json!({ "ref": text(skill, "skill_ref"), "reason_code": reason }))
            }
            None => included_skills.push(skill),
        }
    }
    // Affinity match: deterministic substring goal-pattern match over active affinities —
    // the LONGEST matching pattern wins (most specific), so a broad affinity never shadows
    // a precise one.
    let goal_lower = ctx.goal.to_lowercase();
    let mut matched_affinity: Option<&Value> = None;
    let mut matched_len = 0usize;
    for affinity in affinities {
        if exclusion_reason(affinity, ctx, &now).is_some() {
            excluded.push(json!({ "ref": text(affinity, "affinity_ref"), "reason_code": "inactive_or_incompatible" }));
            continue;
        }
        let pattern = text(affinity, "goal_pattern").to_lowercase();
        if !pattern.is_empty() && goal_lower.contains(&pattern) && pattern.len() > matched_len {
            matched_len = pattern.len();
            matched_affinity = Some(affinity);
        }
    }
    // Accepted memory leads the rendered summary; candidates follow, labeled.
    included_entries.sort_by_key(|entry| {
        if quality_of(entry) == "accepted" {
            0
        } else {
            1
        }
    });
    // Rendered summary: titles + non-private bodies only — the harness-facing artifact.
    let mut lines: Vec<String> = Vec::new();
    for entry in &included_entries {
        let body = text(entry, "body");
        lines.push(format!(
            "[{}{}] {}{}",
            if quality_of(entry) == "candidate" {
                "candidate "
            } else {
                ""
            },
            text(entry, "entry_kind"),
            text(entry, "title"),
            if body.is_empty() {
                String::new()
            } else {
                format!(": {}", body.chars().take(240).collect::<String>())
            }
        ));
    }
    for skill in &included_skills {
        lines.push(format!(
            "[skill] {}: {}",
            text(skill, "title"),
            text(skill, "description")
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    json!({
        "included_entry_refs": included_entries.iter().map(|e| text(e, "entry_ref")).collect::<Vec<_>>(),
        "included_skill_refs": included_skills.iter().map(|s| text(s, "skill_ref")).collect::<Vec<_>>(),
        "included_automation_affinity_refs": matched_affinity.iter().map(|a| text(a, "affinity_ref")).collect::<Vec<_>>(),
        "automation_affinity_match": matched_affinity.map(|a| json!({
            "affinity_ref": text(a, "affinity_ref"),
            "title": text(a, "title"),
            "preferred_policy_ref": text(a, "preferred_policy_ref"),
            "preferred_harness_refs": a.get("preferred_harness_refs").cloned().unwrap_or(json!([])),
            "preferred_automation_refs": a.get("preferred_automation_refs").cloned().unwrap_or(json!([])),
        })).unwrap_or(Value::Null),
        "connector_context_refs": included_entries.iter()
            .filter(|e| text(e, "entry_kind") == "connector_derived")
            .flat_map(|e| refs(e.get("connector_refs")))
            .collect::<Vec<_>>(),
        "redacted_entry_refs": redacted,
        "excluded_refs_with_reasons": excluded,
        "projection_summary": lines.join("\n"),
        "counts": {
            "included_entries": included_entries.len(),
            "included_skills": included_skills.len(),
            "redacted": redacted.len(),
            "excluded": excluded.len(),
        },
    })
}

pub(crate) async fn gather_projection_inputs(
    st: &DaemonState,
) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    ensure_default_space(st);
    (
        read_record_dir(&st.data_dir, ENTRY_KIND),
        read_record_dir(&st.data_dir, SKILL_KIND),
        read_record_dir(&st.data_dir, AFFINITY_KIND),
    )
}

pub(crate) async fn build_projection_context(st: &DaemonState, body: &Value) -> ProjectionContext {
    let live = reqwest::Client::new()
        .get(format!("{}/v1/hypervisor/connectors", st.base_url))
        .timeout(std::time::Duration::from_millis(6000))
        .send()
        .await
        .ok();
    let live_ids = match live {
        Some(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|b| b.get("connectors").and_then(Value::as_array).cloned())
            .map(|cs| {
                cs.iter()
                    .filter(|c| {
                        matches!(
                            text(c, "auth_posture"),
                            "token-lease:bound" | "open" | "local-none"
                        )
                    })
                    .map(|c| text(c, "connector_id").to_string())
                    .collect()
            })
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let privacy = if text(body, "privacy_posture").is_empty() {
        "standard".to_string()
    } else {
        text(body, "privacy_posture").to_string()
    };
    let posture = body.get("memory_posture").cloned().unwrap_or(Value::Null);
    let private_mode = privacy == "private_local";
    ProjectionContext {
        harness_profile_ref: text(body, "harness_profile_ref").to_string(),
        model_route_ref: text(body, "model_route_ref").to_string(),
        privacy_posture: privacy,
        allow_sensitive: body
            .get("allow_sensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        live_connector_ids: live_ids,
        goal: text(body, "goal").to_string(),
        // Private mode is stricter by default: candidates excluded, accepted required for
        // private-sensitivity memory. A policy may widen standard mode, never a harness.
        allow_candidate: posture
            .get("allow_candidate_memory_projection")
            .and_then(Value::as_bool)
            .unwrap_or(!private_mode),
        include_disputed: posture
            .get("include_disputed_memory")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        max_stale_age_days: posture
            .get("max_stale_age")
            .or_else(|| posture.get("max_stale_age_days"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        require_accepted_for_private: posture
            .get("require_accepted_memory_for_private")
            .and_then(Value::as_bool)
            .unwrap_or(private_mode),
    }
}

pub(crate) async fn handle_projection_preview(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let (entries, skills, affinities) = gather_projection_inputs(&st).await;
    let ctx = build_projection_context(&st, &body).await;
    let space = ensure_default_space(&st);
    let plan = plan_projection(&entries, &skills, &affinities, &ctx);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "memory_space_ref": text(&space, "space_ref"),
            "preview": plan,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// Create a durable, receipted MemoryProjection (the record an invocation actually references).
pub(crate) async fn create_projection(st: &DaemonState, body: &Value) -> Value {
    let (entries, skills, affinities) = gather_projection_inputs(st).await;
    let ctx = build_projection_context(st, body).await;
    let space = ensure_default_space(st);
    let plan = plan_projection(&entries, &skills, &affinities, &ctx);
    let id = format!("mpr_{:x}", nanos());
    let receipt_ref = format!("receipt://hypervisor/memory-projection/{id}");
    let record = json!({
        "schema_version": "ioi.hypervisor.memory-projection.v1",
        "projection_id": id,
        "projection_ref": format!("memory-projection://{id}"),
        "memory_space_ref": text(&space, "space_ref"),
        "launch_ref": text(body, "launch_ref"),
        "session_ref": text(body, "session_ref"),
        "goal_run_ref": text(body, "goal_run_ref"),
        "harness_profile_ref": ctx.harness_profile_ref,
        "model_route_ref": ctx.model_route_ref,
        "policy_ref": text(body, "policy_ref"),
        "privacy_posture": ctx.privacy_posture,
        "included_entry_refs": plan["included_entry_refs"],
        "included_skill_refs": plan["included_skill_refs"],
        "included_automation_affinity_refs": plan["included_automation_affinity_refs"],
        "connector_context_refs": plan["connector_context_refs"],
        "redacted_entry_refs": plan["redacted_entry_refs"],
        "excluded_refs_with_reasons": plan["excluded_refs_with_reasons"],
        "counts": plan["counts"],
        "projection_summary": plan["projection_summary"],
        "rendered_projection_ref": format!("artifact://memory-projection/{id}/summary"),
        "receipt_refs": [receipt_ref],
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, PROJECTION_KIND, &id, &record);
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.memory-projection",
        "projection_ref": text(&record, "projection_ref"),
        "memory_space_ref": text(&space, "space_ref"),
        "session_ref": text(body, "session_ref"),
        "goal_run_ref": text(body, "goal_run_ref"),
        "harness_profile_ref": record["harness_profile_ref"],
        "counts": record["counts"],
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
    record
}

pub(crate) async fn handle_projections_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let record = create_projection(&st, &body).await;
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "projection": record })),
    )
}

pub(crate) async fn handle_projections_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut projections = read_record_dir(&st.data_dir, PROJECTION_KIND);
    if let Some(goal_run) = query.get("goal_run_ref") {
        projections.retain(|p| text(p, "goal_run_ref") == goal_run);
    }
    if let Some(session) = query.get("session_ref") {
        projections.retain(|p| text(p, "session_ref") == session);
    }
    projections.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "projections": projections })),
    )
}

pub(crate) async fn handle_projections_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load(&st, PROJECTION_KIND, "projection_id", &id) {
        Some(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "projection": record })),
        ),
        None => bad(
            StatusCode::NOT_FOUND,
            "memory_projection_not_found",
            "Unknown projection.",
        ),
    }
}

// ---------------------------------------------------------------------------
// Obsidian-class portable vault — export/import the MemorySpace as human-readable
// Markdown + frontmatter (strict `key: <json>` lines: readable AND machine-exact),
// with a JSON manifest sidecar only for fields Markdown cannot safely carry
// (structured payloads). Refs round-trip verbatim; credential material can neither
// leave nor enter; import is conflict-EXPLICIT (identical → unchanged, differing →
// reported conflict, never duplicate-spam).
// ---------------------------------------------------------------------------

const VAULT_SCHEMA_VERSION: &str = "ioi.hypervisor.memory-vault.v1";
const CREDENTIAL_MARKERS: &[&str] = &["sealed_client_secret", "IOI_WALLET_SECRET", "-----BEGIN"];

fn record_has_credential_material(record: &Value) -> bool {
    let blob = serde_json::to_string(record).unwrap_or_default();
    CREDENTIAL_MARKERS
        .iter()
        .any(|marker| blob.contains(marker))
}

/// Frontmatter keys per family (order is the document contract).
const ENTRY_FM_KEYS: &[&str] = &[
    "entry_id",
    "entry_ref",
    "memory_space_ref",
    "entry_kind",
    "sensitivity",
    "status",
    "quality_state",
    "supersedes_ref",
    "superseded_by_ref",
    "marked_stale_at",
    "lifecycle_history",
    "tags",
    "source_refs",
    "connector_refs",
    "compatible_harness_refs",
    "compatible_model_route_refs",
    "confidence",
    "expires_at",
    "created_at",
    "updated_at",
];
const SKILL_FM_KEYS: &[&str] = &[
    "skill_id",
    "skill_ref",
    "memory_space_ref",
    "status",
    "description",
    "procedure_ref",
    "quality_state",
    "supersedes_ref",
    "superseded_by_ref",
    "marked_stale_at",
    "lifecycle_history",
    "source_refs",
    "memory_refs",
    "confidence",
    "trigger_conditions",
    "tool_requirements",
    "connector_requirements",
    "compatible_harness_refs",
    "compatible_model_route_refs",
    "created_at",
    "updated_at",
];
const AFFINITY_FM_KEYS: &[&str] = &[
    "affinity_id",
    "affinity_ref",
    "memory_space_ref",
    "status",
    "goal_pattern",
    "preferred_policy_ref",
    "preferred_automation_refs",
    "preferred_harness_refs",
    "preferred_model_route_refs",
    "required_connector_refs",
    "failure_policy",
    "created_at",
    "updated_at",
];

fn md_document(record: &Value, keys: &[&str], title_key: &str, body_key: &str) -> String {
    let mut out = String::from("---\n");
    out.push_str(&format!(
        "title: {}\n",
        serde_json::to_string(text(record, title_key)).unwrap_or_default()
    ));
    for key in keys {
        if let Some(value) = record.get(*key) {
            if !value.is_null() {
                out.push_str(&format!(
                    "{key}: {}\n",
                    serde_json::to_string(value).unwrap_or_default()
                ));
            }
        }
    }
    out.push_str("---\n\n");
    let body = text(record, body_key);
    if !body.is_empty() {
        out.push_str(body);
        out.push('\n');
    }
    out
}

fn parse_md_document(content: &str) -> Option<(serde_json::Map<String, Value>, String)> {
    let rest = content.strip_prefix("---\n")?;
    let (frontmatter, body) = rest.split_once("\n---\n")?;
    let mut map = serde_json::Map::new();
    for line in frontmatter.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (key, raw) = line.split_once(':')?;
        let parsed: Value = serde_json::from_str(raw.trim()).ok()?;
        map.insert(key.trim().to_string(), parsed);
    }
    Some((map, body.trim_start_matches('\n').trim_end().to_string()))
}

pub(crate) async fn handle_vault_export(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let Some(space) = load(&st, SPACE_KIND, "space_id", &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "memory_space_not_found",
            "Unknown memory space.",
        );
    };
    let space_ref = text(&space, "space_ref").to_string();
    let in_space = |r: &Value| text(r, "memory_space_ref") == space_ref;
    let mut files: Vec<Value> = vec![json!({
        "path": "vault/space.md",
        "content": md_document(&space, &["space_id", "space_ref", "scope", "owner_ref", "privacy_posture", "status", "created_at", "updated_at"], "display_name", "description"),
    })];
    let mut structured_payloads = serde_json::Map::new();
    let mut scrubbed: Vec<Value> = Vec::new();
    for entry in read_record_dir(&st.data_dir, ENTRY_KIND)
        .iter()
        .filter(|r| in_space(r))
    {
        // Belt + braces: the create lane already refuses credential material; a record that
        // somehow carries it is SCRUBBED from the vault and reported, never exported.
        if record_has_credential_material(entry) {
            scrubbed.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": "credential_material_scrubbed" }));
            continue;
        }
        files.push(json!({
            "path": format!("vault/entries/{}.md", text(entry, "entry_id")),
            "content": md_document(entry, ENTRY_FM_KEYS, "title", "body"),
        }));
        if let Some(payload) = entry.get("structured_payload") {
            if !payload.is_null() {
                structured_payloads.insert(text(entry, "entry_id").to_string(), payload.clone());
            }
        }
    }
    for skill in read_record_dir(&st.data_dir, SKILL_KIND)
        .iter()
        .filter(|r| in_space(r))
    {
        if record_has_credential_material(skill) {
            scrubbed.push(json!({ "ref": text(skill, "skill_ref"), "reason_code": "credential_material_scrubbed" }));
            continue;
        }
        files.push(json!({
            "path": format!("vault/skills/{}.md", text(skill, "skill_id")),
            "content": md_document(skill, SKILL_FM_KEYS, "title", "body"),
        }));
    }
    for affinity in read_record_dir(&st.data_dir, AFFINITY_KIND)
        .iter()
        .filter(|r| in_space(r))
    {
        if record_has_credential_material(affinity) {
            scrubbed.push(json!({ "ref": text(affinity, "affinity_ref"), "reason_code": "credential_material_scrubbed" }));
            continue;
        }
        files.push(json!({
            "path": format!("vault/affinities/{}.md", text(affinity, "affinity_id")),
            "content": md_document(affinity, AFFINITY_FM_KEYS, "title", ""),
        }));
    }
    let manifest = json!({
        "schema_version": VAULT_SCHEMA_VERSION,
        "space_ref": space_ref,
        "exported_at": iso_now(),
        "counts": {
            "entries": files.iter().filter(|f| text(f, "path").starts_with("vault/entries/")).count(),
            "skills": files.iter().filter(|f| text(f, "path").starts_with("vault/skills/")).count(),
            "affinities": files.iter().filter(|f| text(f, "path").starts_with("vault/affinities/")).count(),
        },
        "sidecars": { "structured_payloads": structured_payloads },
        "scrubbed": scrubbed,
    });
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "vault": { "format": VAULT_SCHEMA_VERSION, "manifest": manifest, "files": files } }),
        ),
    )
}

pub(crate) async fn handle_vault_import(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let vault = body.get("vault").cloned().unwrap_or(body.clone());
    let files = vault
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if files.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "memory_vault_empty",
            "The vault bundle carries no files.",
        );
    }
    // Whole-bundle credential scan FIRST — nothing imports if any file smells like a secret.
    if record_has_credential_material(&vault) {
        return bad(
            StatusCode::FORBIDDEN,
            "memory_vault_credential_material_forbidden",
            "Vault bundles must not contain credential material.",
        );
    }
    let sidecars = vault
        .pointer("/manifest/sidecars/structured_payloads")
        .cloned()
        .unwrap_or(json!({}));
    let mut imported = json!({ "entries": 0, "skills": 0, "affinities": 0 });
    let mut unchanged = 0u64;
    let mut conflicts: Vec<Value> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for file in &files {
        let path = text(file, "path").to_string();
        let (family, kind, id_key) = if path.starts_with("vault/entries/") {
            ("entries", ENTRY_KIND, "entry_id")
        } else if path.starts_with("vault/skills/") {
            ("skills", SKILL_KIND, "skill_id")
        } else if path.starts_with("vault/affinities/") {
            ("affinities", AFFINITY_KIND, "affinity_id")
        } else {
            continue; // space.md / unknown paths are descriptive, not record-bearing
        };
        let Some((frontmatter, doc_body)) = parse_md_document(text(file, "content")) else {
            rejected.push(json!({ "path": path, "reason_code": "frontmatter_unparseable" }));
            continue;
        };
        let mut record = Value::Object(frontmatter);
        if family != "affinities" && !doc_body.is_empty() {
            record["body"] = json!(doc_body);
        }
        // Round-trip identity: keep original ids/refs. Validate through the SAME gates as
        // live creation (enums, connector-derived constraints, credential guard).
        let rid = text(&record, id_key).to_string();
        if rid.is_empty() {
            rejected.push(json!({ "path": path, "reason_code": "record_id_missing" }));
            continue;
        }
        let validation = match family {
            "entries" => {
                let payload = sidecars.get(&rid).cloned();
                if let Some(structured) = payload {
                    record["structured_payload"] = structured;
                }
                let mut base = record.clone();
                validate_entry(&record, &mut base).map(|_| base)
            }
            "skills" => {
                let mut base = record.clone();
                validate_skill(&record, &mut base).map(|_| base)
            }
            _ => {
                let mut base = record.clone();
                validate_affinity(&record, &mut base).map(|_| base)
            }
        };
        let normalized = match validation {
            Ok(normalized) => normalized,
            Err((_, Json(err))) => {
                rejected.push(json!({
                    "path": path,
                    "reason_code": err.pointer("/error/code").and_then(Value::as_str).unwrap_or("validation_failed"),
                }));
                continue;
            }
        };
        if let Some(existing) = load(&st, kind, id_key, &rid) {
            // Idempotence: identical content → unchanged; differing → explicit conflict, skip.
            let mut a = existing.clone();
            let mut b = normalized.clone();
            for volatile in [
                "updated_at",
                "created_at",
                "imported_at",
                "runtimeTruthSource",
                "schema_version",
            ] {
                a.as_object_mut().map(|o| o.remove(volatile));
                b.as_object_mut().map(|o| o.remove(volatile));
            }
            // Default-equivalence: legacy rows stored before defaults became explicit compare
            // equal to their default-filled vault form (a real content edit still conflicts).
            if family == "entries" {
                for side in [&mut a, &mut b] {
                    if side
                        .get("entry_kind")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .is_empty()
                    {
                        side["entry_kind"] = json!("note");
                    }
                    if side
                        .get("sensitivity")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .is_empty()
                    {
                        side["sensitivity"] = json!("normal");
                    }
                }
            }
            for side in [&mut a, &mut b] {
                if side
                    .get("quality_state")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                {
                    side["quality_state"] = json!("accepted");
                }
            }
            if a == b {
                unchanged += 1;
            } else {
                conflicts.push(json!({ "path": path, "ref": text(&existing, &id_key.replace("_id", "_ref")), "reason_code": "differs_from_existing" }));
            }
            continue;
        }
        let mut stored = normalized;
        stored["schema_version"] = json!(match family {
            "entries" => "ioi.hypervisor.memory-entry.v1",
            "skills" => "ioi.hypervisor.skill-entry.v1",
            _ => "ioi.hypervisor.automation-affinity.v1",
        });
        stored["runtimeTruthSource"] = json!("daemon-runtime");
        stored["imported_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, kind, &rid, &stored);
        imported[family] = json!(imported[family].as_u64().unwrap_or(0) + 1);
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "imported": imported,
            "unchanged": unchanged,
            "conflicts": conflicts,
            "rejected": rejected,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ---------------------------------------------------------------------------
// Memory mutation proposals — canon: harnesses/models PROPOSE ContextMutationEnvelope
// changes; they never silently write durable memory. A proposal is evidence until an
// operator approves it (durable change + context_mutation receipt) or rejects it
// (stays as evidence with the review verdict).
// ---------------------------------------------------------------------------

const PROPOSAL_KIND: &str = "memory-mutation-proposals";
const PROPOSAL_OPERATIONS: &[&str] = &["add", "supersede", "archive"];
const MUTATION_TYPES: &[&str] = &[
    "fact",
    "preference",
    "doctrine",
    "route",
    "procedure",
    "eval",
    "failure",
    "tool_affordance",
    "game_lesson",
    "project_convention",
    "connector_observation",
];
const SOURCE_AUTHORITIES: &[&str] = &[
    "user",
    "worker",
    "verifier",
    "benchmark",
    "service_delivery",
    "admin",
];

pub(crate) async fn handle_proposals_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut proposals = read_record_dir(&st.data_dir, PROPOSAL_KIND);
    if let Some(state) = query.get("review_state") {
        proposals.retain(|p| text(p, "review_state") == state);
    }
    proposals.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "proposals": proposals })),
    )
}

pub(crate) async fn handle_proposals_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let operation = text(&body, "operation");
    if !PROPOSAL_OPERATIONS.contains(&operation) {
        return bad(
            StatusCode::BAD_REQUEST,
            "memory_mutation_operation_invalid",
            "operation must be add|supersede|archive",
        );
    }
    let mutation_type = text(&body, "mutation_type");
    if !MUTATION_TYPES.contains(&mutation_type) {
        return bad(
            StatusCode::BAD_REQUEST,
            "memory_mutation_type_invalid",
            &format!("mutation_type must be one of {MUTATION_TYPES:?}"),
        );
    }
    let source_authority = {
        let v = text(&body, "source_authority");
        if v.is_empty() {
            "worker"
        } else {
            v
        }
    };
    if !SOURCE_AUTHORITIES.contains(&source_authority) {
        return bad(
            StatusCode::BAD_REQUEST,
            "memory_mutation_source_authority_invalid",
            "invalid source_authority",
        );
    }
    if record_has_credential_material(&body) {
        return bad(
            StatusCode::FORBIDDEN,
            "memory_entry_credential_material_forbidden",
            "Proposals must not contain credential material.",
        );
    }
    let suggested = body.get("suggested").cloned().unwrap_or(json!({}));
    if operation != "archive" && text(&suggested, "title").trim().is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "memory_mutation_suggested_title_required",
            "add/supersede proposals need suggested.title",
        );
    }
    if operation != "add"
        && !text(&body, "target_ref").starts_with("memory-entry://")
        && !text(&body, "target_ref").starts_with("skill-entry://")
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "memory_mutation_target_required",
            "supersede/archive proposals need a memory-entry:// or skill-entry:// target_ref",
        );
    }
    let id = format!("ctxmut_{:x}", nanos());
    let space_ref = {
        let requested = text(&body, "memory_space_ref");
        if requested.is_empty() {
            "memory-space://ms_workspace_default".to_string()
        } else {
            requested.to_string()
        }
    };
    let record = json!({
        "schema_version": "ioi.hypervisor.memory-mutation-proposal.v1",
        "mutation_id": id,
        "proposal_ref": format!("memory-mutation-proposal://{id}"),
        "memory_space_ref": space_ref,
        "operation": operation,
        "mutation_type": mutation_type,
        "target_ref": body.get("target_ref").cloned().unwrap_or(Value::Null),
        "target_family": if text(&body, "target_family") == "skill" { "skill" } else { "memory" },
        "suggested": suggested,
        "reason": text(&body, "reason"),
        "confidence": body.get("confidence").and_then(Value::as_f64).map(|c| c.clamp(0.0, 1.0)).unwrap_or(0.5),
        "source_run_ref": body.get("source_run_ref").cloned().unwrap_or(Value::Null),
        "source_authority": source_authority,
        "evidence_refs": body.get("evidence_refs").cloned().unwrap_or(json!([])),
        "review_state": "proposed",
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, PROPOSAL_KIND, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "proposal": record })),
    )
}

pub(crate) async fn handle_proposal_approve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = load(&st, PROPOSAL_KIND, "mutation_id", &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "memory_mutation_not_found",
            "Unknown proposal.",
        );
    };
    if text(&proposal, "review_state") != "proposed" {
        return bad(
            StatusCode::CONFLICT,
            "memory_mutation_already_reviewed",
            "This proposal has already been reviewed.",
        );
    }
    let operation = text(&proposal, "operation").to_string();
    let family = if text(&proposal, "target_family") == "skill" {
        &SKILL_FAMILY
    } else {
        &ENTRY_FAMILY
    };
    let validate: fn(&Value, &mut Value) -> Result<(), (StatusCode, Json<Value>)> =
        if text(&proposal, "target_family") == "skill" {
            validate_skill
        } else {
            validate_entry
        };
    let mut suggested = proposal.get("suggested").cloned().unwrap_or(json!({}));
    // Model/run claims never auto-promote: approval yields a CANDIDATE entry unless the
    // reviewer explicitly promotes to accepted at approval time.
    if suggested.get("quality_state").is_none() {
        suggested["quality_state"] = json!("candidate");
    }
    let applied_ref: String;
    match operation.as_str() {
        "add" => {
            let (status, Json(response)) = family_create(&st, family, &suggested, validate);
            if status != StatusCode::CREATED {
                return (status, Json(response));
            }
            applied_ref = response
                .pointer(&format!("/record/{}", family.ref_key))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        "supersede" => {
            let target = text(&proposal, "target_ref")
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();
            let (status, Json(response)) = family_patch(&st, family, &target, &suggested, validate);
            if status != StatusCode::OK {
                return (status, Json(response));
            }
            applied_ref = text(&proposal, "target_ref").to_string();
        }
        _ => {
            let target = text(&proposal, "target_ref")
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();
            let (status, Json(response)) = family_patch(
                &st,
                family,
                &target,
                &json!({ "status": "archived" }),
                validate,
            );
            if status != StatusCode::OK {
                return (status, Json(response));
            }
            applied_ref = text(&proposal, "target_ref").to_string();
        }
    }
    // context_mutation receipt — the durable change is admitted evidence, never silent.
    let receipt_ref = format!("receipt://hypervisor/memory-mutation/{id}");
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.memory-mutation",
        "receipt_type": "context_mutation",
        "mutation_id": id,
        "proposal_ref": text(&proposal, "proposal_ref"),
        "operation": operation,
        "mutation_type": text(&proposal, "mutation_type"),
        "applied_ref": applied_ref,
        "source_run_ref": proposal.get("source_run_ref").cloned().unwrap_or(Value::Null),
        "source_authority": text(&proposal, "source_authority"),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
    if let Some(object) = proposal.as_object_mut() {
        object.insert("review_state".into(), json!("approved"));
        object.insert("applied_ref".into(), json!(applied_ref));
        object.insert("receipt_refs".into(), json!([receipt_ref]));
        object.insert("reviewed_at".into(), json!(iso_now()));
    }
    let _ = persist_record(&st.data_dir, PROPOSAL_KIND, &id, &proposal);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "proposal": proposal })),
    )
}

pub(crate) async fn handle_proposal_reject(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = load(&st, PROPOSAL_KIND, "mutation_id", &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "memory_mutation_not_found",
            "Unknown proposal.",
        );
    };
    if text(&proposal, "review_state") != "proposed" {
        return bad(
            StatusCode::CONFLICT,
            "memory_mutation_already_reviewed",
            "This proposal has already been reviewed.",
        );
    }
    if let Some(object) = proposal.as_object_mut() {
        object.insert("review_state".into(), json!("rejected"));
        object.insert("review_reason".into(), json!(text(&body, "reason")));
        object.insert("reviewed_at".into(), json!(iso_now()));
    }
    let _ = persist_record(&st.data_dir, PROPOSAL_KIND, &id, &proposal);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "proposal": proposal })),
    )
}

// ---------------------------------------------------------------------------
// Memory graph — a READ-ONLY projection derived per request from existing records
// (entries/skills/affinities/projections/proposals + connector registry). No durable
// graph store exists or is created; deleting this handler deletes the graph.
// ---------------------------------------------------------------------------

fn push_node(
    nodes: &mut Vec<Value>,
    seen: &mut std::collections::HashSet<String>,
    id: &str,
    kind: &str,
    label: &str,
    status: &str,
) {
    if id.is_empty() || !seen.insert(id.to_string()) {
        return;
    }
    nodes.push(json!({ "id": id, "node_kind": kind, "label": if label.is_empty() { id } else { label }, "status": status }));
}

fn push_edge(edges: &mut Vec<Value>, from: &str, to: &str, kind: &str) {
    if !from.is_empty() && !to.is_empty() {
        edges.push(json!({ "from": from, "to": to, "edge_kind": kind }));
    }
}

pub(crate) async fn handle_intelligence_graph(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let entries = read_record_dir(&st.data_dir, ENTRY_KIND);
    let skills = read_record_dir(&st.data_dir, SKILL_KIND);
    let affinities = read_record_dir(&st.data_dir, AFFINITY_KIND);
    let proposals = read_record_dir(&st.data_dir, PROPOSAL_KIND);
    let mut projections = read_record_dir(&st.data_dir, PROJECTION_KIND);
    projections.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    projections.truncate(25); // recent proof, not an unbounded graph

    let mut record_edges =
        |record: &Value,
         self_ref: &str,
         nodes: &mut Vec<Value>,
         edges: &mut Vec<Value>,
         seen: &mut std::collections::HashSet<String>| {
            for source in refs(record.get("source_refs")) {
                push_node(nodes, seen, &source, "source_run", &source, "");
                push_edge(edges, self_ref, &source, "cites");
            }
            for connector in refs(record.get("connector_refs")) {
                push_node(nodes, seen, &connector, "connector", &connector, "");
                push_edge(edges, self_ref, &connector, "derives_from");
            }
            for harness in refs(record.get("compatible_harness_refs")) {
                push_node(nodes, seen, &harness, "harness_profile", &harness, "");
                push_edge(edges, self_ref, &harness, "compatible_with");
            }
            for route in refs(record.get("compatible_model_route_refs")) {
                push_node(nodes, seen, &route, "model_route", &route, "");
                push_edge(edges, self_ref, &route, "compatible_with");
            }
            for tag in refs(record.get("tags")) {
                let tag_id = format!("tag://{tag}");
                push_node(nodes, seen, &tag_id, "tag", &tag, "");
                push_edge(edges, self_ref, &tag_id, "tagged");
            }
        };

    for entry in &entries {
        let self_ref = text(entry, "entry_ref");
        push_node(
            &mut nodes,
            &mut seen,
            self_ref,
            "memory_entry",
            text(entry, "title"),
            text(entry, "status"),
        );
        record_edges(entry, self_ref, &mut nodes, &mut edges, &mut seen);
    }
    for skill in &skills {
        let self_ref = text(skill, "skill_ref");
        push_node(
            &mut nodes,
            &mut seen,
            self_ref,
            "skill_entry",
            text(skill, "title"),
            text(skill, "status"),
        );
        record_edges(skill, self_ref, &mut nodes, &mut edges, &mut seen);
    }
    for affinity in &affinities {
        let self_ref = text(affinity, "affinity_ref");
        push_node(
            &mut nodes,
            &mut seen,
            self_ref,
            "automation_affinity",
            text(affinity, "title"),
            text(affinity, "status"),
        );
        record_edges(affinity, self_ref, &mut nodes, &mut edges, &mut seen);
        let policy = text(affinity, "preferred_policy_ref");
        if !policy.is_empty() {
            push_node(&mut nodes, &mut seen, policy, "launch_policy", policy, "");
            push_edge(&mut edges, self_ref, policy, "affinity_to");
        }
        for automation in refs(affinity.get("preferred_automation_refs")) {
            push_node(
                &mut nodes,
                &mut seen,
                &automation,
                "automation",
                &automation,
                "",
            );
            push_edge(&mut edges, self_ref, &automation, "affinity_to");
        }
    }
    for projection in &projections {
        let self_ref = text(projection, "projection_ref");
        push_node(
            &mut nodes,
            &mut seen,
            self_ref,
            "memory_projection",
            &format!("projection · {}", text(projection, "harness_profile_ref")),
            "",
        );
        for included in refs(projection.get("included_entry_refs"))
            .iter()
            .chain(refs(projection.get("included_skill_refs")).iter())
        {
            push_edge(&mut edges, included, self_ref, "projects_to");
        }
        for receipt in refs(projection.get("receipt_refs")) {
            push_node(&mut nodes, &mut seen, &receipt, "receipt", &receipt, "");
            push_edge(&mut edges, self_ref, &receipt, "receipted_by");
        }
    }
    for proposal in &proposals {
        let self_ref = text(proposal, "proposal_ref");
        let label = proposal
            .pointer("/suggested/title")
            .and_then(Value::as_str)
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| text(proposal, "operation"));
        push_node(
            &mut nodes,
            &mut seen,
            self_ref,
            "mutation_proposal",
            label,
            text(proposal, "review_state"),
        );
        let applied = text(proposal, "applied_ref");
        if !applied.is_empty() {
            push_edge(&mut edges, applied, self_ref, "proposed_by");
        }
        for receipt in refs(proposal.get("receipt_refs")) {
            push_node(&mut nodes, &mut seen, &receipt, "receipt", &receipt, "");
            push_edge(
                &mut edges,
                self_ref,
                &receipt,
                if text(proposal, "review_state") == "approved" {
                    "approved_by"
                } else {
                    "rejected_by"
                },
            );
        }
        let source_run = text(proposal, "source_run_ref");
        if !source_run.is_empty() {
            push_node(
                &mut nodes,
                &mut seen,
                source_run,
                "source_run",
                source_run,
                "",
            );
            push_edge(&mut edges, self_ref, source_run, "cites");
        }
    }

    if let Some(q) = query
        .get("q")
        .map(|q| q.to_lowercase())
        .filter(|q| !q.is_empty())
    {
        let matching: std::collections::HashSet<String> = nodes
            .iter()
            .filter(|n| {
                text(n, "label").to_lowercase().contains(&q)
                    || text(n, "id").to_lowercase().contains(&q)
            })
            .map(|n| text(n, "id").to_string())
            .collect();
        edges.retain(|e| matching.contains(text(e, "from")) || matching.contains(text(e, "to")));
        let connected: std::collections::HashSet<String> = edges
            .iter()
            .flat_map(|e| [text(e, "from").to_string(), text(e, "to").to_string()])
            .chain(matching.iter().cloned())
            .collect();
        nodes.retain(|n| connected.contains(text(n, "id")));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "derived_only": true,
            "counts": { "nodes": nodes.len(), "edges": edges.len() },
            "nodes": nodes,
            "edges": edges,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ---------------------------------------------------------------------------
// Projection explainability — vault truth → harness prompt, decision by decision.
// Deterministic: decisions come from the projection's STORED refs/reasons (receipt-
// linked); record lookups add labels/metadata only. Bodies of private/secret entries
// never appear — titles and reason codes only.
// ---------------------------------------------------------------------------

pub(crate) async fn handle_projection_explain(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(projection) = load(&st, PROJECTION_KIND, "projection_id", &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "memory_projection_not_found",
            "Unknown projection.",
        );
    };
    let entries = read_record_dir(&st.data_dir, ENTRY_KIND);
    let skills = read_record_dir(&st.data_dir, SKILL_KIND);
    let lookup = |reference: &str| -> Value {
        entries
            .iter()
            .find(|e| text(e, "entry_ref") == reference)
            .or_else(|| skills.iter().find(|s| text(s, "skill_ref") == reference))
            .map(|record| {
                json!({
                    "title": text(record, "title"),
                    "kind": if reference.starts_with("skill-entry://") { "skill" } else { text(record, "entry_kind") },
                    "quality_state": quality_of(record),
                    "sensitivity": text(record, "sensitivity"),
                    "status": text(record, "status"),
                    "tags": record.get("tags").cloned().unwrap_or(json!([])),
                    "source_refs": record.get("source_refs").cloned().unwrap_or(json!([])),
                    "connector_refs": record.get("connector_refs").cloned().unwrap_or(json!([])),
                    "compatible_harness_refs": record.get("compatible_harness_refs").cloned().unwrap_or(json!([])),
                    "compatible_model_route_refs": record.get("compatible_model_route_refs").cloned().unwrap_or(json!([])),
                })
            })
            .unwrap_or(json!({ "title": "(record no longer present)", "kind": "unknown" }))
    };
    let harness = text(&projection, "harness_profile_ref");
    let route = text(&projection, "model_route_ref");
    let included: Vec<Value> = refs(projection.get("included_entry_refs"))
        .iter()
        .chain(refs(projection.get("included_skill_refs")).iter())
        .map(|reference| {
            let meta = lookup(reference);
            let harness_compat = refs(meta.get("compatible_harness_refs"));
            let route_compat = refs(meta.get("compatible_model_route_refs"));
            json!({
                "ref": reference,
                "decision": "included",
                "meta": meta,
                "checks": [
                    { "check": "status_active", "pass": true },
                    { "check": "not_expired", "pass": true },
                    { "check": "harness_compatible", "pass": true, "detail": if harness_compat.is_empty() { "no restriction".to_string() } else { format!("explicitly compatible with {harness}") } },
                    { "check": "model_route_compatible", "pass": true, "detail": if route_compat.is_empty() { "no restriction".to_string() } else { format!("explicitly compatible with {route}") } },
                    { "check": "sensitivity_allows_projection", "pass": true },
                ],
            })
        })
        .collect();
    let annotate = |list: Option<&Value>, decision: &str| -> Vec<Value> {
        list.and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|item| {
                let reference = text(item, "ref");
                json!({
                    "ref": reference,
                    "decision": decision,
                    "reason_code": text(item, "reason_code"),
                    "meta": lookup(reference),
                })
            })
            .collect()
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "projection_ref": text(&projection, "projection_ref"),
            "memory_space_ref": text(&projection, "memory_space_ref"),
            "context": {
                "harness_profile_ref": harness,
                "model_route_ref": route,
                "privacy_posture": text(&projection, "privacy_posture"),
                "policy_ref": text(&projection, "policy_ref"),
                "session_ref": text(&projection, "session_ref"),
                "goal_run_ref": text(&projection, "goal_run_ref"),
                "launch_ref": text(&projection, "launch_ref"),
            },
            "decisions": {
                "included": included,
                "redacted": annotate(projection.get("redacted_entry_refs"), "redacted"),
                "excluded": annotate(projection.get("excluded_refs_with_reasons"), "excluded"),
            },
            "counts": projection.get("counts").cloned().unwrap_or(json!({})),
            "connector_context_refs": projection.get("connector_context_refs").cloned().unwrap_or(json!([])),
            "receipt_refs": projection.get("receipt_refs").cloned().unwrap_or(json!([])),
            "rendered_projection_ref": text(&projection, "rendered_projection_ref"),
            "body_disclosure": "titles and reason codes only — private/secret bodies never appear in explanations",
            "deterministic": true,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ---------------------------------------------------------------------------
// Memory lifecycle — QUALITY posture (candidate/accepted/stale/disputed/superseded),
// orthogonal to status (active/archived/revoked, unchanged). Every transition is
// reason-coded, receipted, and appended to the record's lifecycle history. Model
// claims never auto-promote: proposal approval creates CANDIDATE entries by default;
// only an explicit operator promote (or a policy that says accepted) makes truth.
// ---------------------------------------------------------------------------

pub(crate) const QUALITY_STATES: &[&str] =
    &["candidate", "accepted", "stale", "disputed", "superseded"];

/// quality_state with the grandfather rule: records created before the lifecycle cut
/// (operator-authored) read as accepted.
pub(crate) fn quality_of(record: &Value) -> &str {
    let state = text(record, "quality_state");
    if state.is_empty() {
        "accepted"
    } else {
        state
    }
}

const TRANSITIONS: &[(&str, &str)] = &[
    ("promote", "accepted"),
    ("dispute", "disputed"),
    ("mark_stale", "stale"),
    ("supersede", "superseded"),
    ("accept", "accepted"),
];

async fn lifecycle_transition(
    st: &DaemonState,
    family: &Family,
    id: &str,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load(st, family.kind, family.id_key, id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "intelligence_record_not_found",
            "Unknown record.",
        );
    };
    let transition = text(body, "transition");
    let Some((_, to_state)) = TRANSITIONS.iter().find(|(t, _)| *t == transition) else {
        return bad(
            StatusCode::BAD_REQUEST,
            "memory_lifecycle_transition_invalid",
            "transition must be promote|dispute|mark_stale|supersede|accept",
        );
    };
    let reason = text(body, "reason");
    if reason.trim().is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "memory_lifecycle_reason_required",
            "Every lifecycle transition carries a reason.",
        );
    }
    let from_state = quality_of(&record).to_string();
    if transition == "promote" && from_state != "candidate" && from_state != "disputed" {
        return bad(
            StatusCode::CONFLICT,
            "memory_lifecycle_promote_invalid",
            "Promote applies to candidate (or disputed-resolved) records.",
        );
    }
    let mut superseded_by = Value::Null;
    if transition == "supersede" {
        let new_ref = text(body, "superseded_by_ref");
        if !new_ref.starts_with(family.ref_scheme) {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "memory_lifecycle_superseded_by_required",
                "supersede requires superseded_by_ref of the same family.",
            );
        }
        let new_id = new_ref.trim_start_matches(family.ref_scheme).to_string();
        let Some(mut successor) = load(st, family.kind, family.id_key, &new_id) else {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "memory_lifecycle_successor_unresolved",
                "The superseding record does not exist.",
            );
        };
        successor["supersedes_ref"] = json!(text(&record, family.ref_key));
        successor["updated_at"] = json!(iso_now());
        let sid = text(&successor, family.id_key).to_string();
        let _ = persist_record(&st.data_dir, family.kind, &sid, &successor);
        superseded_by = json!(new_ref);
    }
    let receipt_ref = format!(
        "receipt://hypervisor/memory-lifecycle/{}_{}_{:x}",
        text(&record, family.id_key),
        transition,
        nanos()
    );
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.memory-lifecycle",
        "receipt_type": "context_mutation",
        "record_ref": text(&record, family.ref_key),
        "transition": transition,
        "from_quality_state": from_state,
        "to_quality_state": to_state,
        "reason": reason,
        "superseded_by_ref": superseded_by,
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
    let mut history = record
        .get("lifecycle_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    history.push(json!({
        "transition": transition, "from": from_state, "to": to_state,
        "reason": reason, "receipt_ref": receipt_ref, "at": iso_now(),
    }));
    if let Some(object) = record.as_object_mut() {
        object.insert("quality_state".into(), json!(to_state));
        if transition == "mark_stale" {
            object.insert("marked_stale_at".into(), json!(iso_now()));
        }
        if !superseded_by.is_null() {
            object.insert("superseded_by_ref".into(), superseded_by.clone());
        }
        object.insert("lifecycle_history".into(), json!(history));
        object.insert("updated_at".into(), json!(iso_now()));
    }
    let rid = text(&record, family.id_key).to_string();
    let _ = persist_record(&st.data_dir, family.kind, &rid, &record);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "record": record, "receipt_ref": receipt_ref })),
    )
}

pub(crate) async fn handle_entry_lifecycle(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    lifecycle_transition(&st, &ENTRY_FAMILY, &id, &body).await
}

pub(crate) async fn handle_skill_lifecycle(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    lifecycle_transition(&st, &SKILL_FAMILY, &id, &body).await
}

// ---------------------------------------------------------------------------
// Review queue — deterministic signals only (no LLM judging). Derived per request.
// ---------------------------------------------------------------------------

pub(crate) async fn handle_review_queue(
    State(st): State<Arc<DaemonState>>,
    Query(_q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let entries = read_record_dir(&st.data_dir, ENTRY_KIND);
    let proposals = read_record_dir(&st.data_dir, PROPOSAL_KIND);
    let mut projections = read_record_dir(&st.data_dir, PROJECTION_KIND);
    projections.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    projections.truncate(25);
    let live_ids: Vec<String> = {
        let ctx = build_projection_context(&st, &json!({})).await;
        ctx.live_connector_ids
    };
    let now = iso_now();
    let soon = {
        // "expiring within 7 days" — ISO strings compare lexicographically; compute a rough
        // +7d bound from the date prefix (deterministic, no chrono dependency).
        let mut bound = now.clone();
        if let Some(day) = now.get(8..10).and_then(|d| d.parse::<u32>().ok()) {
            bound.replace_range(8..10, &format!("{:02}", (day + 7).min(28).max(day % 28)));
        }
        bound
    };
    let mut items: Vec<Value> = Vec::new();
    // proposal signals
    for proposal in proposals
        .iter()
        .filter(|p| text(p, "review_state") == "proposed")
    {
        items.push(json!({
            "ref": text(proposal, "proposal_ref"),
            "title": proposal.pointer("/suggested/title").and_then(Value::as_str).unwrap_or(text(proposal, "operation")),
            "kind": "mutation_proposal",
            "signals": ["proposed_by_run"],
            "quality_state": "proposed",
        }));
    }
    let lower_titles: Vec<(String, String)> = entries
        .iter()
        .filter(|e| text(e, "status") == "active")
        .map(|e| {
            (
                text(e, "title").to_lowercase(),
                text(e, "entry_ref").to_string(),
            )
        })
        .collect();
    for entry in entries.iter().filter(|e| text(e, "status") == "active") {
        let self_ref = text(entry, "entry_ref");
        let mut signals: Vec<&str> = Vec::new();
        let title = text(entry, "title").to_lowercase();
        if lower_titles
            .iter()
            .any(|(t, r)| *t == title && r != self_ref)
        {
            signals.push("conflict_with_existing");
        }
        if entry
            .get("confidence")
            .and_then(Value::as_f64)
            .map(|c| c < 0.5)
            .unwrap_or(false)
        {
            signals.push("low_confidence");
        }
        let expires = text(entry, "expires_at");
        if !expires.is_empty() && expires < soon.as_str() {
            signals.push("expired_or_expiring");
        }
        let uses = projections
            .iter()
            .filter(|p| {
                refs(p.get("included_entry_refs"))
                    .iter()
                    .any(|r| r == self_ref)
            })
            .count();
        if uses >= 3 {
            signals.push("repeated_projection_use");
        }
        if text(entry, "entry_kind") == "connector_derived" {
            let connected = refs(entry.get("connector_refs"))
                .iter()
                .any(|c| live_ids.iter().any(|l| c.contains(l.as_str())));
            if !connected {
                signals.push("connector_lease_missing");
            }
        }
        if text(entry, "sensitivity") == "private" {
            let redactions = projections
                .iter()
                .filter(|p| {
                    p.get("redacted_entry_refs")
                        .and_then(Value::as_array)
                        .map(|list| list.iter().any(|r| text(r, "ref") == self_ref))
                        .unwrap_or(false)
                })
                .count();
            if redactions >= 3 {
                signals.push("private_redaction_frequent");
            }
        }
        if !signals.is_empty() {
            items.push(json!({
                "ref": self_ref,
                "title": text(entry, "title"),
                "kind": text(entry, "entry_kind"),
                "quality_state": quality_of(entry),
                "sensitivity": text(entry, "sensitivity"),
                "projection_use_count": uses,
                "signals": signals,
            }));
        }
    }
    items.sort_by_key(|item| {
        std::cmp::Reverse(
            item.get("signals")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
        )
    });
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "deterministic_signals_only": true,
            "items": items,
            "counts": { "items": items.len() },
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ---------------------------------------------------------------------------
// Outcome learning — repeated work becomes reusable skills, launch-policy suggestions,
// and automation-readiness updates WITHOUT silent behavior change. Two lanes:
//   1. outcome mining: a derived read projection (deterministic signals only, no LLM
//      judging) over recent launches, goal runs, projections, and reviewed memory;
//   2. improvement proposals: durable, evidence-bound records
//      (pending → approved → applied | rejected | superseded). Creation changes NOTHING;
//      apply performs the governed mutation through the ordinary object lanes and mints
//      a receipt. Protected seed policies stay immutable — a policy suggestion applies by
//      CLONING the seed and patching the clone.
// ---------------------------------------------------------------------------

const IMPROVEMENT_KIND: &str = "improvement-proposals";
const IMPROVEMENT_KINDS: &[&str] = &[
    "skill_improvement",
    "launch_policy_suggestion",
    "automation_readiness",
];
const IMPROVEMENT_STATES: &[&str] = &["pending", "approved", "rejected", "applied", "superseded"];

/// Normalize a goal to a deterministic pattern key: first four significant lowercase tokens.
fn goal_pattern_key(goal: &str) -> String {
    goal.to_lowercase()
        .split_whitespace()
        .filter(|token| token.len() > 2)
        .take(4)
        .collect::<Vec<_>>()
        .join(" ")
}

fn mined_confidence(count: usize) -> f64 {
    (0.4 + 0.1 * count as f64).min(0.9)
}

pub(crate) async fn handle_outcome_mining(
    State(st): State<Arc<DaemonState>>,
    Query(_q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let mut launches = read_record_dir(&st.data_dir, "ioi-agent-launches");
    launches.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    launches.truncate(50);
    let entries = read_record_dir(&st.data_dir, ENTRY_KIND);
    let mut projections = read_record_dir(&st.data_dir, PROJECTION_KIND);
    projections.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    projections.truncate(25);
    let mut candidates: Vec<Value> = Vec::new();

    // repeated_successful_goal_pattern + repeated_automation_ready_intent + harness preference
    let mut by_pattern: HashMap<String, Vec<&Value>> = HashMap::new();
    for launch in launches.iter().filter(|l| text(l, "state") == "executed") {
        let succeeded = launch
            .pointer("/outcome/blockers")
            .and_then(Value::as_array)
            .map(|b| b.is_empty())
            .unwrap_or(true);
        if succeeded && !text(launch, "goal").is_empty() {
            by_pattern
                .entry(goal_pattern_key(text(launch, "goal")))
                .or_default()
                .push(launch);
        }
    }
    let mut harness_counts: HashMap<String, Vec<&Value>> = HashMap::new();
    for launch in launches.iter().filter(|l| text(l, "state") == "executed") {
        let harness = text(launch, "harness_profile_ref");
        if !harness.is_empty() {
            harness_counts
                .entry(harness.to_string())
                .or_default()
                .push(launch);
        }
    }
    for (pattern, group) in by_pattern
        .iter()
        .filter(|(p, g)| !p.is_empty() && g.len() >= 2)
    {
        let evidence: Vec<String> = group
            .iter()
            .map(|l| format!("ioi-agent-launch://{}", text(l, "launch_id")))
            .collect();
        candidates.push(json!({
            "candidate_kind": "skill_improvement",
            "signal": "repeated_successful_goal_pattern",
            "pattern": pattern,
            "occurrences": group.len(),
            "confidence": mined_confidence(group.len()),
            "evidence_refs": evidence,
            "suggested": {
                "title": format!("Skill: {pattern}"),
                "description": format!("Learned from {} successful runs matching \"{pattern}\"", group.len()),
                "trigger_conditions": [pattern],
            },
        }));
        candidates.push(json!({
            "candidate_kind": "automation_readiness",
            "signal": "repeated_automation_ready_intent",
            "pattern": pattern,
            "occurrences": group.len(),
            "confidence": mined_confidence(group.len()),
            "evidence_refs": group.iter().map(|l| format!("ioi-agent-launch://{}", text(l, "launch_id"))).collect::<Vec<_>>(),
            "suggested": {
                "title": format!("Affinity: {pattern}"),
                "goal_pattern": pattern,
            },
        }));
    }
    for (harness, group) in harness_counts.iter().filter(|(_, g)| g.len() >= 3) {
        candidates.push(json!({
            "candidate_kind": "launch_policy_suggestion",
            "signal": "repeated_harness_model_preference",
            "occurrences": group.len(),
            "confidence": mined_confidence(group.len()),
            "evidence_refs": group.iter().map(|l| format!("ioi-agent-launch://{}", text(l, "launch_id"))).collect::<Vec<_>>(),
            "suggested": {
                "display_name": format!("Prefers {}", harness.replace("harness-profile:hp_", "")),
                "harness_preferences": { "preferred_harness_refs": [harness], "excluded_harness_refs": [], "allow_fallback": true },
            },
        }));
    }
    // repeated_manual_correction
    let corrections: Vec<&Value> = entries
        .iter()
        .filter(|e| text(e, "entry_kind") == "correction" && text(e, "status") == "active")
        .collect();
    if corrections.len() >= 2 {
        candidates.push(json!({
            "candidate_kind": "skill_improvement",
            "signal": "repeated_manual_correction",
            "occurrences": corrections.len(),
            "confidence": mined_confidence(corrections.len()),
            "evidence_refs": corrections.iter().map(|e| text(e, "entry_ref")).collect::<Vec<_>>(),
            "suggested": {
                "title": "Skill: apply recorded corrections",
                "description": format!("{} recorded corrections indicate a repeatable procedure", corrections.len()),
            },
        }));
    }
    // repeated_memory_projection_inclusion
    for entry in entries.iter().filter(|e| text(e, "status") == "active") {
        let self_ref = text(entry, "entry_ref");
        let uses = projections
            .iter()
            .filter(|p| {
                refs(p.get("included_entry_refs"))
                    .iter()
                    .any(|r| r == self_ref)
            })
            .count();
        if uses >= 5 && text(entry, "entry_kind") != "connector_derived" {
            candidates.push(json!({
                "candidate_kind": "skill_improvement",
                "signal": "repeated_memory_projection_inclusion",
                "occurrences": uses,
                "confidence": mined_confidence(uses),
                "evidence_refs": [self_ref],
                "suggested": {
                    "title": format!("Skill: {}", text(entry, "title")),
                    "description": format!("Memory entry projected into {uses} recent runs — promotable to a reusable skill"),
                    "memory_refs": [self_ref],
                },
            }));
        }
    }
    // repeated_failure_blocker_class
    let mut failure_counts: HashMap<String, Vec<String>> = HashMap::new();
    for launch in &launches {
        for blocker in launch
            .pointer("/outcome/blockers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let code = text(&blocker, "reason_code").to_string();
            if !code.is_empty() {
                failure_counts
                    .entry(code)
                    .or_default()
                    .push(format!("ioi-agent-launch://{}", text(launch, "launch_id")));
            }
        }
    }
    for (code, evidence) in failure_counts.iter().filter(|(_, e)| e.len() >= 2) {
        candidates.push(json!({
            "candidate_kind": "launch_policy_suggestion",
            "signal": "repeated_failure_blocker_class",
            "failure_class": code,
            "occurrences": evidence.len(),
            "confidence": mined_confidence(evidence.len()),
            "evidence_refs": evidence,
            "suggested": {
                "display_name": format!("Mitigate {code}"),
                "failure_policy": "retry_once",
            },
        }));
    }
    candidates.sort_by(|a, b| {
        b.get("occurrences")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(&a.get("occurrences").and_then(Value::as_u64).unwrap_or(0))
    });
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "deterministic_signals_only": true,
            "derived_only": true,
            "counts": { "candidates": candidates.len() },
            "candidates": candidates,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

pub(crate) async fn handle_improvements_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut proposals = read_record_dir(&st.data_dir, IMPROVEMENT_KIND);
    if let Some(state) = query.get("state") {
        proposals.retain(|p| text(p, "state") == state);
    }
    proposals.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    let (sims, approvals, releases) = gate_record_sets(&st);
    let proposals: Vec<Value> = proposals
        .into_iter()
        .map(|mut p| {
            let gate = gate_projection_from(&p, &sims, &approvals, &releases);
            if let Some(object) = p.as_object_mut() {
                object.insert("gate".into(), gate);
            }
            p
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "proposals": proposals })),
    )
}

pub(crate) async fn handle_improvements_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let kind = text(&body, "proposal_kind");
    if !IMPROVEMENT_KINDS.contains(&kind) {
        return bad(
            StatusCode::BAD_REQUEST,
            "improvement_kind_invalid",
            "proposal_kind must be skill_improvement|launch_policy_suggestion|automation_readiness",
        );
    }
    let evidence = refs(body.get("evidence_refs"));
    if evidence.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "improvement_evidence_required",
            "An improvement proposal binds to evidence refs (runs, projections, receipts, memory).",
        );
    }
    if record_has_credential_material(&body) {
        return bad(
            StatusCode::FORBIDDEN,
            "memory_entry_credential_material_forbidden",
            "Proposals must not contain credential material.",
        );
    }
    let id = format!("imp_{:x}", nanos());
    let record = json!({
        "schema_version": "ioi.hypervisor.improvement-proposal.v1",
        "improvement_id": id,
        "proposal_ref": format!("improvement-proposal://{id}"),
        "proposal_kind": kind,
        "signal": text(&body, "signal"),
        "target_ref": body.get("target_ref").cloned().unwrap_or(Value::Null),
        "suggested": body.get("suggested").cloned().unwrap_or(json!({})),
        "evidence_refs": evidence,
        "confidence": body.get("confidence").and_then(Value::as_f64).map(|c| c.clamp(0.0, 1.0)).unwrap_or(0.5),
        "reason": text(&body, "reason"),
        "state": "pending",
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, IMPROVEMENT_KIND, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "proposal": record })),
    )
}

async fn improvement_state_change(
    st: &DaemonState,
    id: &str,
    from: &[&str],
    to: &str,
    extra: Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    let Some(mut proposal) = read_record_dir(&st.data_dir, IMPROVEMENT_KIND)
        .into_iter()
        .find(|p| text(p, "improvement_id") == id)
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "improvement_not_found",
            "Unknown improvement proposal.",
        ));
    };
    if !from.contains(&text(&proposal, "state")) {
        return Err(bad(
            StatusCode::CONFLICT,
            "improvement_state_invalid",
            &format!("This transition requires state {from:?}."),
        ));
    }
    if let Some(object) = proposal.as_object_mut() {
        object.insert("state".into(), json!(to));
        object.insert("reviewed_at".into(), json!(iso_now()));
        if let Some(extra_obj) = extra.as_object() {
            for (key, value) in extra_obj {
                object.insert(key.clone(), value.clone());
            }
        }
    }
    let _ = persist_record(&st.data_dir, IMPROVEMENT_KIND, id, &proposal);
    Ok(proposal)
}

pub(crate) async fn handle_improvement_approve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match improvement_state_change(&st, &id, &["pending"], "approved", json!({})).await {
        Ok(proposal) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "proposal": proposal })),
        ),
        Err(rejection) => rejection,
    }
}

pub(crate) async fn handle_improvement_reject(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match improvement_state_change(
        &st,
        &id,
        &["pending", "approved"],
        "rejected",
        json!({ "review_reason": text(&body, "reason") }),
    )
    .await
    {
        Ok(proposal) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "proposal": proposal })),
        ),
        Err(rejection) => rejection,
    }
}

// ---------------------------------------------------------------------------
// Improvement governance gates — high-impact learned changes cannot apply without a FRESH
// simulation, an APPROVED ApprovalRequest, and an OPEN ReleaseControl targeting the proposal
// or its simulation report. Inputs are loaded LIVE at evaluation time (stale stamped refs are
// never trusted); the same pure evaluation feeds both apply enforcement and the list posture.

const GOV_APPROVAL_KIND: &str = "governance-approval-requests";
const GOV_RELEASE_KIND: &str = "governance-release-controls";

/// Deterministic identity of WHAT a simulation previewed: the proposal's behavior-bearing
/// fields. A report is fresh iff the live proposal still fingerprints to what was simulated.
pub(crate) fn proposal_fingerprint(proposal: &Value) -> String {
    let basis = json!({
        "proposal_kind": text(proposal, "proposal_kind"),
        "target_ref": proposal.get("target_ref").cloned().unwrap_or(Value::Null),
        "suggested": proposal.get("suggested").cloned().unwrap_or(json!({})),
        "evidence_refs": proposal.get("evidence_refs").cloned().unwrap_or(json!([])),
    });
    format!(
        "sha256:{}",
        sha256_hex_str(&serde_json::to_string(&basis).unwrap_or_default())
    )
}

fn load_by_ref(st: &DaemonState, kind: &str, reference: &str, scheme: &str) -> Option<Value> {
    let id = reference.strip_prefix(&format!("{scheme}://"))?;
    read_record_dir(&st.data_dir, kind)
        .into_iter()
        .find(|r| text(r, "id") == id)
}

/// Pick a proposal's gate inputs out of PRE-LOADED record sets (list handlers load each
/// directory once — per-proposal directory re-reads made the list O(N×dir) as records grew).
fn gate_inputs_from(
    proposal: &Value,
    sims: &[Value],
    approvals: &[Value],
    releases: &[Value],
) -> (Option<Value>, Option<Value>, Option<Value>) {
    let report = text(proposal, "latest_simulation_ref")
        .strip_prefix("simulation-report://")
        .and_then(|id| {
            sims.iter()
                .find(|r| text(r, "simulation_id") == id)
                .cloned()
        });
    let approval = text(proposal, "approval_request_ref")
        .strip_prefix("approval-request://")
        .and_then(|id| approvals.iter().find(|r| text(r, "id") == id).cloned());
    let release = text(proposal, "release_control_ref")
        .strip_prefix("release-control://")
        .and_then(|id| releases.iter().find(|r| text(r, "id") == id).cloned());
    (report, approval, release)
}

fn gate_record_sets(st: &DaemonState) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    (
        read_record_dir(&st.data_dir, SIMULATION_KIND),
        read_record_dir(&st.data_dir, GOV_APPROVAL_KIND),
        read_record_dir(&st.data_dir, GOV_RELEASE_KIND),
    )
}

fn gate_inputs(
    st: &DaemonState,
    proposal: &Value,
) -> (Option<Value>, Option<Value>, Option<Value>) {
    let (sims, approvals, releases) = gate_record_sets(st);
    gate_inputs_from(proposal, &sims, &approvals, &releases)
}

pub(crate) struct GateDecision {
    pub(crate) posture: &'static str,
    pub(crate) block: Option<(&'static str, &'static str)>,
}

pub(crate) fn evaluate_improvement_gate(
    proposal: &Value,
    report: Option<&Value>,
    approval: Option<&Value>,
    release: Option<&Value>,
) -> GateDecision {
    let sim_ref = text(proposal, "latest_simulation_ref");
    if sim_ref.is_empty() {
        // Launch-policy suggestions change execution behavior — always previewable before apply.
        if text(proposal, "proposal_kind") == "launch_policy_suggestion" {
            return GateDecision {
                posture: "simulation_required",
                block: Some(("simulation_required", "Launch-policy improvements must carry a saved what-if simulation before apply.")),
            };
        }
        return GateDecision {
            posture: "no_simulation",
            block: None,
        };
    }
    let Some(report) = report else {
        return GateDecision {
            posture: "simulation_stale",
            block: Some(("simulation_stale", "The cited simulation report no longer resolves — re-simulate the proposal as it stands now.")),
        };
    };
    if text(report, "proposal_fingerprint") != proposal_fingerprint(proposal) {
        return GateDecision {
            posture: "simulation_stale",
            block: Some(("simulation_stale", "The proposal changed after its last simulation — the report no longer previews THIS change. Re-simulate.")),
        };
    }
    if report
        .pointer("/governance/high_impact")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return GateDecision {
            posture: "low_impact",
            block: None,
        };
    }
    let subject_ok =
        |candidate: &str| candidate == text(proposal, "proposal_ref") || candidate == sim_ref;
    let Some(approval) = approval else {
        return GateDecision {
            posture: "awaiting_approval",
            block: Some(("approval_required", "High-impact improvements require an ApprovalRequest targeting the proposal or its simulation report.")),
        };
    };
    if !subject_ok(text(approval, "subject_ref")) {
        return GateDecision {
            posture: "awaiting_approval",
            block: Some((
                "approval_required",
                "The bound ApprovalRequest does not target this proposal or its simulation report.",
            )),
        };
    }
    if text(approval, "status") != "approved" {
        return GateDecision {
            posture: "awaiting_approval",
            block: Some((
                "approval_not_approved",
                "The bound ApprovalRequest is not APPROVED.",
            )),
        };
    }
    let Some(release) = release else {
        return GateDecision {
            posture: "awaiting_release",
            block: Some(("release_control_required", "High-impact improvements require a ReleaseControl targeting the proposal or its simulation report.")),
        };
    };
    if !subject_ok(text(release, "release_target_ref")) {
        return GateDecision {
            posture: "awaiting_release",
            block: Some((
                "release_control_required",
                "The bound ReleaseControl does not target this proposal or its simulation report.",
            )),
        };
    }
    if text(release, "state") != "open" {
        return GateDecision {
            posture: "awaiting_release",
            block: Some((
                "release_control_not_open",
                "The bound ReleaseControl gate is not OPEN.",
            )),
        };
    }
    GateDecision {
        posture: "ready",
        block: None,
    }
}

fn gate_projection(st: &DaemonState, proposal: &Value) -> Value {
    let (sims, approvals, releases) = gate_record_sets(st);
    gate_projection_from(proposal, &sims, &approvals, &releases)
}

fn gate_projection_from(
    proposal: &Value,
    sims: &[Value],
    approvals: &[Value],
    releases: &[Value],
) -> Value {
    let (report, approval, release) = gate_inputs_from(proposal, sims, approvals, releases);
    let gate = evaluate_improvement_gate(
        proposal,
        report.as_ref(),
        approval.as_ref(),
        release.as_ref(),
    );
    json!({
        "posture": gate.posture,
        "block_code": gate.block.map(|(code, _)| code),
        "high_impact": report.as_ref().and_then(|r| r.pointer("/governance/high_impact")).cloned().unwrap_or(Value::Null),
        "approval_status": approval.as_ref().map(|a| text(a, "status").to_string()),
        "release_state": release.as_ref().map(|r| text(r, "state").to_string()),
        "release_rollout_mode": release.as_ref().map(|r| { let m = text(r, "rollout_mode"); if m.is_empty() { "full".to_string() } else { m.to_string() } }),
    })
}

pub(crate) async fn handle_improvement_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = read_record_dir(&st.data_dir, IMPROVEMENT_KIND)
        .into_iter()
        .find(|p| text(p, "improvement_id") == id)
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "improvement_not_found",
            "Unknown improvement proposal.",
        );
    };
    let gate = gate_projection(&st, &proposal);
    if let Some(object) = proposal.as_object_mut() {
        object.insert("gate".into(), gate);
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "proposal": proposal })),
    )
}

pub(crate) async fn handle_improvement_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = read_record_dir(&st.data_dir, IMPROVEMENT_KIND)
        .into_iter()
        .find(|p| text(p, "improvement_id") == id)
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "improvement_not_found",
            "Unknown improvement proposal.",
        );
    };
    if !["pending", "approved"].contains(&text(&proposal, "state")) {
        return bad(
            StatusCode::CONFLICT,
            "improvement_not_editable",
            "Only pending/approved proposals can be edited or bound to governance controls.",
        );
    }
    if record_has_credential_material(&body) {
        return bad(
            StatusCode::FORBIDDEN,
            "memory_entry_credential_material_forbidden",
            "Proposals must not contain credential material.",
        );
    }
    // Governance binding: the control must exist NOW and target the proposal or its simulation.
    let subjects = [
        text(&proposal, "proposal_ref").to_string(),
        text(&proposal, "latest_simulation_ref").to_string(),
    ];
    if let Some(reference) = body.get("approval_request_ref").and_then(Value::as_str) {
        let Some(record) = load_by_ref(&st, GOV_APPROVAL_KIND, reference, "approval-request")
        else {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "governance_ref_unresolved",
                "approval_request_ref does not resolve to a recorded ApprovalRequest.",
            );
        };
        if !subjects.contains(&text(&record, "subject_ref").to_string()) {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "governance_subject_mismatch",
                "The ApprovalRequest must target this proposal or its simulation report.",
            );
        }
        proposal["approval_request_ref"] = json!(reference);
    }
    if let Some(reference) = body.get("release_control_ref").and_then(Value::as_str) {
        let Some(record) = load_by_ref(&st, GOV_RELEASE_KIND, reference, "release-control") else {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "governance_ref_unresolved",
                "release_control_ref does not resolve to a recorded ReleaseControl.",
            );
        };
        if !subjects.contains(&text(&record, "release_target_ref").to_string()) {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "governance_subject_mismatch",
                "The ReleaseControl must target this proposal or its simulation report.",
            );
        }
        proposal["release_control_ref"] = json!(reference);
    }
    // Content mutation — freshness is NOT reset here; the fingerprint check at apply time
    // makes any previously saved simulation stale automatically.
    for key in [
        "suggested",
        "evidence_refs",
        "target_ref",
        "reason",
        "confidence",
    ] {
        if let Some(value) = body.get(key) {
            proposal[key] = value.clone();
        }
    }
    proposal["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, IMPROVEMENT_KIND, &id, &proposal);
    let gate = gate_projection(&st, &proposal);
    if let Some(object) = proposal.as_object_mut() {
        object.insert("gate".into(), gate);
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "proposal": proposal })),
    )
}

pub(crate) async fn handle_improvement_apply(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(proposal) = read_record_dir(&st.data_dir, IMPROVEMENT_KIND)
        .into_iter()
        .find(|p| text(p, "improvement_id") == id)
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "improvement_not_found",
            "Unknown improvement proposal.",
        );
    };
    if text(&proposal, "state") != "approved" {
        return bad(StatusCode::CONFLICT, "improvement_not_approved", "Apply requires an APPROVED proposal (creation changes nothing; approval is the review).");
    }
    let (report, approval, release) = gate_inputs(&st, &proposal);
    let decision = evaluate_improvement_gate(
        &proposal,
        report.as_ref(),
        approval.as_ref(),
        release.as_ref(),
    );
    if let Some((code, message)) = decision.block {
        return bad(StatusCode::CONFLICT, code, message);
    }
    let kind = text(&proposal, "proposal_kind").to_string();
    let suggested = proposal.get("suggested").cloned().unwrap_or(json!({}));
    let applied_ref: String;
    match kind.as_str() {
        "skill_improvement" => {
            // Approved learning becomes an ACCEPTED skill carrying its evidence.
            let mut payload = suggested.clone();
            payload["quality_state"] = json!("accepted");
            payload["source_refs"] = proposal.get("evidence_refs").cloned().unwrap_or(json!([]));
            let (status, Json(response)) =
                family_create(&st, &SKILL_FAMILY, &payload, validate_skill);
            if status != StatusCode::CREATED {
                return (status, Json(response));
            }
            applied_ref = response
                .pointer("/record/skill_ref")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        "automation_readiness" => {
            let target = text(&proposal, "target_ref");
            if target.starts_with("automation-affinity://") {
                let tid = target
                    .trim_start_matches("automation-affinity://")
                    .to_string();
                let (status, Json(response)) =
                    family_patch(&st, &AFFINITY_FAMILY, &tid, &suggested, validate_affinity);
                if status != StatusCode::OK {
                    return (status, Json(response));
                }
                applied_ref = target.to_string();
            } else {
                let (status, Json(response)) =
                    family_create(&st, &AFFINITY_FAMILY, &suggested, validate_affinity);
                if status != StatusCode::CREATED {
                    return (status, Json(response));
                }
                applied_ref = response
                    .pointer("/record/affinity_ref")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
            }
        }
        _ => {
            // launch_policy_suggestion: NEVER mutates a protected seed — clone it, patch the clone;
            // a non-protected target patches in place. Both through the ordinary policy lanes.
            let target = text(&proposal, "target_ref")
                .trim_start_matches("ioi-agent-policy://")
                .to_string();
            let client = reqwest::Client::new();
            // A canary/cohort ReleaseControl bounds the audience: apply creates a rollout-bound
            // VARIANT (clone + patch + rollout provenance) — the base policy is never replaced.
            let rollout_mode = release
                .as_ref()
                .map(|r| text(r, "rollout_mode").to_string())
                .unwrap_or_default();
            if rollout_mode == "canary" || rollout_mode == "cohort" {
                if target.is_empty() {
                    return bad(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "improvement_rollout_target_required",
                        "A canary/cohort rollout needs a target base policy to bound against.",
                    );
                }
                let base = load_policy_record(&st, &target).unwrap_or(Value::Null);
                let cloned = client
                    .post(format!("{}/v1/hypervisor/ioi-agent/launch-policies/{target}/clone", st.base_url))
                    .json(&json!({ "display_name": format!("{} ({} rollout)", text(&base, "display_name"), rollout_mode) }))
                    .send().await.ok();
                let clone_body = match cloned {
                    Some(resp) => resp.json::<Value>().await.unwrap_or(Value::Null),
                    None => Value::Null,
                };
                let variant_id = clone_body
                    .pointer("/policy/policy_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if variant_id.is_empty() {
                    return bad(
                        StatusCode::BAD_GATEWAY,
                        "improvement_policy_clone_failed",
                        "Could not clone the base policy for the rollout variant.",
                    );
                }
                let patched = client
                    .patch(format!(
                        "{}/v1/hypervisor/ioi-agent/launch-policies/{variant_id}",
                        st.base_url
                    ))
                    .json(&suggested)
                    .send()
                    .await
                    .ok();
                if !patched.map(|r| r.status().is_success()).unwrap_or(false) {
                    return bad(
                        StatusCode::BAD_GATEWAY,
                        "improvement_policy_patch_failed",
                        "Rollout variant patch was rejected.",
                    );
                }
                let bound = super::ioi_agent_routes::bind_policy_rollout(
                    &st,
                    &variant_id,
                    json!({
                        "base_policy_ref": format!("ioi-agent-policy://{target}"),
                        "release_control_ref": proposal.get("release_control_ref").cloned().unwrap_or(Value::Null),
                        "proposal_ref": text(&proposal, "proposal_ref"),
                        "simulation_ref": proposal.get("latest_simulation_ref").cloned().unwrap_or(Value::Null),
                        "approval_request_ref": proposal.get("approval_request_ref").cloned().unwrap_or(Value::Null),
                        "mode": rollout_mode,
                        "state": "active",
                        "applied_at": iso_now(),
                    }),
                );
                if bound.is_none() {
                    return bad(
                        StatusCode::BAD_GATEWAY,
                        "improvement_rollout_bind_failed",
                        "Could not bind rollout provenance to the variant.",
                    );
                }
                applied_ref = format!("ioi-agent-policy://{variant_id}");
                return finish_apply(&st, proposal, applied_ref).await;
            }
            let patch_target: String;
            if !target.is_empty() {
                let existing = client
                    .get(format!(
                        "{}/v1/hypervisor/ioi-agent/launch-policies/{target}",
                        st.base_url
                    ))
                    .send()
                    .await
                    .ok();
                let policy = match existing {
                    Some(resp) => resp.json::<Value>().await.unwrap_or(Value::Null),
                    None => Value::Null,
                };
                let protected =
                    policy.pointer("/policy/protected").and_then(Value::as_bool) == Some(true);
                if protected {
                    let cloned = client
                        .post(format!("{}/v1/hypervisor/ioi-agent/launch-policies/{target}/clone", st.base_url))
                        .json(&json!({ "display_name": format!("{} (learned)", policy.pointer("/policy/display_name").and_then(Value::as_str).unwrap_or("policy")) }))
                        .send().await.ok();
                    let clone_body = match cloned {
                        Some(resp) => resp.json::<Value>().await.unwrap_or(Value::Null),
                        None => Value::Null,
                    };
                    patch_target = clone_body
                        .pointer("/policy/policy_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if patch_target.is_empty() {
                        return bad(
                            StatusCode::BAD_GATEWAY,
                            "improvement_policy_clone_failed",
                            "Could not clone the protected seed policy.",
                        );
                    }
                } else {
                    patch_target = target;
                }
            } else {
                // No target: create a fresh policy from the suggestion.
                let created = client
                    .post(format!(
                        "{}/v1/hypervisor/ioi-agent/launch-policies",
                        st.base_url
                    ))
                    .json(&suggested)
                    .send()
                    .await
                    .ok();
                let created_body = match created {
                    Some(resp) => resp.json::<Value>().await.unwrap_or(Value::Null),
                    None => Value::Null,
                };
                let pid = created_body
                    .pointer("/policy/policy_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if pid.is_empty() {
                    return bad(
                        StatusCode::BAD_GATEWAY,
                        "improvement_policy_create_failed",
                        "Could not create the suggested policy.",
                    );
                }
                applied_ref = format!("ioi-agent-policy://{pid}");
                return finish_apply(&st, proposal, applied_ref).await;
            }
            let patched = client
                .patch(format!(
                    "{}/v1/hypervisor/ioi-agent/launch-policies/{patch_target}",
                    st.base_url
                ))
                .json(&suggested)
                .send()
                .await
                .ok();
            let ok_patch = patched.map(|r| r.status().is_success()).unwrap_or(false);
            if !ok_patch {
                return bad(
                    StatusCode::BAD_GATEWAY,
                    "improvement_policy_patch_failed",
                    "Policy patch was rejected.",
                );
            }
            applied_ref = format!("ioi-agent-policy://{patch_target}");
        }
    }
    finish_apply(&st, proposal, applied_ref).await
}

async fn finish_apply(
    st: &DaemonState,
    proposal: Value,
    applied_ref: String,
) -> (StatusCode, Json<Value>) {
    let id = text(&proposal, "improvement_id").to_string();
    let receipt_ref = format!("receipt://hypervisor/improvement/{id}");
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.improvement-applied",
        "proposal_ref": text(&proposal, "proposal_ref"),
        "proposal_kind": text(&proposal, "proposal_kind"),
        "signal": text(&proposal, "signal"),
        "applied_ref": applied_ref,
        "evidence_refs": proposal.get("evidence_refs").cloned().unwrap_or(json!([])),
        "simulation_ref": proposal.get("latest_simulation_ref").cloned().unwrap_or(Value::Null),
        "report_hash": proposal.get("latest_simulation_hash").cloned().unwrap_or(Value::Null),
        "approval_request_ref": proposal.get("approval_request_ref").cloned().unwrap_or(Value::Null),
        "release_control_ref": proposal.get("release_control_ref").cloned().unwrap_or(Value::Null),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
    match improvement_state_change(
        st,
        &id,
        &["approved"],
        "applied",
        json!({ "applied_ref": applied_ref, "receipt_refs": [receipt_ref] }),
    )
    .await
    {
        Ok(updated) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "proposal": updated })),
        ),
        Err(rejection) => rejection,
    }
}

// ---------------------------------------------------------------------------
// Governed what-if simulation — replay stored evidence through the PURE planners with a
// proposal's counterfactual overlay. Deterministic, derived, non-mutating by default
// (save=true persists a receipted simulation report and stamps the proposal's
// latest_simulation_ref). No model or harness is ever invoked; registry facts are the
// CURRENT probed posture (recorded plainly on the report). Private/secret bodies never
// appear — refs, counts, and reason codes only.
// ---------------------------------------------------------------------------

const SIMULATION_KIND: &str = "simulation-reports";

/// The counterfactual overlay a proposal represents.
struct Overlay {
    policy_patch: Value, // launch-policy fields (harness prefs / memory_posture / privacy / failure)
    virtual_skill: Value, // suggested SkillEntry (active+accepted) or Null
    virtual_affinity: Value, // suggested AutomationAffinity or Null
}

fn overlay_of(proposal: &Value) -> Overlay {
    let suggested = proposal.get("suggested").cloned().unwrap_or(json!({}));
    match text(proposal, "proposal_kind") {
        "launch_policy_suggestion" => Overlay {
            policy_patch: suggested,
            virtual_skill: Value::Null,
            virtual_affinity: Value::Null,
        },
        "skill_improvement" => Overlay {
            policy_patch: json!({}),
            virtual_skill: json!({
                "skill_ref": "skill-entry://simulated",
                "title": text(&suggested, "title"),
                "description": text(&suggested, "description"),
                "status": "active",
                "quality_state": "accepted",
                "compatible_harness_refs": suggested.get("compatible_harness_refs").cloned().unwrap_or(json!([])),
                "compatible_model_route_refs": suggested.get("compatible_model_route_refs").cloned().unwrap_or(json!([])),
            }),
            virtual_affinity: Value::Null,
        },
        _ => Overlay {
            policy_patch: json!({}),
            virtual_skill: Value::Null,
            virtual_affinity: json!({
                "affinity_ref": "automation-affinity://simulated",
                "title": text(&suggested, "title"),
                "goal_pattern": text(&suggested, "goal_pattern"),
                "preferred_policy_ref": text(&suggested, "preferred_policy_ref"),
                "status": "active",
                "quality_state": "accepted",
            }),
        },
    }
}

/// Merge the overlay policy patch over a base policy record (target or defaults).
fn overlaid_policy(base: &Value, patch: &Value) -> Value {
    let mut merged = if base.is_object() {
        base.clone()
    } else {
        json!({})
    };
    if let (Some(target), Some(fields)) = (merged.as_object_mut(), patch.as_object()) {
        for (key, value) in fields {
            target.insert(key.clone(), value.clone());
        }
    }
    merged
}

fn projection_ctx_for(
    policy: &Value,
    harness: &str,
    route: &str,
    goal: &str,
    privacy: &str,
    live: Vec<String>,
) -> ProjectionContext {
    let posture = policy.get("memory_posture").cloned().unwrap_or(Value::Null);
    let private_mode = privacy == "private_local";
    ProjectionContext {
        harness_profile_ref: harness.to_string(),
        model_route_ref: route.to_string(),
        privacy_posture: privacy.to_string(),
        allow_sensitive: policy
            .pointer("/privacy/allow_private_projection")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        live_connector_ids: live,
        goal: goal.to_string(),
        allow_candidate: posture
            .get("allow_candidate_memory_projection")
            .and_then(Value::as_bool)
            .unwrap_or(!private_mode),
        include_disputed: posture
            .get("include_disputed_memory")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        max_stale_age_days: posture
            .get("max_stale_age")
            .or_else(|| posture.get("max_stale_age_days"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        require_accepted_for_private: posture
            .get("require_accepted_memory_for_private")
            .and_then(Value::as_bool)
            .unwrap_or(private_mode),
    }
}

pub(crate) async fn handle_improvement_simulate(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = read_record_dir(&st.data_dir, IMPROVEMENT_KIND)
        .into_iter()
        .find(|p| text(p, "improvement_id") == id)
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "improvement_not_found",
            "Unknown improvement proposal.",
        );
    };
    let overlay = overlay_of(&proposal);

    // Base policy: the proposal's target (when it names one) or bare defaults.
    let base_policy = match text(&proposal, "target_ref").strip_prefix("ioi-agent-policy://") {
        Some(pid) => load_policy_record(&st, pid).unwrap_or(json!({})),
        None => json!({}),
    };
    let after_policy = overlaid_policy(&base_policy, &overlay.policy_patch);

    // Current registry facts (recorded on the report — replay uses TODAY'S probed posture).
    let profiles = live_profiles(&st).await;
    let (route_ref, route_state, _, _) = route_fact(&st, None);
    let owner_services = RuntimeOwnerServices::new();
    let conductor = profiles
        .iter()
        .find(|p| text(p, "harness") == "hypervisor_worker")
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .unwrap_or(Value::Null);
    let implementer_facts: Vec<Value> = ["opencode", "deepseek_tui", "codex", "claude_code"]
        .iter()
        .filter_map(|h| profiles.iter().find(|p| text(p, "harness") == *h))
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .collect();
    let select = |policy: &Value, goal: &str, strategy: &str| -> Value {
        let policy_arg = if policy.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            Value::Null
        } else {
            json!({
                "policy_ref": text(policy, "policy_ref"),
                "harness_preferences": policy.get("harness_preferences").cloned().unwrap_or(json!({})),
                "assurance": policy.get("assurance").cloned().unwrap_or(json!({})),
                "privacy": policy.get("privacy").cloned().unwrap_or(json!({})),
            })
        };
        owner_services
            .select_ioi_agent_execution(&json!({
                "strategy": strategy,
                "normalized_goal": goal,
                "conductor_ref": text(&conductor, "profile_ref"),
                "implementer_candidates": implementer_facts,
                "policy": policy_arg,
            }))
            .unwrap_or_else(|e| json!({ "blocked": true, "reason_code": e.code }))
    };

    // Scenario subjects: explicit refs or the recent record windows.
    let window = body
        .get("replay_window")
        .and_then(Value::as_u64)
        .unwrap_or(6) as usize;
    let mut launches = read_record_dir(&st.data_dir, "ioi-agent-launches");
    launches.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    launches.retain(|l| text(l, "state") == "executed");
    launches.truncate(window);
    let mut projections = read_record_dir(&st.data_dir, PROJECTION_KIND);
    projections.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    projections.truncate(window);
    let (entries, base_skills, affinities) = gather_projection_inputs(&st).await;
    let mut overlaid_skills = base_skills.clone();
    if !overlay.virtual_skill.is_null() {
        overlaid_skills.push(overlay.virtual_skill.clone());
    }
    let mut overlaid_affinities = affinities.clone();
    if !overlay.virtual_affinity.is_null() {
        overlaid_affinities.push(overlay.virtual_affinity.clone());
    }
    let live_ids = build_projection_context(&st, &json!({}))
        .await
        .live_connector_ids;

    let mut scenarios: Vec<Value> = Vec::new();
    let mut changed_count = 0u64;
    let mut blockers_introduced = 0u64;
    let mut blockers_removed = 0u64;

    // 1+4+6: launch replay — route/strategy selection + failure/blocker deltas.
    for launch_record in &launches {
        let goal = text(launch_record, "goal");
        let strategy = {
            let s = text(launch_record, "strategy");
            if s.is_empty() {
                "auto"
            } else {
                s
            }
        };
        let before = select(&base_policy, goal, strategy);
        let after = select(&after_policy, goal, strategy);
        let before_blocked = before.get("blocked").is_some();
        let after_blocked = after.get("blocked").is_some();
        if !before_blocked && after_blocked {
            blockers_introduced += 1;
        }
        if before_blocked && !after_blocked {
            blockers_removed += 1;
        }
        let changed = before != after;
        if changed {
            changed_count += 1;
        }
        scenarios.push(json!({
            "scenario_kind": "launch_replay",
            "subject_ref": format!("ioi-agent-launch://{}", text(launch_record, "launch_id")),
            "goal_pattern": goal_pattern_key(goal),
            "before": {
                "recorded_execution_kind": text(launch_record, "execution_kind"),
                "recorded_harness_profile_ref": launch_record.get("harness_profile_ref").cloned().unwrap_or(Value::Null),
                "planned_execution_kind": before.get("planned_execution_kind").cloned().unwrap_or(Value::Null),
                "selected_harness_ref": before.get("selected_harness_ref").cloned().unwrap_or(Value::Null),
                "privacy_posture": before.get("privacy_posture").cloned().unwrap_or(Value::Null),
                "blocked_reason": before.get("reason_code").cloned().unwrap_or(Value::Null),
            },
            "after": {
                "planned_execution_kind": after.get("planned_execution_kind").cloned().unwrap_or(Value::Null),
                "selected_harness_ref": after.get("selected_harness_ref").cloned().unwrap_or(Value::Null),
                "eligible_harness_refs": after.get("eligible_harness_refs").cloned().unwrap_or(json!([])),
                "privacy_posture": after.get("privacy_posture").cloned().unwrap_or(Value::Null),
                "policy_constraints_applied": after.get("policy_constraints_applied").cloned().unwrap_or(json!([])),
                "blocked_reason": after.get("reason_code").cloned().unwrap_or(Value::Null),
                "expected_receipt_classes": if after.get("planned_execution_kind") == Some(&json!("goal_run")) {
                    json!(["receipt://goal-run/*/create", "receipt://hypervisor/goal-run-invocation/*", "receipt://hypervisor/goal-run-reconciliation/*"])
                } else {
                    json!(["receipt://hypervisor/session-execute/*"])
                },
                "failure_policy": after_policy.get("failure_policy").cloned().unwrap_or(Value::Null),
            },
            "changed": changed,
            "evidence_refs": [format!("ioi-agent-launch://{}", text(launch_record, "launch_id"))],
        }));
        // 5: affinity matching replay for the same goals.
        if !overlay.virtual_affinity.is_null() {
            let pattern = text(&overlay.virtual_affinity, "goal_pattern").to_lowercase();
            let matches_after = !pattern.is_empty() && goal.to_lowercase().contains(&pattern);
            let matched_before = affinities.iter().any(|a| {
                let p = text(a, "goal_pattern").to_lowercase();
                text(a, "status") == "active" && !p.is_empty() && goal.to_lowercase().contains(&p)
            });
            if matches_after && !matched_before {
                changed_count += 1;
                scenarios.push(json!({
                    "scenario_kind": "affinity_match_replay",
                    "subject_ref": format!("ioi-agent-launch://{}", text(launch_record, "launch_id")),
                    "before": { "automation_affinity_match": Value::Null },
                    "after": { "automation_affinity_match": text(&overlay.virtual_affinity, "title") },
                    "changed": true,
                    "evidence_refs": [format!("ioi-agent-launch://{}", text(launch_record, "launch_id"))],
                }));
            }
        }
    }

    // 2+3: memory projection replay — counts + newly included/excluded refs.
    for projection in &projections {
        let harness = text(projection, "harness_profile_ref");
        let goal = text(projection, "launch_ref");
        let privacy = text(projection, "privacy_posture");
        let recorded_counts = projection.get("counts").cloned().unwrap_or(json!({}));
        let base_ctx = projection_ctx_for(
            &base_policy,
            harness,
            &route_ref,
            goal,
            privacy,
            live_ids.clone(),
        );
        let before_plan = plan_projection(&entries, &base_skills, &affinities, &base_ctx);
        let before_counts = before_plan.get("counts").cloned().unwrap_or(json!({}));
        let ctx = projection_ctx_for(
            &after_policy,
            harness,
            &route_ref,
            goal,
            privacy,
            live_ids.clone(),
        );
        let after_plan = plan_projection(&entries, &overlaid_skills, &overlaid_affinities, &ctx);
        let after_counts = after_plan.get("counts").cloned().unwrap_or(json!({}));
        let skill_eligible = refs(after_plan.get("included_skill_refs"))
            .iter()
            .any(|r| r == "skill-entry://simulated");
        let changed = before_counts != after_counts || skill_eligible;
        if changed {
            changed_count += 1;
        }
        scenarios.push(json!({
            "scenario_kind": "memory_projection_replay",
            "subject_ref": text(projection, "projection_ref"),
            "before": { "counts": before_counts, "recorded_counts": recorded_counts },
            "after": {
                "counts": after_counts,
                "simulated_skill_eligible": skill_eligible,
                "newly_redacted": after_plan.get("redacted_entry_refs").cloned().unwrap_or(json!([])),
                "excluded_refs_with_reasons": after_plan.get("excluded_refs_with_reasons").cloned().unwrap_or(json!([])),
            },
            "changed": changed,
            "evidence_refs": [text(projection, "projection_ref"), projection.pointer("/receipt_refs/0").and_then(Value::as_str).unwrap_or("")],
        }));
    }

    // Deterministic report hash over the scenario content (no timestamps inside).
    let canonical = serde_json::to_string(&scenarios).unwrap_or_default();
    let report_hash = format!("sha256:{}", sha256_hex_str(&canonical));
    let privacy_loosened = overlay
        .policy_patch
        .pointer("/privacy/allow_private_projection")
        .and_then(Value::as_bool)
        == Some(true)
        || overlay
            .policy_patch
            .pointer("/memory_posture/include_disputed_memory")
            .and_then(Value::as_bool)
            == Some(true);
    let high_impact = changed_count >= 3 || blockers_introduced > 0 || privacy_loosened;
    let mut report = json!({
        "schema_version": "ioi.hypervisor.simulation-report.v1",
        "proposal_ref": text(&proposal, "proposal_ref"),
        "proposal_kind": text(&proposal, "proposal_kind"),
        "deterministic": true,
        "derived_only": true,
        "non_mutating": true,
        "registry_posture": "current probed registry facts (recorded, not historical)",
        "report_hash": report_hash,
        "summary": {
            "scenarios": scenarios.len(),
            "changed": changed_count,
            "blockers_introduced": blockers_introduced,
            "blockers_removed": blockers_removed,
        },
        "proposal_fingerprint": proposal_fingerprint(&proposal),
        "governance": {
            "high_impact": high_impact,
            "requirement": if high_impact {
                "enforced: applying this improvement requires a FRESH simulation, an APPROVED approval-request://, and an OPEN release-control:// targeting the proposal or this simulation report"
            } else {
                "none"
            },
            "enforced": high_impact,
            "satisfiable_target_refs": [text(&proposal, "proposal_ref")],
        },
        "scenarios": scenarios,
        "body_disclosure": "refs, counts, and reason codes only — private/secret bodies never appear",
        "runtimeTruthSource": "daemon-runtime",
    });

    // Explicit save: durable receipted report + proposal stamp. Default: read-only.
    if body.get("save").and_then(Value::as_bool) == Some(true) {
        let sim_id = format!("sim_{:x}", nanos());
        let receipt_ref = format!("receipt://hypervisor/simulation/{sim_id}");
        if let Some(object) = report.as_object_mut() {
            object.insert("simulation_id".into(), json!(sim_id));
            object.insert(
                "simulation_ref".into(),
                json!(format!("simulation-report://{sim_id}")),
            );
            object.insert("receipt_refs".into(), json!([receipt_ref]));
            object.insert("created_at".into(), json!(iso_now()));
        }
        if let Some(targets) = report
            .pointer_mut("/governance/satisfiable_target_refs")
            .and_then(Value::as_array_mut)
        {
            targets.push(json!(format!("simulation-report://{sim_id}")));
        }
        let _ = persist_record(&st.data_dir, SIMULATION_KIND, &sim_id, &report);
        let receipt = json!({
            "id": receipt_ref,
            "kind": "hypervisor.simulation-report",
            "simulation_ref": format!("simulation-report://{sim_id}"),
            "proposal_ref": text(&proposal, "proposal_ref"),
            "report_hash": report.get("report_hash").cloned().unwrap_or(Value::Null),
            "summary": report.get("summary").cloned().unwrap_or(json!({})),
            "high_impact": high_impact,
            "at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        });
        let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
        if let Some(object) = proposal.as_object_mut() {
            object.insert(
                "latest_simulation_ref".into(),
                json!(format!("simulation-report://{sim_id}")),
            );
            object.insert(
                "latest_simulation_hash".into(),
                report.get("report_hash").cloned().unwrap_or(Value::Null),
            );
            object.insert("latest_simulation_high_impact".into(), json!(high_impact));
        }
        let _ = persist_record(&st.data_dir, IMPROVEMENT_KIND, &id, &proposal);
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "report": report })),
    )
}

fn load_policy_record(st: &DaemonState, id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, "ioi-agent-launch-policies")
        .into_iter()
        .find(|p| text(p, "policy_id") == id)
}

pub(crate) async fn handle_simulation_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match read_record_dir(&st.data_dir, SIMULATION_KIND)
        .into_iter()
        .find(|r| text(r, "simulation_id") == id)
    {
        Some(report) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "report": report })),
        ),
        None => bad(
            StatusCode::NOT_FOUND,
            "simulation_not_found",
            "Unknown simulation report.",
        ),
    }
}

#[cfg(test)]
mod improvement_gate_tests {
    use super::*;

    fn proposal(kind: &str, sim: Option<&str>) -> Value {
        let mut p = json!({
            "proposal_kind": kind,
            "proposal_ref": "improvement-proposal://imp_t",
            "target_ref": Value::Null,
            "suggested": { "title": "t" },
            "evidence_refs": ["x://e"],
        });
        if let Some(s) = sim {
            p["latest_simulation_ref"] = json!(s);
        }
        p
    }
    fn fresh_report(p: &Value, high: bool) -> Value {
        json!({
            "proposal_fingerprint": proposal_fingerprint(p),
            "governance": { "high_impact": high },
        })
    }

    #[test]
    fn policy_without_simulation_blocks() {
        let p = proposal("launch_policy_suggestion", None);
        let d = evaluate_improvement_gate(&p, None, None, None);
        assert_eq!(d.posture, "simulation_required");
        assert_eq!(d.block.unwrap().0, "simulation_required");
    }

    #[test]
    fn skill_without_simulation_keeps_existing_behavior() {
        let p = proposal("skill_improvement", None);
        let d = evaluate_improvement_gate(&p, None, None, None);
        assert_eq!(d.posture, "no_simulation");
        assert!(d.block.is_none());
    }

    #[test]
    fn mutated_proposal_makes_simulation_stale() {
        let mut p = proposal(
            "launch_policy_suggestion",
            Some("simulation-report://sim_t"),
        );
        let report = fresh_report(&p, true);
        p["suggested"] = json!({ "title": "changed after simulate" });
        let d = evaluate_improvement_gate(&p, Some(&report), None, None);
        assert_eq!(d.posture, "simulation_stale");
        assert_eq!(d.block.unwrap().0, "simulation_stale");
    }

    #[test]
    fn missing_report_record_is_stale_not_trusted() {
        let p = proposal("skill_improvement", Some("simulation-report://sim_gone"));
        let d = evaluate_improvement_gate(&p, None, None, None);
        assert_eq!(d.block.unwrap().0, "simulation_stale");
    }

    #[test]
    fn fresh_low_impact_applies_without_controls() {
        let p = proposal(
            "launch_policy_suggestion",
            Some("simulation-report://sim_t"),
        );
        let report = fresh_report(&p, false);
        let d = evaluate_improvement_gate(&p, Some(&report), None, None);
        assert_eq!(d.posture, "low_impact");
        assert!(d.block.is_none());
    }

    #[test]
    fn high_impact_requires_approval_then_release() {
        let p = proposal(
            "launch_policy_suggestion",
            Some("simulation-report://sim_t"),
        );
        let report = fresh_report(&p, true);
        assert_eq!(
            evaluate_improvement_gate(&p, Some(&report), None, None)
                .block
                .unwrap()
                .0,
            "approval_required"
        );
        let pending = json!({ "subject_ref": "improvement-proposal://imp_t", "status": "pending" });
        assert_eq!(
            evaluate_improvement_gate(&p, Some(&report), Some(&pending), None)
                .block
                .unwrap()
                .0,
            "approval_not_approved"
        );
        let approved = json!({ "subject_ref": "simulation-report://sim_t", "status": "approved" });
        assert_eq!(
            evaluate_improvement_gate(&p, Some(&report), Some(&approved), None)
                .block
                .unwrap()
                .0,
            "release_control_required"
        );
        let closed =
            json!({ "release_target_ref": "improvement-proposal://imp_t", "state": "closed" });
        assert_eq!(
            evaluate_improvement_gate(&p, Some(&report), Some(&approved), Some(&closed))
                .block
                .unwrap()
                .0,
            "release_control_not_open"
        );
        let open = json!({ "release_target_ref": "improvement-proposal://imp_t", "state": "open" });
        let d = evaluate_improvement_gate(&p, Some(&report), Some(&approved), Some(&open));
        assert_eq!(d.posture, "ready");
        assert!(d.block.is_none());
    }

    #[test]
    fn wrong_subject_controls_do_not_satisfy_the_gate() {
        let p = proposal("skill_improvement", Some("simulation-report://sim_t"));
        let report = fresh_report(&p, true);
        let foreign =
            json!({ "subject_ref": "improvement-proposal://imp_OTHER", "status": "approved" });
        assert_eq!(
            evaluate_improvement_gate(&p, Some(&report), Some(&foreign), None)
                .block
                .unwrap()
                .0,
            "approval_required"
        );
        let approved =
            json!({ "subject_ref": "improvement-proposal://imp_t", "status": "approved" });
        let foreign_rel =
            json!({ "release_target_ref": "simulation-report://sim_OTHER", "state": "open" });
        assert_eq!(
            evaluate_improvement_gate(&p, Some(&report), Some(&approved), Some(&foreign_rel))
                .block
                .unwrap()
                .0,
            "release_control_required"
        );
    }
}
