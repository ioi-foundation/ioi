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

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

pub(crate) const SPACE_KIND: &str = "memory-spaces";
pub(crate) const ENTRY_KIND: &str = "memory-entries";
pub(crate) const SKILL_KIND: &str = "skill-entries";
pub(crate) const AFFINITY_KIND: &str = "automation-affinities";
pub(crate) const PROJECTION_KIND: &str = "memory-projections";

const ENTRY_KINDS: &[&str] = &[
    "preference", "instruction", "fact", "concept", "entity", "workstream",
    "note", "correction", "tool_affordance", "blocker", "connector_derived",
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
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// The default portable workspace space — created on first read, never a fixture.
pub(crate) fn ensure_default_space(st: &DaemonState) -> Value {
    let spaces = read_record_dir(&st.data_dir, SPACE_KIND);
    if let Some(space) = spaces.iter().find(|s| text(s, "space_id") == "ms_workspace_default") {
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
            return Err(bad(StatusCode::BAD_REQUEST, "memory_entry_kind_invalid", &format!("entry_kind must be one of {ENTRY_KINDS:?}")));
        }
        record["entry_kind"] = json!(kind);
    }
    if let Some(sens) = body.get("sensitivity").and_then(Value::as_str) {
        if !SENSITIVITIES.contains(&sens) {
            return Err(bad(StatusCode::BAD_REQUEST, "memory_entry_sensitivity_invalid", "sensitivity must be normal|private|secret"));
        }
        record["sensitivity"] = json!(sens);
    }
    // connector_derived entries carry connector refs, NEVER credentials — reject anything that
    // smells like a sealed secret in the payload (defense in depth; the vault never leaves D&I).
    let blob = serde_json::to_string(body).unwrap_or_default();
    if blob.contains("sealed_client_secret") || blob.contains("IOI_WALLET_SECRET") {
        return Err(bad(StatusCode::FORBIDDEN, "memory_entry_credential_material_forbidden", "Memory entries must not contain credential material."));
    }
    if text(record, "entry_kind") == "connector_derived"
        && refs(body.get("connector_refs").or(record.get("connector_refs"))).is_empty()
    {
        return Err(bad(StatusCode::BAD_REQUEST, "memory_entry_connector_refs_required", "connector_derived entries must name their connector refs."));
    }
    for key in ["title", "body"] {
        if let Some(v) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(v.trim());
        }
    }
    for key in ["tags", "source_refs", "connector_refs", "compatible_harness_refs", "compatible_model_route_refs"] {
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
    // Self-describing records: the vault format serializes these explicitly, so defaults are
    // stored rather than implied.
    if record.get("entry_kind").and_then(Value::as_str).unwrap_or("").is_empty() {
        record["entry_kind"] = json!("note");
    }
    if record.get("sensitivity").and_then(Value::as_str).unwrap_or("").is_empty() {
        record["sensitivity"] = json!("normal");
    }
    Ok(())
}

fn validate_skill(body: &Value, record: &mut Value) -> Result<(), (StatusCode, Json<Value>)> {
    for key in ["title", "description", "body", "procedure_ref"] {
        if let Some(v) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(v.trim());
        }
    }
    for key in ["trigger_conditions", "tool_requirements", "connector_requirements", "compatible_harness_refs", "compatible_model_route_refs"] {
        if let Some(v) = body.get(key) {
            record[key] = v.clone();
        }
    }
    Ok(())
}

fn validate_affinity(body: &Value, record: &mut Value) -> Result<(), (StatusCode, Json<Value>)> {
    for key in ["title", "goal_pattern", "preferred_policy_ref", "failure_policy"] {
        if let Some(v) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(v.trim());
        }
    }
    if let Some(policy) = record.get("preferred_policy_ref").and_then(Value::as_str) {
        if !policy.is_empty() && !policy.starts_with("ioi-agent-policy://") {
            return Err(bad(StatusCode::BAD_REQUEST, "automation_affinity_policy_ref_invalid", "preferred_policy_ref must be an ioi-agent-policy:// ref"));
        }
    }
    for key in ["preferred_automation_refs", "preferred_harness_refs", "preferred_model_route_refs", "required_connector_refs"] {
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

const ENTRY_FAMILY: Family = Family { kind: ENTRY_KIND, id_prefix: "mem", id_key: "entry_id", ref_key: "entry_ref", ref_scheme: "memory-entry://", schema: "ioi.hypervisor.memory-entry.v1", plural: "entries" };
const SKILL_FAMILY: Family = Family { kind: SKILL_KIND, id_prefix: "skl", id_key: "skill_id", ref_key: "skill_ref", ref_scheme: "skill-entry://", schema: "ioi.hypervisor.skill-entry.v1", plural: "skills" };
const AFFINITY_FAMILY: Family = Family { kind: AFFINITY_KIND, id_prefix: "aff", id_key: "affinity_id", ref_key: "affinity_ref", ref_scheme: "automation-affinity://", schema: "ioi.hypervisor.automation-affinity.v1", plural: "affinities" };

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
        records.retain(|r| serde_json::to_string(r).unwrap_or_default().to_lowercase().contains(&needle));
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
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "intelligence_title_required", "A title is required.");
    }
    let space_ref = {
        let requested = text(body, "memory_space_ref");
        if requested.is_empty() { text(&space, "space_ref").to_string() } else {
            if load(st, SPACE_KIND, "space_id", requested.trim_start_matches("memory-space://")).is_none() {
                return bad(StatusCode::UNPROCESSABLE_ENTITY, "memory_space_unresolved", "Unknown memory space.");
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
    (StatusCode::CREATED, Json(json!({ "ok": true, "record": record })))
}

fn family_patch(
    st: &DaemonState,
    family: &Family,
    id: &str,
    body: &Value,
    validate: fn(&Value, &mut Value) -> Result<(), (StatusCode, Json<Value>)>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load(st, family.kind, family.id_key, id) else {
        return bad(StatusCode::NOT_FOUND, "intelligence_record_not_found", "Unknown record.");
    };
    if let Err(rejection) = validate(body, &mut record) {
        return rejection;
    }
    if let Some(status) = body.get("status").and_then(Value::as_str) {
        if !STATUSES.contains(&status) {
            return bad(StatusCode::BAD_REQUEST, "intelligence_status_invalid", "status must be active|archived|revoked");
        }
        record["status"] = json!(status);
    }
    record["updated_at"] = json!(iso_now());
    let rid = text(&record, family.id_key).to_string();
    let _ = persist_record(&st.data_dir, family.kind, &rid, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "record": record })))
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

family_handlers!(handle_entries_list, handle_entries_create, handle_entries_get, handle_entries_patch, ENTRY_FAMILY, validate_entry);
family_handlers!(handle_skills_list, handle_skills_create, handle_skills_get, handle_skills_patch, SKILL_FAMILY, validate_skill);
family_handlers!(handle_affinities_list, handle_affinities_create, handle_affinities_get, handle_affinities_patch, AFFINITY_FAMILY, validate_affinity);

pub(crate) async fn handle_spaces_list(
    State(st): State<Arc<DaemonState>>,
    Query(_q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let spaces = read_record_dir(&st.data_dir, SPACE_KIND);
    (StatusCode::OK, Json(json!({ "ok": true, "spaces": spaces })))
}

pub(crate) async fn handle_spaces_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    if text(&body, "display_name").trim().is_empty() {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "memory_space_name_required", "display_name required");
    }
    let scope = text(&body, "scope");
    if !["personal", "project", "workspace", "domain"].contains(&scope) {
        return bad(StatusCode::BAD_REQUEST, "memory_space_scope_invalid", "scope must be personal|project|workspace|domain");
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
    (StatusCode::CREATED, Json(json!({ "ok": true, "space": record })))
}

// ---------------------------------------------------------------------------
// projection planner — pure, deterministic, reason-coded
// ---------------------------------------------------------------------------

pub(crate) struct ProjectionContext {
    pub harness_profile_ref: String,
    pub model_route_ref: String,
    pub privacy_posture: String,       // standard | private_local
    pub allow_sensitive: bool,         // launch policy permits private-sensitivity inclusion
    pub live_connector_ids: Vec<String>, // connectors with a usable auth posture (lease-backed)
    pub goal: String,
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
            ctx.live_connector_ids.iter().any(|live| c.contains(live.as_str()))
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
            Some(reason) => excluded.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": reason })),
            None => {
                let sensitivity = text(entry, "sensitivity");
                // secret NEVER projects; private projects only when the policy allows.
                if sensitivity == "secret" {
                    redacted.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": "sensitivity_secret_always_redacted" }));
                } else if sensitivity == "private" && !ctx.allow_sensitive {
                    redacted.push(json!({ "ref": text(entry, "entry_ref"), "reason_code": "sensitivity_private_policy_disallows" }));
                } else {
                    included_entries.push(entry);
                }
            }
        }
    }
    let mut included_skills: Vec<&Value> = Vec::new();
    for skill in skills {
        match exclusion_reason(skill, ctx, &now) {
            Some(reason) => excluded.push(json!({ "ref": text(skill, "skill_ref"), "reason_code": reason })),
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
    // Rendered summary: titles + non-private bodies only — the harness-facing artifact.
    let mut lines: Vec<String> = Vec::new();
    for entry in &included_entries {
        let body = text(entry, "body");
        lines.push(format!(
            "[{}] {}{}",
            text(entry, "entry_kind"),
            text(entry, "title"),
            if body.is_empty() { String::new() } else { format!(": {}", body.chars().take(240).collect::<String>()) }
        ));
    }
    for skill in &included_skills {
        lines.push(format!("[skill] {}: {}", text(skill, "title"), text(skill, "description").chars().take(200).collect::<String>()));
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

pub(crate) async fn gather_projection_inputs(st: &DaemonState) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
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
                    .filter(|c| matches!(text(c, "auth_posture"), "token-lease:bound" | "open" | "local-none"))
                    .map(|c| text(c, "connector_id").to_string())
                    .collect()
            })
            .unwrap_or_default(),
        None => Vec::new(),
    };
    ProjectionContext {
        harness_profile_ref: text(body, "harness_profile_ref").to_string(),
        model_route_ref: text(body, "model_route_ref").to_string(),
        privacy_posture: if text(body, "privacy_posture").is_empty() { "standard".into() } else { text(body, "privacy_posture").to_string() },
        allow_sensitive: body.get("allow_sensitive").and_then(Value::as_bool).unwrap_or(false),
        live_connector_ids: live_ids,
        goal: text(body, "goal").to_string(),
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
    (StatusCode::CREATED, Json(json!({ "ok": true, "projection": record })))
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
    (StatusCode::OK, Json(json!({ "ok": true, "projections": projections })))
}

pub(crate) async fn handle_projections_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load(&st, PROJECTION_KIND, "projection_id", &id) {
        Some(record) => (StatusCode::OK, Json(json!({ "ok": true, "projection": record }))),
        None => bad(StatusCode::NOT_FOUND, "memory_projection_not_found", "Unknown projection."),
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
    CREDENTIAL_MARKERS.iter().any(|marker| blob.contains(marker))
}

/// Frontmatter keys per family (order is the document contract).
const ENTRY_FM_KEYS: &[&str] = &[
    "entry_id", "entry_ref", "memory_space_ref", "entry_kind", "sensitivity", "status",
    "tags", "source_refs", "connector_refs", "compatible_harness_refs",
    "compatible_model_route_refs", "confidence", "expires_at", "created_at", "updated_at",
];
const SKILL_FM_KEYS: &[&str] = &[
    "skill_id", "skill_ref", "memory_space_ref", "status", "description", "procedure_ref",
    "trigger_conditions", "tool_requirements", "connector_requirements",
    "compatible_harness_refs", "compatible_model_route_refs", "created_at", "updated_at",
];
const AFFINITY_FM_KEYS: &[&str] = &[
    "affinity_id", "affinity_ref", "memory_space_ref", "status", "goal_pattern",
    "preferred_policy_ref", "preferred_automation_refs", "preferred_harness_refs",
    "preferred_model_route_refs", "required_connector_refs", "failure_policy",
    "created_at", "updated_at",
];

fn md_document(record: &Value, keys: &[&str], title_key: &str, body_key: &str) -> String {
    let mut out = String::from("---\n");
    out.push_str(&format!("title: {}\n", serde_json::to_string(text(record, title_key)).unwrap_or_default()));
    for key in keys {
        if let Some(value) = record.get(*key) {
            if !value.is_null() {
                out.push_str(&format!("{key}: {}\n", serde_json::to_string(value).unwrap_or_default()));
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
        return bad(StatusCode::NOT_FOUND, "memory_space_not_found", "Unknown memory space.");
    };
    let space_ref = text(&space, "space_ref").to_string();
    let in_space = |r: &Value| text(r, "memory_space_ref") == space_ref;
    let mut files: Vec<Value> = vec![json!({
        "path": "vault/space.md",
        "content": md_document(&space, &["space_id", "space_ref", "scope", "owner_ref", "privacy_posture", "status", "created_at", "updated_at"], "display_name", "description"),
    })];
    let mut structured_payloads = serde_json::Map::new();
    let mut scrubbed: Vec<Value> = Vec::new();
    for entry in read_record_dir(&st.data_dir, ENTRY_KIND).iter().filter(|r| in_space(r)) {
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
    for skill in read_record_dir(&st.data_dir, SKILL_KIND).iter().filter(|r| in_space(r)) {
        if record_has_credential_material(skill) {
            scrubbed.push(json!({ "ref": text(skill, "skill_ref"), "reason_code": "credential_material_scrubbed" }));
            continue;
        }
        files.push(json!({
            "path": format!("vault/skills/{}.md", text(skill, "skill_id")),
            "content": md_document(skill, SKILL_FM_KEYS, "title", "body"),
        }));
    }
    for affinity in read_record_dir(&st.data_dir, AFFINITY_KIND).iter().filter(|r| in_space(r)) {
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
        Json(json!({ "ok": true, "vault": { "format": VAULT_SCHEMA_VERSION, "manifest": manifest, "files": files } })),
    )
}

pub(crate) async fn handle_vault_import(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let vault = body.get("vault").cloned().unwrap_or(body.clone());
    let files = vault.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
    if files.is_empty() {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "memory_vault_empty", "The vault bundle carries no files.");
    }
    // Whole-bundle credential scan FIRST — nothing imports if any file smells like a secret.
    if record_has_credential_material(&vault) {
        return bad(StatusCode::FORBIDDEN, "memory_vault_credential_material_forbidden", "Vault bundles must not contain credential material.");
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
            for volatile in ["updated_at", "created_at", "imported_at", "runtimeTruthSource", "schema_version"] {
                a.as_object_mut().map(|o| o.remove(volatile));
                b.as_object_mut().map(|o| o.remove(volatile));
            }
            // Default-equivalence: legacy rows stored before defaults became explicit compare
            // equal to their default-filled vault form (a real content edit still conflicts).
            if family == "entries" {
                for side in [&mut a, &mut b] {
                    if side.get("entry_kind").and_then(Value::as_str).unwrap_or("").is_empty() {
                        side["entry_kind"] = json!("note");
                    }
                    if side.get("sensitivity").and_then(Value::as_str).unwrap_or("").is_empty() {
                        side["sensitivity"] = json!("normal");
                    }
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
    "fact", "preference", "doctrine", "route", "procedure", "eval", "failure",
    "tool_affordance", "game_lesson", "project_convention", "connector_observation",
];
const SOURCE_AUTHORITIES: &[&str] = &["user", "worker", "verifier", "benchmark", "service_delivery", "admin"];

pub(crate) async fn handle_proposals_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut proposals = read_record_dir(&st.data_dir, PROPOSAL_KIND);
    if let Some(state) = query.get("review_state") {
        proposals.retain(|p| text(p, "review_state") == state);
    }
    proposals.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    (StatusCode::OK, Json(json!({ "ok": true, "proposals": proposals })))
}

pub(crate) async fn handle_proposals_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_default_space(&st);
    let operation = text(&body, "operation");
    if !PROPOSAL_OPERATIONS.contains(&operation) {
        return bad(StatusCode::BAD_REQUEST, "memory_mutation_operation_invalid", "operation must be add|supersede|archive");
    }
    let mutation_type = text(&body, "mutation_type");
    if !MUTATION_TYPES.contains(&mutation_type) {
        return bad(StatusCode::BAD_REQUEST, "memory_mutation_type_invalid", &format!("mutation_type must be one of {MUTATION_TYPES:?}"));
    }
    let source_authority = { let v = text(&body, "source_authority"); if v.is_empty() { "worker" } else { v } };
    if !SOURCE_AUTHORITIES.contains(&source_authority) {
        return bad(StatusCode::BAD_REQUEST, "memory_mutation_source_authority_invalid", "invalid source_authority");
    }
    if record_has_credential_material(&body) {
        return bad(StatusCode::FORBIDDEN, "memory_entry_credential_material_forbidden", "Proposals must not contain credential material.");
    }
    let suggested = body.get("suggested").cloned().unwrap_or(json!({}));
    if operation != "archive" && text(&suggested, "title").trim().is_empty() {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "memory_mutation_suggested_title_required", "add/supersede proposals need suggested.title");
    }
    if operation != "add" && !text(&body, "target_ref").starts_with("memory-entry://") && !text(&body, "target_ref").starts_with("skill-entry://") {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "memory_mutation_target_required", "supersede/archive proposals need a memory-entry:// or skill-entry:// target_ref");
    }
    let id = format!("ctxmut_{:x}", nanos());
    let space_ref = {
        let requested = text(&body, "memory_space_ref");
        if requested.is_empty() { "memory-space://ms_workspace_default".to_string() } else { requested.to_string() }
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
    (StatusCode::CREATED, Json(json!({ "ok": true, "proposal": record })))
}

pub(crate) async fn handle_proposal_approve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = load(&st, PROPOSAL_KIND, "mutation_id", &id) else {
        return bad(StatusCode::NOT_FOUND, "memory_mutation_not_found", "Unknown proposal.");
    };
    if text(&proposal, "review_state") != "proposed" {
        return bad(StatusCode::CONFLICT, "memory_mutation_already_reviewed", "This proposal has already been reviewed.");
    }
    let operation = text(&proposal, "operation").to_string();
    let family = if text(&proposal, "target_family") == "skill" { &SKILL_FAMILY } else { &ENTRY_FAMILY };
    let validate: fn(&Value, &mut Value) -> Result<(), (StatusCode, Json<Value>)> =
        if text(&proposal, "target_family") == "skill" { validate_skill } else { validate_entry };
    let suggested = proposal.get("suggested").cloned().unwrap_or(json!({}));
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
            let target = text(&proposal, "target_ref").rsplit('/').next().unwrap_or("").to_string();
            let (status, Json(response)) = family_patch(&st, family, &target, &suggested, validate);
            if status != StatusCode::OK {
                return (status, Json(response));
            }
            applied_ref = text(&proposal, "target_ref").to_string();
        }
        _ => {
            let target = text(&proposal, "target_ref").rsplit('/').next().unwrap_or("").to_string();
            let (status, Json(response)) = family_patch(&st, family, &target, &json!({ "status": "archived" }), validate);
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
    (StatusCode::OK, Json(json!({ "ok": true, "proposal": proposal })))
}

pub(crate) async fn handle_proposal_reject(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut proposal) = load(&st, PROPOSAL_KIND, "mutation_id", &id) else {
        return bad(StatusCode::NOT_FOUND, "memory_mutation_not_found", "Unknown proposal.");
    };
    if text(&proposal, "review_state") != "proposed" {
        return bad(StatusCode::CONFLICT, "memory_mutation_already_reviewed", "This proposal has already been reviewed.");
    }
    if let Some(object) = proposal.as_object_mut() {
        object.insert("review_state".into(), json!("rejected"));
        object.insert("review_reason".into(), json!(text(&body, "reason")));
        object.insert("reviewed_at".into(), json!(iso_now()));
    }
    let _ = persist_record(&st.data_dir, PROPOSAL_KIND, &id, &proposal);
    (StatusCode::OK, Json(json!({ "ok": true, "proposal": proposal })))
}
