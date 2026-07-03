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
